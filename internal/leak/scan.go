package leak

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxScanFileSize  = 2 << 20
	maxScanObject    = 32 << 20
	maxScanFiles     = 100000
	maxScanBytes     = 1 << 30
	maxGitOutput     = 1 << 30
	maxGitScanLines  = 5_000_000
	maxGenericSecret = 500
)

// Rule is one detection rule.
type Rule struct {
	Name     string
	Pattern  *regexp.Regexp
	Mask     bool
	Group    int
	Priority int
	// Decode, when set, turns a match into its decoded plaintext. The match is
	// dropped if decoding fails or the result does not look like a flag.
	Decode func(string) string
}

// ScanFinding is one deduplicated match. Value is safe for output; Raw is
// retained only in memory for deduplication.
type ScanFinding struct {
	Rule   string
	Value  string
	Raw    string
	Source string
	Path   string
	Line   int
	Commit string
}

// ScanOptions controls history and worktree scanning.
type ScanOptions struct {
	RepoDir     string
	OutDir      string
	FlagPattern string
	UseGit      bool
	Gitleaks    bool
	Verbose     bool
	Timeout     time.Duration
	Concurrency int
}

// ScanResult is the output of Scan.
type ScanResult struct {
	Findings     []ScanFinding
	Warnings     []string
	Sources      map[string]int
	GitUsed      bool
	GitleaksUsed bool
}

// FindingsMeta is written at the top of findings.txt.
type FindingsMeta struct {
	Target       string
	Generated    time.Time
	Sources      map[string]int
	Warnings     []string
	GitUsed      bool
	GitleaksUsed bool
}

const (
	defaultFlagPattern = `flag\{[^}]{1,200}\}`
	hexFlagPattern     = `(?i)666c61677b[0-9a-f]*?7d`
	base64FlagPattern  = `ZmxhZ3[A-Za-z0-9+/_-]*={0,2}`
	binaryFlagPattern  = `01100110011011000110000101100111(?:[01]{8})*01111101`
	entityFlagPattern  = `(?:&#102;|&#[xX]66;)(?:&#(?:108|49);|&#[xX](?:6[cC]|31);)(?:&#97;|&#[xX]61;)(?:&#103;|&#[xX]67;)(?:&#\d{1,7};|&#[xX][0-9A-Fa-f]{1,6};)*`
)

// BuildRules compiles the built-in rules plus the user's flag pattern. When the
// user leaves the pattern empty, the default plaintext flag rule is extended
// with the common encoded forms so a flag is found no matter how it is stored.
func BuildRules(flagPattern string) ([]Rule, error) {
	rules := make([]Rule, 0, 9)
	if strings.TrimSpace(flagPattern) == "" {
		rules = append(rules, defaultFlagRules()...)
	} else {
		flagRE, err := regexp.Compile(flagPattern)
		if err != nil {
			return nil, fmt.Errorf("invalid flag pattern: %w", err)
		}
		rules = append(rules, Rule{Name: "flag", Pattern: flagRE, Group: 0, Priority: 0})
	}
	rules = append(rules,
		Rule{Name: "Private key", Pattern: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`), Mask: true, Group: 0, Priority: 5},
		Rule{Name: "AWS access key ID", Pattern: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), Mask: true, Group: 0, Priority: 10},
		Rule{Name: "GitHub token", Pattern: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b`), Mask: true, Group: 0, Priority: 20},
		Rule{Name: "Generic secret assignment", Pattern: regexp.MustCompile(`(?i)\b(?:[A-Za-z0-9_-]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token))\b\s*[:=]\s*['"]?([^\s'"]{6,})`), Mask: true, Group: 1, Priority: 30},
	)
	return rules, nil
}

func defaultFlagRules() []Rule {
	return []Rule{
		{Name: "flag", Pattern: regexp.MustCompile(defaultFlagPattern), Group: 0, Priority: 0},
		{Name: "flag-hex", Pattern: regexp.MustCompile(hexFlagPattern), Group: 0, Priority: 0, Decode: decodeHexFlag},
		{Name: "flag-base64", Pattern: regexp.MustCompile(base64FlagPattern), Group: 0, Priority: 0, Decode: decodeBase64Flag},
		{Name: "flag-ascii-bin", Pattern: regexp.MustCompile(binaryFlagPattern), Group: 0, Priority: 0, Decode: decodeBinaryFlag},
		{Name: "flag-unicode-entity", Pattern: regexp.MustCompile(entityFlagPattern), Group: 0, Priority: 0, Decode: decodeEntityFlag},
	}
}

// Scan performs worktree, loose-object, metadata and optional Git-history
// scans. Loose objects are always scanned so dangling blobs are not missed
// even when git is unavailable.
func Scan(ctx context.Context, opts ScanOptions) (*ScanResult, error) {
	rules, err := BuildRules(opts.FlagPattern)
	if err != nil {
		return nil, err
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Minute
	}
	if opts.OutDir == "" {
		opts.OutDir = filepath.Dir(opts.RepoDir)
	}

	result := &ScanResult{Sources: make(map[string]int)}
	seen := make(map[string]bool)
	emit := func(f ScanFinding) {
		f.Raw = strings.TrimSpace(f.Raw)
		if f.Raw == "" {
			return
		}
		if len([]rune(f.Raw)) > maxGenericSecret {
			f.Raw = string([]rune(f.Raw)[:maxGenericSecret])
		}
		key := f.Rule + "\x00" + f.Raw
		if seen[key] {
			return
		}
		seen[key] = true
		if f.Value == "" {
			f.Value = f.Raw
		}
		if strings.HasPrefix(f.Rule, "gitleaks:") {
			f.Value = MaskValue(f.Value)
		} else {
			for _, rule := range rules {
				if rule.Name == f.Rule && rule.Mask {
					f.Value = MaskValue(f.Value)
					break
				}
			}
		}
		result.Findings = append(result.Findings, f)
		result.Sources[f.Source]++
	}

	repoAvailable := false
	if info, err := os.Stat(opts.RepoDir); err != nil || !info.IsDir() {
		result.Warnings = append(result.Warnings, "repository directory is not available; skipping worktree and object scan")
	} else {
		repoAvailable = true
		scanWorktree(ctx, opts.RepoDir, rules, emit, result)
	}

	if opts.UseGit {
		if !gitRepoValid(ctx, opts.RepoDir) {
			result.Warnings = append(result.Warnings, "git history scan skipped: git is unavailable or the reconstructed repository is not usable")
		} else {
			result.GitUsed = true
			runGitScan(ctx, opts, "history", []string{"log", "-p", "--all", "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/"}, rules, emit, result)
			runGitScan(ctx, opts, "reflog", []string{"reflog", "--all", "--date=iso"}, rules, emit, result)
			scanStashes(ctx, opts, rules, emit, result)
			runGitScan(ctx, opts, "fsck", []string{"fsck", "--lost-found", "--no-reflogs"}, rules, emit, result)
			scanLostFound(ctx, opts.RepoDir, rules, emit, result)
		}
	}

	if repoAvailable {
		scanLooseObjects(ctx, opts.RepoDir, rules, emit, result)
		scanMetadata(ctx, opts.RepoDir, rules, emit, result)
	}

	if opts.Gitleaks {
		scanGitleaks(ctx, opts, emit, result)
	}

	sort.SliceStable(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if rulePriority(a.Rule) != rulePriority(b.Rule) {
			return rulePriority(a.Rule) < rulePriority(b.Rule)
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		if a.Value != b.Value {
			return a.Value < b.Value
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Line < b.Line
	})
	return result, nil
}

func rulePriority(name string) int {
	if name == "flag" || strings.HasPrefix(name, "flag-") {
		return 0
	}
	switch name {
	case "Private key":
		return 5
	case "AWS access key ID":
		return 10
	case "GitHub token":
		return 20
	case "Generic secret assignment":
		return 30
	}
	if strings.HasPrefix(name, "gitleaks:") {
		return 40
	}
	return 50
}

func scanWorktree(ctx context.Context, repoDir string, rules []Rule, emit func(ScanFinding), result *ScanResult) {
	files := 0
	bytesRead := int64(0)
	err := filepath.WalkDir(repoDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".hg", ".svn":
				if path != repoDir {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		if files >= maxScanFiles || bytesRead >= maxScanBytes {
			return filepath.SkipAll
		}
		info, err := entry.Info()
		if err != nil || info.Size() > maxScanFileSize {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		files++
		bytesRead += int64(len(data))
		if IsBinary(data) {
			return nil
		}
		rel, err := filepath.Rel(repoDir, path)
		if err != nil {
			return nil
		}
		scanText(data, "worktree", filepath.ToSlash(rel), "", rules, emit)
		return nil
	})
	if err != nil && ctx.Err() == nil && !errors.Is(err, filepath.SkipAll) {
		result.Warnings = append(result.Warnings, "worktree scan: "+err.Error())
	}
}

func scanLooseObjects(ctx context.Context, repoDir string, rules []Rule, emit func(ScanFinding), result *ScanResult) {
	objectsDir := filepath.Join(repoDir, ".git", "objects")
	info, err := os.Stat(objectsDir)
	if err != nil || !info.IsDir() {
		return
	}
	count := 0
	bytesRead := int64(0)
	err = filepath.WalkDir(objectsDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		if count >= maxScanFiles || bytesRead >= maxScanBytes {
			return filepath.SkipAll
		}
		rel, err := filepath.Rel(objectsDir, path)
		if err != nil {
			return nil
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) != 2 || len(parts[0]) != 2 || len(parts[1]) != 38 {
			return nil
		}
		info, err := entry.Info()
		if err != nil || info.Size() > maxScanObject {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		count++
		bytesRead += int64(len(raw))
		typ, content, err := ParseLooseObject(raw)
		if err != nil {
			return nil
		}
		switch typ {
		case "blob":
			if IsBinary(content) {
				return nil
			}
			scanText(content, "object", "objects/"+filepath.ToSlash(rel), "", rules, emit)
		case "commit":
			sha := parts[0] + parts[1]
			scanText(content, "history-object", "", sha, rules, emit)
		case "tag":
			sha := parts[0] + parts[1]
			scanText(content, "tag-object", "", sha, rules, emit)
		}
		return nil
	})
	if err != nil && ctx.Err() == nil && !errors.Is(err, filepath.SkipAll) {
		result.Warnings = append(result.Warnings, "object scan: "+err.Error())
	}
}

func scanMetadata(ctx context.Context, repoDir string, rules []Rule, emit func(ScanFinding), result *ScanResult) {
	gitDir := filepath.Join(repoDir, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		return
	}
	err := filepath.WalkDir(gitDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if entry.IsDir() {
			switch entry.Name() {
			case "objects", "lost-found":
				if path != gitDir {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		base := entry.Name()
		if base == "index" || base == "index.lock" {
			return nil
		}
		info, err := entry.Info()
		if err != nil || info.Size() > maxScanFileSize {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil || IsBinary(data) {
			return nil
		}
		rel, err := filepath.Rel(repoDir, path)
		if err != nil {
			return nil
		}
		scanText(data, "metadata", filepath.ToSlash(rel), "", rules, emit)
		return nil
	})
	if err != nil && ctx.Err() == nil {
		result.Warnings = append(result.Warnings, "metadata scan: "+err.Error())
	}
}

func scanText(data []byte, source, path, commit string, rules []Rule, emit func(ScanFinding)) {
	lineNumber := 0
	for _, line := range strings.Split(string(data), "\n") {
		lineNumber++
		line = strings.TrimSuffix(line, "\r")
		matchLine(line, rules, source, path, lineNumber, commit, emit)
	}
}

func matchLine(line string, rules []Rule, source, path string, lineNumber int, commit string, emit func(ScanFinding)) {
	for _, rule := range rules {
		matches := rule.Pattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			value := ""
			if rule.Group > 0 {
				if len(match) > rule.Group {
					value = match[rule.Group]
				}
			} else if len(match) > 0 {
				value = match[0]
			}
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			finding := ScanFinding{
				Rule:   rule.Name,
				Raw:    value,
				Source: source,
				Path:   path,
				Line:   lineNumber,
				Commit: commit,
			}
			if rule.Decode != nil {
				decoded := rule.Decode(value)
				if decoded == "" {
					continue
				}
				finding.Raw = decoded
				finding.Value = decoded
			}
			emit(finding)
		}
	}
}

func gitRepoValid(ctx context.Context, repo string) bool {
	if _, err := exec.LookPath("git"); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(repo, ".git")); err != nil {
		return false
	}
	runCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "git", "-C", repo, "rev-parse", "--git-dir")
	return cmd.Run() == nil
}

func runGitScan(ctx context.Context, opts ScanOptions, source string, args []string, rules []Rule, emit func(ScanFinding), result *ScanResult) {
	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "git", append([]string{"-C", opts.RepoDir}, args...)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("git %s: %v", args[0], err))
		return
	}
	var stderr limitedBuffer
	stderr.limit = 64 << 10
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("git %s: %v", args[0], err))
		return
	}

	scanner := bufio.NewScanner(io.LimitReader(stdout, maxGitOutput))
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	currentCommit := ""
	currentPath := ""
	currentOld := 0
	currentNew := 0
	inHunk := false
	lines := 0
	for scanner.Scan() {
		line := scanner.Text()
		lines++
		if strings.HasPrefix(line, "commit ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && IsHexSHA(fields[1]) {
				currentCommit = fields[1]
			}
			currentPath = ""
			inHunk = false
		}
		if source == "reflog" {
			fields := strings.Fields(line)
			if len(fields) > 0 && IsHexSHA(fields[0]) {
				currentCommit = fields[0]
			}
		}
		if strings.HasPrefix(line, "diff --git a/") {
			rest := strings.TrimPrefix(line, "diff --git a/")
			if idx := strings.LastIndex(rest, " b/"); idx >= 0 {
				currentPath = rest[idx+3:]
			}
			inHunk = false
		} else if strings.HasPrefix(line, "+++ b/") {
			currentPath = strings.TrimPrefix(line, "+++ b/")
			inHunk = false
		} else if strings.HasPrefix(line, "--- a/") && currentPath == "" {
			currentPath = strings.TrimPrefix(line, "--- a/")
		}
		lineNumber := lines
		if strings.HasPrefix(line, "@@ ") {
			if oldStart, newStart, ok := hunkStarts(line); ok {
				currentOld = oldStart
				currentNew = newStart
				inHunk = true
			}
		} else if inHunk {
			switch {
			case strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---"):
				inHunk = false
			case strings.HasPrefix(line, "+"):
				lineNumber = currentNew
				currentNew++
			case strings.HasPrefix(line, "-"):
				lineNumber = currentOld
				currentOld++
			case strings.HasPrefix(line, " "):
				lineNumber = currentNew
				currentOld++
				currentNew++
			default:
				inHunk = false
			}
		}
		matchLine(line, rules, source, currentPath, lineNumber, currentCommit, emit)
		if lines >= maxGitScanLines {
			cancel()
			break
		}
	}
	scanErr := scanner.Err()
	waitErr := cmd.Wait()
	if scanErr != nil && runCtx.Err() == nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("git %s output: %v", args[0], scanErr))
	}
	if waitErr != nil && runCtx.Err() == nil && source != "fsck" {
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			result.Warnings = append(result.Warnings, fmt.Sprintf("git %s: %v: %s", args[0], waitErr, message))
		} else {
			result.Warnings = append(result.Warnings, fmt.Sprintf("git %s: %v", args[0], waitErr))
		}
	}
}

// hunkStarts parses old and new start lines from an "@@ -a,b +c,d @@" header.
func hunkStarts(line string) (int, int, bool) {
	minus := strings.Index(line, " -")
	plus := strings.Index(line, " +")
	if minus < 0 || plus < 0 || plus < minus {
		return 0, 0, false
	}
	parse := func(part string) (int, bool) {
		end := strings.IndexAny(part, ", @")
		if end < 0 {
			return 0, false
		}
		value, err := strconv.Atoi(part[:end])
		if err != nil || value < 0 {
			return 0, false
		}
		return value, true
	}
	oldStart, ok := parse(line[minus+2:])
	if !ok {
		return 0, 0, false
	}
	newStart, ok := parse(line[plus+2:])
	if !ok {
		return 0, 0, false
	}
	return oldStart, newStart, true
}

func scanStashes(ctx context.Context, opts ScanOptions, rules []Rule, emit func(ScanFinding), result *ScanResult) {
	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "git", "-C", opts.RepoDir, "stash", "list")
	output, err := cmd.Output()
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for i, line := range lines {
		if i >= 20 {
			break
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], "stash@{") {
			continue
		}
		runGitScan(ctx, opts, "stash", []string{"stash", "show", "-p", fields[0]}, rules, emit, result)
	}
}

func scanLostFound(ctx context.Context, repoDir string, rules []Rule, emit func(ScanFinding), result *ScanResult) {
	root := filepath.Join(repoDir, ".git", "lost-found")
	if _, err := os.Stat(root); err != nil {
		return
	}
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || ctx.Err() != nil {
			return nil
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || info.Size() > maxScanFileSize {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil || IsBinary(data) {
			return nil
		}
		rel, _ := filepath.Rel(repoDir, path)
		scanText(data, "fsck", filepath.ToSlash(rel), "", rules, emit)
		return nil
	})
}

type gitleaksFinding struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	Match       string `json:"Match"`
	Secret      string `json:"Secret"`
	Commit      string `json:"Commit"`
}

func scanGitleaks(ctx context.Context, opts ScanOptions, emit func(ScanFinding), result *ScanResult) {
	gitleaks, err := exec.LookPath("gitleaks")
	if err != nil {
		result.Warnings = append(result.Warnings, "gitleaks was requested but was not found in PATH; skipped")
		return
	}
	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		result.Warnings = append(result.Warnings, "gitleaks: create output directory: "+err.Error())
		return
	}
	tmp, err := os.CreateTemp(opts.OutDir, ".gitleaks-report-*.json")
	if err != nil {
		result.Warnings = append(result.Warnings, "gitleaks: create report path: "+err.Error())
		return
	}
	reportPath := tmp.Name()
	_ = tmp.Close()
	_ = os.Remove(reportPath)
	defer os.Remove(reportPath)

	args := []string{
		"detect",
		"--source", opts.RepoDir,
		"--report-format", "json",
		"--report-path", reportPath,
		"--no-banner",
		"--exit-code", "0",
	}
	if !opts.UseGit {
		args = append(args, "--no-git")
	}
	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, gitleaks, args...)
	var stderr limitedBuffer
	stderr.limit = 64 << 10
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil && runCtx.Err() == nil {
		message := strings.TrimSpace(stderr.String())
		result.Warnings = append(result.Warnings, fmt.Sprintf("gitleaks: %v: %s", err, message))
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		result.Warnings = append(result.Warnings, "gitleaks: report was not produced")
		return
	}
	findings, err := parseGitleaksReport(data)
	if err != nil {
		result.Warnings = append(result.Warnings, "gitleaks: parse report: "+err.Error())
		return
	}
	result.GitleaksUsed = true
	for _, finding := range findings {
		value := finding.Secret
		if strings.TrimSpace(value) == "" {
			value = finding.Match
		}
		if strings.TrimSpace(value) == "" {
			continue
		}
		rule := finding.RuleID
		if rule == "" {
			rule = finding.Description
		}
		emit(ScanFinding{
			Rule:   "gitleaks:" + rule,
			Raw:    value,
			Source: "gitleaks",
			Path:   finding.File,
			Line:   finding.StartLine,
			Commit: finding.Commit,
		})
	}
}

func parseGitleaksReport(data []byte) ([]gitleaksFinding, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	var findings []gitleaksFinding
	if err := json.Unmarshal(trimmed, &findings); err == nil {
		return findings, nil
	}
	var wrapper struct {
		Findings []gitleaksFinding `json:"findings"`
	}
	if err := json.Unmarshal(trimmed, &wrapper); err != nil {
		return nil, err
	}
	return wrapper.Findings, nil
}

func looksLikeFlag(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(s, "flag") || strings.HasPrefix(s, "f1ag")
}

func decodeHexFlag(s string) string {
	data, err := hex.DecodeString(s)
	if err != nil {
		return ""
	}
	decoded := string(data)
	if !looksLikeFlag(decoded) {
		return ""
	}
	return decoded
}

func decodeBase64Flag(s string) string {
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		data, err := encoding.DecodeString(s)
		if err != nil {
			continue
		}
		decoded := string(data)
		if looksLikeFlag(decoded) {
			return decoded
		}
	}
	return ""
}

func decodeBinaryFlag(s string) string {
	if len(s) == 0 || len(s)%8 != 0 {
		return ""
	}
	var out strings.Builder
	out.Grow(len(s) / 8)
	for i := 0; i < len(s); i += 8 {
		value, err := strconv.ParseUint(s[i:i+8], 2, 8)
		if err != nil {
			return ""
		}
		out.WriteByte(byte(value))
	}
	decoded := out.String()
	if !looksLikeFlag(decoded) {
		return ""
	}
	return decoded
}

func decodeEntityFlag(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if !strings.HasPrefix(s[i:], "&#") {
			out.WriteByte(s[i])
			i++
			continue
		}
		end := strings.IndexByte(s[i:], ';')
		if end < 0 {
			out.WriteString(s[i:])
			break
		}
		body := s[i+2 : i+end]
		var value int64
		var err error
		if body != "" && (body[0] == 'x' || body[0] == 'X') {
			value, err = strconv.ParseInt(body[1:], 16, 32)
		} else {
			value, err = strconv.ParseInt(body, 10, 32)
		}
		if err != nil || value <= 0 || value > 0x10FFFF {
			out.WriteString(s[i : i+end+1])
		} else {
			out.WriteRune(rune(value))
		}
		i += end + 1
	}
	decoded := out.String()
	if !looksLikeFlag(decoded) {
		return ""
	}
	return decoded
}

// WriteFindings writes the report. Only masked values are written for secret
// rules; raw matches never leave memory.
func WriteFindings(outDir string, findings []ScanFinding, meta FindingsMeta) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if meta.Generated.IsZero() {
		meta.Generated = time.Now()
	}
	var buf bytes.Buffer
	buf.WriteString("# WebKiller-leak 命中报告\n")
	if meta.Target != "" {
		buf.WriteString("# target: " + meta.Target + "\n")
	}
	buf.WriteString("# 生成时间: " + meta.Generated.Format(time.RFC3339) + "\n")
	buf.WriteString(fmt.Sprintf("# Git 历史: %t, gitleaks: %t\n", meta.GitUsed, meta.GitleaksUsed))
	if len(meta.Sources) > 0 {
		keys := SortedKeys(meta.Sources)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", key, meta.Sources[key]))
		}
		buf.WriteString("# 来源: " + strings.Join(parts, ", ") + "\n")
	}
	buf.WriteString("\n")
	if len(findings) == 0 {
		buf.WriteString("未发现命中项。\n")
	} else {
		for _, finding := range findings {
			buf.WriteString(formatFinding(finding) + "\n")
		}
	}
	if len(meta.Warnings) > 0 {
		buf.WriteString("\n# warnings\n")
		for _, warning := range meta.Warnings {
			buf.WriteString("# " + strings.ReplaceAll(warning, "\n", " ") + "\n")
		}
	}
	return os.WriteFile(filepath.Join(outDir, "findings.txt"), buf.Bytes(), 0o644)
}

// FormatFinding renders one finding for console output.
func FormatFinding(f ScanFinding) string {
	return formatFinding(f)
}

func formatFinding(f ScanFinding) string {
	value := strings.ReplaceAll(f.Value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\r", "")
	runes := []rune(value)
	if len(runes) > 300 {
		value = string(runes[:300]) + "..."
	}
	location := f.Source
	if f.Path != "" {
		location += ", " + f.Path
		if f.Line > 0 {
			location += fmt.Sprintf(":%d", f.Line)
		}
	}
	if f.Commit != "" {
		location += ", commit " + ShortSHA(f.Commit)
	}
	return fmt.Sprintf("[%s] %s (%s)", f.Rule, value, location)
}

type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		b.limit = 64 << 10
	}
	remaining := b.limit - b.buf.Len()
	if remaining <= 0 {
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = b.buf.Write(p[:remaining])
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *limitedBuffer) String() string {
	return b.buf.String()
}

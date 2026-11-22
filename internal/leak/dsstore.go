package leak

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"html"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf16"
)

// DSEntry is one file or directory name recovered from .DS_Store.
type DSEntry struct {
	Path       string
	Name       string
	Dir        string
	Source     string
	Accessible bool
	Status     int
	Note       string
}

// DSStoreResult summarizes .DS_Store enumeration.
type DSStoreResult struct {
	Entries  []DSEntry
	Sources  []string
	RawFiles []string
	Warnings []string
}

const maxDSStoreSources = 64

var commonDSDirs = []string{
	"admin", "backup", "backups", "config", "includes", "src", "app",
	"static", "uploads", "files", "data", "db", "test", "tests", "old",
	"www", "public", "private", "tmp", "logs", "assets", "images", "css",
	"js", "api", "v1", "v2", "web", "site", "pages", "views", "controllers",
	"models", "routes", "storage", "vendor", "node_modules",
}

// DumpDSStore downloads and heuristically parses .DS_Store files, then probes
// every extracted entry for reachability. It never downloads entry contents.
func DumpDSStore(ctx context.Context, client *Client, siteBase, outDir string, concurrency int, verbose bool) *DSStoreResult {
	if concurrency < 1 {
		concurrency = 1
	}
	result := &DSStoreResult{}
	type source struct {
		dir   string
		depth int
	}
	queue := []source{{dir: "", depth: 0}}
	seenDirs := map[string]bool{"": true}
	addDir := func(dir string, depth int) {
		dir = strings.Trim(strings.TrimSpace(dir), "/")
		if dir == "" || seenDirs[dir] || depth > 2 {
			return
		}
		seenDirs[dir] = true
		queue = append(queue, source{dir: dir, depth: depth})
	}

	// Use the root directory listing when it is available; otherwise fall
	// back to a small set of common directory names.
	for _, dir := range discoverRootDirs(ctx, client, siteBase) {
		addDir(dir, 1)
	}
	for _, dir := range commonDSDirs {
		addDir(dir, 1)
	}

	for len(queue) > 0 && len(result.Sources) < maxDSStoreSources {
		if ctx.Err() != nil {
			result.Warnings = append(result.Warnings, "DS_Store enumeration canceled")
			break
		}
		src := queue[0]
		queue = queue[1:]
		rel := path.Join(src.dir, ".DS_Store")
		target, err := JoinURL(siteBase, rel)
		if err != nil {
			continue
		}
		body, status, err := client.Get(ctx, target)
		if err != nil {
			if verbose && client.logger != nil {
				client.logger.Printf("[dsstore] %s: %v", rel, err)
			}
			continue
		}
		if status != http.StatusOK || !isDSStore(body) {
			continue
		}
		result.Sources = append(result.Sources, rel)
		rawName := SHA1Hex([]byte(target)) + ".DS_Store"
		rawPath := filepath.Join(outDir, "dsstore", "raw", rawName)
		if err := os.MkdirAll(filepath.Dir(rawPath), 0o755); err == nil {
			if err := os.WriteFile(rawPath, body, 0o644); err == nil {
				result.RawFiles = append(result.RawFiles, rawPath)
			}
		}
		names := extractDSStoreNames(body)
		if len(names) == 0 {
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s: no names extracted (raw file preserved)", rel))
			continue
		}
		for _, name := range names {
			entryPath := path.Join(src.dir, name)
			result.Entries = append(result.Entries, DSEntry{
				Path:   entryPath,
				Name:   name,
				Dir:    src.dir,
				Source: rel,
			})
			if src.depth < 2 && looksLikeDirectory(name) {
				addDir(entryPath, src.depth+1)
			}
		}
	}

	result.Entries = dedupeDSEntries(result.Entries)
	probeDSEntries(ctx, client, siteBase, result.Entries, concurrency)
	sort.Slice(result.Entries, func(i, j int) bool {
		if result.Entries[i].Dir != result.Entries[j].Dir {
			return result.Entries[i].Dir < result.Entries[j].Dir
		}
		return result.Entries[i].Path < result.Entries[j].Path
	})
	sort.Strings(result.Sources)
	sort.Strings(result.RawFiles)
	if err := writeDSStoreReport(outDir, result); err != nil {
		result.Warnings = append(result.Warnings, "write dsstore.txt: "+err.Error())
	}
	return result
}

func discoverRootDirs(ctx context.Context, client *Client, siteBase string) []string {
	body, status, err := client.GetLimited(ctx, siteBase, 2<<20)
	if err != nil || status != http.StatusOK {
		return nil
	}
	re := regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`)
	seen := make(map[string]bool)
	out := make([]string, 0)
	for _, match := range re.FindAllStringSubmatch(string(body), -1) {
		href := html.UnescapeString(strings.TrimSpace(match[1]))
		if href == "" || strings.HasPrefix(href, "?") || strings.HasPrefix(href, "#") ||
			strings.HasPrefix(href, "/") || strings.Contains(href, "://") ||
			strings.HasPrefix(href, "mailto:") {
			continue
		}
		href = strings.SplitN(href, "?", 2)[0]
		href = strings.SplitN(href, "#", 2)[0]
		href = strings.TrimSuffix(href, "/")
		if href == "" || href == "." || href == ".." {
			continue
		}
		href = strings.SplitN(href, "/", 2)[0]
		if href == "" || seen[href] {
			continue
		}
		seen[href] = true
		out = append(out, href)
		if len(out) >= 64 {
			break
		}
	}
	return out
}

func isDSStore(body []byte) bool {
	if len(body) < 8 {
		return false
	}
	if bytes.HasPrefix(body, []byte{0x00, 0x00, 0x00, 0x01}) && bytes.Equal(body[4:8], []byte("Bud1")) {
		return true
	}
	head := body
	if len(head) > 64 {
		head = head[:64]
	}
	return bytes.Contains(head, []byte("Bud1"))
}

// extractDSStoreNames applies the heuristic described in DESIGN.md: scan for
// printable UTF-16BE runs, filter internal tokens, and fall back to ASCII runs
// only when the UTF-16 pass yields nothing.
func extractDSStoreNames(data []byte) []string {
	names := extractUTF16BEStrings(data)
	if len(names) == 0 {
		names = extractASCIIStrings(data)
	}
	seen := make(map[string]bool)
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || !validDSName(name) {
			continue
		}
		key := strings.ToLower(name)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, name)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i]) < strings.ToLower(out[j])
	})
	return out
}

func extractUTF16BEStrings(data []byte) []string {
	var out []string
	for i := 0; i+1 < len(data); i++ {
		units := make([]uint16, 0, 32)
		j := i
		for j+1 < len(data) {
			u := binary.BigEndian.Uint16(data[j : j+2])
			if u == 0 {
				break
			}
			r := rune(u)
			isSurrogate := u >= 0xD800 && u <= 0xDFFF
			if !isSurrogate && !unicode.IsPrint(r) {
				break
			}
			units = append(units, u)
			j += 2
		}
		if len(units) >= 2 {
			name := string(utf16.Decode(units))
			if validDSName(name) {
				out = append(out, strings.TrimSpace(name))
			}
			i = j - 1
		}
	}
	return out
}

func extractASCIIStrings(data []byte) []string {
	var out []string
	start := -1
	for i, b := range data {
		if b >= 0x20 && b < 0x7f {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= 4 {
			name := string(data[start:i])
			if validDSName(name) {
				out = append(out, name)
			}
		}
		start = -1
	}
	if start >= 0 && len(data)-start >= 4 {
		name := string(data[start:])
		if validDSName(name) {
			out = append(out, name)
		}
	}
	return out
}

func validDSName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return false
	}
	runes := []rune(name)
	if len(runes) < 2 || len(runes) > 255 {
		return false
	}
	if strings.ContainsAny(name, "/\\\x00") {
		return false
	}
	hasUseful := false
	asciiLetters := 0
	for _, r := range runes {
		if unicode.IsControl(r) {
			return false
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-' {
			hasUseful = true
		}
		if r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			asciiLetters++
		}
	}
	if !hasUseful || asciiLetters == 0 {
		return false
	}
	lower := strings.ToLower(name)
	switch lower {
	case ".ds_store", "ds_store", "bud1", "dsdb", "iloc", "bplist", "icvp",
		"lsvp", "moddate", "physize", "logicalsize", "foldersettings",
		"thevolumesettingsfolder", "blob", "utf-16":
		return false
	}
	for _, token := range []string{"com.apple", "mac os x", "application/x-", "ds_store"} {
		if strings.Contains(lower, token) {
			return false
		}
	}
	if strings.Count(name, " ") > 4 {
		return false
	}
	if isHexString(name) && len(name) >= 16 {
		return false
	}
	if looksLikeBase64(name) {
		return false
	}
	return true
}

func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func looksLikeBase64(s string) bool {
	if len(s) < 24 || len(s)%4 != 0 {
		return false
	}
	hasUpper, hasLower, hasDigit := false, false, false
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '+' || r == '/' || r == '=':
		default:
			return false
		}
	}
	return hasUpper && hasLower && hasDigit
}

func looksLikeDirectory(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	if path.Ext(name) == "" {
		return true
	}
	for _, dir := range commonDSDirs {
		if strings.EqualFold(name, dir) {
			return true
		}
	}
	return false
}

func dedupeDSEntries(entries []DSEntry) []DSEntry {
	seen := make(map[string]bool)
	out := make([]DSEntry, 0, len(entries))
	for _, entry := range entries {
		key := strings.ToLower(entry.Path)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, entry)
	}
	return out
}

func probeDSEntries(ctx context.Context, client *Client, siteBase string, entries []DSEntry, concurrency int) {
	const maxProbes = 1000
	if len(entries) > maxProbes {
		entries = entries[:maxProbes]
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := range entries {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			target, err := JoinURL(siteBase, entries[i].Path)
			if err != nil {
				return
			}
			status, err := client.Head(ctx, target)
			if err != nil {
				entries[i].Note = shortError(err)
				return
			}
			if status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented {
				if _, getStatus, getErr := client.GetLimited(ctx, target, 1); getErr == nil {
					status = getStatus
				} else if getStatus > 0 {
					status = getStatus
				}
			}
			entries[i].Status = status
			switch {
			case status >= 200 && status < 400:
				entries[i].Accessible = true
			case status == http.StatusForbidden:
				entries[i].Note = "forbidden"
			case status == http.StatusNotFound:
				entries[i].Note = "not found"
			case status == http.StatusUnauthorized:
				entries[i].Note = "unauthorized"
			default:
				entries[i].Note = fmt.Sprintf("HTTP %d", status)
			}
		}()
	}
	wg.Wait()
}

func writeDSStoreReport(outDir string, result *DSStoreResult) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString("# WebKiller-leak .DS_Store 枚举报告\n")
	buf.WriteString("# 说明：.DS_Store 只包含目录结构，不包含文件内容。\n")
	buf.WriteString(fmt.Sprintf("# 来源：%d，条目：%d\n\n", len(result.Sources), len(result.Entries)))
	if len(result.Entries) == 0 {
		buf.WriteString("未提取到 .DS_Store 条目。\n")
		if len(result.RawFiles) > 0 {
			buf.WriteString("\n已保留原始文件，供人工分析：\n")
			for _, file := range result.RawFiles {
				buf.WriteString("  " + file + "\n")
			}
		}
		return os.WriteFile(filepath.Join(outDir, "dsstore.txt"), buf.Bytes(), 0o644)
	}

	byDir := make(map[string][]DSEntry)
	for _, entry := range result.Entries {
		byDir[entry.Dir] = append(byDir[entry.Dir], entry)
	}
	dirs := SortedKeys(byDir)
	for _, dir := range dirs {
		if dir == "" {
			buf.WriteString("./\n")
		} else {
			buf.WriteString(dir + "/\n")
		}
		items := byDir[dir]
		sort.Slice(items, func(i, j int) bool {
			return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
		})
		for i, entry := range items {
			branch := "├── "
			if i == len(items)-1 {
				branch = "└── "
			}
			status := ""
			if entry.Accessible {
				status = " [accessible]"
			} else if entry.Status != 0 {
				status = fmt.Sprintf(" [%s]", entry.Note)
			}
			buf.WriteString("  " + branch + entry.Name + status + "\n")
		}
		buf.WriteString("\n")
	}
	return os.WriteFile(filepath.Join(outDir, "dsstore.txt"), buf.Bytes(), 0o644)
}

package leak

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxTextSource  = 8 << 20
	maxIndexSource = 64 << 20
	maxPackBytes   = 512 << 20
	maxObjects     = 100000
	maxTotalBytes  = 1 << 30
)

// Object is one parsed Git object. Blob content is deliberately not kept in
// memory; it is stored as a loose object on disk and read back when needed.
type Object struct {
	SHA    string
	Type   string
	Size   int64
	Commit *CommitInfo
	Tree   []TreeEntry
	Tag    *TagInfo
}

// CommitInfo is the parsed subset of a commit object used by the dumper.
type CommitInfo struct {
	SHA       string
	Tree      string
	Parents   []string
	Author    string
	Committer string
	Timestamp int64
	Message   string
}

// TreeEntry is one entry in a Git tree object.
type TreeEntry struct {
	Mode string
	Name string
	SHA  string
}

// TagInfo is the parsed subset of an annotated tag object.
type TagInfo struct {
	Object  string
	Type    string
	Tag     string
	Message string
}

// IndexEntry is one path/SHA pair from the Git index.
type IndexEntry struct {
	Path string
	SHA  string
	Mode uint32
	Size uint32
}

// MissingObject records an object referenced by the repository but not
// retrievable from the target.
type MissingObject struct {
	SHA     string
	Context string
}

// DumpStats summarizes a dump.
type DumpStats struct {
	Objects       int
	Commits       int
	Trees         int
	Blobs         int
	Tags          int
	Files         int
	IndexEntries  int
	Refs          int
	Branches      int
	Packs         int
	Bytes         int64
	ObjectsDenied bool
	Canceled      bool
}

// DumpResult is returned by Dumper.Run.
type DumpResult struct {
	Stats    DumpStats
	Missing  []MissingObject
	Warnings []string
	Errors   []string
	HeadSHA  string
	Base     string
	RepoDir  string
}

// Dumper reconstructs a Git repository from a remote .git directory.
type Dumper struct {
	Client     *Client
	Base       string
	OutDir     string
	Out        string
	Sem        chan struct{}
	Bruteforce bool
	Verbose    bool
	MaxObjects int
	MaxBytes   int64

	mu       sync.Mutex
	seen     map[string]bool
	roots    map[string]bool
	objects  map[string]*Object
	missing  map[string]string
	refs     map[string]string
	headSHA  string
	headRef  string
	index    []IndexEntry
	packs    []string
	sources  map[string][]byte
	indexRaw []byte
	warnings []string
	errors   []string

	downloadedBytes int64
	objectsDenied   bool
	filesWritten    int
}

// NewDumper creates a dumper. outDir is the user's output directory; the
// restored repository is placed in outDir/repo.
func NewDumper(client *Client, gitBase, outDir string, concurrency int, bruteforce, verbose bool) *Dumper {
	if concurrency < 1 {
		concurrency = 1
	}
	return &Dumper{
		Client:     client,
		Base:       gitBase,
		OutDir:     outDir,
		Out:        filepath.Join(outDir, "repo"),
		Sem:        make(chan struct{}, concurrency),
		Bruteforce: bruteforce,
		Verbose:    verbose,
		MaxObjects: maxObjects,
		MaxBytes:   maxTotalBytes,
		seen:       make(map[string]bool),
		roots:      make(map[string]bool),
		objects:    make(map[string]*Object),
		missing:    make(map[string]string),
		refs:       make(map[string]string),
		sources:    make(map[string][]byte),
	}
}

// Run executes the reconstruction pipeline. Individual failures are collected
// in the result; a non-nil error means no usable repository could be built.
func (d *Dumper) Run(ctx context.Context) (*DumpResult, error) {
	d.logf("git: base=%s", d.Base)
	if err := d.prepareDirs(); err != nil {
		return nil, err
	}
	d.fetchMetadata(ctx)
	d.initRepo()
	if d.Bruteforce {
		d.bruteforce(ctx)
	}
	d.downloadPacks(ctx)

	roots := d.unseenRoots()
	if len(roots) == 0 {
		d.addWarning("no Git object starting points were discovered; HEAD, refs, logs, index and pack metadata were unavailable")
		return d.result(), fmt.Errorf("no Git objects discovered")
	}
	d.walk(ctx, roots)
	if len(d.objects) == 0 {
		d.addWarning("no loose Git objects could be downloaded")
		return d.result(), fmt.Errorf("no Git objects could be downloaded")
	}

	d.writeRepoFiles()
	d.materialize(ctx)
	d.writeMissing()
	return d.result(), nil
}

func (d *Dumper) prepareDirs() error {
	for _, dir := range []string{
		filepath.Join(d.Out, ".git", "objects"),
		filepath.Join(d.Out, ".git", "objects", "info"),
		filepath.Join(d.Out, ".git", "objects", "pack"),
		filepath.Join(d.Out, ".git", "refs", "heads"),
		filepath.Join(d.Out, ".git", "refs", "tags"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create repository directory: %w", err)
		}
	}
	return nil
}

func (d *Dumper) initRepo() {
	configPath := filepath.Join(d.Out, ".git", "config")
	if _, err := os.Stat(configPath); err != nil {
		_ = os.WriteFile(configPath, []byte(minimalGitConfig), 0o644)
	}
	headPath := filepath.Join(d.Out, ".git", "HEAD")
	if _, err := os.Stat(headPath); err != nil {
		_ = os.WriteFile(headPath, []byte("ref: refs/heads/master\n"), 0o644)
	}
}

const minimalGitConfig = `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
`

func (d *Dumper) fetchMetadata(ctx context.Context) {
	paths := []string{
		"HEAD",
		"config",
		"info/refs",
		"packed-refs",
		"logs/HEAD",
		"refs/stash",
		"logs/refs/stash",
		"ORIG_HEAD",
		"FETCH_HEAD",
		"MERGE_HEAD",
		"CHERRY_PICK_HEAD",
		"REBASE_HEAD",
		"BISECT_HEAD",
		"objects/info/packs",
		"objects/pack/",
		"info/grafts",
		"shallow",
		"refs/heads/master",
		"refs/heads/main",
		"logs/refs/heads/master",
		"logs/refs/heads/main",
	}
	for _, rel := range paths {
		d.fetchSource(ctx, rel)
	}

	// The index is binary and can be larger than text metadata.
	if body, status, err := d.Client.GetLimited(ctx, mustJoin(d.Base, "index"), maxIndexSource); err != nil {
		d.logf("index: %v (HTTP %d)", err, status)
	} else if status == 200 {
		d.indexRaw = body
		entries, err := ParseIndex(body)
		if err != nil {
			d.addWarning("parse index: %v", err)
		} else {
			d.index = entries
			for _, entry := range entries {
				d.addRoot(entry.SHA)
			}
			d.logf("index: %d entries", len(entries))
		}
	}

	// Parse what we already have.
	d.parseHead()
	d.parseRefs("info/refs")
	d.parseRefs("packed-refs")
	d.parseRefFiles()
	d.parseLogs()
	d.parseSimpleSHAs()
	d.parseGrafts()
	d.parsePackNames()

	// Fetch branch refs and reflogs discovered in the metadata.
	branches := d.discoverBranches()
	for _, branch := range branches {
		ref := "refs/heads/" + branch
		if _, ok := d.sources[ref]; !ok {
			d.fetchSource(ctx, ref)
		}
		logRef := "logs/" + ref
		if _, ok := d.sources[logRef]; !ok {
			d.fetchSource(ctx, logRef)
		}
	}
	// Parsing the newly fetched refs/logs may reveal more SHAs.
	d.parseRefs("info/refs")
	d.parseRefs("packed-refs")
	d.parseRefFiles()
	d.parseLogs()
	d.parseSimpleSHAs()
	d.parseHead()
}

func (d *Dumper) fetchSource(ctx context.Context, rel string) {
	u := mustJoin(d.Base, rel)
	body, status, err := d.Client.GetLimited(ctx, u, maxTextSource)
	if err != nil {
		d.logf("%s: %v (HTTP %d)", rel, err, status)
		return
	}
	if status != 200 {
		d.logf("%s: HTTP %d", rel, status)
		return
	}
	if len(body) <= maxTextSource {
		d.mu.Lock()
		d.sources[rel] = body
		d.mu.Unlock()
	}
}

func (d *Dumper) parseHead() {
	body, ok := d.sources["HEAD"]
	if !ok {
		return
	}
	text := strings.TrimSpace(string(body))
	if strings.HasPrefix(text, "ref: ") {
		ref := strings.TrimSpace(strings.TrimPrefix(text, "ref: "))
		if _, err := SanitizeRefName(ref); err == nil {
			d.headRef = ref
			if sha, ok := d.refs[ref]; ok {
				d.headSHA = sha
				d.addRoot(sha)
			}
		}
		return
	}
	if IsHexSHA(text) {
		d.headSHA = strings.ToLower(text)
		d.addRoot(d.headSHA)
	}
}

func (d *Dumper) parseRefs(source string) {
	body, ok := d.sources[source]
	if !ok {
		return
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "^") {
			if sha := strings.TrimSpace(line[1:]); IsHexSHA(sha) {
				d.addRoot(strings.ToLower(sha))
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		sha := strings.ToLower(fields[0])
		if !IsHexSHA(sha) {
			continue
		}
		ref := fields[1]
		if !strings.HasPrefix(ref, "refs/") {
			continue
		}
		if _, err := SanitizeRefName(ref); err != nil {
			continue
		}
		d.refs[ref] = sha
		d.addRoot(sha)
		if d.headRef == ref {
			d.headSHA = sha
		}
	}
}

func (d *Dumper) parseRefFiles() {
	for rel, body := range d.sources {
		if !strings.HasPrefix(rel, "refs/") || strings.HasSuffix(rel, "/") {
			continue
		}
		if _, err := SanitizeRefName(rel); err != nil {
			continue
		}
		sha := strings.ToLower(strings.TrimSpace(string(body)))
		if !IsHexSHA(sha) {
			continue
		}
		d.refs[rel] = sha
		d.addRoot(sha)
		if d.headRef == rel {
			d.headSHA = sha
		}
	}
}

func (d *Dumper) parseLogs() {
	for rel, body := range d.sources {
		if !strings.HasPrefix(rel, "logs/") {
			continue
		}
		for _, sha := range ExtractSHAs(string(body)) {
			d.addRoot(sha)
		}
	}
}

func (d *Dumper) parseSimpleSHAs() {
	for rel, body := range d.sources {
		switch rel {
		case "config", "objects/info/packs", "objects/pack/":
			continue
		}
		if strings.HasPrefix(rel, "logs/") {
			continue
		}
		if rel == "index" {
			continue
		}
		for _, sha := range ExtractSHAs(string(body)) {
			d.addRoot(sha)
		}
	}
}

func (d *Dumper) parseGrafts() {
	for _, rel := range []string{"info/grafts", "shallow"} {
		body, ok := d.sources[rel]
		if !ok {
			continue
		}
		for _, line := range strings.Split(string(body), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if IsHexSHA(fields[0]) {
				d.addRoot(strings.ToLower(fields[0]))
			}
			for _, field := range fields[1:] {
				if IsHexSHA(field) {
					d.addRoot(strings.ToLower(field))
				}
			}
		}
	}
}

func (d *Dumper) discoverBranches() []string {
	seen := make(map[string]bool)
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" || strings.Contains(name, "..") {
			return
		}
		if _, err := SanitizeRefName("refs/heads/" + name); err != nil {
			return
		}
		seen[name] = true
	}
	if d.headRef != "" && strings.HasPrefix(d.headRef, "refs/heads/") {
		add(strings.TrimPrefix(d.headRef, "refs/heads/"))
	}
	for ref := range d.refs {
		if strings.HasPrefix(ref, "refs/heads/") {
			add(strings.TrimPrefix(ref, "refs/heads/"))
		}
	}
	for rel := range d.sources {
		if strings.HasPrefix(rel, "logs/refs/heads/") {
			add(strings.TrimPrefix(rel, "logs/refs/heads/"))
		}
	}
	re := regexp.MustCompile(`refs/heads/([A-Za-z0-9._/-]+)`)
	for _, body := range d.sources {
		for _, match := range re.FindAllStringSubmatch(string(body), -1) {
			add(strings.TrimSuffix(match[1], "/"))
		}
	}
	branches := SortedKeys(seen)
	if len(branches) > 128 {
		branches = branches[:128]
	}
	return branches
}

func (d *Dumper) parsePackNames() {
	seen := make(map[string]bool)
	add := func(name string) {
		name = strings.TrimSpace(name)
		name = strings.TrimSuffix(name, ".pack")
		name = strings.TrimSuffix(name, ".idx")
		if strings.HasPrefix(name, "pack-") && len(name) == len("pack-")+40 {
			if IsHexSHA(strings.TrimPrefix(name, "pack-")) {
				seen[name] = true
			}
		}
	}
	if body, ok := d.sources["objects/info/packs"]; ok {
		for _, line := range strings.Split(string(body), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.EqualFold(fields[0], "P") {
				add(fields[1])
			}
		}
	}
	if body, ok := d.sources["objects/pack/"]; ok {
		re := regexp.MustCompile(`(?i)(pack-[0-9a-f]{40})\.(?:pack|idx)`)
		for _, match := range re.FindAllStringSubmatch(string(body), -1) {
			add(match[1])
		}
	}
	d.packs = SortedKeys(seen)
	if len(d.packs) > 0 {
		d.logf("packs: %v", d.packs)
	}
}

func (d *Dumper) bruteforce(ctx context.Context) {
	d.logf("bruteforce: first trying exact objects from known SHA seeds")
	d.mu.Lock()
	known := make([]string, 0, len(d.roots))
	for sha := range d.roots {
		known = append(known, sha)
	}
	d.mu.Unlock()
	sort.Strings(known)

	exactFound := 0
	for _, sha := range known {
		if ctx.Err() != nil {
			break
		}
		u := mustJoin(d.Base, "objects/"+sha[:2]+"/"+sha[2:])
		body, status, err := d.Client.GetLimited(ctx, u, MaxObjectSize)
		if err == nil && status == 200 {
			if _, _, parseErr := ParseLooseObject(body); parseErr == nil {
				if err := d.writeRawObject(sha, body); err != nil {
					d.addWarning("store object %s: %v", ShortSHA(sha), err)
				}
				d.mu.Lock()
				d.downloadedBytes += int64(len(body))
				d.mu.Unlock()
				exactFound++
			}
		}
	}
	d.logf("bruteforce: exact enumeration recovered %d known object(s)", exactFound)

	d.logf("bruteforce: scanning 256 object directories as fallback")
	type result struct {
		prefix string
		body   []byte
		status int
		err    error
	}
	jobs := make(chan string)
	results := make(chan result, 32)
	var wg sync.WaitGroup
	workers := cap(d.Sem)
	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for prefix := range jobs {
				u := mustJoin(d.Base, "objects/"+prefix+"/")
				body, status, err := d.Client.GetLimited(ctx, u, 1<<20)
				select {
				case results <- result{prefix: prefix, body: body, status: status, err: err}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for i := 0; i < 256; i++ {
			prefix := fmt.Sprintf("%02x", i)
			select {
			case jobs <- prefix:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	found := 0
	denied := 0
	listed := 0
	for r := range results {
		if r.err != nil {
			if r.status == 403 {
				denied++
			}
			continue
		}
		switch r.status {
		case 200:
			listed++
			names := parseObjectDirListing(r.body)
			for _, name := range names {
				d.addRoot(r.prefix + name)
				found++
			}
		case 403:
			denied++
		}
	}
	if found == 0 {
		if denied > 0 {
			d.addWarning("bruteforce: object directory listings are denied (%d/256 returned 403); unknown object names cannot be enumerated without a listing or pack", denied)
		} else if listed == 0 {
			d.addWarning("bruteforce: no object directory listings were available")
		}
	} else {
		d.logf("bruteforce: discovered %d object names in %d listed directories", found, listed)
	}
}

func (d *Dumper) downloadPacks(ctx context.Context) {
	if len(d.packs) == 0 {
		return
	}
	packDir := filepath.Join(d.Out, ".git", "objects", "pack")
	if err := os.MkdirAll(packDir, 0o755); err != nil {
		d.addWarning("create pack directory: %v", err)
		return
	}
	for _, base := range d.packs {
		for _, ext := range []string{".pack", ".idx"} {
			name := base + ext
			target := filepath.Join(packDir, name)
			if info, err := os.Stat(target); err == nil && info.Size() > 0 {
				if ext == ".idx" {
					d.parsePackIndexFile(target)
				}
				continue
			}
			u := mustJoin(d.Base, "objects/pack/"+name)
			written, status, err := d.Client.Download(ctx, u, target, maxPackBytes)
			if err != nil {
				d.logf("pack %s: %v (HTTP %d)", name, err, status)
				if status == 404 {
					continue
				}
				d.addWarning("download %s: %v", name, err)
				continue
			}
			d.logf("pack %s: %d bytes", name, written)
			if ext == ".idx" {
				d.parsePackIndexFile(target)
			}
		}
	}
	d.tryUnpackPacks(ctx, packDir)
}

func (d *Dumper) parsePackIndexFile(file string) {
	data, err := os.ReadFile(file)
	if err != nil {
		d.addWarning("read pack index %s: %v", filepath.Base(file), err)
		return
	}
	shas, err := ParsePackIndex(data)
	if err != nil {
		d.addWarning("parse pack index %s: %v", filepath.Base(file), err)
		return
	}
	for _, sha := range shas {
		d.addRoot(sha)
	}
	d.logf("pack index %s: %d objects", filepath.Base(file), len(shas))
}

func (d *Dumper) tryUnpackPacks(ctx context.Context, packDir string) {
	packs, err := filepath.Glob(filepath.Join(packDir, "*.pack"))
	if err != nil || len(packs) == 0 {
		return
	}
	gitBin, err := exec.LookPath("git")
	if err != nil {
		d.addWarning("packs were downloaded but git is not available; run 'git index-pack' and 'git unpack-objects' in %s manually", packDir)
		return
	}
	for _, pack := range packs {
		f, err := os.Open(pack)
		if err != nil {
			d.addWarning("open pack %s: %v", filepath.Base(pack), err)
			continue
		}
		cmd := exec.CommandContext(ctx, gitBin, "-C", d.Out, "unpack-objects", "-r", "-q")
		cmd.Stdin = f
		output, err := cmd.CombinedOutput()
		_ = f.Close()
		if err != nil {
			d.logf("git unpack-objects %s: %v: %s", filepath.Base(pack), err, strings.TrimSpace(string(output)))
		}
	}

	// git may consider objects already present in the pack and therefore not
	// write loose copies. Materialize every object through cat-file so the
	// rest of the pipeline can read loose objects directly and so the
	// reconstructed repository is self-contained even if the pack is removed.
	materialized, err := d.materializePackObjects(ctx, gitBin)
	if err != nil {
		d.addWarning("packs were downloaded but could not be materialized automatically: %v", err)
		return
	}
	if materialized == 0 {
		d.addWarning("packs were downloaded but no objects could be materialized; use git index-pack/unpack-objects manually")
		return
	}
	d.logf("materialized %d pack object(s) as loose objects", materialized)
}

func (d *Dumper) materializePackObjects(ctx context.Context, gitBin string) (int, error) {
	cmd := exec.CommandContext(ctx, gitBin, "-C", d.Out, "cat-file", "--batch-all-objects", "--batch")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	var stderr limitedBuffer
	stderr.limit = 64 << 10
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	reader := bufio.NewReaderSize(stdout, 64<<10)
	materialized := 0
	for {
		header, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = cmd.Wait()
			return materialized, err
		}
		fields := strings.Fields(strings.TrimSuffix(header, "\n"))
		if len(fields) != 3 {
			continue
		}
		sha := fields[0]
		typ := fields[1]
		size, parseErr := strconv.ParseInt(fields[2], 10, 64)
		if parseErr != nil || size < 0 {
			continue
		}
		if typ == "missing" {
			continue
		}
		if size > MaxObjectSize {
			if _, err := io.CopyN(io.Discard, reader, size+1); err != nil {
				_ = cmd.Wait()
				return materialized, err
			}
			continue
		}
		content := make([]byte, size)
		if _, err := io.ReadFull(reader, content); err != nil {
			_ = cmd.Wait()
			return materialized, err
		}
		// cat-file terminates the content with a newline.
		if _, err := reader.ReadByte(); err != nil && err != io.EOF {
			_ = cmd.Wait()
			return materialized, err
		}
		raw, err := EncodeLooseObject(typ, content)
		if err != nil {
			continue
		}
		if err := d.writeRawObject(sha, raw); err != nil {
			d.addWarning("store pack object %s: %v", ShortSHA(sha), err)
			continue
		}
		d.addRoot(sha)
		materialized++
	}
	if err := cmd.Wait(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return materialized, fmt.Errorf("%v: %s", err, message)
		}
		return materialized, err
	}
	return materialized, nil
}

func (d *Dumper) walk(ctx context.Context, roots []string) {
	wave := roots
	for len(wave) > 0 {
		if ctx.Err() != nil {
			d.addWarning("object walk canceled: %v", ctx.Err())
			return
		}
		if len(d.objects) >= d.MaxObjects {
			d.addWarning("object limit reached (%d); remaining objects were not downloaded", d.MaxObjects)
			return
		}
		if d.downloadedBytes >= d.MaxBytes {
			d.addWarning("download limit reached (%d bytes); remaining objects were not downloaded", d.MaxBytes)
			return
		}

		sort.Strings(wave)
		dispatch := make([]string, 0, len(wave))
		for _, sha := range wave {
			if d.markSeen(sha) {
				dispatch = append(dispatch, sha)
			}
		}
		if len(dispatch) == 0 {
			return
		}

		workers := cap(d.Sem)
		if workers < 1 {
			workers = 1
		}
		if workers > len(dispatch) {
			workers = len(dispatch)
		}
		jobs := make(chan string)
		results := make(chan walkResult, workers)
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for sha := range jobs {
					results <- d.fetchAndParse(ctx, sha)
				}
			}()
		}
		go func() {
			defer close(jobs)
			for _, sha := range dispatch {
				select {
				case jobs <- sha:
				case <-ctx.Done():
					return
				}
			}
		}()
		go func() {
			wg.Wait()
			close(results)
		}()

		nextSet := make(map[string]bool)
		for result := range results {
			if result.err != nil {
				continue
			}
			for _, child := range result.children {
				if !d.isSeen(child) {
					nextSet[child] = true
				}
			}
		}
		wave = wave[:0]
		for sha := range nextSet {
			wave = append(wave, sha)
		}
	}
}

type walkResult struct {
	sha      string
	children []string
	err      error
}

func (d *Dumper) fetchAndParse(ctx context.Context, sha string) walkResult {
	raw, status, err := d.fetchObject(ctx, sha)
	if err != nil {
		contextNote := "HTTP " + strconv.Itoa(status)
		if status == 403 {
			d.mu.Lock()
			d.objectsDenied = true
			d.mu.Unlock()
			contextNote = "objects denied (403)"
		}
		d.addMissing(sha, contextNote)
		d.logf("object %s: %v", ShortSHA(sha), err)
		return walkResult{sha: sha, err: err}
	}
	typ, content, err := ParseLooseObject(raw)
	if err != nil {
		d.addError("parse object %s: %v", ShortSHA(sha), err)
		d.addMissing(sha, "invalid loose object")
		return walkResult{sha: sha, err: err}
	}

	obj := &Object{SHA: sha, Type: typ, Size: int64(len(content))}
	var children []string
	switch typ {
	case "commit":
		commit, err := ParseCommit(sha, content)
		if err != nil {
			d.addError("parse commit %s: %v", ShortSHA(sha), err)
			return walkResult{sha: sha, err: err}
		}
		obj.Commit = commit
		if commit.Tree != "" {
			children = append(children, commit.Tree)
		}
		children = append(children, commit.Parents...)
	case "tree":
		entries, err := ParseTree(content)
		if err != nil {
			d.addError("parse tree %s: %v", ShortSHA(sha), err)
			return walkResult{sha: sha, err: err}
		}
		obj.Tree = entries
		for _, entry := range entries {
			if entry.Mode == "160000" {
				continue
			}
			children = append(children, entry.SHA)
		}
	case "blob":
		// Content is already stored as a loose object.
	case "tag":
		tag, err := ParseTag(sha, content)
		if err != nil {
			d.addError("parse tag %s: %v", ShortSHA(sha), err)
			return walkResult{sha: sha, err: err}
		}
		obj.Tag = tag
		if tag.Object != "" {
			children = append(children, tag.Object)
		}
	default:
		err := fmt.Errorf("unsupported object type %q", typ)
		d.addError("object %s: %v", ShortSHA(sha), err)
		return walkResult{sha: sha, err: err}
	}
	d.storeObject(obj)
	return walkResult{sha: sha, children: children}
}

func (d *Dumper) fetchObject(ctx context.Context, sha string) ([]byte, int, error) {
	local := d.localObjectPath(sha)
	if data, err := os.ReadFile(local); err == nil && len(data) > 0 {
		return data, 200, nil
	}
	u := mustJoin(d.Base, "objects/"+sha[:2]+"/"+sha[2:])
	body, status, err := d.Client.Get(ctx, u)
	if err != nil {
		return nil, status, err
	}
	if status != 200 {
		return nil, status, fmt.Errorf("HTTP %d", status)
	}
	if looksLikeHTML(body) {
		return nil, status, fmt.Errorf("object path returned HTML")
	}
	d.mu.Lock()
	d.downloadedBytes += int64(len(body))
	d.mu.Unlock()
	if err := d.writeRawObject(sha, body); err != nil {
		d.addWarning("store object %s: %v", ShortSHA(sha), err)
	}
	return body, status, nil
}

func (d *Dumper) localObjectPath(sha string) string {
	if len(sha) < 3 {
		return ""
	}
	return filepath.Join(d.Out, ".git", "objects", sha[:2], sha[2:])
}

func (d *Dumper) writeRawObject(sha string, raw []byte) error {
	if !IsHexSHA(sha) {
		return fmt.Errorf("invalid object name %q", sha)
	}
	target := d.localObjectPath(sha)
	if info, err := os.Stat(target); err == nil && info.Size() > 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".object-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func (d *Dumper) readObjectContent(sha string) (string, []byte, error) {
	raw, err := os.ReadFile(d.localObjectPath(sha))
	if err != nil {
		return "", nil, err
	}
	return ParseLooseObject(raw)
}

func (d *Dumper) writeRepoFiles() {
	gitDir := filepath.Join(d.Out, ".git")
	_ = os.MkdirAll(gitDir, 0o755)
	_ = os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0o755)
	_ = os.MkdirAll(filepath.Join(gitDir, "refs", "tags"), 0o755)
	_ = os.MkdirAll(filepath.Join(gitDir, "objects", "info"), 0o755)
	_ = os.MkdirAll(filepath.Join(gitDir, "objects", "pack"), 0o755)
	_ = os.WriteFile(filepath.Join(gitDir, "config"), []byte(minimalGitConfig), 0o644)

	best := d.bestCommit()
	head := "ref: refs/heads/master\n"
	if d.headRef != "" {
		if _, ok := d.refs[d.headRef]; ok {
			head = "ref: " + d.headRef + "\n"
		}
	}
	if head == "ref: refs/heads/master\n" && d.headSHA != "" {
		head = d.headSHA + "\n"
	}
	if head == "ref: refs/heads/master\n" && best != nil {
		head = best.SHA + "\n"
	}
	_ = os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte(head), 0o644)

	writtenRefs := 0
	for ref, sha := range d.refs {
		if _, err := SanitizeRefName(ref); err != nil {
			continue
		}
		obj, ok := d.objects[sha]
		if !ok {
			d.addWarning("ref %s points to missing object %s; skipped", ref, ShortSHA(sha))
			continue
		}
		if obj.Type != "commit" && obj.Type != "tag" {
			continue
		}
		target := filepath.Join(gitDir, filepath.FromSlash(ref))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			d.addWarning("create ref directory %s: %v", ref, err)
			continue
		}
		if err := os.WriteFile(target, []byte(sha+"\n"), 0o644); err != nil {
			d.addWarning("write ref %s: %v", ref, err)
			continue
		}
		writtenRefs++
	}

	// Make every recovered commit visible to "git log --all" without creating
	// one file per commit.
	commits := make([]string, 0)
	for sha, obj := range d.objects {
		if obj.Type == "commit" {
			commits = append(commits, sha)
		}
	}
	sort.Strings(commits)
	if len(commits) > 0 {
		var buf bytes.Buffer
		buf.WriteString("# pack-refs with: peeled fully-peeled sorted\n")
		for _, sha := range commits {
			fmt.Fprintf(&buf, "%s refs/webkiller/recovered/%s\n", sha, sha)
		}
		_ = os.WriteFile(filepath.Join(gitDir, "packed-refs"), buf.Bytes(), 0o644)
	}

	// Treat commits whose parents are missing as shallow roots so git can
	// still traverse the partial history.
	var shallow bytes.Buffer
	for _, sha := range commits {
		commit := d.objects[sha].Commit
		if commit == nil {
			continue
		}
		missingParent := false
		for _, parent := range commit.Parents {
			if _, ok := d.objects[parent]; !ok {
				missingParent = true
				break
			}
		}
		if missingParent {
			shallow.WriteString(sha + "\n")
		}
	}
	shallowPath := filepath.Join(gitDir, "shallow")
	if shallow.Len() > 0 {
		_ = os.WriteFile(shallowPath, shallow.Bytes(), 0o644)
	} else {
		_ = os.Remove(shallowPath)
	}

	// Preserve fetched metadata for auditing and for the no-git scanner.
	for rel, body := range d.sources {
		var target string
		if strings.HasPrefix(rel, "logs/") {
			target = filepath.Join(gitDir, "webkiller", "logs", filepath.FromSlash(rel))
		} else {
			target = filepath.Join(gitDir, "webkiller", "sources", filepath.FromSlash(rel))
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			continue
		}
		_ = os.WriteFile(target, body, 0o644)
	}
	if len(d.indexRaw) > 0 {
		_ = os.WriteFile(filepath.Join(gitDir, "webkiller", "index"), d.indexRaw, 0o644)
	}

	var manifest bytes.Buffer
	fmt.Fprintf(&manifest, "WebKiller-leak Git reconstruction\n")
	fmt.Fprintf(&manifest, "base: %s\n", d.Base)
	fmt.Fprintf(&manifest, "head: %s\n", d.headSHA)
	fmt.Fprintf(&manifest, "head_ref: %s\n", d.headRef)
	fmt.Fprintf(&manifest, "objects: %d\n", len(d.objects))
	fmt.Fprintf(&manifest, "refs_written: %d\n", writtenRefs)
	fmt.Fprintf(&manifest, "recovered_commits: %d\n", len(commits))
	fmt.Fprintf(&manifest, "packs: %s\n", strings.Join(d.packs, ", "))
	_ = os.MkdirAll(filepath.Join(gitDir, "webkiller"), 0o755)
	_ = os.WriteFile(filepath.Join(gitDir, "webkiller", "summary.txt"), manifest.Bytes(), 0o644)
}

func (d *Dumper) bestCommit() *CommitInfo {
	resolve := func(sha string) *CommitInfo {
		for i := 0; i < 10 && sha != ""; i++ {
			obj, ok := d.objects[sha]
			if !ok {
				return nil
			}
			switch obj.Type {
			case "commit":
				return obj.Commit
			case "tag":
				if obj.Tag == nil {
					return nil
				}
				sha = obj.Tag.Object
			default:
				return nil
			}
		}
		return nil
	}
	if d.headSHA != "" {
		if commit := resolve(d.headSHA); commit != nil {
			return commit
		}
	}
	var best *CommitInfo
	for _, obj := range d.objects {
		if obj.Type != "commit" || obj.Commit == nil {
			continue
		}
		if best == nil || obj.Commit.Timestamp > best.Timestamp {
			best = obj.Commit
		}
	}
	return best
}

func (d *Dumper) materialize(ctx context.Context) {
	best := d.bestCommit()
	written := make(map[string]bool)
	if best != nil {
		d.materializeTree(ctx, best.Tree, "", 0, written)
	}
	d.materializeIndex(ctx, written)

	var manifest bytes.Buffer
	paths := make([]string, 0, len(written))
	for rel := range written {
		paths = append(paths, rel)
	}
	sort.Strings(paths)
	for _, rel := range paths {
		manifest.WriteString(rel + "\n")
	}
	_ = os.MkdirAll(filepath.Join(d.Out, ".git", "webkiller"), 0o755)
	_ = os.WriteFile(filepath.Join(d.Out, ".git", "webkiller", "files.txt"), manifest.Bytes(), 0o644)
	d.filesWritten = len(written)
}

func (d *Dumper) materializeTree(ctx context.Context, treeSHA, prefix string, depth int, written map[string]bool) {
	if ctx.Err() != nil || depth > 100 || treeSHA == "" {
		return
	}
	obj, ok := d.objects[treeSHA]
	if !ok {
		d.addMissing(treeSHA, "tree "+prefix)
		return
	}
	if obj.Type != "tree" {
		d.addWarning("object %s referenced as tree is %s", ShortSHA(treeSHA), obj.Type)
		return
	}
	for _, entry := range obj.Tree {
		rel := path.Join(prefix, entry.Name)
		if !validWorktreePath(rel) {
			d.addWarning("skip unsafe tree path %q", rel)
			continue
		}
		clean, err := SanitizeRelPath(rel)
		if err != nil {
			d.addWarning("skip unsafe tree path %q: %v", rel, err)
			continue
		}
		rel = clean
		mode := entry.Mode
		switch {
		case mode == "40000" || mode == "040000":
			d.materializeTree(ctx, entry.SHA, rel, depth+1, written)
		case mode == "160000":
			d.addWarning("skip submodule %s (%s)", rel, ShortSHA(entry.SHA))
		default:
			typ, content, err := d.readObjectContent(entry.SHA)
			if err != nil {
				d.addMissing(entry.SHA, rel)
				continue
			}
			if typ != "blob" {
				d.addWarning("object %s for %s is %s, not blob", ShortSHA(entry.SHA), rel, typ)
				continue
			}
			fileMode := os.FileMode(0o644)
			if mode == "100755" {
				fileMode = 0o755
			}
			if mode == "120000" {
				// Never create a symlink from remote data: it could point
				// outside the output tree. Preserve the target as text.
				fileMode = 0o644
			}
			if _, err := SafeWriteFile(d.Out, rel, content, fileMode); err != nil {
				d.addWarning("write %s: %v", rel, err)
				continue
			}
			written[rel] = true
			d.filesWritten++
		}
	}
}

func (d *Dumper) materializeIndex(ctx context.Context, written map[string]bool) {
	for _, entry := range d.index {
		if ctx.Err() != nil {
			return
		}
		if !validWorktreePath(entry.Path) {
			continue
		}
		rel, err := SanitizeRelPath(entry.Path)
		if err != nil {
			d.addWarning("skip unsafe index path %q: %v", entry.Path, err)
			continue
		}
		if written[rel] {
			continue
		}
		typ, content, err := d.readObjectContent(entry.SHA)
		if err != nil {
			d.addMissing(entry.SHA, rel)
			continue
		}
		if typ != "blob" {
			continue
		}
		mode := os.FileMode(0o644)
		if entry.Mode&0o111 != 0 {
			mode = 0o755
		}
		if _, err := SafeWriteFile(d.Out, rel, content, mode); err != nil {
			d.addWarning("write index path %s: %v", rel, err)
			continue
		}
		written[rel] = true
		d.filesWritten++
	}
}

func validWorktreePath(rel string) bool {
	clean := strings.ReplaceAll(rel, "\\", "/")
	parts := strings.Split(clean, "/")
	for _, part := range parts {
		if part == ".." || part == "" || part == "." {
			return false
		}
	}
	if len(parts) > 0 && strings.EqualFold(parts[0], ".git") {
		return false
	}
	return true
}

func (d *Dumper) writeMissing() {
	missing := d.missingList()
	target := filepath.Join(d.OutDir, "missing_objects.txt")
	if len(missing) == 0 {
		_ = os.Remove(target)
		return
	}
	var buf bytes.Buffer
	buf.WriteString("# Objects referenced by the remote repository but not retrievable\n")
	buf.WriteString("# SHA\tcontext\n")
	for _, item := range missing {
		fmt.Fprintf(&buf, "%s\t%s\n", item.SHA, item.Context)
	}
	_ = os.WriteFile(target, buf.Bytes(), 0o644)
}

func (d *Dumper) missingList() []MissingObject {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]MissingObject, 0, len(d.missing))
	for sha, context := range d.missing {
		out = append(out, MissingObject{SHA: sha, Context: context})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SHA < out[j].SHA })
	return out
}

func (d *Dumper) result() *DumpResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	stats := DumpStats{
		Objects:       len(d.objects),
		IndexEntries:  len(d.index),
		Refs:          len(d.refs),
		Packs:         len(d.packs),
		Bytes:         d.downloadedBytes,
		ObjectsDenied: d.objectsDenied,
		Files:         d.filesWritten,
	}
	for _, obj := range d.objects {
		switch obj.Type {
		case "commit":
			stats.Commits++
		case "tree":
			stats.Trees++
		case "blob":
			stats.Blobs++
		case "tag":
			stats.Tags++
		}
	}
	for ref := range d.refs {
		if strings.HasPrefix(ref, "refs/heads/") {
			stats.Branches++
		}
	}
	head := d.headSHA
	if head == "" {
		if best := d.bestCommit(); best != nil {
			head = best.SHA
		}
	}
	return &DumpResult{
		Stats:    stats,
		Missing:  d.missingListLocked(),
		Warnings: append([]string(nil), d.warnings...),
		Errors:   append([]string(nil), d.errors...),
		HeadSHA:  head,
		Base:     d.Base,
		RepoDir:  d.Out,
	}
}

func (d *Dumper) missingListLocked() []MissingObject {
	out := make([]MissingObject, 0, len(d.missing))
	for sha, context := range d.missing {
		out = append(out, MissingObject{SHA: sha, Context: context})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SHA < out[j].SHA })
	return out
}

func (d *Dumper) addRoot(sha string) {
	sha = strings.ToLower(strings.TrimSpace(sha))
	if !IsHexSHA(sha) || isZeroSHA(sha) {
		return
	}
	d.mu.Lock()
	d.roots[sha] = true
	d.mu.Unlock()
}

func isZeroSHA(sha string) bool {
	if len(sha) != 40 {
		return false
	}
	for _, r := range sha {
		if r != '0' {
			return false
		}
	}
	return true
}

func (d *Dumper) markSeen(sha string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen[sha] {
		return false
	}
	d.seen[sha] = true
	return true
}

func (d *Dumper) isSeen(sha string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.seen[sha]
}

func (d *Dumper) unseenRoots() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, 0, len(d.roots))
	for sha := range d.roots {
		if !d.seen[sha] {
			out = append(out, sha)
		}
	}
	sort.Strings(out)
	return out
}

func (d *Dumper) storeObject(obj *Object) {
	d.mu.Lock()
	d.objects[obj.SHA] = obj
	delete(d.missing, obj.SHA)
	d.mu.Unlock()
}

func (d *Dumper) addMissing(sha, context string) {
	sha = strings.ToLower(strings.TrimSpace(sha))
	if !IsHexSHA(sha) {
		return
	}
	d.mu.Lock()
	if _, ok := d.missing[sha]; !ok {
		d.missing[sha] = context
	}
	d.mu.Unlock()
}

func (d *Dumper) addWarning(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	d.mu.Lock()
	d.warnings = append(d.warnings, message)
	d.mu.Unlock()
	d.logf("warning: %s", message)
}

func (d *Dumper) addError(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	d.mu.Lock()
	d.errors = append(d.errors, message)
	d.mu.Unlock()
	d.logf("error: %s", message)
}

func (d *Dumper) logf(format string, args ...any) {
	if d.Verbose && d.Client != nil && d.Client.logger != nil {
		d.Client.logger.Printf("[git] "+format, args...)
	}
}

func mustJoin(base, rel string) string {
	u, err := JoinURL(base, rel)
	if err != nil {
		return base
	}
	return u
}

// ParseCommit parses a commit object's content.
func ParseCommit(sha string, content []byte) (*CommitInfo, error) {
	commit := &CommitInfo{SHA: strings.ToLower(sha)}
	header, message := splitObjectHeader(content)
	for _, line := range strings.Split(header, "\n") {
		line = strings.TrimSuffix(line, "\r")
		switch {
		case strings.HasPrefix(line, "tree "):
			commit.Tree = strings.TrimSpace(strings.TrimPrefix(line, "tree "))
		case strings.HasPrefix(line, "parent "):
			parent := strings.TrimSpace(strings.TrimPrefix(line, "parent "))
			if IsHexSHA(parent) {
				commit.Parents = append(commit.Parents, strings.ToLower(parent))
			}
		case strings.HasPrefix(line, "author "):
			commit.Author = strings.TrimPrefix(line, "author ")
			if ts, ok := identityTimestamp(commit.Author); ok {
				commit.Timestamp = ts
			}
		case strings.HasPrefix(line, "committer "):
			commit.Committer = strings.TrimPrefix(line, "committer ")
			if ts, ok := identityTimestamp(commit.Committer); ok {
				commit.Timestamp = ts
			}
		}
	}
	commit.Message = message
	if !IsHexSHA(commit.Tree) {
		return nil, fmt.Errorf("commit has no valid tree")
	}
	return commit, nil
}

// ParseTree parses a tree object's content.
func ParseTree(content []byte) ([]TreeEntry, error) {
	entries := make([]TreeEntry, 0)
	rest := content
	for len(rest) > 0 {
		space := bytes.IndexByte(rest, ' ')
		if space <= 0 {
			return nil, fmt.Errorf("malformed tree entry")
		}
		mode := string(rest[:space])
		if !validTreeMode(mode) {
			return nil, fmt.Errorf("invalid tree mode %q", mode)
		}
		rest = rest[space+1:]
		nul := bytes.IndexByte(rest, 0)
		if nul <= 0 || len(rest) < nul+21 {
			return nil, fmt.Errorf("malformed tree entry name")
		}
		name := string(rest[:nul])
		if strings.Contains(name, "/") || name == "." || name == ".." {
			return nil, fmt.Errorf("invalid tree entry name %q", name)
		}
		sha := hex.EncodeToString(rest[nul+1 : nul+21])
		entries = append(entries, TreeEntry{Mode: mode, Name: name, SHA: sha})
		rest = rest[nul+21:]
	}
	return entries, nil
}

// ParseTag parses an annotated tag object's content.
func ParseTag(sha string, content []byte) (*TagInfo, error) {
	tag := &TagInfo{}
	header, message := splitObjectHeader(content)
	for _, line := range strings.Split(header, "\n") {
		line = strings.TrimSuffix(line, "\r")
		switch {
		case strings.HasPrefix(line, "object "):
			tag.Object = strings.TrimSpace(strings.TrimPrefix(line, "object "))
		case strings.HasPrefix(line, "type "):
			tag.Type = strings.TrimSpace(strings.TrimPrefix(line, "type "))
		case strings.HasPrefix(line, "tag "):
			tag.Tag = strings.TrimSpace(strings.TrimPrefix(line, "tag "))
		}
	}
	tag.Message = message
	if !IsHexSHA(tag.Object) {
		return nil, fmt.Errorf("tag %s has no valid object", ShortSHA(sha))
	}
	return tag, nil
}

func splitObjectHeader(content []byte) (header, message string) {
	if idx := bytes.Index(content, []byte("\n\n")); idx >= 0 {
		return string(content[:idx]), string(content[idx+2:])
	}
	return string(content), ""
}

func identityTimestamp(identity string) (int64, bool) {
	fields := strings.Fields(identity)
	if len(fields) < 2 {
		return 0, false
	}
	ts, err := strconv.ParseInt(fields[len(fields)-2], 10, 64)
	if err != nil {
		return 0, false
	}
	return ts, true
}

func validTreeMode(mode string) bool {
	if mode == "" || len(mode) > 6 {
		return false
	}
	for _, r := range mode {
		if r < '0' || r > '7' {
			return false
		}
	}
	return true
}

// ParseIndex parses a Git index (DIRC) version 2, 3 or 4.
func ParseIndex(data []byte) ([]IndexEntry, error) {
	if len(data) < 12 || string(data[:4]) != "DIRC" {
		return nil, fmt.Errorf("not a Git index")
	}
	version := binary.BigEndian.Uint32(data[4:8])
	if version < 2 || version > 4 {
		return nil, fmt.Errorf("unsupported index version %d", version)
	}
	count := binary.BigEndian.Uint32(data[8:12])
	if count > 10_000_000 {
		return nil, fmt.Errorf("unreasonable index entry count %d", count)
	}
	pos := 12
	prev := ""
	entries := make([]IndexEntry, 0, count)
	for i := uint32(0); i < count; i++ {
		start := pos
		if pos+62 > len(data) {
			return nil, fmt.Errorf("truncated index entry %d", i)
		}
		mode := binary.BigEndian.Uint32(data[pos+24 : pos+28])
		size := binary.BigEndian.Uint32(data[pos+36 : pos+40])
		sha := hex.EncodeToString(data[pos+40 : pos+60])
		flags := binary.BigEndian.Uint16(data[pos+60 : pos+62])
		pos += 62
		if version >= 3 && flags&0x4000 != 0 {
			if pos+2 > len(data) {
				return nil, fmt.Errorf("truncated extended flags")
			}
			pos += 2
		}

		var name string
		if version == 4 {
			strip, n := binary.Uvarint(data[pos:])
			if n <= 0 {
				return nil, fmt.Errorf("invalid v4 path prefix length")
			}
			pos += n
			end := bytes.IndexByte(data[pos:], 0)
			if end < 0 {
				return nil, fmt.Errorf("unterminated v4 path")
			}
			suffix := string(data[pos : pos+end])
			pos += end + 1
			if int(strip) > len(prev) {
				return nil, fmt.Errorf("invalid v4 path compression")
			}
			name = prev[:len(prev)-int(strip)] + suffix
		} else {
			pathLen := int(flags & 0x0fff)
			if pathLen != 0x0fff && pathLen > 0 {
				if pos+pathLen > len(data) {
					return nil, fmt.Errorf("truncated index path")
				}
				name = string(data[pos : pos+pathLen])
				pos += pathLen
				if pos < len(data) && data[pos] == 0 {
					pos++
				}
			} else {
				end := bytes.IndexByte(data[pos:], 0)
				if end < 0 {
					return nil, fmt.Errorf("unterminated index path")
				}
				name = string(data[pos : pos+end])
				pos += end + 1
			}
			if pad := (8 - (pos-start)%8) % 8; pad > 0 {
				if pos+pad > len(data) {
					return nil, fmt.Errorf("truncated index padding")
				}
				pos += pad
			}
		}
		prev = name
		if name == "" || !IsHexSHA(sha) {
			continue
		}
		entries = append(entries, IndexEntry{Path: name, SHA: sha, Mode: mode, Size: size})
	}
	return entries, nil
}

// ParsePackIndex extracts object names from a pack .idx file (v1 or v2).
func ParsePackIndex(data []byte) ([]string, error) {
	if len(data) < 256*4+20 {
		return nil, fmt.Errorf("pack index is too short")
	}
	if bytes.Equal(data[:4], []byte{0xff, 't', 'O', 'c'}) {
		if len(data) < 8 {
			return nil, fmt.Errorf("truncated pack index")
		}
		version := binary.BigEndian.Uint32(data[4:8])
		if version != 2 {
			return nil, fmt.Errorf("unsupported pack index version %d", version)
		}
		base := 8
		if len(data) < base+256*4 {
			return nil, fmt.Errorf("truncated pack index fanout")
		}
		count := binary.BigEndian.Uint32(data[base+255*4 : base+256*4])
		if count > 10_000_000 {
			return nil, fmt.Errorf("unreasonable pack object count %d", count)
		}
		need := base + 256*4 + int(count)*20
		if len(data) < need {
			return nil, fmt.Errorf("truncated pack index SHA table")
		}
		shas := make([]string, 0, count)
		pos := base + 256*4
		for i := uint32(0); i < count; i++ {
			shas = append(shas, hex.EncodeToString(data[pos:pos+20]))
			pos += 20
		}
		return shas, nil
	}

	count := binary.BigEndian.Uint32(data[255*4 : 256*4])
	if count > 10_000_000 {
		return nil, fmt.Errorf("unreasonable pack object count %d", count)
	}
	need := 256*4 + int(count)*24
	if len(data) < need {
		return nil, fmt.Errorf("truncated v1 pack index")
	}
	shas := make([]string, 0, count)
	pos := 256 * 4
	for i := uint32(0); i < count; i++ {
		pos += 4 // 32-bit offset
		shas = append(shas, hex.EncodeToString(data[pos:pos+20]))
		pos += 20
	}
	return shas, nil
}

var objectNamePattern = regexp.MustCompile(`(?i)\b[0-9a-f]{38}\b`)

func parseObjectDirListing(body []byte) []string {
	matches := objectNamePattern.FindAllString(string(body), -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(matches))
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		match = strings.ToLower(match)
		if !seen[match] {
			seen[match] = true
			out = append(out, match)
		}
	}
	return out
}

// WaitForGit is a small helper for tests that need to know whether the git
// binary is available.
func WaitForGit() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// SetTimeout is a convenience used by tests to keep contexts bounded.
func SetTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, d)
}

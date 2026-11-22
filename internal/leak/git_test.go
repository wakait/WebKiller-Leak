package leak

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=WebKiller Test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=WebKiller Test",
		"GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_AUTHOR_DATE=2024-01-01T00:00:00Z",
		"GIT_COMMITTER_DATE=2024-01-01T00:00:00Z",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func createGitFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "init", "-b", "master")
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app.go", "package main\n\nfunc main() {}\n")
	gitRun(t, repo, "add", "app.go")
	gitRun(t, repo, "commit", "-m", "initial app")

	write("secret.txt", "flag{history_secret}\ndb_password=supersecret123\n")
	gitRun(t, repo, "add", "secret.txt")
	gitRun(t, repo, "commit", "-m", "add temporary secret")

	gitRun(t, repo, "rm", "secret.txt")
	gitRun(t, repo, "commit", "-m", "remove secret")

	gitRun(t, repo, "checkout", "-b", "feature")
	write("feature.txt", "feature branch\n")
	gitRun(t, repo, "add", "feature.txt")
	gitRun(t, repo, "commit", "-m", "feature work")
	gitRun(t, repo, "checkout", "master")
	gitRun(t, repo, "tag", "v1")

	// A commit that is no longer reachable from any branch, but remains in
	// the reflog and object database.
	gitRun(t, repo, "checkout", "-b", "temporary")
	write("dangling.txt", "flag{dangling_secret}\n")
	gitRun(t, repo, "add", "dangling.txt")
	gitRun(t, repo, "commit", "-m", "dangling secret")
	gitRun(t, repo, "checkout", "master")
	gitRun(t, repo, "branch", "-D", "temporary")
	return root
}

func newTestClient(t *testing.T) *Client {
	t.Helper()
	client := NewClient(ClientOptions{Concurrency: 8, Timeout: 10 * time.Second, Rate: 0, Verbose: false})
	t.Cleanup(client.Close)
	return client
}

func TestDumperReconstructsRepositoryAndHistory(t *testing.T) {
	if !WaitForGit() {
		t.Skip("git is not available")
	}
	root := createGitFixture(t)
	server := httptest.NewServer(http.FileServer(http.Dir(root)))
	defer server.Close()
	base := server.URL + "/repo/.git/"

	out := t.TempDir()
	dumper := NewDumper(newTestClient(t), base, out, 8, false, false)
	result, err := dumper.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v (result=%#v)", err, result)
	}
	if result.Stats.Commits < 4 {
		t.Fatalf("commits = %d, want at least 4", result.Stats.Commits)
	}
	if result.Stats.Blobs < 3 {
		t.Fatalf("blobs = %d, want at least 3", result.Stats.Blobs)
	}
	if result.Stats.Files < 1 {
		t.Fatalf("files = %d, want at least 1", result.Stats.Files)
	}
	if result.Stats.IndexEntries < 1 {
		t.Fatalf("index entries = %d, want at least 1", result.Stats.IndexEntries)
	}
	repoDir := filepath.Join(out, "repo")
	if _, err := os.Stat(filepath.Join(repoDir, "app.go")); err != nil {
		t.Fatalf("latest worktree file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repoDir, "secret.txt")); err == nil {
		t.Fatal("deleted secret.txt should not be in the latest worktree")
	}
	logOut, err := exec.Command("git", "-C", repoDir, "log", "--all", "--oneline").CombinedOutput()
	if err != nil {
		t.Fatalf("reconstructed git log failed: %v\n%s", err, logOut)
	}
	if lines := strings.Count(strings.TrimSpace(string(logOut)), "\n") + 1; lines < 4 {
		t.Fatalf("reconstructed history has %d commits:\n%s", lines, logOut)
	}

	scanResult, err := Scan(context.Background(), ScanOptions{
		RepoDir: repoDir,
		OutDir:  out,
		UseGit:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	flags := 0
	for _, finding := range scanResult.Findings {
		if finding.Rule == "flag" && strings.Contains(finding.Value, "history_secret") {
			flags++
		}
	}
	if flags == 0 {
		t.Fatalf("historical flag not found: %#v", scanResult.Findings)
	}
	if !scanResult.GitUsed {
		t.Fatal("Git history scan was not used")
	}
	if err := WriteFindings(out, scanResult.Findings, FindingsMeta{Target: base, Sources: scanResult.Sources, Warnings: scanResult.Warnings, GitUsed: scanResult.GitUsed}); err != nil {
		t.Fatal(err)
	}
	report, err := os.ReadFile(filepath.Join(out, "findings.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(report), "flag{history_secret}") {
		t.Fatalf("findings report missing flag:\n%s", report)
	}
	if strings.Contains(string(report), "supersecret123") {
		t.Fatalf("findings report leaked a raw secret:\n%s", report)
	}
}

func TestDumperPackScenario(t *testing.T) {
	if !WaitForGit() {
		t.Skip("git is not available")
	}
	root := createGitFixture(t)
	repo := filepath.Join(root, "repo")
	gitRun(t, repo, "gc", "--aggressive", "--prune=now")
	server := httptest.NewServer(http.FileServer(http.Dir(root)))
	defer server.Close()

	out := t.TempDir()
	dumper := NewDumper(newTestClient(t), server.URL+"/repo/.git/", out, 8, false, true)
	result, err := dumper.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v (result=%#v)", err, result)
	}
	if result.Stats.Commits < 4 {
		t.Fatalf("packed commits = %d, want at least 4", result.Stats.Commits)
	}
	if result.Stats.Packs == 0 {
		t.Fatal("no pack was detected")
	}
	if result.Stats.Files < 1 {
		t.Fatalf("packed files = %d", result.Stats.Files)
	}
}

func TestScanWithoutGitStillFindsObjectSecrets(t *testing.T) {
	if !WaitForGit() {
		t.Skip("git is not available")
	}
	root := createGitFixture(t)
	server := httptest.NewServer(http.FileServer(http.Dir(root)))
	defer server.Close()
	out := t.TempDir()
	dumper := NewDumper(newTestClient(t), server.URL+"/repo/.git/", out, 8, false, false)
	if _, err := dumper.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	result, err := Scan(context.Background(), ScanOptions{
		RepoDir: filepath.Join(out, "repo"),
		OutDir:  out,
		UseGit:  false,
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, finding := range result.Findings {
		if finding.Rule == "flag" && strings.Contains(finding.Value, "history_secret") {
			found = true
		}
	}
	if !found {
		t.Fatalf("fallback object scan did not find the flag: %#v", result.Findings)
	}
	if result.GitUsed {
		t.Fatal("GitUsed should be false")
	}
}

func TestBruteforceDownloadsExactKnownObjectBeforeDirectoryFallback(t *testing.T) {
	content := []byte("flag{bruteforce_seed}")
	header := fmt.Sprintf("blob %d\x00", len(content))
	sum := sha1.Sum(append([]byte(header), content...))
	sha := hex.EncodeToString(sum[:])

	raw, err := EncodeLooseObject("blob", content)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exact := "/.git/objects/" + sha[:2] + "/" + sha[2:]
		if r.URL.Path == exact {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(raw)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/.git/objects/") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	out := t.TempDir()
	dumper := NewDumper(newTestClient(t), server.URL+"/.git/", out, 8, true, false)
	dumper.addRoot(sha)
	dumper.prepareDirs()
	dumper.bruteforce(context.Background())

	local := dumper.localObjectPath(sha)
	got, err := os.ReadFile(local)
	if err != nil {
		t.Fatalf("known SHA object was not saved: %v", err)
	}
	typ, parsed, err := ParseLooseObject(got)
	if err != nil || typ != "blob" || string(parsed) != string(content) {
		t.Fatalf("saved object = typ %q, content %q, err %v", typ, parsed, err)
	}
	if dumper.downloadedBytes == 0 {
		t.Fatal("known SHA download was not counted")
	}
}

package leak

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNormalizeBase(t *testing.T) {
	cases := []struct {
		in       string
		wantSite string
		wantGit  string
		wantErr  bool
	}{
		{"http://example.com", "http://example.com/", "http://example.com/.git/", false},
		{"http://example.com/", "http://example.com/", "http://example.com/.git/", false},
		{"http://example.com/.git/", "http://example.com/", "http://example.com/.git/", false},
		{"http://example.com/app/.git", "http://example.com/app/", "http://example.com/app/.git/", false},
		{"https://example.com/app", "https://example.com/app/", "https://example.com/app/.git/", false},
		{"ftp://example.com/", "", "", true},
		{"", "", "", true},
	}
	for _, tc := range cases {
		site, git, err := NormalizeBase(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("NormalizeBase(%q) unexpectedly succeeded", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeBase(%q): %v", tc.in, err)
			continue
		}
		if site != tc.wantSite || git != tc.wantGit {
			t.Errorf("NormalizeBase(%q) = (%q, %q), want (%q, %q)", tc.in, site, git, tc.wantSite, tc.wantGit)
		}
	}
}

func TestJoinURL(t *testing.T) {
	got, err := JoinURL("http://example.com/base/", "dir/file name.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://example.com/base/dir/file%20name.txt" {
		t.Fatalf("JoinURL = %q", got)
	}
}

func TestProbeFindsGitAndDSStore(t *testing.T) {
	sha := strings.Repeat("a", 40)
	mux := http.NewServeMux()
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ref: refs/heads/master\n"))
	})
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("[core]\n\trepositoryformatversion = 0\n"))
	})
	mux.HandleFunc("/.git/refs/heads/master", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sha + "\n"))
	})
	mux.HandleFunc("/.git/info/refs", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sha + "\trefs/heads/master\n"))
	})
	mux.HandleFunc("/.git/logs/HEAD", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("0", 40) + " " + sha + " A <a@b> 1700000000 +0000\tcommit\n"))
	})
	mux.HandleFunc("/.git/index", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("DIRC\x00\x00\x00\x02\x00\x00\x00\x00"))
	})
	mux.HandleFunc("/.git/objects/info/packs", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("P pack-" + sha + ".pack\n"))
	})
	mux.HandleFunc("/.DS_Store", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte{0, 0, 0, 1, 'B', 'u', 'd', '1', 0, 0, 'c', 'o', 'n', 'f', 'i', 'g'})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><title>Index of /</title><a href=\"admin/\">admin/</a></html>"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(ClientOptions{Concurrency: 4, Timeout: 5 * time.Second, Rate: 0})
	defer client.Close()
	findings := Probe(context.Background(), client, server.URL+"/", 4)
	if !HasKind(findings, "git") {
		t.Fatalf("git leak not detected: %#v", findings)
	}
	if !HasKind(findings, "dsstore") {
		t.Fatalf(".DS_Store leak not detected: %#v", findings)
	}
	if !HasKind(findings, "listing") {
		t.Fatalf("directory listing not detected: %#v", findings)
	}
	if !AnyReachable(findings) {
		t.Fatal("AnyReachable = false")
	}
	if HasKind(findings, "svn") || HasKind(findings, "hg") {
		t.Fatalf("unexpected leak kind: %#v", findings)
	}
}

func TestProbeUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	base := server.URL
	server.Close()

	client := NewClient(ClientOptions{Concurrency: 2, Timeout: 200 * time.Millisecond, Rate: 0})
	defer client.Close()
	findings := Probe(context.Background(), client, base+"/", 2)
	if AnyReachable(findings) {
		t.Fatalf("expected unreachable target, got %#v", findings)
	}
}

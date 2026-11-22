package leak

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Finding is one probed leak path.
type Finding struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Status int    `json:"status"`
	OK     bool   `json:"ok"`
	Note   string `json:"note,omitempty"`
}

type probeSpec struct {
	Path     string
	Kind     string
	MaxBytes int64
	Check    func(path string, status int, body []byte) (bool, string)
}

var probeSpecs = []probeSpec{
	{Path: ".git/HEAD", Kind: "git", Check: checkGitHEAD},
	{Path: ".git/config", Kind: "git", Check: checkGitConfig},
	{Path: ".git/refs/heads/master", Kind: "git", Check: checkGitRef},
	{Path: ".git/refs/heads/main", Kind: "git", Check: checkGitRef},
	{Path: ".git/info/refs", Kind: "git", Check: checkGitInfoRefs},
	{Path: ".git/logs/HEAD", Kind: "git", Check: checkGitLog},
	{Path: ".git/index", Kind: "git", MaxBytes: 1 << 20, Check: checkGitIndex},
	{Path: ".git/objects/info/packs", Kind: "git", Check: checkGitPackInfo},
	{Path: ".DS_Store", Kind: "dsstore", Check: checkDSStore},
	{Path: ".svn/entries", Kind: "svn", Check: checkSVNEntries},
	{Path: ".svn/wc.db", Kind: "svn", Check: checkSQLite},
	{Path: ".hg/hgrc", Kind: "hg", Check: checkHG},
	{Path: ".bzr/README", Kind: "bzr", Check: checkBZR},
	{Path: "", Kind: "listing", Check: checkListing},
}

// Probe checks all known leak paths concurrently. It returns one Finding per
// path, including negative results, so the caller can distinguish "reachable
// but no leak" from "target unreachable".
func Probe(ctx context.Context, client *Client, siteBase string, concurrency int) []Finding {
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	results := make(chan Finding, len(probeSpecs))
	var wg sync.WaitGroup

	for _, spec := range probeSpecs {
		spec := spec
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results <- Finding{Path: spec.Path, Kind: spec.Kind, Note: "canceled"}
				return
			}
			defer func() { <-sem }()

			target, err := JoinURL(siteBase, spec.Path)
			if err != nil {
				results <- Finding{Path: spec.Path, Kind: spec.Kind, Note: "invalid URL"}
				return
			}
			var body []byte
			var status int
			if spec.MaxBytes > 0 {
				body, status, err = client.GetLimited(ctx, target, spec.MaxBytes)
			} else {
				body, status, err = client.Get(ctx, target)
			}
			if err != nil {
				results <- Finding{
					Path:   spec.Path,
					Kind:   spec.Kind,
					Status: status,
					Note:   shortError(err),
				}
				return
			}
			ok, note := spec.Check(spec.Path, status, body)
			results <- Finding{
				Path:   spec.Path,
				Kind:   spec.Kind,
				Status: status,
				OK:     ok,
				Note:   note,
			}
		}()
	}

	wg.Wait()
	close(results)

	findings := make([]Finding, 0, len(probeSpecs))
	for f := range results {
		findings = append(findings, f)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Kind != findings[j].Kind {
			return findings[i].Kind < findings[j].Kind
		}
		return findings[i].Path < findings[j].Path
	})
	return findings
}

// HasKind reports whether at least one positive finding of kind exists.
func HasKind(findings []Finding, kind string) bool {
	for _, f := range findings {
		if f.Kind == kind && f.OK {
			return true
		}
	}
	return false
}

// AnyReachable reports whether any probe received an HTTP response.
func AnyReachable(findings []Finding) bool {
	for _, f := range findings {
		if f.Status > 0 {
			return true
		}
	}
	return false
}

// PositiveFindings returns only confirmed leaks.
func PositiveFindings(findings []Finding) []Finding {
	out := make([]Finding, 0)
	for _, f := range findings {
		if f.OK {
			out = append(out, f)
		}
	}
	return out
}

func checkGitHEAD(_ string, status int, body []byte) (bool, string) {
	if status != http.StatusOK {
		return false, statusNote(status)
	}
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "ref: ") {
		return true, "HEAD 指向 " + strings.TrimSpace(strings.TrimPrefix(trimmed, "ref: "))
	}
	if IsHexSHA(trimmed) {
		return true, "HEAD 已处于 detached 状态"
	}
	return false, "HEAD 内容格式异常"
}

func checkGitConfig(_ string, status int, body []byte) (bool, string) {
	if status != http.StatusOK {
		return false, statusNote(status)
	}
	if bytes.Contains(body, []byte("[core]")) {
		return true, "Git config exposed"
	}
	return false, "unexpected config content"
}

func checkGitRef(_ string, status int, body []byte) (bool, string) {
	if status != http.StatusOK {
		return false, statusNote(status)
	}
	if IsHexSHA(strings.TrimSpace(string(body))) {
		return true, "ref exposed"
	}
	return false, "unexpected ref content"
}

func checkGitInfoRefs(_ string, status int, body []byte) (bool, string) {
	if status != http.StatusOK {
		return false, statusNote(status)
	}
	text := string(body)
	if strings.Contains(text, "refs/") && len(ExtractSHAs(text)) > 0 {
		return true, "dumb HTTP info/refs exposed"
	}
	return false, "unexpected info/refs content"
}

func checkGitLog(_ string, status int, body []byte) (bool, string) {
	if status != http.StatusOK {
		return false, statusNote(status)
	}
	if len(ExtractSHAs(string(body))) > 0 {
		return true, "reflog exposed"
	}
	return false, "unexpected reflog content"
}

func checkGitIndex(_ string, status int, body []byte) (bool, string) {
	if status != http.StatusOK {
		return false, statusNote(status)
	}
	if len(body) >= 12 && string(body[:4]) == "DIRC" {
		return true, "Git index exposed"
	}
	return false, "unexpected index content"
}

func checkGitPackInfo(_ string, status int, body []byte) (bool, string) {
	if status != http.StatusOK {
		return false, statusNote(status)
	}
	text := string(body)
	if strings.Contains(text, "pack-") || strings.Contains(text, "P pack") {
		return true, "pack metadata exposed"
	}
	return false, "unexpected pack metadata"
}

func checkDSStore(_ string, status int, body []byte) (bool, string) {
	if status != http.StatusOK {
		return false, statusNote(status)
	}
	if len(body) >= 8 && bytes.HasPrefix(body, []byte{0x00, 0x00, 0x00, 0x01}) &&
		bytes.Equal(body[4:8], []byte("Bud1")) {
		return true, "macOS .DS_Store magic found"
	}
	head := body
	if len(head) > 64 {
		head = head[:64]
	}
	if bytes.Contains(head, []byte("Bud1")) {
		return true, "possible .DS_Store"
	}
	return false, "unexpected .DS_Store content"
}

func checkSVNEntries(_ string, status int, body []byte) (bool, string) {
	if status != http.StatusOK {
		return false, statusNote(status)
	}
	if len(body) == 0 || looksLikeHTML(body) {
		return false, "unexpected entries content"
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return false, "empty entries file"
	}
	first := trimmed[0]
	if (first >= '0' && first <= '9') || strings.Contains(trimmed, "dir\n") ||
		strings.Contains(trimmed, "file\n") || strings.HasPrefix(trimmed, "<?xml") {
		return true, "Subversion metadata exposed"
	}
	return false, "unexpected entries content"
}

func checkSQLite(_ string, status int, body []byte) (bool, string) {
	if status != http.StatusOK {
		return false, statusNote(status)
	}
	if bytes.HasPrefix(body, []byte("SQLite format 3\x00")) {
		return true, "Subversion wc.db (SQLite) exposed"
	}
	return false, "not a SQLite database"
}

func checkHG(_ string, status int, body []byte) (bool, string) {
	if status != http.StatusOK {
		return false, statusNote(status)
	}
	text := string(body)
	if strings.Contains(text, "[paths]") || strings.Contains(text, "[ui]") ||
		strings.Contains(text, "[extensions]") {
		return true, "Mercurial config exposed"
	}
	return false, "unexpected hgrc content"
}

func checkBZR(_ string, status int, body []byte) (bool, string) {
	if status != http.StatusOK {
		return false, statusNote(status)
	}
	if len(body) > 0 && !looksLikeHTML(body) {
		return true, "Bazaar metadata reachable"
	}
	return false, "unexpected Bazaar content"
}

func checkListing(path string, status int, body []byte) (bool, string) {
	if status != http.StatusOK {
		return false, statusNote(status)
	}
	lower := strings.ToLower(string(body))
	if strings.Contains(lower, "<title>index of") ||
		strings.Contains(lower, "<h1>index of") ||
		strings.Contains(lower, "directory listing for") {
		return true, "directory listing enabled"
	}
	if path == "" {
		return false, "root reachable, no directory listing"
	}
	return false, "unexpected listing content"
}

func looksLikeHTML(body []byte) bool {
	head := body
	if len(head) > 1024 {
		head = head[:1024]
	}
	lower := strings.ToLower(string(head))
	return strings.Contains(lower, "<!doctype html") || strings.Contains(lower, "<html")
}

func statusNote(status int) string {
	switch status {
	case http.StatusForbidden:
		return "forbidden (403)"
	case http.StatusNotFound:
		return "not found (404)"
	case http.StatusUnauthorized:
		return "unauthorized (401)"
	case 0:
		return "request failed"
	default:
		return fmt.Sprintf("HTTP %d", status)
	}
}

func shortError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return s
}

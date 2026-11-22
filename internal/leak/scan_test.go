package leak

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func flagBinary(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		fmt.Fprintf(&b, "%08b", c)
	}
	return b.String()
}

func flagEntity(s string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, "&#%d;", r)
	}
	return b.String()
}

func ruleNames(rules []Rule) map[string]bool {
	names := make(map[string]bool, len(rules))
	for _, rule := range rules {
		names[rule.Name] = true
	}
	return names
}

func TestBuildRulesDefaultEncodings(t *testing.T) {
	rules, err := BuildRules("")
	if err != nil {
		t.Fatal(err)
	}
	names := ruleNames(rules)
	for _, want := range []string{"flag", "flag-hex", "flag-base64", "flag-ascii-bin", "flag-unicode-entity"} {
		if !names[want] {
			t.Errorf("default rules missing %q in %#v", want, names)
		}
	}

	custom, err := BuildRules(`ctf\{[^}]+\}`)
	if err != nil {
		t.Fatal(err)
	}
	names = ruleNames(custom)
	if !names["flag"] {
		t.Errorf("custom pattern should register flag rule: %#v", names)
	}
	for _, unwanted := range []string{"flag-hex", "flag-base64", "flag-ascii-bin", "flag-unicode-entity"} {
		if names[unwanted] {
			t.Errorf("custom pattern should not register %q", unwanted)
		}
	}
}

func TestDefaultFlagRulesDetectEncodedFlags(t *testing.T) {
	repo := t.TempDir()
	want := map[string]string{
		"flag":                "flag{plain_ok}",
		"flag-hex":            "flag{hex_ok}",
		"flag-base64":         "flag{base64_ok}",
		"flag-ascii-bin":      "flag{binary_ok}",
		"flag-unicode-entity": "flag{entity_ok}",
	}
	content := strings.Join([]string{
		want["flag"],
		"666c61677b6865785f6f6b7d",
		base64.StdEncoding.EncodeToString([]byte(want["flag-base64"])),
		flagBinary(want["flag-ascii-bin"]),
		flagEntity(want["flag-unicode-entity"]),
	}, "\n")
	if err := os.WriteFile(filepath.Join(repo, "notes.txt"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(context.Background(), ScanOptions{RepoDir: repo, OutDir: t.TempDir(), UseGit: false})
	if err != nil {
		t.Fatal(err)
	}
	byRule := make(map[string][]ScanFinding)
	for _, finding := range result.Findings {
		byRule[finding.Rule] = append(byRule[finding.Rule], finding)
	}
	for rule, value := range want {
		findings := byRule[rule]
		if len(findings) == 0 {
			t.Errorf("rule %q produced no findings", rule)
			continue
		}
		found := false
		for _, finding := range findings {
			if finding.Value == value {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("rule %q did not decode to %q: %#v", rule, value, findings)
		}
	}
}

func TestBuildRulesRejectsInvalidPattern(t *testing.T) {
	if _, err := BuildRules("("); err == nil {
		t.Fatal("expected invalid regexp error")
	}
	rules, err := BuildRules("")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) < 5 {
		t.Fatalf("rules = %#v", rules)
	}
}

func TestScanFindsAndMasksSecrets(t *testing.T) {
	repo := t.TempDir()
	worktree := "flag{worktree_flag}\n" +
		"pass" + "word = 'supersecret123'\n" +
		"AKIAIOSFODNN7EXAMPLE\n" +
		"ghp_" + strings.Repeat("a", 36) + "\n" +
		"-----BEGIN RSA PRIVATE KEY-----\n"
	if err := os.WriteFile(filepath.Join(repo, "config.php"), []byte(worktree), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "copy.txt"), []byte("flag{worktree_flag}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	objectContent := []byte("flag{object_flag}\npass" + "word=objectsecret123\n")
	raw, err := EncodeLooseObject("blob", objectContent)
	if err != nil {
		t.Fatal(err)
	}
	objectDir := filepath.Join(repo, ".git", "objects", "ab")
	if err := os.MkdirAll(objectDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(objectDir, strings.Repeat("c", 38)), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "config"), []byte("[core]\n\ttoken = metadatasecret123\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "hidden.txt"), []byte("flag{metadata_flag}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(context.Background(), ScanOptions{RepoDir: repo, OutDir: t.TempDir(), UseGit: false})
	if err != nil {
		t.Fatal(err)
	}
	byRule := make(map[string][]ScanFinding)
	for _, finding := range result.Findings {
		byRule[finding.Rule] = append(byRule[finding.Rule], finding)
		if strings.Contains(finding.Value, "supersecret123") ||
			strings.Contains(finding.Value, "objectsecret123") ||
			strings.Contains(finding.Value, "metadatasecret123") {
			t.Errorf("raw secret leaked into value: %#v", finding)
		}
	}
	if len(byRule["flag"]) != 3 {
		t.Fatalf("flags = %#v", byRule["flag"])
	}
	flagValues := make(map[string]bool)
	for _, finding := range byRule["flag"] {
		flagValues[finding.Value] = true
	}
	for _, want := range []string{"flag{worktree_flag}", "flag{object_flag}", "flag{metadata_flag}"} {
		if !flagValues[want] {
			t.Errorf("missing flag %q in %#v", want, flagValues)
		}
	}
	for _, rule := range []string{"AWS access key ID", "GitHub token", "Private key", "Generic secret assignment"} {
		if len(byRule[rule]) == 0 {
			t.Errorf("missing rule %q in %#v", rule, byRule)
		}
	}
	if result.Sources["worktree"] == 0 || result.Sources["object"] == 0 || result.Sources["metadata"] == 0 {
		t.Fatalf("sources = %#v", result.Sources)
	}

	out := t.TempDir()
	if err := WriteFindings(out, result.Findings, FindingsMeta{Target: "http://example.test/", Sources: result.Sources}); err != nil {
		t.Fatal(err)
	}
	report, err := os.ReadFile(filepath.Join(out, "findings.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(report), "supersecret123") ||
		strings.Contains(string(report), "objectsecret123") ||
		strings.Contains(string(report), "metadatasecret123") {
		t.Fatalf("report leaked a raw secret:\n%s", report)
	}
	if !strings.Contains(string(report), "flag{worktree_flag}") {
		t.Fatalf("report missing flag:\n%s", report)
	}
}

func TestScanSkipsBinaryWorktreeFiles(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "binary.bin"), []byte("flag{binary_flag}\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Scan(context.Background(), ScanOptions{RepoDir: repo, OutDir: t.TempDir(), UseGit: false})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range result.Findings {
		if strings.Contains(finding.Value, "binary_flag") {
			t.Fatalf("binary file was scanned: %#v", finding)
		}
	}
}

func TestParseGitleaksReport(t *testing.T) {
	data := []byte(`[{"RuleID":"generic-api-key","File":"a.txt","StartLine":3,"Secret":"secretvalue","Commit":"` + strings.Repeat("a", 40) + `"}]`)
	findings, err := parseGitleaksReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != "generic-api-key" || findings[0].StartLine != 3 {
		t.Fatalf("findings = %#v", findings)
	}
	wrapped := []byte(`{"findings":[{"RuleID":"x","Secret":"y"}]}`)
	findings, err = parseGitleaksReport(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Secret != "y" {
		t.Fatalf("wrapped findings = %#v", findings)
	}
}

func TestWriteFindingsEmpty(t *testing.T) {
	out := t.TempDir()
	if err := WriteFindings(out, nil, FindingsMeta{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(out, "findings.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "未发现命中项。") {
		t.Fatalf("report = %s", data)
	}
}

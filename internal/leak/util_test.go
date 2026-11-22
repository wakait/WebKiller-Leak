package leak

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseLooseObject(t *testing.T) {
	raw, err := EncodeLooseObject("blob", []byte("hello flag{test}"))
	if err != nil {
		t.Fatal(err)
	}
	typ, content, err := ParseLooseObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	if typ != "blob" || string(content) != "hello flag{test}" {
		t.Fatalf("got type=%q content=%q", typ, content)
	}

	if _, _, err := ParseLooseObject([]byte("not zlib")); err == nil {
		t.Fatal("expected error for invalid zlib data")
	}
}

func TestSanitizeRelPath(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"a/b.txt", "a/b.txt", false},
		{"./a/b.txt", "a/b.txt", false},
		{"a//b.txt", "a/b.txt", false},
		{"a/../b.txt", "", true},
		{"../etc/passwd", "", true},
		{"/etc/passwd", "", true},
		{"a\\b.txt", "a/b.txt", false},
		{"a/\x01/b", "", true},
	}
	for _, tc := range cases {
		got, err := SanitizeRelPath(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("SanitizeRelPath(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("SanitizeRelPath(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("SanitizeRelPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSafeWriteFileRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	if _, err := SafeWriteFile(root, "../escape.txt", []byte("x"), 0o644); err == nil {
		t.Fatal("expected traversal error")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escape.txt")); err == nil {
		t.Fatal("file escaped the output root")
	}
	if _, err := SafeWriteFile(root, "nested/ok.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestMaskValue(t *testing.T) {
	cases := map[string]string{
		"AKIAIOSFODNN7EXAMPLE":            "AKIA****MPLE",
		"short":                           "****",
		"-----BEGIN RSA PRIVATE KEY-----": "-----BEGIN **** PRIVATE KEY-----",
	}
	for in, want := range cases {
		if got := MaskValue(in); got != want {
			t.Errorf("MaskValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractSHAs(t *testing.T) {
	a := strings.Repeat("a", 40)
	b := strings.Repeat("b", 40)
	got := ExtractSHAs("x " + a + " y " + a + " z " + b)
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("ExtractSHAs = %v", got)
	}
}

func TestParseCommitTreeTag(t *testing.T) {
	treeSHA := strings.Repeat("1", 40)
	parentSHA := strings.Repeat("2", 40)
	commitBody := "tree " + treeSHA + "\n" +
		"parent " + parentSHA + "\n" +
		"author Alice <a@example.com> 1700000000 +0000\n" +
		"committer Alice <a@example.com> 1700000100 +0000\n\n" +
		"add flag{commit_message}\n"
	commit, err := ParseCommit(strings.Repeat("3", 40), []byte(commitBody))
	if err != nil {
		t.Fatal(err)
	}
	if commit.Tree != treeSHA || len(commit.Parents) != 1 || commit.Parents[0] != parentSHA {
		t.Fatalf("commit = %#v", commit)
	}
	if commit.Timestamp != 1700000100 {
		t.Fatalf("timestamp = %d", commit.Timestamp)
	}
	if !strings.Contains(commit.Message, "flag{commit_message}") {
		t.Fatalf("message = %q", commit.Message)
	}

	blobSHA := strings.Repeat("4", 40)
	treeBody := []byte("100644 file.txt\x00")
	shaBytes, _ := hex.DecodeString(blobSHA)
	treeBody = append(treeBody, shaBytes...)
	entries, err := ParseTree(treeBody)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "file.txt" || entries[0].SHA != blobSHA {
		t.Fatalf("tree entries = %#v", entries)
	}

	tagBody := "object " + commit.SHA + "\ntype commit\ntag v1\n\nrelease flag{tag_message}\n"
	tag, err := ParseTag(strings.Repeat("5", 40), []byte(tagBody))
	if err != nil {
		t.Fatal(err)
	}
	if tag.Object != commit.SHA || tag.Tag != "v1" || !strings.Contains(tag.Message, "flag{tag_message}") {
		t.Fatalf("tag = %#v", tag)
	}
}

func TestParseIndexV2(t *testing.T) {
	sha := strings.Repeat("a", 40)
	shaBytes, _ := hex.DecodeString(sha)
	path := []byte("file.txt")
	var buf bytes.Buffer
	buf.WriteString("DIRC")
	_ = binary.Write(&buf, binary.BigEndian, uint32(2))
	_ = binary.Write(&buf, binary.BigEndian, uint32(1))

	entry := make([]byte, 62)
	binary.BigEndian.PutUint32(entry[24:28], 0o100644)
	binary.BigEndian.PutUint32(entry[36:40], 8)
	copy(entry[40:60], shaBytes)
	binary.BigEndian.PutUint16(entry[60:62], uint16(len(path)))
	buf.Write(entry)
	buf.Write(path)
	buf.WriteByte(0)
	for buf.Len()%8 != 0 {
		buf.WriteByte(0)
	}
	buf.Write(make([]byte, 20)) // checksum is not validated

	entries, err := ParseIndex(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %#v", entries)
	}
	if entries[0].Path != "file.txt" || entries[0].SHA != sha || entries[0].Mode != 0o100644 {
		t.Fatalf("entry = %#v", entries[0])
	}
}

func TestParsePackIndexV2(t *testing.T) {
	sha := strings.Repeat("b", 40)
	shaBytes, _ := hex.DecodeString(sha)
	var buf bytes.Buffer
	buf.Write([]byte{0xff, 't', 'O', 'c'})
	_ = binary.Write(&buf, binary.BigEndian, uint32(2))
	fanout := make([]byte, 256*4)
	binary.BigEndian.PutUint32(fanout[255*4:], 1)
	buf.Write(fanout)
	buf.Write(shaBytes)
	buf.Write(make([]byte, 4+4+20)) // CRC, offset and trailer (not needed for SHA extraction)
	shas, err := ParsePackIndex(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(shas) != 1 || shas[0] != sha {
		t.Fatalf("shas = %v", shas)
	}
}

func TestParseObjectDirListing(t *testing.T) {
	name := strings.Repeat("c", 38)
	body := `<a href="` + name + `">` + name + `</a> <a href="../">..</a>`
	got := parseObjectDirListing([]byte(body))
	if len(got) != 1 || got[0] != name {
		t.Fatalf("got %v", got)
	}
}

func TestSanitizeRefName(t *testing.T) {
	valid := []string{"refs/heads/master", "refs/tags/v1.0", "refs/webkiller/recovered/" + strings.Repeat("a", 40)}
	for _, ref := range valid {
		if _, err := SanitizeRefName(ref); err != nil {
			t.Errorf("SanitizeRefName(%q): %v", ref, err)
		}
	}
	invalid := []string{"../refs/heads/master", "refs/heads/a..b", "refs/heads/a b", "refs/heads/a.lock", "/refs/heads/a"}
	for _, ref := range invalid {
		if _, err := SanitizeRefName(ref); err == nil {
			t.Errorf("SanitizeRefName(%q) unexpectedly succeeded", ref)
		}
	}
}

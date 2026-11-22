package leak

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxObjectSize bounds a decompressed loose object. Git blobs larger than
	// this are unusual for CTF/web targets and are skipped to protect memory.
	MaxObjectSize = 128 << 20
)

var shaPattern = regexp.MustCompile(`(?i)\b[0-9a-f]{40}\b`)

// ParseLooseObject decompresses a Git loose object and returns its type and
// content. The on-disk format is zlib("type size\x00content").
func ParseLooseObject(raw []byte) (typ string, content []byte, err error) {
	if len(raw) == 0 {
		return "", nil, errors.New("empty object")
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return "", nil, fmt.Errorf("zlib: %w", err)
	}
	defer zr.Close()

	data, err := io.ReadAll(io.LimitReader(zr, MaxObjectSize+1))
	if err != nil {
		return "", nil, fmt.Errorf("decompress object: %w", err)
	}
	if len(data) > MaxObjectSize {
		return "", nil, fmt.Errorf("object exceeds %d bytes", MaxObjectSize)
	}
	nul := bytes.IndexByte(data, 0)
	if nul <= 0 {
		return "", nil, errors.New("object header is missing")
	}
	header := string(data[:nul])
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("malformed object header %q", header)
	}
	typ = parts[0]
	switch typ {
	case "commit", "tree", "blob", "tag":
	default:
		return "", nil, fmt.Errorf("unsupported object type %q", typ)
	}
	var size int64
	if _, err := fmt.Sscanf(parts[1], "%d", &size); err != nil || size < 0 {
		return "", nil, fmt.Errorf("malformed object size %q", parts[1])
	}
	content = data[nul+1:]
	if int64(len(content)) != size {
		return "", nil, fmt.Errorf("object size mismatch: header %d, content %d", size, len(content))
	}
	return typ, content, nil
}

// EncodeLooseObject builds a loose object in the same format Git uses. It is
// exported for tests and for callers that need to synthesize evidence.
func EncodeLooseObject(typ string, content []byte) ([]byte, error) {
	switch typ {
	case "commit", "tree", "blob", "tag":
	default:
		return nil, fmt.Errorf("unsupported object type %q", typ)
	}
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := fmt.Fprintf(zw, "%s %d\x00", typ, len(content)); err != nil {
		return nil, err
	}
	if _, err := zw.Write(content); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SHA1Hex returns the lower-case hex SHA-1 of data.
func SHA1Hex(data []byte) string {
	sum := sha1.Sum(data)
	return hex.EncodeToString(sum[:])
}

// IsHexSHA reports whether s is a 40-character SHA-1.
func IsHexSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// ShortSHA abbreviates a SHA for display.
func ShortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// ExtractSHAs returns unique SHA-1 strings found in text, preserving order.
func ExtractSHAs(text string) []string {
	matches := shaPattern.FindAllString(text, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		m = strings.ToLower(m)
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

// SanitizeRelPath validates a repository-relative path and returns a cleaned
// slash-separated path. It rejects traversal, absolute paths, NUL bytes and
// control characters. Components that are unsafe on Windows are rewritten
// rather than silently dropped, so evidence is still preserved.
func SanitizeRelPath(rel string) (string, error) {
	rel = strings.TrimSpace(rel)
	rel = strings.ReplaceAll(rel, "\\", "/")
	rel = strings.TrimPrefix(rel, "./")
	if rel == "" {
		return "", errors.New("empty path")
	}
	if strings.HasPrefix(rel, "/") {
		return "", fmt.Errorf("absolute path is not allowed: %q", rel)
	}
	parts := strings.Split(rel, "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return "", fmt.Errorf("path traversal is not allowed: %q", rel)
		}
		clean, err := sanitizeComponent(part)
		if err != nil {
			return "", err
		}
		out = append(out, clean)
	}
	if len(out) == 0 {
		return "", errors.New("path has no components")
	}
	return strings.Join(out, "/"), nil
}

func sanitizeComponent(part string) (string, error) {
	if part == "" || part == "." || part == ".." {
		return "", fmt.Errorf("invalid path component %q", part)
	}
	var b strings.Builder
	for _, r := range part {
		switch {
		case r == 0 || r == '/' || r == '\\':
			return "", fmt.Errorf("invalid character in path component %q", part)
		case unicode.IsControl(r):
			return "", fmt.Errorf("control character in path component %q", part)
		case strings.ContainsRune(`<>:"|?*`, r):
			// Windows-incompatible character: replace to keep the file
			// name usable on all supported platforms.
			b.WriteRune('_')
		default:
			b.WriteRune(r)
		}
	}
	clean := strings.TrimRight(b.String(), " .")
	if clean == "" || clean == "." || clean == ".." {
		return "", fmt.Errorf("invalid path component %q", part)
	}
	if len(clean) > 200 {
		clean = clean[:200]
	}
	upper := strings.ToUpper(clean)
	switch upper {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		clean += "_"
	}
	return clean, nil
}

// SafeJoin joins rel under root and verifies that the result cannot escape
// root. The returned path is absolute.
func SafeJoin(root, rel string) (string, error) {
	clean, err := SanitizeRelPath(rel)
	if err != nil {
		return "", err
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve output root: %w", err)
	}
	full := filepath.Join(rootAbs, filepath.FromSlash(clean))
	fullAbs, err := filepath.Abs(full)
	if err != nil {
		return "", fmt.Errorf("resolve output path: %w", err)
	}
	if fullAbs != rootAbs && !strings.HasPrefix(fullAbs, rootAbs+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes output root: %q", rel)
	}
	return fullAbs, nil
}

// SafeWriteFile writes data to root/rel after validating the path. The write
// is atomic: a temporary file is renamed into place.
func SafeWriteFile(root, rel string, data []byte, mode os.FileMode) (string, error) {
	full, err := SafeJoin(root, rel)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return "", fmt.Errorf("create parent directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(full), ".webkiller-file-*")
	if err != nil {
		return "", fmt.Errorf("create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("write temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("close temporary file: %w", err)
	}
	if mode == 0 {
		mode = 0o644
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("set file mode: %w", err)
	}
	if err := os.Rename(tmpName, full); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("store file: %w", err)
	}
	return full, nil
}

// MaskValue partially redacts a secret for console and report output.
func MaskValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "-----BEGIN") {
		return "-----BEGIN **** PRIVATE KEY-----"
	}
	runes := []rune(value)
	if len(runes) <= 8 {
		return "****"
	}
	return string(runes[:4]) + "****" + string(runes[len(runes)-4:])
}

// IsBinary reports whether data looks binary. It is intentionally
// conservative: NUL bytes and invalid UTF-8 are treated as binary.
func IsBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	sample := data
	if len(sample) > 8192 {
		sample = sample[:8192]
		// Do not misclassify UTF-8 text merely because the sample ends in
		// the middle of a multi-byte rune.
		for i := 0; i < 3 && len(sample) > 0; i++ {
			r, size := utf8.DecodeLastRune(sample)
			if r != utf8.RuneError || size != 1 {
				break
			}
			sample = sample[:len(sample)-1]
		}
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return true
	}
	if !utf8.Valid(sample) {
		return true
	}
	control := 0
	for _, b := range sample {
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			control++
		}
	}
	return control*100/len(sample) > 10
}

// SanitizeRefName validates a ref discovered on the target before writing it
// under .git/refs. It follows the important parts of git-check-ref-format.
func SanitizeRefName(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "/") || strings.HasSuffix(ref, "/") {
		return "", errors.New("invalid ref name")
	}
	if strings.Contains(ref, "..") || strings.Contains(ref, "@{") ||
		strings.Contains(ref, "//") || strings.HasSuffix(ref, ".lock") ||
		strings.HasSuffix(ref, ".") {
		return "", fmt.Errorf("invalid ref name %q", ref)
	}
	for _, r := range ref {
		if r <= 0x20 || r == 0x7f || strings.ContainsRune("~^:?*[\\", r) {
			return "", fmt.Errorf("invalid ref name %q", ref)
		}
	}
	parts := strings.Split(ref, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return "", fmt.Errorf("invalid ref name %q", ref)
		}
	}
	return ref, nil
}

// SortedKeys returns map keys in sorted order.
func SortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

package leak

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func makeFakeDSStore(names ...string) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0, 1, 'B', 'u', 'd', '1'})
	for _, name := range names {
		buf.Write([]byte{0, 0})
		for _, r := range name {
			_ = binary.Write(&buf, binary.BigEndian, uint16(r))
		}
	}
	return buf.Bytes()
}

func TestExtractDSStoreNames(t *testing.T) {
	data := makeFakeDSStore("config.php", "admin_bak.php", "backup_2024.zip", ".env", "Bud1")
	names := extractDSStoreNames(data)
	joined := strings.Join(names, ",")
	for _, want := range []string{"config.php", "admin_bak.php", "backup_2024.zip", ".env"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, names)
		}
	}
	if strings.Contains(joined, "Bud1") {
		t.Errorf("internal token leaked into names: %v", names)
	}
}

func TestDumpDSStore(t *testing.T) {
	data := makeFakeDSStore("config.php", "admin_bak.php", "backup_2024.zip", ".env")
	mux := http.NewServeMux()
	mux.HandleFunc("/.DS_Store", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/config.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/admin_bak.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/backup_2024.zip", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte("<html><title>Index of /</title></html>"))
			return
		}
		http.NotFound(w, r)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(ClientOptions{Concurrency: 8, Timeout: 5 * time.Second, Rate: 0})
	defer client.Close()
	out := t.TempDir()
	result := DumpDSStore(context.Background(), client, server.URL+"/", out, 8, false)
	if len(result.Entries) < 4 {
		t.Fatalf("entries = %#v", result.Entries)
	}
	byName := make(map[string]DSEntry)
	for _, entry := range result.Entries {
		byName[entry.Name] = entry
	}
	if !byName["config.php"].Accessible {
		t.Errorf("config.php not accessible: %#v", byName["config.php"])
	}
	if byName["backup_2024.zip"].Accessible {
		t.Errorf("backup_2024.zip unexpectedly accessible: %#v", byName["backup_2024.zip"])
	}
	if byName[".env"].Status != http.StatusNotFound {
		t.Errorf(".env status = %d, want 404", byName[".env"].Status)
	}
	report, err := os.ReadFile(filepath.Join(out, "dsstore.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"config.php", "admin_bak.php", "backup_2024.zip", ".env"} {
		if !strings.Contains(string(report), want) {
			t.Errorf("report missing %q:\n%s", want, report)
		}
	}
}

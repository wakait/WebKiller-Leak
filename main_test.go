package main

import (
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wakait/WebKiller-Leak/internal/leak"
)

func TestParseFlagsDefaults(t *testing.T) {
	cfg, _, err := parseFlags([]string{
		"-u", "https://example.test/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.target != "https://example.test/" {
		t.Fatalf("target = %q", cfg.target)
	}
	if cfg.outDir != "out" {
		t.Fatalf("outDir = %q", cfg.outDir)
	}
	if cfg.threads != 16 {
		t.Fatalf("threads = %d", cfg.threads)
	}
	if cfg.timeout != 15*time.Second {
		t.Fatalf("timeout = %s", cfg.timeout)
	}
	if cfg.rate != 20 {
		t.Fatalf("rate = %v", cfg.rate)
	}
}

func TestParseFlagsRejectsInvalidRegexp(t *testing.T) {
	cfg, _, err := parseFlags([]string{
		"-u", "https://example.test/",
		"-p", "(",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leak.BuildRules(cfg.flagPattern); err == nil {
		t.Fatal("expected invalid regular expression")
	}
}

func TestParseFlagsHelp(t *testing.T) {
	_, _, err := parseFlags([]string{"-h"})
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("parseFlags(-h) error = %v, want ErrHelp", err)
	}
}

func TestRunWithoutArgumentsPrintsUsage(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"WebKiller-leak"}
	defer func() { os.Args = oldArgs }()

	oldStdout := os.Stdout
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writeEnd
	code := run()
	_ = writeEnd.Close()
	os.Stdout = oldStdout

	output, err := io.ReadAll(readEnd)
	_ = readEnd.Close()
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("run() exit code = %d, want 0", code)
	}
	for _, want := range []string{
		"用法：",
		"-u",
		"-p",
		"-o",
		"-t",
		"-bruteforce",
		"-gitleaks",
		"-no-git",
		"-timeout",
		"-rate",
		"-v",
	} {
		if !strings.Contains(string(output), want) {
			t.Errorf("help output missing %q:\n%s", want, output)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		0:    "0 B",
		512:  "512 B",
		1024: "1.0 KiB",
	}
	for input, want := range cases {
		if got := humanBytes(input); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", input, got, want)
		}
	}
}

func TestColorHonorsNoColorEnvironment(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if got := color("32", "ok"); got != "ok" {
		t.Fatalf("color() = %q, want plain text", got)
	}
}

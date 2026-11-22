package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/wakait/WebKiller-Leak/internal/leak"
)

var version = "dev"

type config struct {
	target      string
	flagPattern string
	outDir      string
	threads     int
	bruteforce  bool
	gitleaks    bool
	noGit       bool
	timeout     time.Duration
	rate        float64
	verbose     bool
}

func main() {
	code := 0
	defer func() {
		if recovered := recover(); recovered != nil {
			fmt.Fprintf(os.Stderr, "internal error: %v\n", recovered)
			code = 3
		}
		os.Exit(code)
	}()
	code = run()
}

func run() int {
	args := os.Args[1:]
	cfg, fs, err := parseFlags(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if len(args) == 0 {
		fs.SetOutput(os.Stdout)
		fs.Usage()
		return 0
	}
	if cfg.target == "" {
		fmt.Fprintln(os.Stderr, "错误：必须通过 -u 指定目标 URL")
		fs.Usage()
		return 1
	}
	if cfg.threads < 1 || cfg.threads > 256 {
		fmt.Fprintln(os.Stderr, "错误：-t 并发数必须介于 1 到 256")
		return 1
	}
	if cfg.timeout <= 0 {
		fmt.Fprintln(os.Stderr, "错误：-timeout 必须大于零")
		return 1
	}
	if cfg.rate < 0 {
		fmt.Fprintln(os.Stderr, "错误：-rate 必须为零或正数")
		return 1
	}
	if _, err := leak.BuildRules(cfg.flagPattern); err != nil {
		fmt.Fprintf(os.Stderr, "错误：%v\n", err)
		return 1
	}

	siteBase, gitBase, err := leak.NormalizeBase(cfg.target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if err := os.MkdirAll(cfg.outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "错误：无法创建输出目录：%v\n", err)
		return 3
	}
	repoDir := filepath.Join(cfg.outDir, "repo")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "错误：无法创建仓库目录：%v\n", err)
		return 3
	}

	logger := log.New(os.Stderr, "", log.Ltime)
	client := leak.NewClient(leak.ClientOptions{
		Concurrency: cfg.threads,
		Timeout:     cfg.timeout,
		Rate:        cfg.rate,
		Verbose:     cfg.verbose,
		Logger:      logger,
	})
	defer client.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	printBanner(os.Stdout, siteBase, cfg)

	// Step 1: probe leak paths.
	fmt.Printf("\n[1/4] 正在探测泄露路径\n")
	probeFindings := leak.Probe(ctx, client, siteBase, cfg.threads)
	printProbeFindings(probeFindings)
	if !leak.AnyReachable(probeFindings) {
		fmt.Fprintln(os.Stderr, "\n错误：目标未返回任何 HTTP 响应")
		fmt.Fprintln(os.Stderr, "请检查 URL、网络连接，并确认已获得目标授权")
		return 2
	}
	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "\n已中断；已保留已落盘产物")
		return 3
	}
	positive := leak.PositiveFindings(probeFindings)
	if len(positive) == 0 {
		fmt.Println("  未确认任何泄露路径；后续步骤可能不产生有效结果")
	}

	// Step 2: Git reconstruction.
	var dumpResult *leak.DumpResult
	if leak.HasKind(probeFindings, "git") && !cfg.noGit {
		fmt.Printf("\n[2/4] 正在还原 Git 仓库\n")
		stepCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		dumper := leak.NewDumper(client, gitBase, cfg.outDir, cfg.threads, cfg.bruteforce, cfg.verbose)
		dumpResult, err = dumper.Run(stepCtx)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  git restore: %v (partial artifacts may have been written)\n", err)
		}
		printDumpResult(dumpResult, cfg.verbose)
	} else if cfg.noGit {
		fmt.Printf("\n[2/4] 已跳过 Git 还原（-no-git）\n")
	} else {
		fmt.Printf("\n[2/4] 已跳过 Git 还原（未确认 Git 泄露）\n")
	}

	// Step 3: .DS_Store enumeration.
	var dsResult *leak.DSStoreResult
	if leak.HasKind(probeFindings, "dsstore") {
		fmt.Printf("\n[3/4] 正在枚举 .DS_Store\n")
		stepCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		dsResult = leak.DumpDSStore(stepCtx, client, siteBase, cfg.outDir, cfg.threads, cfg.verbose)
		cancel()
		printDSStoreResult(dsResult, cfg.verbose)
	} else {
		fmt.Printf("\n[3/4] 已跳过 .DS_Store 枚举（未确认泄露）\n")
	}

	// Steps 4 and 5: history/worktree scanning and optional gitleaks.
	fmt.Printf("\n[4/4] 正在扫描历史、工作区和元数据\n")
	stepCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	scanResult, err := leak.Scan(stepCtx, leak.ScanOptions{
		RepoDir:     repoDir,
		OutDir:      cfg.outDir,
		FlagPattern: cfg.flagPattern,
		UseGit:      !cfg.noGit,
		Gitleaks:    cfg.gitleaks,
		Verbose:     cfg.verbose,
		Timeout:     10 * time.Minute,
		Concurrency: cfg.threads,
	})
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误：扫描失败：%v\n", err)
		return 3
	}
	meta := leak.FindingsMeta{
		Target:       siteBase,
		Generated:    time.Now(),
		Sources:      scanResult.Sources,
		Warnings:     scanResult.Warnings,
		GitUsed:      scanResult.GitUsed,
		GitleaksUsed: scanResult.GitleaksUsed,
	}
	if err := leak.WriteFindings(cfg.outDir, scanResult.Findings, meta); err != nil {
		fmt.Fprintf(os.Stderr, "错误：无法写入命中报告：%v\n", err)
		return 3
	}
	printScanResult(scanResult, cfg.verbose)
	printSummary(cfg, client, dumpResult, dsResult, scanResult)

	if ctx.Err() != nil {
		fmt.Fprintln(os.Stderr, "\n已中断；已保留已落盘产物")
		return 3
	}
	return 0
}

func parseFlags(args []string) (config, *flag.FlagSet, error) {
	var cfg config
	fs := flag.NewFlagSet("WebKiller-leak", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&cfg.target, "u", "", "目标基础 URL（必填），例如 http://target/ 或 http://target/.git/")
	fs.StringVar(&cfg.flagPattern, "p", "", "自定义 Flag 正则（RE2）；留空时扫描 flag{} 及 hex/base64/ascii-bin/unicode-entity 编码")
	fs.StringVar(&cfg.outDir, "o", "out", "输出目录")
	fs.IntVar(&cfg.threads, "t", 16, "并发工作协程数（1-256）")
	fs.BoolVar(&cfg.bruteforce, "bruteforce", false, "对象目录拒绝时枚举可访问目录和已知 SHA")
	fs.BoolVar(&cfg.gitleaks, "gitleaks", false, "存在时运行外部 gitleaks")
	fs.BoolVar(&cfg.noGit, "no-git", false, "跳过 Git 还原和 Git 历史遍历")
	fs.DurationVar(&cfg.timeout, "timeout", 15*time.Second, "每个请求的超时")
	fs.Float64Var(&cfg.rate, "rate", leak.DefaultRate, "请求速率（请求/秒，0表示关闭限速）")
	fs.BoolVar(&cfg.verbose, "v", false, "输出详细请求和模块日志")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "WebKiller-leak %s - 授权范围内的 Web 泄露侦察工具\n\n", version)
		fmt.Fprintln(fs.Output(), "用法：")
		fmt.Fprintln(fs.Output(), "  WebKiller-leak -u http://target/ [options]")
		fmt.Fprintln(fs.Output(), "\n参数：")
		fs.PrintDefaults()
		fmt.Fprintln(fs.Output(), "\n仅发送只读 GET/HEAD 请求。请仅在已获得书面授权的目标上使用。")
	}
	return cfg, fs, fs.Parse(args)
}

func printBanner(out io.Writer, site string, cfg config) {
	fmt.Fprintf(out, "WebKiller-leak v%s\n", version)
	fmt.Fprintln(out, "仅限授权安全测试。本工具只发送只读 GET/HEAD 请求；")
	fmt.Fprintln(out, "不会利用漏洞、绕过认证，也不会使用发现的凭据。")
	fmt.Fprintf(out, "目标：%s\n", site)
	fmt.Fprintf(out, "输出：%s   并发：%d   限速：%g 请求/秒   超时：%s\n", cfg.outDir, cfg.threads, cfg.rate, cfg.timeout)
}

func printProbeFindings(findings []leak.Finding) {
	for _, finding := range findings {
		mark := "  "
		if finding.OK {
			mark = color("32", "OK")
		}
		path := finding.Path
		if path == "" {
			path = "/"
		}
		note := finding.Note
		if note == "" {
			note = "-"
		}
		fmt.Printf("  %-2s %-8s %-32s %3d  %s\n", mark, finding.Kind, path, finding.Status, note)
	}
}

func printDumpResult(result *leak.DumpResult, verbose bool) {
	if result == nil {
		return
	}
	stats := result.Stats
	fmt.Printf("  对象：%d（commit=%d tree=%d blob=%d tag=%d）\n",
		stats.Objects, stats.Commits, stats.Trees, stats.Blobs, stats.Tags)
	fmt.Printf("  还原文件：%d   index 条目：%d   refs：%d   pack：%d\n",
		stats.Files, stats.IndexEntries, stats.Refs, stats.Packs)
	if result.HeadSHA != "" {
		fmt.Printf("  HEAD: %s\n", leak.ShortSHA(result.HeadSHA))
	}
	if len(result.Missing) > 0 {
		fmt.Printf("  缺失对象：%d（详见 %s）\n", len(result.Missing), filepath.Join(filepath.Dir(result.RepoDir), "missing_objects.txt"))
	}
	printWarnings("git", result.Warnings, verbose)
}

func printDSStoreResult(result *leak.DSStoreResult, verbose bool) {
	if result == nil {
		return
	}
	accessible := 0
	for _, entry := range result.Entries {
		if entry.Accessible {
			accessible++
		}
	}
	fmt.Printf("  .DS_Store 来源：%d   条目：%d   可访问：%d\n", len(result.Sources), len(result.Entries), accessible)
	printWarnings("dsstore", result.Warnings, verbose)
}

func printScanResult(result *leak.ScanResult, verbose bool) {
	fmt.Printf("  命中：%d   Git 历史：%t   gitleaks：%t\n", len(result.Findings), result.GitUsed, result.GitleaksUsed)
	if len(result.Findings) > 0 {
		limit := len(result.Findings)
		if limit > 50 {
			limit = 50
		}
		for _, finding := range result.Findings[:limit] {
			line := leak.FormatFinding(finding)
			if finding.Rule == "flag" {
				line = color("1;31", line)
			} else {
				line = color("33", line)
			}
			fmt.Println("  " + line)
		}
		if len(result.Findings) > limit {
			fmt.Printf("  ……另有 %d 项（详见 findings.txt）\n", len(result.Findings)-limit)
		}
	} else {
		fmt.Println("  未匹配到敏感值或 Flag")
	}
	printWarnings("scan", result.Warnings, verbose)
}

func printWarnings(label string, warnings []string, verbose bool) {
	if len(warnings) == 0 {
		return
	}
	limit := len(warnings)
	if !verbose && limit > 5 {
		limit = 5
	}
	for _, warning := range warnings[:limit] {
		fmt.Fprintf(os.Stderr, "  [%s] warning: %s\n", label, warning)
	}
	if limit < len(warnings) {
		fmt.Fprintf(os.Stderr, "  [%s] %d more warning(s); rerun with -v to see them\n", label, len(warnings)-limit)
	}
}

func printSummary(cfg config, client *leak.Client, dump *leak.DumpResult, ds *leak.DSStoreResult, scan *leak.ScanResult) {
	stats := client.Stats()
	fmt.Printf("\n[汇总]\n")
	fmt.Printf("  HTTP 请求：%d   重试：%d   下载：%s\n", stats.Requests, stats.Retries, humanBytes(stats.Bytes))
	if dump != nil {
		fmt.Printf("  还原文件：%d   缺失对象：%d\n", dump.Stats.Files, len(dump.Missing))
	}
	if ds != nil {
		fmt.Printf("  .DS_Store 条目：%d\n", len(ds.Entries))
	}
	fmt.Printf("  命中：%d\n", len(scan.Findings))
	fmt.Printf("  报告：%s\n", filepath.Join(cfg.outDir, "findings.txt"))
	if ds != nil {
		fmt.Printf("          %s\n", filepath.Join(cfg.outDir, "dsstore.txt"))
	}
	if dump != nil {
		fmt.Printf("          %s\n", filepath.Join(cfg.outDir, "repo"))
		if len(dump.Missing) > 0 {
			fmt.Printf("          %s\n", filepath.Join(cfg.outDir, "missing_objects.txt"))
		}
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for value := n / unit; value >= unit; value /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func color(code, text string) string {
	if os.Getenv("NO_COLOR") != "" || !isTerminal(os.Stdout) {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

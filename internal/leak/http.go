package leak

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultRate is the default request rate limit in requests per second.
	DefaultRate = 20.0

	// UserAgent identifies the tool in outbound requests.
	UserAgent = "Mozilla/5.0 (compatible; WebKiller-leak/1.0; +https://github.com/wakait/WebKiller-Leak)"

	maxResponseBytes = 128 << 20 // 128 MiB
)

// Client wraps a pooled HTTP client with retries, a shared rate limiter and
// request accounting. Every network access in this package goes through it.
type Client struct {
	HTTP    *http.Client
	limiter *limiter
	logger  *log.Logger
	verbose bool

	requests int64
	retries  int64
	errors   int64
	bytes    int64
}

// ClientOptions configures a Client.
type ClientOptions struct {
	Concurrency int
	Timeout     time.Duration
	Rate        float64
	Verbose     bool
	Logger      *log.Logger
}

// Stats is a snapshot of client counters.
type Stats struct {
	Requests int64
	Retries  int64
	Errors   int64
	Bytes    int64
}

// NewClient builds a Client with connection reuse suitable for many small
// object requests. TLS verification is disabled because CTF targets commonly
// use self-signed certificates; this tool only performs read-only requests.
func NewClient(opts ClientOptions) *Client {
	if opts.Concurrency < 1 {
		opts.Concurrency = 1
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.Logger == nil {
		opts.Logger = log.New(os.Stderr, "", log.LstdFlags)
	}
	if opts.Rate < 0 {
		opts.Rate = 0
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          opts.Concurrency * 4,
		MaxIdleConnsPerHost:   opts.Concurrency * 2,
		MaxConnsPerHost:       opts.Concurrency * 2,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
		TLSClientConfig: &tls.Config{
			//nolint:gosec // authorized CTF/lab targets frequently use self-signed certs.
			InsecureSkipVerify: true,
		},
	}

	return &Client{
		HTTP: &http.Client{
			Transport: transport,
			Timeout:   opts.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return errors.New("stopped after 10 redirects")
				}
				return nil
			},
		},
		limiter: newLimiter(opts.Rate),
		logger:  opts.Logger,
		verbose: opts.Verbose,
	}
}

// SetLogger replaces the client logger.
func (c *Client) SetLogger(l *log.Logger) {
	if l != nil {
		c.logger = l
	}
}

// Close releases the limiter and idle connections.
func (c *Client) Close() {
	c.limiter.Close()
	c.HTTP.CloseIdleConnections()
}

// Stats returns current counters.
func (c *Client) Stats() Stats {
	return Stats{
		Requests: atomic.LoadInt64(&c.requests),
		Retries:  atomic.LoadInt64(&c.retries),
		Errors:   atomic.LoadInt64(&c.errors),
		Bytes:    atomic.LoadInt64(&c.bytes),
	}
}

// Get performs a GET with retry on network errors and 5xx responses. 4xx
// responses are returned to the caller without retrying.
func (c *Client) Get(ctx context.Context, rawURL string) ([]byte, int, error) {
	return c.get(ctx, rawURL, maxResponseBytes)
}

// GetLimited is Get with an explicit body size limit.
func (c *Client) GetLimited(ctx context.Context, rawURL string, limit int64) ([]byte, int, error) {
	if limit <= 0 || limit > maxResponseBytes {
		limit = maxResponseBytes
	}
	return c.get(ctx, rawURL, limit)
}

func (c *Client) get(ctx context.Context, rawURL string, limit int64) ([]byte, int, error) {
	var lastErr error
	for attempt := 0; attempt <= 2; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, 0, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("User-Agent", UserAgent)
		req.Header.Set("Accept", "*/*")

		atomic.AddInt64(&c.requests, 1)
		c.logf("GET %s", rawURL)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			atomic.AddInt64(&c.errors, 1)
			lastErr = err
			if attempt < 2 && ctx.Err() == nil {
				c.backoff(ctx, attempt)
				continue
			}
			return nil, 0, err
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		closeErr := resp.Body.Close()
		if readErr == nil {
			readErr = closeErr
		}
		if readErr != nil {
			atomic.AddInt64(&c.errors, 1)
			lastErr = readErr
			if attempt < 2 && ctx.Err() == nil {
				c.backoff(ctx, attempt)
				continue
			}
			return nil, resp.StatusCode, readErr
		}
		if int64(len(body)) > limit {
			return nil, resp.StatusCode, fmt.Errorf("response body exceeds %d bytes", limit)
		}
		atomic.AddInt64(&c.bytes, int64(len(body)))

		if resp.StatusCode >= 500 && attempt < 2 {
			lastErr = fmt.Errorf("server returned HTTP %d", resp.StatusCode)
			c.logf("retrying after HTTP %d for %s", resp.StatusCode, rawURL)
			c.backoff(ctx, attempt)
			continue
		}
		return body, resp.StatusCode, nil
	}
	if lastErr == nil {
		lastErr = errors.New("request failed")
	}
	return nil, 0, lastErr
}

// Head performs a HEAD request. If the server rejects HEAD (405/501) the
// caller may fall back to Get.
func (c *Client) Head(ctx context.Context, rawURL string) (int, error) {
	var lastErr error
	for attempt := 0; attempt <= 2; attempt++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if err := c.limiter.Wait(ctx); err != nil {
			return 0, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
		if err != nil {
			return 0, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("User-Agent", UserAgent)
		atomic.AddInt64(&c.requests, 1)
		c.logf("HEAD %s", rawURL)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			atomic.AddInt64(&c.errors, 1)
			lastErr = err
			if attempt < 2 && ctx.Err() == nil {
				c.backoff(ctx, attempt)
				continue
			}
			return 0, err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
		if resp.StatusCode >= 500 && attempt < 2 {
			lastErr = fmt.Errorf("server returned HTTP %d", resp.StatusCode)
			c.backoff(ctx, attempt)
			continue
		}
		return resp.StatusCode, nil
	}
	if lastErr == nil {
		lastErr = errors.New("request failed")
	}
	return 0, lastErr
}

// Download streams a URL to path. A partial file is never left in place: the
// body is written to a temporary file in the same directory and renamed only
// after a successful copy.
func (c *Client) Download(ctx context.Context, rawURL, target string, maxBytes int64) (int64, int, error) {
	if maxBytes <= 0 {
		maxBytes = maxResponseBytes
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return 0, 0, fmt.Errorf("create download directory: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= 2; attempt++ {
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		if err := c.limiter.Wait(ctx); err != nil {
			return 0, 0, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return 0, 0, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("User-Agent", UserAgent)
		atomic.AddInt64(&c.requests, 1)
		c.logf("GET %s -> %s", rawURL, target)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			atomic.AddInt64(&c.errors, 1)
			lastErr = err
			if attempt < 2 && ctx.Err() == nil {
				c.backoff(ctx, attempt)
				continue
			}
			return 0, 0, err
		}
		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
			_ = resp.Body.Close()
			if resp.StatusCode >= 500 && attempt < 2 {
				lastErr = fmt.Errorf("server returned HTTP %d", resp.StatusCode)
				c.backoff(ctx, attempt)
				continue
			}
			return 0, resp.StatusCode, fmt.Errorf("download returned HTTP %d", resp.StatusCode)
		}

		tmp, err := os.CreateTemp(filepath.Dir(target), ".webkiller-download-*")
		if err != nil {
			_ = resp.Body.Close()
			return 0, resp.StatusCode, fmt.Errorf("create temporary download: %w", err)
		}
		tmpName := tmp.Name()
		written, copyErr := io.Copy(tmp, io.LimitReader(resp.Body, maxBytes+1))
		closeErr := tmp.Close()
		_ = resp.Body.Close()
		if copyErr == nil {
			copyErr = closeErr
		}
		if copyErr != nil {
			_ = os.Remove(tmpName)
			atomic.AddInt64(&c.errors, 1)
			lastErr = copyErr
			if attempt < 2 && ctx.Err() == nil {
				c.backoff(ctx, attempt)
				continue
			}
			return 0, resp.StatusCode, copyErr
		}
		if written > maxBytes {
			_ = os.Remove(tmpName)
			return written, resp.StatusCode, fmt.Errorf("download exceeds %d bytes", maxBytes)
		}
		if err := os.Rename(tmpName, target); err != nil {
			_ = os.Remove(tmpName)
			return written, resp.StatusCode, fmt.Errorf("store download: %w", err)
		}
		atomic.AddInt64(&c.bytes, written)
		return written, resp.StatusCode, nil
	}
	if lastErr == nil {
		lastErr = errors.New("download failed")
	}
	return 0, 0, lastErr
}

func (c *Client) backoff(ctx context.Context, attempt int) {
	atomic.AddInt64(&c.retries, 1)
	delay := time.Duration(150*(1<<attempt)) * time.Millisecond
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (c *Client) logf(format string, args ...any) {
	if c.verbose && c.logger != nil {
		c.logger.Printf("[http] "+format, args...)
	}
}

// limiter is a simple shared token source. It is deliberately small: the
// design only needs a process-wide upper bound on request rate.
type limiter struct {
	ticker *time.Ticker
	ch     <-chan time.Time
	mu     sync.Mutex
	closed bool
}

func newLimiter(rate float64) *limiter {
	if rate <= 0 {
		return &limiter{}
	}
	interval := time.Duration(float64(time.Second) / rate)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	t := time.NewTicker(interval)
	return &limiter{ticker: t, ch: t.C}
}

func (l *limiter) Wait(ctx context.Context) error {
	if l == nil || l.ch == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-l.ch:
		return nil
	}
}

func (l *limiter) Close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.closed = true
	if l.ticker != nil {
		l.ticker.Stop()
	}
}

// NormalizeBase validates a target URL and returns the site root and the Git
// metadata root. A user may pass either a site URL (http://host/) or the Git
// directory itself (http://host/.git/).
func NormalizeBase(raw string) (site, gitBase string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("target URL is required (-u)")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("parse target URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", fmt.Errorf("target URL must use http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return "", "", errors.New("target URL has no host")
	}
	u.Fragment = ""
	u.RawQuery = ""

	if u.Path == "" {
		u.Path = "/"
	}
	if !strings.HasPrefix(u.Path, "/") {
		u.Path = "/" + u.Path
	}
	u.Path = path.Clean(u.Path)
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}

	if strings.HasSuffix(u.Path, "/.git/") {
		gitBase = u.String()
		siteURL := *u
		siteURL.Path = strings.TrimSuffix(u.Path, ".git/")
		if siteURL.Path == "" {
			siteURL.Path = "/"
		}
		if !strings.HasSuffix(siteURL.Path, "/") {
			siteURL.Path += "/"
		}
		return siteURL.String(), gitBase, nil
	}

	site = u.String()
	gitURL := *u
	gitURL.Path = strings.TrimSuffix(u.Path, "/") + "/.git/"
	return site, gitURL.String(), nil
}

// JoinURL appends a relative path to a base URL. The relative path is kept as
// a URL path so spaces and non-ASCII file names are escaped correctly.
func JoinURL(base, rel string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse base URL: %w", err)
	}
	rel = strings.TrimPrefix(strings.TrimSpace(rel), "/")
	if rel == "" {
		return u.String(), nil
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + rel
	u.RawPath = ""
	return u.String(), nil
}

// ResolveReference is a small helper used by tests and callers that need
// standard URL resolution semantics.
func ResolveReference(base, ref string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return b.ResolveReference(r).String(), nil
}

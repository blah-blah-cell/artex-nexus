package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/blah-blah-cell/artex-nexus/internal/mcpserver"
)

const (
	maxPatchBytes = 256 * 1024
	maxSignals    = 60
)

type hintRule struct {
	name string
	re   *regexp.Regexp
}

var (
	ghCommitRe = regexp.MustCompile(`^/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)/commit/([0-9a-fA-F]{7,40})$`)
	ghPullRe   = regexp.MustCompile(`^/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)/pull/(\d+)$`)
	apiGhRe    = regexp.MustCompile(`^/repos/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/(commits/[0-9a-fA-F]{7,40}|pulls/\d+)$`)
	glCommitRe = regexp.MustCompile(`^/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+/-/commit/[0-9a-fA-F]{7,40}$`)

	allowedHosts = map[string]bool{
		"github.com":     true,
		"api.github.com": true,
		"gitlab.com":     true,
	}

	extraBlockedPrefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),      // CGNAT
		netip.MustParsePrefix("192.0.0.0/24"),       // IETF protocol assignments
		netip.MustParsePrefix("192.0.2.0/24"),       // TEST-NET-1
		netip.MustParsePrefix("198.18.0.0/15"),      // Benchmarking
		netip.MustParsePrefix("198.51.100.0/24"),    // TEST-NET-2
		netip.MustParsePrefix("203.0.113.0/24"),     // TEST-NET-3
		netip.MustParsePrefix("240.0.0.0/4"),        // Reserved
		netip.MustParsePrefix("255.255.255.255/32"), // Limited broadcast
		netip.MustParsePrefix("64:ff9b::/96"),       // NAT64 well-known
		netip.MustParsePrefix("64:ff9b:1::/48"),     // NAT64 local-use
		netip.MustParsePrefix("2001:db8::/32"),      // Documentation
		netip.MustParsePrefix("2002::/16"),          // 6to4
	}

	securityHintRules = []hintRule{
		{name: "sanitize", re: regexp.MustCompile(`(?i)\b(sanitize\w*|html\.escape|escapestring|quote_plus|urlencode)\b`)},
		{name: "validate", re: regexp.MustCompile(`(?i)\b(validate\w*|verify\w*token|verify\w*sig\w*|verifyauth\w*|constanttimecompare|hmac\.equal)\b`)},
		{name: "authz", re: regexp.MustCompile(`(?i)\b(authorize\w*|checkpermission\w*|haspermission\w*|requireauth\w*|isadmin|rbac|acl)\b`)},
		{name: "allowlist", re: regexp.MustCompile(`(?i)\b(allowlist\w*|denylist\w*|whitelist\w*|blacklist\w*)\b`)},
		{name: "csrf_ssrf", re: regexp.MustCompile(`(?i)\b(csrf\w*|ssrf\w*|xsrf\w*|samesite|cors\w*)\b`)},
		{name: "path_confinement", re: regexp.MustCompile(`(?i)\b(realpath|normpath|evalsymlinks|filepath\.clean|path\.clean|traversal)\b`)},
		{name: "exec_eval", re: regexp.MustCompile(`(?i)\b(exec\.command|child_process|subprocess|os\.system|shell_exec|proc_open|eval\s*\()\b`)},
		{name: "deserialize", re: regexp.MustCompile(`(?i)\b(deserialize\w*|unserialize|objectinputstream|pickle\.loads?|yaml\.safe_load|safeloader)\b`)},
		{name: "sql", re: regexp.MustCompile(`(?i)\b(preparedstatement|parameterize\w*|sqli|sql\w*inject\w*)\b`)},
		{name: "bounds", re: regexp.MustCompile(`(?i)\b(overflow|underflow|out.?of.?bounds|bounds.?check)\b`)},
	}
)

func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	for _, pfx := range extraBlockedPrefixes {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

// resolveSafePatchEndpoint restricts fetches to allowlisted public Git hosts and
// rewrites github.com commit/PR URLs onto api.github.com so we don't need redirects.
// isGitHub is only true when the resolved host is actually api.github.com, so
// GITHUB_TOKEN can never leak to a gitlab.com repo whose path contains "github.com".
func resolveSafePatchEndpoint(rawURL string) (targetURL, acceptHeader string, isGitHub bool, err error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", "", false, fmt.Errorf("invalid URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", "", false, errors.New("only HTTPS URLs on allowlisted public code hosts are permitted")
	}
	if u.User != nil {
		return "", "", false, errors.New("URL userinfo is prohibited")
	}
	host := strings.ToLower(u.Hostname())
	if !allowedHosts[host] {
		return "", "", false, fmt.Errorf("host %q is not in allowlist [api.github.com, github.com, gitlab.com]", host)
	}
	if strings.Contains(u.Path, "..") || strings.Contains(u.RawPath, "..") ||
		strings.ContainsAny(u.Path, "?#%") || strings.ContainsAny(u.RawPath, "?#%") {
		return "", "", false, errors.New("path traversal or encoded delimiters are prohibited")
	}
	cleanPath := strings.TrimSuffix(u.Path, "/")
	cleanPath = strings.TrimSuffix(cleanPath, ".diff")
	cleanPath = strings.TrimSuffix(cleanPath, ".patch")

	switch host {
	case "github.com":
		if m := ghCommitRe.FindStringSubmatch(cleanPath); m != nil {
			return fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s", m[1], m[2], m[3]),
				"application/vnd.github.diff", true, nil
		}
		if m := ghPullRe.FindStringSubmatch(cleanPath); m != nil {
			return fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%s", m[1], m[2], m[3]),
				"application/vnd.github.diff", true, nil
		}
		return "", "", false, errors.New("github.com URL must be a /<owner>/<repo>/commit/<sha> or /pull/<id> URL")
	case "api.github.com":
		if !apiGhRe.MatchString(cleanPath) {
			return "", "", false, errors.New("api.github.com URL must target /repos/<owner>/<repo>/commits/<sha> or /pulls/<id>")
		}
		return "https://api.github.com" + cleanPath, "application/vnd.github.diff", true, nil
	case "gitlab.com":
		if !glCommitRe.MatchString(cleanPath) {
			return "", "", false, errors.New("gitlab.com URL must be a /-/commit/<sha> URL")
		}
		return "https://gitlab.com" + cleanPath + ".diff", "text/plain", false, nil
	default:
		return "", "", false, errors.New("unsupported host")
	}
}

func newSSRFHardenedClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("DNS returned no addresses for %s", host)
			}
			for _, ip := range ips {
				if isBlockedIP(ip) {
					return nil, fmt.Errorf("SSRF guard blocked connection to private/reserved IP %s (%s)", ip.String(), host)
				}
			}
			var lastErr error
			for _, ip := range ips {
				conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
	}
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type fileDiffSummary struct {
	File    string   `json:"file"`
	Added   int      `json:"added"`
	Removed int      `json:"removed"`
	Hunks   []string `json:"hunks"`
}

type securitySignal struct {
	File  string   `json:"file"`
	Op    string   `json:"op"`
	Hints []string `json:"hints"`
	Line  string   `json:"line"`
}

func unquoteGitPath(raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if u, err := strconv.Unquote(s); err == nil {
			s = u
		}
	}
	s = strings.TrimPrefix(s, "b/")
	s = strings.TrimPrefix(s, "a/")
	return s
}

func parseDiffGitHeader(line string) string {
	rest := strings.TrimPrefix(line, "diff --git ")
	// Handle quoted paths ("a/foo bar" "b/foo bar") and unquoted paths containing spaces.
	if idx := strings.LastIndex(rest, `" "b/`); idx >= 0 {
		return unquoteGitPath(rest[idx+2:])
	}
	if idx := strings.LastIndex(rest, " b/"); idx >= 0 {
		return unquoteGitPath(rest[idx+1:])
	}
	return unquoteGitPath(rest)
}

func extractDiffHunks(patchText string) map[string]any {
	var files []fileDiffSummary
	var current *fileDiffSummary
	var signals []securitySignal
	signalsTruncated := false
	inHunk := false

	for _, line := range strings.Split(patchText, "\n") {
		line = strings.TrimSuffix(line, "\r")
		switch {
		case strings.HasPrefix(line, "diff --git "):
			if current != nil {
				files = append(files, *current)
			}
			current = &fileDiffSummary{File: parseDiffGitHeader(line)}
			inHunk = false
		case !inHunk && current != nil && strings.HasPrefix(line, "+++ "):
			p := strings.TrimSpace(strings.TrimPrefix(line, "+++ "))
			if p != "/dev/null" {
				current.File = unquoteGitPath(p)
			}
		case !inHunk && current != nil && strings.HasPrefix(line, "--- "):
			// Ignore pre-hunk old-file header.
		case strings.HasPrefix(line, "@@ ") && current != nil:
			current.Hunks = append(current.Hunks, line)
			inHunk = true
		case inHunk && current != nil && strings.HasPrefix(line, "+"):
			current.Added++
			checkHints(current.File, "added", line[1:], &signals, &signalsTruncated)
		case inHunk && current != nil && strings.HasPrefix(line, "-"):
			current.Removed++
			checkHints(current.File, "removed", line[1:], &signals, &signalsTruncated)
		}
	}
	if current != nil {
		files = append(files, *current)
	}
	return map[string]any{
		"files_changed":     len(files),
		"files":             files,
		"security_signals":  signals,
		"signals_truncated": signalsTruncated,
	}
}

func checkHints(file, op, rawLine string, signals *[]securitySignal, truncated *bool) {
	var matched []string
	for _, r := range securityHintRules {
		if r.re.MatchString(rawLine) {
			matched = append(matched, r.name)
		}
	}
	if len(matched) == 0 {
		return
	}
	if len(*signals) >= maxSignals {
		*truncated = true
		return
	}
	trimmed := strings.TrimSpace(rawLine)
	if len(trimmed) > 200 {
		trimmed = trimmed[:200]
	}
	*signals = append(*signals, securitySignal{
		File:  file,
		Op:    op,
		Hints: matched,
		Line:  trimmed,
	})
}

func buildServer(client *http.Client) *mcpserver.Server {
	srv := mcpserver.New("patch-diff-mcp", "0.5.0")

	srv.Register(mcpserver.Tool{
		Name:        "fetch_cve_patch_diff",
		Description: "Fetch a public GitHub or GitLab commit/PR diff over HTTPS (no redirects, private IPs blocked) and extract changed files and security-relevant lines.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"commit_or_pr_url": map[string]any{"type": "string"},
			},
			"required": []string{"commit_or_pr_url"},
		},
		Handler: func(ctx context.Context, args map[string]any) (any, error) {
			rawURL, _ := args["commit_or_pr_url"].(string)
			target, accept, isGitHub, err := resolveSafePatchEndpoint(rawURL)
			if err != nil {
				return nil, err
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("User-Agent", "artex-nexus-patch-diff/0.5.0")
			req.Header.Set("Accept", accept)
			if tok := os.Getenv("GITHUB_TOKEN"); tok != "" && isGitHub {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			resp, err := client.Do(req)
			if err != nil {
				return nil, fmt.Errorf("fetch failed: %w", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				return nil, fmt.Errorf("refused HTTP %d redirect (no-redirect policy)", resp.StatusCode)
			}
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("upstream returned HTTP %d", resp.StatusCode)
			}
			raw, err := io.ReadAll(io.LimitReader(resp.Body, maxPatchBytes+1))
			if err != nil {
				return nil, err
			}
			truncated := len(raw) > maxPatchBytes
			if truncated {
				raw = raw[:maxPatchBytes]
			}
			patchStr := string(raw)
			return map[string]any{
				"url":       target,
				"truncated": truncated,
				"patch":     patchStr,
				"analysis":  extractDiffHunks(patchStr),
			}, nil
		},
	})

	srv.Register(mcpserver.Tool{
		Name:        "extract_diff_hunks",
		Description: "Parse a unified git diff into changed files, hunks, and added/removed lines matching security keywords.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"patch_text": map[string]any{"type": "string"},
			},
			"required": []string{"patch_text"},
		},
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			text, _ := args["patch_text"].(string)
			return extractDiffHunks(text), nil
		},
	})

	return srv
}

func main() {
	transport := flag.String("transport", mcpserver.EnvOr("MCP_TRANSPORT", "stdio"), "stdio or http")
	host := flag.String("host", mcpserver.EnvOr("MCP_HOST", "127.0.0.1"), "HTTP bind host")
	port := flag.Int("port", 8902, "HTTP bind port")
	flag.Parse()

	srv := buildServer(newSSRFHardenedClient())
	if err := srv.Run(*transport, *host, *port); err != nil {
		fmt.Fprintf(os.Stderr, "patch-diff-mcp error: %v\n", err)
		os.Exit(1)
	}
}

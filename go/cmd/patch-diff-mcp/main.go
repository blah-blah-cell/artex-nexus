package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/blah-blah-cell/artex-nexus/internal/mcpserver"
)

const maxPatchBytes = 256 * 1024

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

	securityHints = []string{
		"auth", "token", "sanitize", "escape", "validate", "verify",
		"permission", "check", "allowlist", "denylist", "csrf", "ssrf",
		"path", "traversal", "sql", "exec", "eval", "deserialize",
		"bounds", "overflow", "realpath", "normpath",
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
	if ip4 := ip.To4(); ip4 != nil {
		// CGNAT 100.64.0.0/10 and 0.0.0.0/8
		if (ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127) || ip4[0] == 0 {
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

func extractDiffHunks(patchText string) map[string]any {
	var files []fileDiffSummary
	var current *fileDiffSummary
	var signals []securitySignal

	for _, line := range strings.Split(patchText, "\n") {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			if current != nil {
				files = append(files, *current)
			}
			parts := strings.Fields(line)
			fname := line
			if len(parts) >= 4 {
				fname = strings.TrimPrefix(parts[len(parts)-1], "b/")
			}
			current = &fileDiffSummary{File: fname}
		case strings.HasPrefix(line, "@@ ") && current != nil:
			current.Hunks = append(current.Hunks, line)
		case current != nil && strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			current.Added++
			checkHints(current.File, "added", line[1:], &signals)
		case current != nil && strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---"):
			current.Removed++
			checkHints(current.File, "removed", line[1:], &signals)
		}
	}
	if current != nil {
		files = append(files, *current)
	}
	return map[string]any{
		"files_changed":    len(files),
		"files":            files,
		"security_signals": signals,
	}
}

func checkHints(file, op, rawLine string, signals *[]securitySignal) {
	if len(*signals) >= 60 {
		return
	}
	lower := strings.ToLower(rawLine)
	var matched []string
	for _, h := range securityHints {
		if strings.Contains(lower, h) {
			matched = append(matched, h)
		}
	}
	if len(matched) > 0 {
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

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blah-blah-cell/artex-nexus/internal/mcpserver"
	"gopkg.in/yaml.v3"
)

type ScopePolicy struct {
	ScopeID    string   `json:"scope_id" yaml:"scope_id"`
	Program    string   `json:"program" yaml:"program"`
	InScope    []string `json:"in_scope" yaml:"in_scope"`
	OutOfScope []string `json:"out_of_scope" yaml:"out_of_scope"`
	Notes      string   `json:"notes" yaml:"notes"`
}

type LedgerEntry struct {
	Seq                   int    `json:"seq"`
	ScopeID               string `json:"scope_id"`
	FindingID             string `json:"finding_id"`
	Program               string `json:"program"`
	Title                 string `json:"title"`
	Target                string `json:"target"`
	CWE                   string `json:"cwe"`
	Severity              string `json:"severity"`
	CVSSVector            string `json:"cvss_vector"`
	VerificationCommand   string `json:"verification_command"`
	ObservedOutputSummary string `json:"observed_output_summary"`
	Remediation           string `json:"remediation"`
	RecordedAt            string `json:"recorded_at"`
	PrevSHA256            string `json:"prev_sha256"`
	SHA256                string `json:"sha256"`
}

type GuardState struct {
	mu        sync.RWMutex
	configDir string
	stateDir  string
	scopes    map[string]ScopePolicy
}

func NewGuardState(configDir, stateDir string) (*GuardState, error) {
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return nil, err
	}
	gs := &GuardState{
		configDir: configDir,
		stateDir:  stateDir,
		scopes:    make(map[string]ScopePolicy),
	}
	_ = gs.loadPersistedScopes()
	return gs, nil
}

func (g *GuardState) scopesFile() string {
	return filepath.Join(g.stateDir, "scopes.json")
}

func (g *GuardState) ledgerFile() string {
	return filepath.Join(g.stateDir, "receipts.jsonl")
}

func (g *GuardState) loadPersistedScopes() error {
	raw, err := os.ReadFile(g.scopesFile())
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, &g.scopes)
}

func (g *GuardState) persistScopesLocked() error {
	raw, err := json.MarshalIndent(g.scopes, "", "  ")
	if err != nil {
		return err
	}
	tmp := g.scopesFile() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, g.scopesFile())
}

// resolveConfinedPolicyPath strictly confines policy reads inside configDir.
func (g *GuardState) resolveConfinedPolicyPath(name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", errors.New("policy_file is required")
	}
	if filepath.IsAbs(name) {
		return "", errors.New("absolute paths are prohibited; pass a relative filename inside SCOPE_CONFIG_DIR")
	}
	rootAbs, err := filepath.Abs(g.configDir)
	if err != nil {
		return "", err
	}
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", fmt.Errorf("config directory %q is unavailable: %w", g.configDir, err)
	}
	candidate := filepath.Join(rootReal, name)
	candReal, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("policy file %q not found inside config dir", name)
	}
	rel, err := filepath.Rel(rootReal, candReal)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", errors.New("path traversal or symlink escape outside SCOPE_CONFIG_DIR blocked")
	}
	return candReal, nil
}

func extractHost(target string) string {
	raw := strings.TrimSpace(target)
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		}
	}
	if _, _, err := net.ParseCIDR(raw); err != nil && strings.Contains(raw, "/") {
		raw = strings.SplitN(raw, "/", 2)[0]
	}
	if net.ParseIP(raw) == nil && strings.Contains(raw, ":") {
		if h, _, err := net.SplitHostPort(raw); err == nil {
			raw = h
		}
	}
	return strings.ToLower(strings.TrimSuffix(raw, "."))
}

func ruleMatches(host, rule string) bool {
	r := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rule), "."))
	if r == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if _, cidr, err := net.ParseCIDR(r); err == nil {
			return cidr.Contains(ip)
		}
		if rip := net.ParseIP(r); rip != nil {
			return ip.Equal(rip)
		}
	}
	if strings.HasPrefix(r, "*.") {
		base := r[2:]
		return host == base || strings.HasSuffix(host, "."+base)
	}
	ok, _ := path.Match(r, host)
	return ok
}

func computeEntryHash(e LedgerEntry) string {
	e.SHA256 = ""
	canonical, _ := json.Marshal(e)
	h := sha256.New()
	h.Write([]byte(e.PrevSHA256))
	h.Write([]byte("|"))
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil))
}

func (g *GuardState) readLedgerLocked() ([]LedgerEntry, error) {
	f, err := os.Open(g.ledgerFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []LedgerEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e LedgerEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("corrupt ledger line: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, sc.Err()
}

func (g *GuardState) VerifyLedger() map[string]any {
	g.mu.RLock()
	defer g.mu.RUnlock()
	entries, err := g.readLedgerLocked()
	if err != nil {
		return map[string]any{"valid": false, "error": err.Error()}
	}
	expectedPrev := "GENESIS"
	for i, e := range entries {
		if e.Seq != i+1 {
			return map[string]any{"valid": false, "entries": len(entries), "tampered_seq": i + 1, "reason": "sequence discontinuity"}
		}
		if e.PrevSHA256 != expectedPrev {
			return map[string]any{"valid": false, "entries": len(entries), "tampered_seq": e.Seq, "reason": "prev_sha256 link mismatch"}
		}
		recomputed := computeEntryHash(e)
		if e.SHA256 != recomputed {
			return map[string]any{"valid": false, "entries": len(entries), "tampered_seq": e.Seq, "reason": "entry sha256 mismatch"}
		}
		expectedPrev = e.SHA256
	}
	return map[string]any{"valid": true, "entries": len(entries), "head_sha256": expectedPrev}
}

func scopeIDFromArgs(args map[string]any) string {
	if v, ok := args["scope_id"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return "default"
}

func strArg(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return strings.TrimSpace(v)
}

func buildServer(state *GuardState) *mcpserver.Server {
	srv := mcpserver.New("scope-guard-mcp", "0.2.0")

	srv.Register(mcpserver.Tool{
		Name:        "load_scope_policy",
		Description: "Load a YAML/JSON scope policy confined strictly within SCOPE_CONFIG_DIR and persist it per scope_id.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"policy_file": map[string]any{"type": "string", "description": "Relative filename inside SCOPE_CONFIG_DIR (e.g. scope.example.yaml)"},
				"scope_id":    map[string]any{"type": "string", "default": "default", "description": "Isolated task or engagement identifier"},
			},
			"required": []string{"policy_file"},
		},
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			pfile := strArg(args, "policy_file")
			sid := scopeIDFromArgs(args)
			resolved, err := state.resolveConfinedPolicyPath(pfile)
			if err != nil {
				return nil, err
			}
			raw, err := os.ReadFile(resolved)
			if err != nil {
				return nil, err
			}
			var pol ScopePolicy
			if strings.HasSuffix(strings.ToLower(resolved), ".json") {
				if err := json.Unmarshal(raw, &pol); err != nil {
					return nil, err
				}
			} else {
				if err := yaml.Unmarshal(raw, &pol); err != nil {
					return nil, err
				}
			}
			pol.ScopeID = sid
			if pol.Program == "" {
				pol.Program = strings.TrimSuffix(filepath.Base(resolved), filepath.Ext(resolved))
			}

			state.mu.Lock()
			state.scopes[sid] = pol
			err = state.persistScopesLocked()
			state.mu.Unlock()
			if err != nil {
				return nil, err
			}
			return map[string]any{"loaded": true, "policy": pol}, nil
		},
	})

	srv.Register(mcpserver.Tool{
		Name:        "check_target_in_scope",
		Description: "Deterministically check whether a domain, URL, or IP is allowed under a persisted scope_id (out_of_scope takes strict precedence).",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target":   map[string]any{"type": "string"},
				"scope_id": map[string]any{"type": "string", "default": "default"},
			},
			"required": []string{"target"},
		},
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			target := strArg(args, "target")
			sid := scopeIDFromArgs(args)
			host := extractHost(target)
			if host == "" {
				return map[string]any{"allowed": false, "target": target, "reason": "empty or unparseable host"}, nil
			}
			state.mu.RLock()
			pol, exists := state.scopes[sid]
			state.mu.RUnlock()
			if !exists || len(pol.InScope) == 0 {
				return map[string]any{"allowed": false, "scope_id": sid, "host": host, "reason": "no scope policy loaded for this scope_id"}, nil
			}
			for _, deny := range pol.OutOfScope {
				if ruleMatches(host, deny) {
					return map[string]any{"allowed": false, "scope_id": sid, "host": host, "matched_rule": deny, "reason": "excluded by out_of_scope"}, nil
				}
			}
			for _, allow := range pol.InScope {
				if ruleMatches(host, allow) {
					return map[string]any{"allowed": true, "scope_id": sid, "program": pol.Program, "host": host, "matched_rule": allow, "reason": "matched in_scope"}, nil
				}
			}
			return map[string]any{"allowed": false, "scope_id": sid, "host": host, "reason": "did not match any in_scope rule"}, nil
		},
	})

	srv.Register(mcpserver.Tool{
		Name:        "list_in_scope_assets",
		Description: "Return the persisted scope policy for a scope_id.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"scope_id": map[string]any{"type": "string", "default": "default"}},
		},
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			sid := scopeIDFromArgs(args)
			state.mu.RLock()
			pol, ok := state.scopes[sid]
			state.mu.RUnlock()
			return map[string]any{"found": ok, "policy": pol}, nil
		},
	})

	srv.Register(mcpserver.Tool{
		Name:        "record_evidence_receipt",
		Description: "Append a cryptographically hash-chained SHA-256 verification receipt to receipts.jsonl.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"scope_id":                map[string]any{"type": "string", "default": "default"},
				"finding_id":              map[string]any{"type": "string"},
				"title":                   map[string]any{"type": "string"},
				"target":                  map[string]any{"type": "string"},
				"cwe":                     map[string]any{"type": "string"},
				"severity":                map[string]any{"type": "string"},
				"cvss_vector":             map[string]any{"type": "string"},
				"verification_command":    map[string]any{"type": "string"},
				"observed_output_summary": map[string]any{"type": "string"},
				"remediation":             map[string]any{"type": "string"},
			},
			"required": []string{"finding_id", "title", "target", "cwe", "severity", "verification_command", "observed_output_summary"},
		},
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			sid := scopeIDFromArgs(args)
			state.mu.Lock()
			defer state.mu.Unlock()

			entries, err := state.readLedgerLocked()
			if err != nil {
				return nil, err
			}
			prevHash := "GENESIS"
			if len(entries) > 0 {
				prevHash = entries[len(entries)-1].SHA256
			}
			prog := "unconfigured"
			if p, ok := state.scopes[sid]; ok && p.Program != "" {
				prog = p.Program
			}
			entry := LedgerEntry{
				Seq:                   len(entries) + 1,
				ScopeID:               sid,
				FindingID:             strArg(args, "finding_id"),
				Program:               prog,
				Title:                 strArg(args, "title"),
				Target:                strArg(args, "target"),
				CWE:                   strings.ToUpper(strArg(args, "cwe")),
				Severity:              strings.ToUpper(strArg(args, "severity")),
				CVSSVector:            strArg(args, "cvss_vector"),
				VerificationCommand:   strArg(args, "verification_command"),
				ObservedOutputSummary: strArg(args, "observed_output_summary"),
				Remediation:           strArg(args, "remediation"),
				RecordedAt:            time.Now().UTC().Format(time.RFC3339),
				PrevSHA256:            prevHash,
			}
			entry.SHA256 = computeEntryHash(entry)

			f, err := os.OpenFile(state.ledgerFile(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			line, _ := json.Marshal(entry)
			if _, err := f.Write(append(line, '\n')); err != nil {
				return nil, err
			}
			return map[string]any{
				"recorded":    true,
				"seq":         entry.Seq,
				"prev_sha256": entry.PrevSHA256,
				"sha256":      entry.SHA256,
			}, nil
		},
	})

	srv.Register(mcpserver.Tool{
		Name:        "verify_ledger_chain",
		Description: "Cryptographically verify the entire append-only SHA-256 hash chain from GENESIS to head.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		Handler: func(_ context.Context, _ map[string]any) (any, error) {
			return state.VerifyLedger(), nil
		},
	})

	srv.Register(mcpserver.Tool{
		Name:        "export_report",
		Description: "Export verified hash-chained receipts as Markdown or SARIF 2.1.0.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"report_format": map[string]any{"type": "string", "default": "markdown"},
				"scope_id":      map[string]any{"type": "string"},
			},
		},
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			fmtType := strings.ToLower(strArg(args, "report_format"))
			if fmtType == "" {
				fmtType = "markdown"
			}
			filterScope := strArg(args, "scope_id")
			chainStatus := state.VerifyLedger()

			state.mu.RLock()
			all, err := state.readLedgerLocked()
			state.mu.RUnlock()
			if err != nil {
				return nil, err
			}
			var filtered []LedgerEntry
			for _, e := range all {
				if filterScope == "" || e.ScopeID == filterScope {
					filtered = append(filtered, e)
				}
			}

			if fmtType == "sarif" {
				var results []map[string]any
				for _, e := range filtered {
					lvl := "warning"
					if e.Severity == "CRITICAL" || e.Severity == "HIGH" {
						lvl = "error"
					}
					results = append(results, map[string]any{
						"ruleId":  e.CWE,
						"level":   lvl,
						"message": map[string]string{"text": e.Title + " — " + e.ObservedOutputSummary},
						"properties": map[string]any{
							"seq":         e.Seq,
							"finding_id":  e.FindingID,
							"target":      e.Target,
							"cvss_vector": e.CVSSVector,
							"prev_sha256": e.PrevSHA256,
							"sha256":      e.SHA256,
						},
					})
				}
				sarif := map[string]any{
					"version": "2.1.0",
					"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
					"runs": []map[string]any{{
						"tool":    map[string]any{"driver": map[string]any{"name": "artex-nexus-scope-guard", "version": "0.2.0"}},
						"results": results,
					}},
				}
				b, _ := json.MarshalIndent(sarif, "", "  ")
				return map[string]any{"format": "sarif", "count": len(filtered), "chain": chainStatus, "content": string(b)}, nil
			}

			var sb strings.Builder
			fmt.Fprintf(&sb, "# Security Verification Report (Chain Valid: %v)\n\n", chainStatus["valid"])
			for _, e := range filtered {
				fmt.Fprintf(&sb, "## #%d [%s] %s\n", e.Seq, e.FindingID, e.Title)
				fmt.Fprintf(&sb, "- **Scope:** `%s` (%s)\n", e.ScopeID, e.Program)
				fmt.Fprintf(&sb, "- **Severity:** %s (`%s`)\n", e.Severity, e.CVSSVector)
				fmt.Fprintf(&sb, "- **CWE:** %s\n", e.CWE)
				fmt.Fprintf(&sb, "- **Target:** `%s`\n", e.Target)
				fmt.Fprintf(&sb, "- **Verification:** `%s`\n", e.VerificationCommand)
				fmt.Fprintf(&sb, "- **Observed Evidence:** %s\n", e.ObservedOutputSummary)
				fmt.Fprintf(&sb, "- **Chain:** `%s` -> `%s`\n\n", e.PrevSHA256, e.SHA256)
			}
			return map[string]any{"format": "markdown", "count": len(filtered), "chain": chainStatus, "content": sb.String()}, nil
		},
	})

	return srv
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func main() {
	transport := flag.String("transport", envOr("MCP_TRANSPORT", "stdio"), "stdio or http")
	host := flag.String("host", envOr("MCP_HOST", "127.0.0.1"), "HTTP bind host")
	port := flag.Int("port", 8903, "HTTP bind port")
	configDir := flag.String("config-dir", envOr("SCOPE_CONFIG_DIR", "config"), "Confined directory for scope policies")
	stateDir := flag.String("state-dir", envOr("SCOPE_STATE_DIR", "data/receipts"), "Directory for persisted scopes and hash-chained ledger")
	flag.Parse()

	state, err := NewGuardState(*configDir, *stateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scope-guard-mcp init error: %v\n", err)
		os.Exit(1)
	}
	srv := buildServer(state)
	if err := srv.Run(*transport, *host, *port); err != nil {
		fmt.Fprintf(os.Stderr, "scope-guard-mcp error: %v\n", err)
		os.Exit(1)
	}
}

package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blah-blah-cell/artex-nexus/internal/mcpserver"
	"github.com/blah-blah-cell/artex-nexus/internal/pathguard"
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

type ledgerTailCache struct {
	valid    bool
	fileSize int64
	modTime  time.Time
	seq      int
	headHash string
}

type GuardState struct {
	mu        sync.RWMutex
	configDir string
	stateDir  string
	hmacKey   []byte
	scopes    map[string]ScopePolicy
	tail      ledgerTailCache
}

func NewGuardState(configDir, stateDir string) (*GuardState, error) {
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return nil, err
	}
	var hmacKey []byte
	if k := os.Getenv("SCOPE_LEDGER_HMAC_KEY"); k != "" {
		hmacKey = []byte(k)
	}
	gs := &GuardState{
		configDir: configDir,
		stateDir:  stateDir,
		hmacKey:   hmacKey,
		scopes:    make(map[string]ScopePolicy),
	}
	if err := gs.loadPersistedScopes(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("loading persisted scopes.json: %w", err)
	}
	return gs, nil
}

func (g *GuardState) scopesFile() string {
	return filepath.Join(g.stateDir, "scopes.json")
}

func (g *GuardState) ledgerFile() string {
	return filepath.Join(g.stateDir, "receipts.jsonl")
}

func (g *GuardState) lockFile() string {
	return filepath.Join(g.stateDir, "receipts.jsonl.lock")
}

func (g *GuardState) loadPersistedScopes() error {
	raw, err := os.ReadFile(g.scopesFile())
	if err != nil {
		return err
	}
	var parsed map[string]ScopePolicy
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("corrupt scopes.json (refusing to overwrite): %w", err)
	}
	if parsed != nil {
		g.scopes = parsed
	}
	return nil
}

func (g *GuardState) persistScopesLocked() error {
	raw, err := json.MarshalIndent(g.scopes, "", "  ")
	if err != nil {
		return err
	}
	tmp := g.scopesFile() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, g.scopesFile())
}

func (g *GuardState) resolveConfinedPolicyPath(name string) (string, error) {
	return pathguard.ResolveConfined(g.configDir, name, false)
}

// acquireFileLock provides portable cross-process mutual exclusion via atomic O_CREATE|O_EXCL.
func (g *GuardState) acquireFileLock() (func(), error) {
	lockPath := g.lockFile()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
			_ = f.Close()
			return func() { _ = os.Remove(lockPath) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if st, statErr := os.Stat(lockPath); statErr == nil && time.Since(st.ModTime()) > 30*time.Second {
			_ = os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return nil, errors.New("timed out waiting for ledger lock")
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func isValidHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// parseNonStandardIPv4 normalizes decimal (2130706433), hex (0x7f000001), octal (0177.0.0.1),
// and shorthand (127.1) IPv4 representations into canonical net.IP.
func parseNonStandardIPv4(h string) net.IP {
	if h == "" {
		return nil
	}
	parts := strings.Split(h, ".")
	if len(parts) > 4 {
		return nil
	}
	vals := make([]uint64, len(parts))
	for i, p := range parts {
		if p == "" {
			return nil
		}
		v, err := strconv.ParseUint(p, 0, 32)
		if err != nil {
			return nil
		}
		vals[i] = v
	}
	var ip uint32
	switch len(vals) {
	case 1:
		ip = uint32(vals[0])
	case 2:
		if vals[0] > 0xff || vals[1] > 0xffffff {
			return nil
		}
		ip = uint32(vals[0]<<24 | vals[1])
	case 3:
		if vals[0] > 0xff || vals[1] > 0xff || vals[2] > 0xffff {
			return nil
		}
		ip = uint32(vals[0]<<24 | vals[1]<<16 | vals[2])
	case 4:
		if vals[0] > 0xff || vals[1] > 0xff || vals[2] > 0xff || vals[3] > 0xff {
			return nil
		}
		ip = uint32(vals[0]<<24 | vals[1]<<16 | vals[2]<<8 | vals[3])
	}
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

type parsedTarget struct {
	host string
	port string
	path string
}

func parseTarget(raw string) (parsedTarget, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return parsedTarget{}, false
	}
	if ip := net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")); ip != nil {
		return parsedTarget{host: ip.String()}, true
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return parsedTarget{host: strings.ToLower(s)}, true
	}
	toParse := s
	if !strings.Contains(toParse, "://") {
		toParse = "http://" + toParse
	}
	u, err := url.Parse(toParse)
	if err != nil || u.User != nil {
		return parsedTarget{}, false
	}
	h := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if ip := net.ParseIP(h); ip != nil {
		return parsedTarget{host: ip.String(), port: u.Port(), path: u.Path}, true
	}
	if ip := parseNonStandardIPv4(h); ip != nil {
		return parsedTarget{host: ip.String(), port: u.Port(), path: u.Path}, true
	}
	if !isValidHostname(h) {
		return parsedTarget{}, false
	}
	return parsedTarget{host: h, port: u.Port(), path: u.Path}, true
}

func validateRule(rawRule string) error {
	r := strings.ToLower(strings.TrimSpace(rawRule))
	if r == "" {
		return errors.New("empty scope rule")
	}
	// Strip scheme if present
	if idx := strings.Index(r, "://"); idx >= 0 {
		r = r[idx+3:]
	}
	// Split optional path prefix
	hostPort := r
	if slash := strings.IndexByte(r, '/'); slash >= 0 {
		if _, _, err := net.ParseCIDR(r); err == nil {
			return nil
		}
		hostPort = r[:slash]
	}
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSuffix(host, "]"), "["), ".")
	if net.ParseIP(host) != nil {
		return nil
	}
	if strings.HasPrefix(host, "*.") {
		base := host[2:]
		if strings.Contains(base, "*") || strings.Count(base, ".") < 1 || !isValidHostname(base) {
			return fmt.Errorf("overly broad or invalid wildcard rule %q (must be *.<domain.tld>)", rawRule)
		}
		return nil
	}
	if strings.ContainsAny(host, "*?[]") {
		return fmt.Errorf("disallowed glob pattern in scope rule %q (use exact host, CIDR, or *.domain.tld)", rawRule)
	}
	if !isValidHostname(host) {
		return fmt.Errorf("invalid hostname in scope rule %q", rawRule)
	}
	return nil
}

func ruleMatches(t parsedTarget, rule string) bool {
	r := strings.ToLower(strings.TrimSpace(rule))
	if r == "" {
		return false
	}
	if ip := net.ParseIP(t.host); ip != nil {
		if _, cidr, err := net.ParseCIDR(r); err == nil {
			return cidr.Contains(ip)
		}
	}
	// Parse optional scheme, host, port, and path prefix on the rule.
	if idx := strings.Index(r, "://"); idx >= 0 {
		r = r[idx+3:]
	}
	rulePath := ""
	hostPort := r
	if slash := strings.IndexByte(r, '/'); slash >= 0 {
		hostPort = r[:slash]
		rulePath = strings.TrimSuffix(r[slash:], "*")
	}
	ruleHost := hostPort
	rulePort := ""
	if h, p, err := net.SplitHostPort(hostPort); err == nil {
		ruleHost = h
		rulePort = p
	}
	ruleHost = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSuffix(ruleHost, "]"), "["), ".")

	if rulePort != "" && t.port != rulePort {
		return false
	}
	if rulePath != "" {
		tp := strings.ToLower(t.path)
		if tp == "" {
			tp = "/"
		}
		if !strings.HasPrefix(tp, rulePath) {
			return false
		}
	}

	if ip := net.ParseIP(t.host); ip != nil {
		if rip := net.ParseIP(ruleHost); rip != nil {
			return ip.Equal(rip)
		}
		if rip := parseNonStandardIPv4(ruleHost); rip != nil {
			return ip.Equal(rip)
		}
		return false
	}
	if strings.HasPrefix(ruleHost, "*.") {
		base := ruleHost[2:]
		if strings.Contains(base, "*") || strings.Count(base, ".") < 1 {
			return false
		}
		// *.example.com matches subdomains ONLY, not the apex example.com.
		return strings.HasSuffix(t.host, "."+base)
	}
	if strings.ContainsAny(ruleHost, "*?[]") {
		return false
	}
	return t.host == ruleHost
}

func computeEntryHash(e LedgerEntry, hmacKey []byte) string {
	e.SHA256 = ""
	canonical, _ := json.Marshal(e)
	if len(hmacKey) > 0 {
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write([]byte(e.PrevSHA256))
		mac.Write([]byte("|"))
		mac.Write(canonical)
		return hex.EncodeToString(mac.Sum(nil))
	}
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

func (g *GuardState) currentTailLocked() (int, string, error) {
	st, err := os.Stat(g.ledgerFile())
	if errors.Is(err, os.ErrNotExist) {
		g.tail = ledgerTailCache{valid: true, seq: 0, headHash: "GENESIS"}
		return 0, "GENESIS", nil
	}
	if err != nil {
		return 0, "", err
	}
	if g.tail.valid && g.tail.fileSize == st.Size() && g.tail.modTime.Equal(st.ModTime()) {
		return g.tail.seq, g.tail.headHash, nil
	}
	entries, err := g.readLedgerLocked()
	if err != nil {
		return 0, "", err
	}
	seq := len(entries)
	head := "GENESIS"
	if seq > 0 {
		head = entries[seq-1].SHA256
	}
	g.tail = ledgerTailCache{
		valid:    true,
		fileSize: st.Size(),
		modTime:  st.ModTime(),
		seq:      seq,
		headHash: head,
	}
	return seq, head, nil
}

func verifyEntries(entries []LedgerEntry, hmacKey []byte) map[string]any {
	keyed := len(hmacKey) > 0
	expectedPrev := "GENESIS"
	for i, e := range entries {
		if e.Seq != i+1 {
			return map[string]any{"valid": false, "keyed_hmac": keyed, "entries": len(entries), "tampered_seq": i + 1, "reason": "sequence discontinuity"}
		}
		if e.PrevSHA256 != expectedPrev {
			return map[string]any{"valid": false, "keyed_hmac": keyed, "entries": len(entries), "tampered_seq": e.Seq, "reason": "prev_sha256 link mismatch"}
		}
		recomputed := computeEntryHash(e, hmacKey)
		if e.SHA256 != recomputed {
			return map[string]any{"valid": false, "keyed_hmac": keyed, "entries": len(entries), "tampered_seq": e.Seq, "reason": "entry sha256 mismatch"}
		}
		expectedPrev = e.SHA256
	}
	out := map[string]any{"valid": true, "keyed_hmac": keyed, "entries": len(entries), "head_sha256": expectedPrev}
	if !keyed {
		out["note"] = "unkeyed SHA-256 chain detects in-place edits; set SCOPE_LEDGER_HMAC_KEY to detect full rewrites"
	}
	return out
}

func (g *GuardState) VerifyLedger() map[string]any {
	g.mu.RLock()
	defer g.mu.RUnlock()
	entries, err := g.readLedgerLocked()
	if err != nil {
		return map[string]any{"valid": false, "error": err.Error()}
	}
	return verifyEntries(entries, g.hmacKey)
}

func (g *GuardState) evaluateTargetLocked(target, sid string) (bool, string, string, string) {
	pt, ok := parseTarget(target)
	if !ok {
		return false, "", "", "empty or unparseable host"
	}
	pol, exists := g.scopes[sid]
	if !exists || len(pol.InScope) == 0 {
		return false, pt.host, "", "no scope policy loaded for this scope_id"
	}
	for _, deny := range pol.OutOfScope {
		if ruleMatches(pt, deny) {
			return false, pt.host, deny, "excluded by out_of_scope"
		}
	}
	for _, allow := range pol.InScope {
		if ruleMatches(pt, allow) {
			return true, pt.host, allow, "matched in_scope"
		}
	}
	return false, pt.host, "", "did not match any in_scope rule"
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

func escapeMarkdownInline(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	replacer := strings.NewReplacer(
		`\`, `\\`,
		"`", `\'`,
		"*", `\*`,
		"_", `\_`,
		"[", `\[`,
		"]", `\]`,
		"<", `&lt;`,
		">", `&gt;`,
		"#", `\#`,
	)
	return replacer.Replace(s)
}

func (g *GuardState) LoadPolicyFile(policyFile, sid string) (ScopePolicy, error) {
	if strings.TrimSpace(sid) == "" {
		sid = "default"
	}
	resolved, err := g.resolveConfinedPolicyPath(policyFile)
	if err != nil {
		return ScopePolicy{}, err
	}
	raw, err := os.ReadFile(resolved)
	if err != nil {
		return ScopePolicy{}, err
	}
	var pol ScopePolicy
	if strings.HasSuffix(strings.ToLower(resolved), ".json") {
		if err := json.Unmarshal(raw, &pol); err != nil {
			return ScopePolicy{}, err
		}
	} else {
		if err := yaml.Unmarshal(raw, &pol); err != nil {
			return ScopePolicy{}, err
		}
	}
	for _, r := range pol.InScope {
		if err := validateRule(r); err != nil {
			return ScopePolicy{}, fmt.Errorf("invalid in_scope rule: %w", err)
		}
	}
	for _, r := range pol.OutOfScope {
		if err := validateRule(r); err != nil {
			return ScopePolicy{}, fmt.Errorf("invalid out_of_scope rule: %w", err)
		}
	}
	pol.ScopeID = sid
	if pol.Program == "" {
		pol.Program = strings.TrimSuffix(filepath.Base(resolved), filepath.Ext(resolved))
	}

	g.mu.Lock()
	g.scopes[sid] = pol
	err = g.persistScopesLocked()
	g.mu.Unlock()
	if err != nil {
		return ScopePolicy{}, err
	}
	return pol, nil
}

func buildServer(state *GuardState) *mcpserver.Server {
	srv := mcpserver.New("scope-guard-mcp", "0.5.0")

	srv.Register(mcpserver.Tool{
		Name:        "load_scope_policy",
		Description: "Load a YAML or JSON scope policy from SCOPE_CONFIG_DIR and save it under scope_id.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"policy_file": map[string]any{"type": "string", "description": "Relative filename inside SCOPE_CONFIG_DIR (e.g. scope.example.yaml)"},
				"scope_id":    map[string]any{"type": "string", "default": "default", "description": "Isolated task or engagement identifier"},
			},
			"required": []string{"policy_file"},
		},
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			pol, err := state.LoadPolicyFile(strArg(args, "policy_file"), scopeIDFromArgs(args))
			if err != nil {
				return nil, err
			}
			return map[string]any{"loaded": true, "policy": pol}, nil
		},
	})

	srv.Register(mcpserver.Tool{
		Name:        "check_target_in_scope",
		Description: "Check whether a domain, URL, host:port/path, or IP is allowed under a persisted scope_id (out_of_scope wins over in_scope).",
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
			state.mu.RLock()
			allowed, host, matchedRule, reason := state.evaluateTargetLocked(target, sid)
			pol := state.scopes[sid]
			state.mu.RUnlock()
			out := map[string]any{
				"allowed":  allowed,
				"scope_id": sid,
				"host":     host,
				"reason":   reason,
			}
			if matchedRule != "" {
				out["matched_rule"] = matchedRule
			}
			if allowed {
				out["program"] = pol.Program
			}
			return out, nil
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
		Description: "Append a hash-chained verification receipt to receipts.jsonl after verifying target scope.",
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
				"allow_out_of_scope":      map[string]any{"type": "boolean", "default": false},
			},
			"required": []string{"finding_id", "title", "target", "cwe", "severity", "verification_command", "observed_output_summary"},
		},
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			findingID := strArg(args, "finding_id")
			title := strArg(args, "title")
			target := strArg(args, "target")
			cwe := strings.ToUpper(strArg(args, "cwe"))
			sev := strings.ToUpper(strArg(args, "severity"))
			verifyCmd := strArg(args, "verification_command")
			obs := strArg(args, "observed_output_summary")
			if findingID == "" || title == "" || target == "" || cwe == "" || sev == "" || verifyCmd == "" || obs == "" {
				return nil, errors.New("finding_id, title, target, cwe, severity, verification_command, and observed_output_summary are required")
			}
			allowOOS, _ := args["allow_out_of_scope"].(bool)

			sid := scopeIDFromArgs(args)
			state.mu.Lock()
			defer state.mu.Unlock()

			pol, hasPolicy := state.scopes[sid]
			if hasPolicy && !allowOOS {
				allowed, _, _, reason := state.evaluateTargetLocked(target, sid)
				if !allowed {
					return nil, fmt.Errorf("target %q failed scope check for %q: %s", target, sid, reason)
				}
			}

			unlock, err := state.acquireFileLock()
			if err != nil {
				return nil, err
			}
			defer unlock()

			lastSeq, prevHash, err := state.currentTailLocked()
			if err != nil {
				return nil, err
			}
			prog := "unconfigured"
			if hasPolicy && pol.Program != "" {
				prog = pol.Program
			}
			entry := LedgerEntry{
				Seq:                   lastSeq + 1,
				ScopeID:               sid,
				FindingID:             findingID,
				Program:               prog,
				Title:                 title,
				Target:                target,
				CWE:                   cwe,
				Severity:              sev,
				CVSSVector:            strArg(args, "cvss_vector"),
				VerificationCommand:   verifyCmd,
				ObservedOutputSummary: obs,
				Remediation:           strArg(args, "remediation"),
				RecordedAt:            time.Now().UTC().Format(time.RFC3339),
				PrevSHA256:            prevHash,
			}
			entry.SHA256 = computeEntryHash(entry, state.hmacKey)

			f, err := os.OpenFile(state.ledgerFile(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				return nil, err
			}
			line, _ := json.Marshal(entry)
			if _, err := f.Write(append(line, '\n')); err != nil {
				_ = f.Close()
				return nil, err
			}
			if err := f.Sync(); err != nil {
				_ = f.Close()
				return nil, err
			}
			if err := f.Close(); err != nil {
				return nil, err
			}
			if st, statErr := os.Stat(state.ledgerFile()); statErr == nil {
				state.tail = ledgerTailCache{
					valid:    true,
					fileSize: st.Size(),
					modTime:  st.ModTime(),
					seq:      entry.Seq,
					headHash: entry.SHA256,
				}
			} else {
				state.tail.valid = false
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
		Description: "Verify the hash chain in receipts.jsonl from GENESIS to the latest entry.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		Handler: func(_ context.Context, _ map[string]any) (any, error) {
			return state.VerifyLedger(), nil
		},
	})

	srv.Register(mcpserver.Tool{
		Name:        "export_report",
		Description: "Export receipts as Markdown or SARIF 2.1.0.",
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

			state.mu.RLock()
			all, err := state.readLedgerLocked()
			hmacKey := state.hmacKey
			state.mu.RUnlock()
			if err != nil {
				return nil, err
			}
			chainStatus := verifyEntries(all, hmacKey)
			var filtered []LedgerEntry
			for _, e := range all {
				if filterScope == "" || e.ScopeID == filterScope {
					filtered = append(filtered, e)
				}
			}

			if fmtType == "sarif" {
				results := make([]map[string]any, 0, len(filtered))
				rulesSeen := make(map[string]bool)
				rules := make([]map[string]any, 0)
				for _, e := range filtered {
					if !rulesSeen[e.CWE] {
						rulesSeen[e.CWE] = true
						rules = append(rules, map[string]any{
							"id":               e.CWE,
							"shortDescription": map[string]string{"text": "Verified security finding (" + e.CWE + ")"},
						})
					}
					lvl := "warning"
					if e.Severity == "CRITICAL" || e.Severity == "HIGH" {
						lvl = "error"
					}
					results = append(results, map[string]any{
						"ruleId":  e.CWE,
						"level":   lvl,
						"message": map[string]string{"text": e.Title + " - " + e.ObservedOutputSummary},
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
						"tool": map[string]any{
							"driver": map[string]any{
								"name":    "artex-nexus-scope-guard",
								"version": "0.5.0",
								"rules":   rules,
							},
						},
						"results": results,
					}},
				}
				b, _ := json.MarshalIndent(sarif, "", "  ")
				return map[string]any{
					"format":              "sarif",
					"count":               len(filtered),
					"total_ledger_count":  len(all),
					"filtered_by_scope":   filterScope,
					"full_ledger_chain":   chainStatus,
					"chain":               chainStatus,
					"content":             string(b),
				}, nil
			}

			var sb strings.Builder
			fmt.Fprintf(&sb, "# Security Verification Report (Full Ledger Chain Valid: %v, Showing %d/%d Entries)\n\n",
				chainStatus["valid"], len(filtered), len(all))
			for _, e := range filtered {
				fmt.Fprintf(&sb, "## #%d [%s] %s\n", e.Seq, escapeMarkdownInline(e.FindingID), escapeMarkdownInline(e.Title))
				fmt.Fprintf(&sb, "- **Scope:** `%s` (%s)\n", escapeMarkdownInline(e.ScopeID), escapeMarkdownInline(e.Program))
				fmt.Fprintf(&sb, "- **Severity:** %s (`%s`)\n", escapeMarkdownInline(e.Severity), escapeMarkdownInline(e.CVSSVector))
				fmt.Fprintf(&sb, "- **CWE:** %s\n", escapeMarkdownInline(e.CWE))
				fmt.Fprintf(&sb, "- **Target:** `%s`\n", escapeMarkdownInline(e.Target))
				fmt.Fprintf(&sb, "- **Verification:** `%s`\n", escapeMarkdownInline(e.VerificationCommand))
				fmt.Fprintf(&sb, "- **Observed Evidence:** %s\n", escapeMarkdownInline(e.ObservedOutputSummary))
				fmt.Fprintf(&sb, "- **Chain:** `%s` -> `%s`\n\n", e.PrevSHA256, e.SHA256)
			}
			return map[string]any{
				"format":             "markdown",
				"count":              len(filtered),
				"total_ledger_count": len(all),
				"filtered_by_scope":  filterScope,
				"full_ledger_chain":  chainStatus,
				"chain":              chainStatus,
				"content":            sb.String(),
			}, nil
		},
	})

	return srv
}

func main() {
	transport := flag.String("transport", mcpserver.EnvOr("MCP_TRANSPORT", "stdio"), "stdio or http")
	host := flag.String("host", mcpserver.EnvOr("MCP_HOST", "127.0.0.1"), "HTTP bind host")
	port := flag.Int("port", 8903, "HTTP bind port")
	configDir := flag.String("config-dir", mcpserver.EnvOr("SCOPE_CONFIG_DIR", "config"), "Confined directory for scope policies")
	stateDir := flag.String("state-dir", mcpserver.EnvOr("SCOPE_STATE_DIR", "data/receipts"), "Directory for persisted scopes and hash-chained ledger")
	defaultPolicy := flag.String("default-policy", mcpserver.EnvOr("SCOPE_DEFAULT_POLICY", ""), "Optional relative YAML/JSON policy file in config-dir to preload into 'default' scope on startup")
	flag.Parse()

	state, err := NewGuardState(*configDir, *stateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scope-guard-mcp init error: %v\n", err)
		os.Exit(1)
	}
	if strings.TrimSpace(*defaultPolicy) != "" {
		if _, err := state.LoadPolicyFile(*defaultPolicy, "default"); err != nil {
			fmt.Fprintf(os.Stderr, "scope-guard-mcp default-policy error: %v\n", err)
			os.Exit(1)
		}
	}
	srv := buildServer(state)
	if err := srv.Run(*transport, *host, *port); err != nil {
		fmt.Fprintf(os.Stderr, "scope-guard-mcp error: %v\n", err)
		os.Exit(1)
	}
}

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScopeConfinementMultiTenantPersistenceAndHashChain(t *testing.T) {
	tmp := t.TempDir()
	cfgDir := filepath.Join(tmp, "config")
	stateDir := filepath.Join(tmp, "state")
	if err := os.MkdirAll(cfgDir, 0o750); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(tmp, "secret.yaml")
	_ = os.WriteFile(outsideFile, []byte("program: secret\nin_scope:\n  - '*'\n"), 0o600)

	_ = os.WriteFile(filepath.Join(cfgDir, "task-a.yaml"), []byte(
		"program: task-a\nin_scope:\n  - '*.a.example.test'\n  - '10.1.0.0/16'\n  - 'port.example.test:8443/v1/'\nout_of_scope:\n  - 'pay.a.example.test'\n  - '10.1.0.1'\n",
	), 0o600)
	_ = os.WriteFile(filepath.Join(cfgDir, "task-b.yaml"), []byte(
		"program: task-b\nin_scope:\n  - 'api.b.example.test'\n",
	), 0o600)
	_ = os.WriteFile(filepath.Join(cfgDir, "bad-wildcard.yaml"), []byte(
		"program: bad\nin_scope:\n  - '*example.test'\n",
	), 0o600)

	gs, err := NewGuardState(cfgDir, stateDir)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := gs.resolveConfinedPolicyPath("../secret.yaml"); err == nil {
		t.Fatal("expected traversal ../secret.yaml to be blocked")
	}
	if _, err := gs.resolveConfinedPolicyPath(outsideFile); err == nil {
		t.Fatal("expected absolute path to be blocked")
	}
	if _, err := gs.LoadPolicyFile("bad-wildcard.yaml", "bad"); err == nil {
		t.Fatal("expected overly broad wildcard *example.test to be rejected")
	}

	srv := buildServer(gs)
	callRaw := func(name string, args map[string]any) (map[string]any, bool) {
		t.Helper()
		req, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": name, "arguments": args},
		})
		raw, _ := srv.HandleRPC(context.Background(), req)
		var resp map[string]any
		_ = json.Unmarshal(raw, &resp)
		res := resp["result"].(map[string]any)
		isErr, _ := res["isError"].(bool)
		txt := res["content"].([]any)[0].(map[string]any)["text"].(string)
		var out map[string]any
		_ = json.Unmarshal([]byte(txt), &out)
		return out, isErr
	}
	call := func(name string, args map[string]any) map[string]any {
		out, _ := callRaw(name, args)
		return out
	}

	// Empty SARIF export must serialize results as [] rather than null.
	emptySarif := call("export_report", map[string]any{"report_format": "sarif"})
	if !strings.Contains(emptySarif["content"].(string), `"results": []`) {
		t.Fatalf("expected empty SARIF results array, got: %s", emptySarif["content"])
	}

	if !call("load_scope_policy", map[string]any{"policy_file": "task-a.yaml", "scope_id": "task-a"})["loaded"].(bool) {
		t.Fatal("failed to load task-a")
	}
	if !call("load_scope_policy", map[string]any{"policy_file": "task-b.yaml", "scope_id": "task-b"})["loaded"].(bool) {
		t.Fatal("failed to load task-b")
	}

	gs2, err := NewGuardState(cfgDir, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	srv = buildServer(gs2)

	if !call("check_target_in_scope", map[string]any{"target": "https://sub.a.example.test/x", "scope_id": "task-a"})["allowed"].(bool) {
		t.Fatal("expected sub.a.example.test allowed in task-a after restart")
	}
	// *.a.example.test must NOT match apex a.example.test.
	if call("check_target_in_scope", map[string]any{"target": "https://a.example.test/x", "scope_id": "task-a"})["allowed"].(bool) {
		t.Fatal("expected apex a.example.test NOT to match *.a.example.test")
	}
	// Port and path scoped rule matching.
	if !call("check_target_in_scope", map[string]any{"target": "https://port.example.test:8443/v1/users", "scope_id": "task-a"})["allowed"].(bool) {
		t.Fatal("expected port+path matching target allowed")
	}
	if call("check_target_in_scope", map[string]any{"target": "https://port.example.test:9000/v1/users", "scope_id": "task-a"})["allowed"].(bool) {
		t.Fatal("expected wrong port rejected")
	}
	if call("check_target_in_scope", map[string]any{"target": "https://port.example.test:8443/v2/users", "scope_id": "task-a"})["allowed"].(bool) {
		t.Fatal("expected wrong path rejected")
	}
	// Decimal/hex IPv4 obfuscation must normalize and hit out_of_scope (10.1.0.1 == 0x0a010001 == 167837697).
	for _, obf := range []string{"0x0a010001", "167837697", "012.1.0.1"} {
		if call("check_target_in_scope", map[string]any{"target": obf, "scope_id": "task-a"})["allowed"].(bool) {
			t.Fatalf("expected obfuscated out-of-scope IP %s to be denied", obf)
		}
	}
	if call("check_target_in_scope", map[string]any{"target": "https://pay.a.example.test/x", "scope_id": "task-a"})["allowed"].(bool) {
		t.Fatal("expected pay.a.example.test denied in task-a")
	}
	if call("check_target_in_scope", map[string]any{"target": "https://sub.a.example.test/x", "scope_id": "task-b"})["allowed"].(bool) {
		t.Fatal("task-a scope leaked into task-b")
	}
	// Schemeless query/fragment/userinfo smuggling must never bypass scope rules.
	for _, smuggled := range []string{
		"evil.com?x=.a.example.test",
		"evil.com#.a.example.test",
		"evil@sub.a.example.test",
		"pay.a.example.test?x=.a.example.test",
	} {
		if call("check_target_in_scope", map[string]any{"target": smuggled, "scope_id": "task-a"})["allowed"].(bool) {
			t.Fatalf("smuggled target should be rejected: %s", smuggled)
		}
	}

	// Recording an out-of-scope target must be rejected.
	if _, isErr := callRaw("record_evidence_receipt", map[string]any{
		"scope_id": "task-a", "finding_id": "F-OOS", "title": "OOS", "target": "pay.a.example.test",
		"cwe": "CWE-79", "severity": "HIGH", "verification_command": "curl ...", "observed_output_summary": "x",
	}); !isErr {
		t.Fatal("expected record_evidence_receipt to reject out-of-scope target")
	}

	r1 := call("record_evidence_receipt", map[string]any{
		"scope_id": "task-a", "finding_id": "F-1", "title": "First [injected](link)", "target": "sub.a.example.test",
		"cwe": "CWE-79", "severity": "HIGH", "verification_command": "curl ...", "observed_output_summary": "ok1",
	})
	r2 := call("record_evidence_receipt", map[string]any{
		"scope_id": "task-a", "finding_id": "F-2", "title": "Second", "target": "sub.a.example.test",
		"cwe": "CWE-918", "severity": "CRITICAL", "verification_command": "curl ...", "observed_output_summary": "ok2",
	})
	if r2["prev_sha256"] != r1["sha256"] {
		t.Fatalf("expected hash chain link: %v != %v", r2["prev_sha256"], r1["sha256"])
	}
	if !call("verify_ledger_chain", map[string]any{})["valid"].(bool) {
		t.Fatal("expected valid chain")
	}

	// Markdown export escapes bracketed links; SARIF includes driver rules.
	md := call("export_report", map[string]any{"report_format": "markdown"})
	if !strings.Contains(md["content"].(string), `\[injected\]`) {
		t.Fatalf("expected markdown escaping in report: %s", md["content"])
	}
	sarif := call("export_report", map[string]any{"report_format": "sarif"})
	if !strings.Contains(sarif["content"].(string), `"rules"`) || !strings.Contains(sarif["content"].(string), `"CWE-79"`) {
		t.Fatalf("expected SARIF driver rules in export: %s", sarif["content"])
	}

	rawLedger, _ := os.ReadFile(gs2.ledgerFile())
	tampered := strings.Replace(string(rawLedger), `"First [injected](link)"`, `"Tampered"`, 1)
	_ = os.WriteFile(gs2.ledgerFile(), []byte(tampered), 0o600)
	v := call("verify_ledger_chain", map[string]any{})
	if v["valid"].(bool) {
		t.Fatal("expected verify_ledger_chain to detect tampering")
	}

	// Corrupt scopes.json must fail startup rather than silently resetting state.
	_ = os.WriteFile(gs2.scopesFile(), []byte("{not valid json"), 0o600)
	if _, err := NewGuardState(cfgDir, stateDir); err == nil {
		t.Fatal("expected corrupt scopes.json to return an error")
	}
}

func TestDefaultPolicyAutoload(t *testing.T) {
	tmp := t.TempDir()
	cfgDir := filepath.Join(tmp, "config")
	stateDir := filepath.Join(tmp, "state")
	if err := os.MkdirAll(cfgDir, 0o750); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(cfgDir, "lab.yaml"), []byte("program: local-lab\nin_scope:\n  - '127.0.0.1'\n  - 'localhost'\n"), 0o600)
	gs, err := NewGuardState(cfgDir, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := gs.LoadPolicyFile("lab.yaml", "default")
	if err != nil {
		t.Fatalf("LoadPolicyFile failed: %v", err)
	}
	if pol.Program != "local-lab" || len(pol.InScope) != 2 {
		t.Fatalf("unexpected policy loaded: %+v", pol)
	}
}

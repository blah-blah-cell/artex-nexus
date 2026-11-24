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
		"program: task-a\nin_scope:\n  - '*.a.example.test'\n  - '10.1.0.0/16'\nout_of_scope:\n  - 'pay.a.example.test'\n",
	), 0o600)
	_ = os.WriteFile(filepath.Join(cfgDir, "task-b.yaml"), []byte(
		"program: task-b\nin_scope:\n  - 'api.b.example.test'\n",
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

	srv := buildServer(gs)
	call := func(name string, args map[string]any) map[string]any {
		t.Helper()
		req, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1, "method": "tools/call",
			"params": map[string]any{"name": name, "arguments": args},
		})
		raw, _ := srv.HandleRPC(context.Background(), req)
		var resp map[string]any
		_ = json.Unmarshal(raw, &resp)
		txt := resp["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
		var out map[string]any
		_ = json.Unmarshal([]byte(txt), &out)
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

	r1 := call("record_evidence_receipt", map[string]any{
		"scope_id": "task-a", "finding_id": "F-1", "title": "First", "target": "sub.a.example.test",
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

	rawLedger, _ := os.ReadFile(gs2.ledgerFile())
	tampered := strings.Replace(string(rawLedger), `"First"`, `"Tampered"`, 1)
	_ = os.WriteFile(gs2.ledgerFile(), []byte(tampered), 0o600)
	v := call("verify_ledger_chain", map[string]any{})
	if v["valid"].(bool) {
		t.Fatal("expected verify_ledger_chain to detect tampering")
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

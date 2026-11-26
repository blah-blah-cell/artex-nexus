package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditOpenAPISpecWithRefsAndConfinement(t *testing.T) {
	tmp := t.TempDir()
	ws := filepath.Join(tmp, "ws")
	if err := os.MkdirAll(ws, 0o750); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(tmp, "outside.yaml")
	_ = os.WriteFile(outside, []byte("openapi: 3.0.3\npaths: {}\n"), 0o600)

	spec := filepath.Join(ws, "openapi.yaml")
	content := `openapi: 3.0.3
info:
  title: Demo API
  version: 1.0.0
components:
  schemas:
    UserUpdate:
      type: object
      properties:
        display_name:
          type: string
        is_admin:
          type: boolean
        self:
          $ref: '#/components/schemas/UserUpdate'
paths:
  /api/auth/login:
    post:
      operationId: login
  /api/devices/{android}/{valid}:
    get:
      operationId: getDevice
      parameters:
        - name: host_header_hint
          in: query
          schema:
            type: string
  /api/users/{user_id}:
    put:
      operationId: updateUser
      parameters:
        - name: callback_url
          in: query
          schema:
            type: string
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UserUpdate'
`
	if err := os.WriteFile(spec, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := auditOpenAPISpec(ws, "openapi.yaml")
	if err != nil {
		t.Fatalf("auditOpenAPISpec failed: %v", err)
	}
	sum := res["summary"].(map[string]int)
	// /api/auth/login must NOT be flagged as unauthenticated write; {android}/{valid} must NOT match BOLA; host_header_hint must NOT match SSRF.
	if sum["unauthenticated_writes"] != 1 || sum["bola_idor_candidates"] != 1 ||
		sum["ssrf_redirect_params"] != 1 || sum["mass_assignment_risks"] != 1 {
		t.Fatalf("expected exactly 1 per category (skipping login, {android}/{valid}, host_header_hint), got %+v", sum)
	}

	if _, err := auditOpenAPISpec(ws, "../outside.yaml"); err == nil {
		t.Fatal("expected traversal outside workspace root to be blocked")
	}
	if _, err := auditOpenAPISpec(ws, outside); err == nil {
		t.Fatal("expected absolute path outside workspace root to be blocked")
	}
}

func TestScanSourceSinksRedactionAndNoiseReduction(t *testing.T) {
	tmp := t.TempDir()
	ws := filepath.Join(tmp, "ws")
	if err := os.MkdirAll(ws, 0o750); err != nil {
		t.Fatal(err)
	}
	pyFile := filepath.Join(ws, "handler.py")
	pyCode := strings.Join([]string{
		"import subprocess, pickle, yaml",
		"subprocess.run(cmd, shell=True)",
		"pickle.loads(data)",
		"yaml.load(raw, Loader=yaml.SafeLoader)", // safe: must NOT flag
		`cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))`, // parameterized: must NOT flag
		`TOKEN = "ghp_123456789012345678901234567890123456"`,         // must flag AND redact!
	}, "\n")
	_ = os.WriteFile(pyFile, []byte(pyCode), 0o600)
	outside := filepath.Join(tmp, "secret.env")
	_ = os.WriteFile(outside, []byte("TOKEN=ghp_123456789012345678901234567890123456\n"), 0o600)

	res, err := scanSourceSinks(ws, ".", 50)
	if err != nil {
		t.Fatalf("scanSourceSinks failed: %v", err)
	}
	findings := res["findings"].([]map[string]any)
	if len(findings) != 3 {
		t.Fatalf("expected exactly 3 findings (shell, pickle, redacted secret), got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f["rule_id"] == "HARDCODED_SECRET" {
			snip := f["snippet"].(string)
			if strings.Contains(snip, "ghp_123456789012345678901234567890123456") {
				t.Fatalf("raw secret leaked in snippet: %s", snip)
			}
		}
	}
	if _, err := scanSourceSinks(ws, outside, 50); err == nil {
		t.Fatal("expected scan outside workspace root to be blocked")
	}
}

func TestInspectJWTMalformedHeaderDoesNotClaimAlgNone(t *testing.T) {
	// Corrupt base64 header must be INFO decode failure, NEVER CRITICAL alg=none.
	bad := inspectJWTAndHeaders("!!!not-base64!!!.eyJzdWIiOiJhZG1pbiJ9.sig", nil)
	issues := bad["issues"].([]map[string]any)
	for _, iss := range issues {
		if iss["severity"] == "CRITICAL" {
			t.Fatalf("malformed JWT header must not be reported as CRITICAL alg=none: %+v", iss)
		}
	}

	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"../../etc/passwd","jku":"https://evil.test/jwks.json"}`))
	pay := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin"}`))
	token := hdr + "." + pay + "."

	// One hardened cookie alongside an insecure sibling (even named secure_id) must still flag the insecure cookie.
	res := inspectJWTAndHeaders(token, map[string]any{
		"Access-Control-Allow-Origin":      "*",
		"Access-Control-Allow-Credentials": "true",
		"Set-Cookie": []any{
			"csrf=ok; Secure; HttpOnly; SameSite=Strict",
			"secure_id=httponly_val; Path=/",
		},
	})
	if res["issue_count"].(int) < 6 {
		t.Fatalf("expected >=6 JWT + header + sibling-cookie issues, got %v: %+v", res["issue_count"], res["issues"])
	}
}

func TestExtractJSEndpoints(t *testing.T) {
	tmp := t.TempDir()
	js := filepath.Join(tmp, "app.chunk.js")
	bundle := `
	const API = "/api/v1/internal/users/{id}";
	const NEXT = {"buildId":"build-2026-abc","next":"15.1.0"};
	fetch("https://api.example.test/v2/orders", { headers: { "X-Internal-Auth": "1", "Authorization": "Bearer x" } });
	const q = "mutation UpdateRole($id: ID!) { updateRole(id: $id) { ok } }";
	const lib = "lodash@4.17.20";
	`
	if err := os.WriteFile(js, []byte(bundle), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := extractJSEndpoints(tmp, ".", 50)
	if err != nil {
		t.Fatalf("extractJSEndpoints failed: %v", err)
	}
	sum := res["summary"].(map[string]int)
	if sum["api_paths"] < 1 || sum["absolute_urls"] < 1 || sum["graphql_ops"] < 1 || sum["custom_headers"] < 2 || sum["package_versions"] < 1 {
		t.Fatalf("expected all SPA extraction categories populated, got %+v", sum)
	}
}

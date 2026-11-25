package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
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
	if sum["unauthenticated_writes"] != 1 || sum["bola_idor_candidates"] != 1 ||
		sum["ssrf_redirect_params"] != 1 || sum["mass_assignment_risks"] != 1 {
		t.Fatalf("expected all 4 vulnerability surfaces flagged (including $ref), got %+v", sum)
	}

	if _, err := auditOpenAPISpec(ws, "../outside.yaml"); err == nil {
		t.Fatal("expected traversal outside workspace root to be blocked")
	}
	if _, err := auditOpenAPISpec(ws, outside); err == nil {
		t.Fatal("expected absolute path outside workspace root to be blocked")
	}
}

func TestScanSourceSinksAndConfinement(t *testing.T) {
	tmp := t.TempDir()
	ws := filepath.Join(tmp, "ws")
	if err := os.MkdirAll(ws, 0o750); err != nil {
		t.Fatal(err)
	}
	pyFile := filepath.Join(ws, "handler.py")
	_ = os.WriteFile(pyFile, []byte("import subprocess, pickle\nsubprocess.run(cmd, shell=True)\npickle.loads(data)\n"), 0o600)
	outside := filepath.Join(tmp, "secret.env")
	_ = os.WriteFile(outside, []byte("TOKEN=ghp_123456789012345678901234567890123456\n"), 0o600)

	res, err := scanSourceSinks(ws, ".", 50)
	if err != nil {
		t.Fatalf("scanSourceSinks failed: %v", err)
	}
	if res["finding_count"].(int) < 2 {
		t.Fatalf("expected >=2 sink findings, got %v", res["finding_count"])
	}
	if _, err := scanSourceSinks(ws, outside, 50); err == nil {
		t.Fatal("expected scan outside workspace root to be blocked")
	}
}

func TestInspectJWTAndMultipleCookies(t *testing.T) {
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

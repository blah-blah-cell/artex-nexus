package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditOpenAPISpec(t *testing.T) {
	tmp := t.TempDir()
	spec := filepath.Join(tmp, "openapi.yaml")
	content := `openapi: 3.0.3
info:
  title: Demo API
  version: 1.0.0
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
              type: object
              properties:
                display_name:
                  type: string
                is_admin:
                  type: boolean
`
	if err := os.WriteFile(spec, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := auditOpenAPISpec(spec)
	if err != nil {
		t.Fatalf("auditOpenAPISpec failed: %v", err)
	}
	sum := res["summary"].(map[string]int)
	if sum["unauthenticated_writes"] != 1 || sum["bola_idor_candidates"] != 1 ||
		sum["ssrf_redirect_params"] != 1 || sum["mass_assignment_risks"] != 1 {
		t.Fatalf("expected all 4 vulnerability surfaces flagged, got %+v", sum)
	}
}

func TestScanSourceSinks(t *testing.T) {
	tmp := t.TempDir()
	pyFile := filepath.Join(tmp, "handler.py")
	_ = os.WriteFile(pyFile, []byte("import subprocess, pickle\nsubprocess.run(cmd, shell=True)\npickle.loads(data)\n"), 0o600)

	res, err := scanSourceSinks(tmp, 50)
	if err != nil {
		t.Fatalf("scanSourceSinks failed: %v", err)
	}
	if res["finding_count"].(int) < 2 {
		t.Fatalf("expected >=2 sink findings, got %v", res["finding_count"])
	}
}

func TestInspectJWTAndHeaders(t *testing.T) {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"../../etc/passwd","jku":"https://evil.test/jwks.json"}`))
	pay := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin"}`))
	token := hdr + "." + pay + "."

	res := inspectJWTAndHeaders(token, map[string]any{
		"Access-Control-Allow-Origin":      "*",
		"Access-Control-Allow-Credentials": "true",
		"Set-Cookie":                       "session=abc123; Path=/",
	})
	if res["issue_count"].(int) < 5 {
		t.Fatalf("expected >=5 JWT + header issues, got %v: %+v", res["issue_count"], res["issues"])
	}
}

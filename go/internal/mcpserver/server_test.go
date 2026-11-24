package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStreamableHTTPAndStdioWireProtocol(t *testing.T) {
	srv := New("test-mcp", "0.5.0")
	srv.Register(Tool{
		Name:        "echo",
		Description: "old description",
		InputSchema: map[string]any{"type": "object"},
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			return map[string]any{"echoed": args["msg"]}, nil
		},
	})
	// Re-registering must update the slice entry in place.
	srv.Register(Tool{
		Name:        "echo",
		Description: "Echo input",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"msg": map[string]any{"type": "string"}}},
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			return map[string]any{"echoed": args["msg"]}, nil
		},
	})
	srv.Register(Tool{
		Name:        "boom",
		Description: "Panics on call",
		InputSchema: map[string]any{"type": "object"},
		Handler: func(_ context.Context, _ map[string]any) (any, error) {
			panic("unexpected crash")
		},
	})

	t.Setenv("MCP_AUTH_TOKEN", "secret-tok")
	ts := httptest.NewServer(srv.HTTPHandler())
	defer ts.Close()

	doPost := func(body, origin, auth string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("http post: %v", err)
		}
		return resp
	}

	// Non-loopback origin must be rejected.
	if r := doPost(`{"jsonrpc":"2.0","id":1,"method":"ping"}`, "https://evil.example", "Bearer secret-tok"); r.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for foreign origin, got %d", r.StatusCode)
	}
	// Missing "Bearer " prefix must be rejected.
	if r := doPost(`{"jsonrpc":"2.0","id":1,"method":"ping"}`, "", "secret-tok"); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 when Bearer prefix missing, got %d", r.StatusCode)
	}

	r1 := doPost(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01"}}`, "http://127.0.0.1:8787", "Bearer secret-tok")
	defer r1.Body.Close()
	if r1.StatusCode != 200 {
		t.Fatalf("expected 200 on initialize, got %d", r1.StatusCode)
	}
	var initOut map[string]any
	_ = json.NewDecoder(r1.Body).Decode(&initOut)
	if initOut["result"].(map[string]any)["protocolVersion"] != "2025-11-25" {
		t.Fatalf("expected fallback to newest protocol, got %v", initOut)
	}

	r2 := doPost(`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`, "", "Bearer secret-tok")
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 on notification, got %d", r2.StatusCode)
	}

	// Unknown tool name with quotes must still emit valid JSON.
	rUnknown := doPost(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bad\"tool"}}`, "", "Bearer secret-tok")
	defer rUnknown.Body.Close()
	var unkOut map[string]any
	_ = json.NewDecoder(rUnknown.Body).Decode(&unkOut)
	unkTxt := unkOut["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	var parsedErr map[string]string
	if err := json.Unmarshal([]byte(unkTxt), &parsedErr); err != nil {
		t.Fatalf("unknown tool text was not valid JSON: %v (%s)", err, unkTxt)
	}

	// Panicking tool must return an error result instead of crashing.
	rBoom := doPost(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"boom"}}`, "", "Bearer secret-tok")
	defer rBoom.Body.Close()
	var boomOut map[string]any
	_ = json.NewDecoder(rBoom.Body).Decode(&boomOut)
	if !boomOut["result"].(map[string]any)["isError"].(bool) {
		t.Fatalf("expected isError=true for panicking tool")
	}

	// Stdio transport test + updated description from re-register.
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}` + "\n" +
			`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}` + "\n",
	)
	var out bytes.Buffer
	if err := srv.ServeStdio(context.Background(), in, &out); err != nil {
		t.Fatalf("stdio: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[1], "Echo input") || strings.Contains(lines[1], "old description") {
		t.Fatalf("unexpected stdio tools/list output: %s", out.String())
	}
}

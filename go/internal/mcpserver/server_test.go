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
	srv := New("test-mcp", "0.2.0")
	srv.Register(Tool{
		Name:        "echo",
		Description: "Echo input",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"msg": map[string]any{"type": "string"}}},
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			return map[string]any{"echoed": args["msg"]}, nil
		},
	})

	// 1. Streamable HTTP handshake (exact ARTEX mcphttp sequence)
	ts := httptest.NewServer(srv.HTTPHandler())
	defer ts.Close()

	post := func(body string) *http.Response {
		t.Helper()
		resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("http post: %v", err)
		}
		return resp
	}

	r1 := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"artex","version":"0.2"}}}`)
	defer r1.Body.Close()
	if r1.StatusCode != 200 {
		t.Fatalf("expected 200 on initialize, got %d", r1.StatusCode)
	}
	var initOut map[string]any
	_ = json.NewDecoder(r1.Body).Decode(&initOut)
	res := initOut["result"].(map[string]any)
	if res["protocolVersion"] != "2025-11-25" {
		t.Fatalf("unexpected protocolVersion: %v", res["protocolVersion"])
	}

	r2 := post(`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`)
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 on notification, got %d", r2.StatusCode)
	}

	r3 := post(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hello-artex"}}}`)
	defer r3.Body.Close()
	var callOut map[string]any
	_ = json.NewDecoder(r3.Body).Decode(&callOut)
	content := callOut["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(content, "hello-artex") {
		t.Fatalf("unexpected tool output: %s", content)
	}

	// 2. Stdio transport test
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
	if len(lines) != 2 {
		t.Fatalf("expected 2 responses (notification skipped), got %d: %s", len(lines), out.String())
	}
}

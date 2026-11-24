package mcpserver

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const maxBodyBytes = 8 << 20

// Newest first; unknown client versions fall back to the newest we support.
var supportedProtocols = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

func negotiateProtocol(requested string) string {
	for _, v := range supportedProtocols {
		if v == requested {
			return v
		}
	}
	return supportedProtocols[0]
}

// EnvOr returns the environment variable k if non-empty, otherwise fallback.
func EnvOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

type Tool struct {
	Name        string                                                      `json:"name"`
	Description string                                                      `json:"description"`
	InputSchema map[string]any                                              `json:"inputSchema"`
	Handler     func(ctx context.Context, args map[string]any) (any, error) `json:"-"`
}

type Server struct {
	Name    string
	Version string
	mu      sync.RWMutex
	tools   []Tool
	byName  map[string]Tool
}

func New(name, version string) *Server {
	return &Server{
		Name:    name,
		Version: version,
		byName:  make(map[string]Tool),
	}
}

func (s *Server) Register(t Tool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byName[t.Name]; exists {
		for i := range s.tools {
			if s.tools[i].Name == t.Name {
				s.tools[i] = t
				break
			}
		}
	} else {
		s.tools = append(s.tools, t)
	}
	s.byName[t.Name] = t
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// callTool runs a handler and catches panics so one buggy tool can't crash the process.
func callTool(ctx context.Context, t Tool, args map[string]any) (out any, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
			err = fmt.Errorf("tool %q panicked: %v", t.Name, r)
		}
	}()
	return t.Handler(ctx, args)
}

// HandleRPC processes one JSON-RPC 2.0 message. Returns (nil, true) for notifications.
func (s *Server) HandleRPC(ctx context.Context, raw []byte) ([]byte, bool) {
	var req rpcRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		b, _ := json.Marshal(rpcResponse{
			JSONRPC: "2.0",
			ID:      json.RawMessage("null"),
			Error:   &rpcError{Code: -32700, Message: err.Error()},
		})
		return b, false
	}

	if req.Method == "notifications/initialized" || (len(req.ID) == 0 && strings.HasPrefix(req.Method, "notifications/")) {
		return nil, true
	}

	id := req.ID
	if len(id) == 0 {
		id = json.RawMessage("null")
	}

	var resp rpcResponse
	resp.JSONRPC = "2.0"
	resp.ID = id

	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		resp.Result = map[string]any{
			"protocolVersion": negotiateProtocol(p.ProtocolVersion),
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": s.Name, "version": s.Version},
		}

	case "ping":
		resp.Result = map[string]any{}

	case "tools/list":
		s.mu.RLock()
		list := make([]Tool, len(s.tools))
		copy(list, s.tools)
		s.mu.RUnlock()
		resp.Result = map[string]any{"tools": list}

	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			resp.Error = &rpcError{Code: -32602, Message: err.Error()}
			break
		}
		s.mu.RLock()
		tool, ok := s.byName[p.Name]
		s.mu.RUnlock()
		if !ok {
			errJSON, _ := json.Marshal(map[string]string{"error": "unknown tool: " + p.Name})
			resp.Result = map[string]any{
				"content": []map[string]string{{"type": "text", "text": string(errJSON)}},
				"isError": true,
			}
			break
		}
		if p.Arguments == nil {
			p.Arguments = map[string]any{}
		}
		out, err := callTool(ctx, tool, p.Arguments)
		if err != nil {
			errJSON, _ := json.Marshal(map[string]string{"error": err.Error()})
			resp.Result = map[string]any{
				"content": []map[string]string{{"type": "text", "text": string(errJSON)}},
				"isError": true,
			}
		} else {
			payload, _ := json.MarshalIndent(out, "", "  ")
			resp.Result = map[string]any{
				"content": []map[string]string{{"type": "text", "text": string(payload)}},
				"isError": false,
			}
		}

	default:
		resp.Error = &rpcError{Code: -32601, Message: "Method not found: " + req.Method}
	}

	b, _ := json.Marshal(resp)
	return b, false
}

func (s *Server) ServeStdio(ctx context.Context, r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxBodyBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		resp, isNotif := s.HandleRPC(ctx, []byte(line))
		if isNotif {
			continue
		}
		if _, err := fmt.Fprintf(w, "%s\n", resp); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// originAllowed blocks browser DNS-rebinding requests while letting non-browser
// MCP clients (no Origin header) and loopback browser origins through.
func originAllowed(origin string) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

func originsAllowed(origins []string) bool {
	if len(origins) == 0 {
		return true
	}
	if len(origins) > 1 {
		return false
	}
	return originAllowed(origins[0])
}

func tokenOK(r *http.Request, token string) bool {
	if token == "" {
		return true
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

func (s *Server) HTTPHandler() http.Handler {
	token := os.Getenv("MCP_AUTH_TOKEN")
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if !originsAllowed(r.Header.Values("Origin")) {
			http.Error(w, "Forbidden origin", http.StatusForbidden)
			return
		}
		if !tokenOK(r, token) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
		if err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		if len(body) > maxBodyBytes {
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		resp, isNotif := s.HandleRPC(r.Context(), body)
		if isNotif {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
	}
	mux.HandleFunc("/mcp", handler)
	mux.HandleFunc("/", handler)
	return mux
}

func (s *Server) Run(transport, host string, port int) error {
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "stdio", "":
		return s.ServeStdio(context.Background(), os.Stdin, os.Stdout)
	case "http", "streamable-http":
		addr := fmt.Sprintf("%s:%d", host, port)
		fmt.Fprintf(os.Stderr, "[+] %s listening on http://%s/mcp\n", s.Name, addr)
		srv := &http.Server{
			Addr:              addr,
			Handler:           s.HTTPHandler(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      120 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}
		return srv.ListenAndServe()
	default:
		return fmt.Errorf("unsupported transport %q (use stdio or http)", transport)
	}
}

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/blah-blah-cell/artex-nexus/internal/mcpserver"
	"gopkg.in/yaml.v3"
)

const (
	maxScanFiles    = 2000
	maxFileSizeByte = 1 << 20
)

type sinkRule struct {
	ID       string
	CWE      string
	Severity string
	Title    string
	Exts     map[string]bool
	Pattern  *regexp.Regexp
}

var sinkRules = []sinkRule{
	{
		ID: "CMD_EXEC_SHELL", CWE: "CWE-78", Severity: "HIGH",
		Title:   "OS command execution sink (verify shell metacharacter & argv isolation)",
		Exts:    extSet(".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".go"),
		Pattern: regexp.MustCompile(`(?i)(shell\s*=\s*True|child_process\.(exec|execSync)\s*\(|os\.system\s*\(|subprocess\.(Popen|call|run)\s*\([^)]*shell|exec\.Command\s*\(\s*"(sh|bash|cmd)"|\b(shell_exec|passthru|proc_open)\s*\()`),
	},
	{
		ID: "DYNAMIC_SQL_CONCAT", CWE: "CWE-89", Severity: "HIGH",
		Title:   "Dynamic SQL query string formatting/concatenation (verify parameterization)",
		Exts:    extSet(".py", ".js", ".ts", ".go", ".java", ".php", ".rb", ".cs"),
		Pattern: regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.{0,80}(\+\s*[a-zA-Z_]|%s|\$\{|\.format\s*\(|f["'])`),
	},
	{
		ID: "UNSAFE_DESERIALIZE", CWE: "CWE-502", Severity: "CRITICAL",
		Title:   "Unsafe deserialization sink (pickle/yaml.load/ObjectInputStream/unserialize)",
		Exts:    extSet(".py", ".java", ".php", ".rb", ".js", ".ts"),
		Pattern: regexp.MustCompile(`(pickle\.(loads|load)\s*\(|yaml\.load\s*\([^)]*\)|ObjectInputStream|readObject\s*\(|\bunserialize\s*\(|Marshal\.load\s*\(|node-serialize)`),
	},
	{
		ID: "DOM_XSS_SINK", CWE: "CWE-79", Severity: "MEDIUM",
		Title:   "DOM / template HTML injection sink (verify sanitization/escaping)",
		Exts:    extSet(".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte", ".html"),
		Pattern: regexp.MustCompile(`(dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|v-html\s*=|\[innerHTML\])`),
	},
	{
		ID: "PATH_TRAVERSAL_JOIN", CWE: "CWE-22", Severity: "MEDIUM",
		Title:   "File read/open on path join (verify canonical realpath prefix check)",
		Exts:    extSet(".go", ".py", ".js", ".ts", ".java", ".php", ".rs"),
		Pattern: regexp.MustCompile(`(os\.ReadFile\s*\(\s*filepath\.Join|fs\.readFile(Sync)?\s*\(\s*path\.join|send_file\s*\(|FileInputStream\s*\([^)]*\+)`),
	},
	{
		ID: "HARDCODED_SECRET", CWE: "CWE-798", Severity: "HIGH",
		Title:   "Potential hardcoded private key or cloud/API credential",
		Exts:    extSet(".go", ".py", ".js", ".ts", ".java", ".php", ".rs", ".yml", ".yaml", ".json", ".env", ".toml"),
		Pattern: regexp.MustCompile(`(-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36}|gho_[0-9A-Za-z]{36}|sk-[a-zA-Z0-9]{20,})`),
	},
}

var (
	bolaParamRe       = regexp.MustCompile(`(?i)\{(id|[a-z_]*(id|uuid|slug|account|user|org|tenant|order|invoice|project|token))\}`)
	ssrfParamNameRe   = regexp.MustCompile(`(?i)(url|uri|callback|webhook|redirect|next|dest|target|endpoint|host|proxy|fetch|import)`)
	massAssignFieldRe = regexp.MustCompile(`(?i)^(role|roles|is_admin|isadmin|admin|permissions|scopes|verified|is_verified|balance|credits|plan|tier|owner_id|tenant_id|org_id)$`)
	stateChangingVerb = map[string]bool{"post": true, "put": true, "patch": true, "delete": true}
	skipDirs          = map[string]bool{".git": true, "node_modules": true, "target": true, "vendor": true, ".venv": true, "dist": true, "build": true}
)

func extSet(exts ...string) map[string]bool {
	m := make(map[string]bool, len(exts))
	for _, e := range exts {
		m[e] = true
	}
	return m
}

func auditOpenAPISpec(specPath string) (map[string]any, error) {
	raw, err := os.ReadFile(specPath)
	if err != nil {
		return nil, fmt.Errorf("reading OpenAPI spec: %w", err)
	}
	var doc map[string]any
	if strings.HasSuffix(strings.ToLower(specPath), ".json") {
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("parsing JSON OpenAPI spec: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("parsing YAML OpenAPI spec: %w", err)
		}
	}

	pathsObj, ok := doc["paths"].(map[string]any)
	if !ok {
		return nil, errors.New("document does not contain an OpenAPI/Swagger 'paths' object")
	}

	globalSec, hasGlobalSec := doc["security"].([]any)
	hasGlobalAuth := hasGlobalSec && len(globalSec) > 0

	var unauthWrites []map[string]any
	var bolaCandidates []map[string]any
	var ssrfParams []map[string]any
	var massAssign []map[string]any
	endpointCount := 0

	for route, rawItem := range pathsObj {
		item, ok := rawItem.(map[string]any)
		if !ok {
			continue
		}
		for method, rawOp := range item {
			mLower := strings.ToLower(method)
			if !matchesHTTPMethod(mLower) {
				continue
			}
			op, ok := rawOp.(map[string]any)
			if !ok {
				continue
			}
			endpointCount++
			opID, _ := op["operationId"].(string)

			// 1. Check auth on state-changing routes (CWE-306)
			opSecRaw, hasOpSec := op["security"]
			isUnauth := false
			if hasOpSec {
				if secSlice, ok := opSecRaw.([]any); ok && len(secSlice) == 0 {
					isUnauth = true
				}
			} else if !hasGlobalAuth {
				isUnauth = true
			}
			if isUnauth && stateChangingVerb[mLower] {
				unauthWrites = append(unauthWrites, map[string]any{
					"method": strings.ToUpper(mLower), "path": route, "operation_id": opID,
					"cwe": "CWE-306", "risk": "State-changing operation with no declared authentication requirement",
				})
			}

			// 2. Check BOLA/IDOR object ID path parameters (CWE-639)
			if matches := bolaParamRe.FindAllString(route, -1); len(matches) > 0 {
				bolaCandidates = append(bolaCandidates, map[string]any{
					"method": strings.ToUpper(mLower), "path": route, "operation_id": opID,
					"object_params": matches, "cwe": "CWE-639",
				})
			}

			// 3. Check SSRF / Open-Redirect parameters (CWE-918 / CWE-601) and Swagger 2.0 body params
			var fields []string
			if params, ok := op["parameters"].([]any); ok {
				for _, rp := range params {
					pm, ok := rp.(map[string]any)
					if !ok {
						continue
					}
					pname, _ := pm["name"].(string)
					pin, _ := pm["in"].(string)
					if pin == "body" {
						if schema, ok := pm["schema"]; ok {
							collectSensitiveSchemaFields(schema, &fields)
						}
					} else if ssrfParamNameRe.MatchString(pname) {
						ssrfParams = append(ssrfParams, map[string]any{
							"method": strings.ToUpper(mLower), "path": route, "param": pname, "in": pin,
							"cwe": "CWE-918",
						})
					}
				}
			}

			// 4. Check Mass-Assignment sensitive properties in requestBody (CWE-915)
			if rb, ok := op["requestBody"].(map[string]any); ok {
				collectSensitiveSchemaFields(rb, &fields)
			}
			if len(fields) > 0 {
				massAssign = append(massAssign, map[string]any{
					"method": strings.ToUpper(mLower), "path": route, "operation_id": opID,
					"sensitive_fields": fields, "cwe": "CWE-915",
				})
			}
		}
	}

	return map[string]any{
		"spec_path":               specPath,
		"endpoints_audited":       endpointCount,
		"global_security_defined": hasGlobalAuth,
		"summary": map[string]int{
			"unauthenticated_writes": len(unauthWrites),
			"bola_idor_candidates":   len(bolaCandidates),
			"ssrf_redirect_params":   len(ssrfParams),
			"mass_assignment_risks":  len(massAssign),
		},
		"unauthenticated_writes": unauthWrites,
		"bola_idor_candidates":   bolaCandidates,
		"ssrf_redirect_params":   ssrfParams,
		"mass_assignment_risks":  massAssign,
	}, nil
}

func matchesHTTPMethod(m string) bool {
	switch m {
	case "get", "post", "put", "patch", "delete", "head", "options":
		return true
	default:
		return false
	}
}

func collectSensitiveSchemaFields(node any, out *[]string) {
	m, ok := node.(map[string]any)
	if !ok {
		return
	}
	if props, ok := m["properties"].(map[string]any); ok {
		for k, v := range props {
			if vm, ok := v.(map[string]any); ok {
				if ro, _ := vm["readOnly"].(bool); ro {
					continue
				}
			}
			if massAssignFieldRe.MatchString(k) {
				*out = append(*out, k)
			}
			collectSensitiveSchemaFields(v, out)
		}
	}
	for k, v := range m {
		if k == "properties" {
			continue
		}
		switch child := v.(type) {
		case map[string]any:
			collectSensitiveSchemaFields(child, out)
		case []any:
			for _, elem := range child {
				collectSensitiveSchemaFields(elem, out)
			}
		}
	}
}

func scanSourceSinks(targetPath string, maxFindings int) (map[string]any, error) {
	if maxFindings <= 0 || maxFindings > 500 {
		maxFindings = 100
	}
	info, err := os.Stat(targetPath)
	if err != nil {
		return nil, err
	}

	var findings []map[string]any
	filesScanned := 0

	scanFile := func(p string) {
		if filesScanned >= maxScanFiles || len(findings) >= maxFindings {
			return
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext == "" && strings.EqualFold(filepath.Base(p), ".env") {
			ext = ".env"
		}
		var active []sinkRule
		for _, r := range sinkRules {
			if r.Exts[ext] {
				active = append(active, r)
			}
		}
		if len(active) == 0 {
			return
		}
		fi, err := os.Stat(p)
		if err != nil || fi.Size() > maxFileSizeByte {
			return
		}
		f, err := os.Open(p)
		if err != nil {
			return
		}
		defer f.Close()
		filesScanned++

		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 512*1024)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			line := sc.Text()
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
				continue
			}
			for _, rule := range active {
				if rule.Pattern.MatchString(line) {
					snip := trimmed
					if len(snip) > 180 {
						snip = snip[:180]
					}
					findings = append(findings, map[string]any{
						"rule_id":             rule.ID,
						"cwe":                 rule.CWE,
						"severity":            rule.Severity,
						"title":               rule.Title,
						"file":                p,
						"line":                lineNo,
						"snippet":             snip,
						"suggested_cve_query": fmt.Sprintf("cve-intel-mcp:list_cwe_writeups(cwe_id=%q)", rule.CWE),
					})
					if len(findings) >= maxFindings {
						return
					}
				}
			}
		}
	}

	if !info.IsDir() {
		scanFile(targetPath)
	} else {
		_ = filepath.WalkDir(targetPath, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.IsDir() {
				if skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if filesScanned >= maxScanFiles || len(findings) >= maxFindings {
				return filepath.SkipAll
			}
			scanFile(p)
			return nil
		})
	}

	return map[string]any{
		"target_path":   targetPath,
		"files_scanned": filesScanned,
		"finding_count": len(findings),
		"truncated":     len(findings) >= maxFindings,
		"findings":      findings,
	}, nil
}

func inspectJWTAndHeaders(jwtStr string, headers map[string]any) map[string]any {
	var issues []map[string]any
	var jwtDecoded map[string]any

	if strings.TrimSpace(jwtStr) != "" {
		parts := strings.Split(strings.TrimSpace(jwtStr), ".")
		if len(parts) != 3 {
			issues = append(issues, map[string]any{"category": "jwt", "severity": "INFO", "cwe": "CWE-347", "detail": "Malformed JWT structure (expected 3 dot-separated segments)"})
		} else {
			hdrBytes, errH := base64.RawURLEncoding.DecodeString(parts[0])
			payBytes, errP := base64.RawURLEncoding.DecodeString(parts[1])
			var hdr, pay map[string]any
			if errH == nil {
				_ = json.Unmarshal(hdrBytes, &hdr)
			}
			if errP == nil {
				_ = json.Unmarshal(payBytes, &pay)
			}
			jwtDecoded = map[string]any{"header": hdr, "payload": pay, "signature_empty": parts[2] == ""}

			alg := strings.ToLower(fmt.Sprintf("%v", hdr["alg"]))
			if alg == "none" || alg == "" || alg == "<nil>" || parts[2] == "" {
				issues = append(issues, map[string]any{"category": "jwt", "severity": "CRITICAL", "cwe": "CWE-347", "detail": "Unsigned JWT or alg=none detected"})
			}
			for _, riskHdr := range []string{"jku", "x5u", "jwk"} {
				if _, ok := hdr[riskHdr]; ok {
					issues = append(issues, map[string]any{"category": "jwt", "severity": "HIGH", "cwe": "CWE-347", "detail": fmt.Sprintf("JWT header contains %q — test for SSRF/untrusted key injection", riskHdr)})
				}
			}
			if kid, ok := hdr["kid"].(string); ok && (strings.Contains(kid, "..") || strings.Contains(kid, "'") || strings.Contains(kid, "/")) {
				issues = append(issues, map[string]any{"category": "jwt", "severity": "HIGH", "cwe": "CWE-22", "detail": "JWT kid header contains traversal/SQL metacharacters"})
			}
			if pay != nil {
				if _, hasExp := pay["exp"]; !hasExp {
					issues = append(issues, map[string]any{"category": "jwt", "severity": "MEDIUM", "cwe": "CWE-613", "detail": "JWT payload missing exp (expiration) claim"})
				}
			}
		}
	}

	if len(headers) > 0 {
		norm := make(map[string]string, len(headers))
		for k, v := range headers {
			norm[strings.ToLower(strings.TrimSpace(k))] = fmt.Sprintf("%v", v)
		}
		acao := strings.TrimSpace(norm["access-control-allow-origin"])
		acac := strings.ToLower(strings.TrimSpace(norm["access-control-allow-credentials"]))
		if acao == "*" && acac == "true" {
			issues = append(issues, map[string]any{"category": "cors", "severity": "HIGH", "cwe": "CWE-942", "detail": "CORS Access-Control-Allow-Origin: * paired with Allow-Credentials: true"})
		} else if acao == "null" && acac == "true" {
			issues = append(issues, map[string]any{"category": "cors", "severity": "HIGH", "cwe": "CWE-942", "detail": "CORS allows 'null' origin with credentials (sandboxed iframe bypass)"})
		}
		if csp := norm["content-security-policy"]; csp == "" {
			issues = append(issues, map[string]any{"category": "headers", "severity": "LOW", "cwe": "CWE-693", "detail": "Missing Content-Security-Policy header"})
		} else if strings.Contains(csp, "unsafe-inline") && strings.Contains(csp, "unsafe-eval") {
			issues = append(issues, map[string]any{"category": "headers", "severity": "MEDIUM", "cwe": "CWE-693", "detail": "Weak CSP containing both unsafe-inline and unsafe-eval"})
		}
		if sc := strings.ToLower(norm["set-cookie"]); sc != "" {
			if !strings.Contains(sc, "httponly") {
				issues = append(issues, map[string]any{"category": "cookie", "severity": "MEDIUM", "cwe": "CWE-1004", "detail": "Set-Cookie missing HttpOnly flag"})
			}
			if !strings.Contains(sc, "secure") {
				issues = append(issues, map[string]any{"category": "cookie", "severity": "MEDIUM", "cwe": "CWE-614", "detail": "Set-Cookie missing Secure flag"})
			}
		}
	}

	return map[string]any{
		"issue_count": len(issues),
		"issues":      issues,
		"jwt_decoded": jwtDecoded,
	}
}

func buildServer() *mcpserver.Server {
	srv := mcpserver.New("attack-surface-mcp", "0.4.0")

	srv.Register(mcpserver.Tool{
		Name:        "audit_openapi_spec",
		Description: "Audit an OpenAPI 3.x / Swagger 2.0 JSON or YAML spec for unauthenticated writes (CWE-306), BOLA/IDOR object IDs (CWE-639), SSRF params (CWE-918), and mass-assignment fields (CWE-915).",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"spec_path": map[string]any{"type": "string", "description": "Path to local OpenAPI/Swagger .yaml or .json file"},
			},
			"required": []string{"spec_path"},
		},
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			p, _ := args["spec_path"].(string)
			return auditOpenAPISpec(strings.TrimSpace(p))
		},
	})

	srv.Register(mcpserver.Tool{
		Name:        "scan_source_sinks",
		Description: "Fast offline static sink & secret scan across Go/Rust/Python/JS/TS/Java/PHP mapping hits to CWEs and cve-intel-mcp variant queries.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target_path":  map[string]any{"type": "string"},
				"max_findings": map[string]any{"type": "integer", "default": 100},
			},
			"required": []string{"target_path"},
		},
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			p, _ := args["target_path"].(string)
			maxF := 100
			if f, ok := args["max_findings"].(float64); ok {
				maxF = int(f)
			}
			return scanSourceSinks(strings.TrimSpace(p), maxF)
		},
	})

	srv.Register(mcpserver.Tool{
		Name:        "inspect_jwt_and_headers",
		Description: "Offline inspection of JWT header/claims (alg=none, jku/x5u/kid risks, missing exp) and HTTP security headers (CORS, CSP, Set-Cookie).",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"jwt":     map[string]any{"type": "string", "description": "Optional JWT token to decode and inspect offline"},
				"headers": map[string]any{"type": "object", "description": "Optional map of HTTP response headers"},
			},
		},
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			jwtStr, _ := args["jwt"].(string)
			hdrs, _ := args["headers"].(map[string]any)
			return inspectJWTAndHeaders(jwtStr, hdrs), nil
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
	port := flag.Int("port", 8904, "HTTP bind port")
	flag.Parse()

	srv := buildServer()
	if err := srv.Run(*transport, *host, *port); err != nil {
		fmt.Fprintf(os.Stderr, "attack-surface-mcp error: %v\n", err)
		os.Exit(1)
	}
}

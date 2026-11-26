package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/blah-blah-cell/artex-nexus/internal/mcpserver"
	"github.com/blah-blah-cell/artex-nexus/internal/pathguard"
	"gopkg.in/yaml.v3"
)

const (
	maxScanFiles    = 2000
	maxFileSizeByte = 1 << 20
	maxSpecSizeByte = 16 << 20
	maxLineBytes    = 1 << 20
)

type sinkRule struct {
	ID         string
	CWE        string
	Severity   string
	Confidence string
	Title      string
	Exts       map[string]bool
	Pattern    *regexp.Regexp
	Exclude    *regexp.Regexp
}

var sinkRules = []sinkRule{
	{
		ID: "CMD_EXEC_SHELL", CWE: "CWE-78", Severity: "HIGH", Confidence: "high",
		Title:   "OS command execution sink (check shell metacharacter and argv isolation)",
		Exts:    extSet(".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".go"),
		Pattern: regexp.MustCompile(`(?i)(shell\s*=\s*True|child_process\.(exec|execSync)\s*\(|os\.system\s*\(|subprocess\.(Popen|call|run)\s*\([^)]*shell\s*=\s*True|exec\.Command\s*\(\s*"(sh|bash|cmd)"|\b(shell_exec|passthru|proc_open)\s*\()`),
	},
	{
		ID: "DYNAMIC_SQL_CONCAT", CWE: "CWE-89", Severity: "HIGH", Confidence: "medium",
		Title:   "Dynamic SQL query formatting or concatenation (check parameterization)",
		Exts:    extSet(".py", ".js", ".ts", ".go", ".java", ".php", ".rb", ".cs"),
		// Avoid flagging parameterized %s placeholders (psycopg2/MySQLdb); match concatenation, template interpolation, .format, f-strings, or % formatting.
		Pattern: regexp.MustCompile(`(?i)(f["']\s*(SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{|(SELECT|INSERT|UPDATE|DELETE)\s+.{0,80}(\+\s*[a-zA-Z_][a-zA-Z0-9_]*|\$\{|\.format\s*\(|["']\s*%\s*[a-zA-Z_(]))`),
	},
	{
		ID: "UNSAFE_DESERIALIZE", CWE: "CWE-502", Severity: "CRITICAL", Confidence: "high",
		Title:   "Unsafe deserialization sink (pickle/yaml.load/ObjectInputStream/unserialize)",
		Exts:    extSet(".py", ".java", ".php", ".rb", ".js", ".ts"),
		Pattern: regexp.MustCompile(`(pickle\.(loads|load)\s*\(|yaml\.load\s*\([^)]*\)|ObjectInputStream|readObject\s*\(|\bunserialize\s*\(|Marshal\.load\s*\(|node-serialize)`),
		Exclude: regexp.MustCompile(`yaml\.load\s*\([^)]*Loader\s*=\s*(yaml\.)?(C?SafeLoader|C?BaseLoader)`),
	},
	{
		ID: "DOM_XSS_SINK", CWE: "CWE-79", Severity: "MEDIUM", Confidence: "medium",
		Title:   "DOM or template HTML injection sink (check sanitization)",
		Exts:    extSet(".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte", ".html"),
		Pattern: regexp.MustCompile(`(dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|v-html\s*=|\[innerHTML\])`),
	},
	{
		ID: "PATH_TRAVERSAL_JOIN", CWE: "CWE-22", Severity: "LOW", Confidence: "low",
		Title:   "File read on dynamic path join (review canonical realpath confinement)",
		Exts:    extSet(".go", ".py", ".js", ".ts", ".java", ".php", ".rs"),
		Pattern: regexp.MustCompile(`(os\.ReadFile\s*\(\s*filepath\.Join\s*\([^)]*,\s*[a-zA-Z_][a-zA-Z0-9_.]*|fs\.readFile(Sync)?\s*\(\s*path\.join\s*\([^)]*,\s*[a-zA-Z_][a-zA-Z0-9_.]*|send_file\s*\(\s*[a-zA-Z_][a-zA-Z0-9_.]*|FileInputStream\s*\([^)]*\+\s*[a-zA-Z_])`),
	},
	{
		ID: "HARDCODED_SECRET", CWE: "CWE-798", Severity: "HIGH", Confidence: "high",
		Title:   "Potential hardcoded private key or cloud/API credential",
		Exts:    extSet(".go", ".py", ".js", ".ts", ".java", ".php", ".rs", ".yml", ".yaml", ".json", ".env", ".toml"),
		Pattern: regexp.MustCompile(`(-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36}|gho_[0-9A-Za-z]{36}|sk-[a-zA-Z0-9]{20,})`),
	},
}

var (
	// Match genuine object identifiers ({id}, {user_id}, {userId}, {account}, etc.), never {android} or {valid}.
	bolaParamRe = regexp.MustCompile(`\{(id|ID|uuid|UUID|slug|account|user|org|tenant|order|invoice|project|[a-zA-Z0-9]+_(id|ID|uuid|UUID|slug|key)|[a-z][a-z0-9]*(Id|Uuid|Slug))\}`)
	// Match URL/redirect/callback parameter names specifically rather than generic 'host', 'next', or 'target'.
	ssrfParamNameRe   = regexp.MustCompile(`(?i)^(url|uri|callback|callback_url|callback_uri|webhook|webhook_url|redirect|redirect_url|redirect_uri|return_url|next_url|dest_url|target_url|endpoint_url|proxy_url|fetch_url|import_url|feed_url|image_url|avatar_url|file_url)$`)
	massAssignFieldRe = regexp.MustCompile(`(?i)^(role|roles|is_admin|isadmin|admin|permissions|scopes|verified|is_verified|balance|credits|plan|tier|owner_id|tenant_id|org_id)$`)
	publicAuthPathRe  = regexp.MustCompile(`(?i)/(login|signin|sign-in|register|signup|sign-up|logout|oauth/token|auth/token|forgot-password|reset-password|health|healthz|ready|metrics)(/|$)`)
	stateChangingVerb = map[string]bool{"post": true, "put": true, "patch": true, "delete": true}
	skipDirs          = map[string]bool{".git": true, "node_modules": true, "target": true, "vendor": true, ".venv": true, "dist": true, "build": true}

	jsAPIPathRe    = regexp.MustCompile(`["'` + "`" + `](/(?:api|v[0-9]+|graphql|rest|auth|oauth|oauth2|oidc|admin|internal|bff|webhook|webhooks|_next/data)[a-zA-Z0-9_\-./{}:?$&=]{1,140})["'` + "`" + `]`)
	jsAbsURLRe     = regexp.MustCompile(`https?://[a-zA-Z0-9._\-]+(?::[0-9]+)?/[a-zA-Z0-9_\-./{}:?$&=%]{0,140}`)
	jsGraphQLOpRe  = regexp.MustCompile(`(?i)\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]{2,64})\s*[\(\{]`)
	jsHeaderRe     = regexp.MustCompile(`["'` + "`" + `](X-[A-Za-z0-9\-]{3,40}|Authorization|X-Api-Key|Api-Key|X-CSRF-Token|X-Requested-With)["'` + "`" + `]`)
	jsNextBuildRe  = regexp.MustCompile(`"buildId"\s*:\s*"([^"]{4,80})"`)
	jsPkgVersionRe = regexp.MustCompile(`(?i)\b(next|react|react-dom|axios|lodash|jquery|express|angular|vue|svelte|graphql|apollo-client|jsonwebtoken|socket\.io)[/@":\s]+v?([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.]+)?)`)
	jsSecretRe     = regexp.MustCompile(`(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|ghp_[0-9A-Za-z]{36}|gho_[0-9A-Za-z]{36}|sk-[a-zA-Z0-9]{20,}|sk_live_[0-9A-Za-z]{16,}|eyJ[A-Za-z0-9_\-]{12,}\.eyJ[A-Za-z0-9_\-]{12,}\.[A-Za-z0-9_\-]{8,}|-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)`)
)

func extSet(exts ...string) map[string]bool {
	m := make(map[string]bool, len(exts))
	for _, e := range exts {
		m[e] = true
	}
	return m
}

func redactSecretToken(tok string) string {
	if strings.HasPrefix(tok, "-----BEGIN ") {
		return "[REDACTED PRIVATE KEY HEADER]"
	}
	if len(tok) <= 12 {
		return "[REDACTED]"
	}
	return tok[:6] + "..." + tok[len(tok)-4:]
}

func redactSecretsInSnippet(s string) string {
	return jsSecretRe.ReplaceAllStringFunc(s, redactSecretToken)
}

func resolveRef(doc map[string]any, ref string) any {
	if !strings.HasPrefix(ref, "#/") {
		return nil
	}
	var cur any = doc
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[part]
		if !ok {
			return nil
		}
	}
	return cur
}

func securityAllowsAnonymous(sec []any) bool {
	if len(sec) == 0 {
		return true
	}
	for _, entry := range sec {
		if m, ok := entry.(map[string]any); ok && len(m) == 0 {
			return true
		}
	}
	return false
}

func auditOpenAPISpec(workspaceRoot, specPath string) (map[string]any, error) {
	resolvedPath, err := pathguard.ResolveConfined(workspaceRoot, specPath, true)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("stat OpenAPI spec: %w", err)
	}
	if fi.IsDir() {
		return nil, errors.New("spec_path must point to a file, not a directory")
	}
	if fi.Size() > maxSpecSizeByte {
		return nil, fmt.Errorf("OpenAPI spec exceeds %d byte limit", maxSpecSizeByte)
	}
	raw, err := os.ReadFile(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("reading OpenAPI spec: %w", err)
	}
	var doc map[string]any
	if strings.HasSuffix(strings.ToLower(resolvedPath), ".json") {
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
	hasGlobalAuth := hasGlobalSec && !securityAllowsAnonymous(globalSec)

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
		pathParams, _ := item["parameters"].([]any)
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

			opSecRaw, hasOpSec := op["security"]
			undeclaredAuth := false
			if hasOpSec {
				if secSlice, ok := opSecRaw.([]any); ok && securityAllowsAnonymous(secSlice) {
					undeclaredAuth = true
				}
			} else if !hasGlobalAuth {
				undeclaredAuth = true
			}
			if undeclaredAuth && stateChangingVerb[mLower] && !publicAuthPathRe.MatchString(route) {
				unauthWrites = append(unauthWrites, map[string]any{
					"method": strings.ToUpper(mLower), "path": route, "operation_id": opID,
					"cwe": "CWE-306", "risk": "No OpenAPI security requirement declared on state-changing operation (verify server-side authentication)",
				})
			}

			if matches := bolaParamRe.FindAllString(route, -1); len(matches) > 0 {
				bolaCandidates = append(bolaCandidates, map[string]any{
					"method": strings.ToUpper(mLower), "path": route, "operation_id": opID,
					"object_params": matches, "cwe": "CWE-639",
				})
			}

			var fields []string
			seenRefs := make(map[string]bool)
			var allParams []any
			allParams = append(allParams, pathParams...)
			if opParams, ok := op["parameters"].([]any); ok {
				allParams = append(allParams, opParams...)
			}
			for _, rp := range allParams {
				pm, ok := rp.(map[string]any)
				if !ok {
					continue
				}
				if ref, ok := pm["$ref"].(string); ok {
					if target, ok := resolveRef(doc, ref).(map[string]any); ok {
						pm = target
					}
				}
				pname, _ := pm["name"].(string)
				pin, _ := pm["in"].(string)
				if pin == "body" {
					if schema, ok := pm["schema"]; ok {
						collectSensitiveSchemaFields(doc, schema, seenRefs, &fields)
					}
				} else if ssrfParamNameRe.MatchString(strings.TrimSpace(pname)) {
					ssrfParams = append(ssrfParams, map[string]any{
						"method": strings.ToUpper(mLower), "path": route, "param": pname, "in": pin,
						"cwe": "CWE-918",
					})
				}
			}

			if rb, ok := op["requestBody"].(map[string]any); ok {
				collectSensitiveSchemaFields(doc, rb, seenRefs, &fields)
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
		"workspace_root":          workspaceRoot,
		"spec_path":               resolvedPath,
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

func collectSensitiveSchemaFields(doc map[string]any, node any, seenRefs map[string]bool, out *[]string) {
	m, ok := node.(map[string]any)
	if !ok {
		return
	}
	if ref, ok := m["$ref"].(string); ok && ref != "" {
		if seenRefs[ref] {
			return
		}
		seenRefs[ref] = true
		if target := resolveRef(doc, ref); target != nil {
			collectSensitiveSchemaFields(doc, target, seenRefs, out)
		}
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
			collectSensitiveSchemaFields(doc, v, seenRefs, out)
		}
	}
	for k, v := range m {
		if k == "properties" {
			continue
		}
		switch child := v.(type) {
		case map[string]any:
			collectSensitiveSchemaFields(doc, child, seenRefs, out)
		case []any:
			for _, elem := range child {
				collectSensitiveSchemaFields(doc, elem, seenRefs, out)
			}
		}
	}
}

func scanSourceSinks(workspaceRoot, targetPath string, maxFindings int) (map[string]any, error) {
	if maxFindings <= 0 || maxFindings > 500 {
		maxFindings = 100
	}
	resolvedPath, err := pathguard.ResolveConfined(workspaceRoot, targetPath, true)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(resolvedPath)
	if err != nil {
		return nil, err
	}

	var findings []map[string]any
	filesScanned := 0
	filesTruncated := false
	findingsTruncated := false
	skippedOversizedFiles := 0
	longLinesSkipped := 0

	scanFile := func(p string) {
		if filesScanned >= maxScanFiles {
			filesTruncated = true
			return
		}
		if len(findings) >= maxFindings {
			findingsTruncated = true
			return
		}
		safePath, err := pathguard.ResolveConfined(workspaceRoot, p, true)
		if err != nil {
			return
		}
		ext := strings.ToLower(filepath.Ext(safePath))
		if ext == "" && strings.EqualFold(filepath.Base(safePath), ".env") {
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
		fi, err := os.Stat(safePath)
		if err != nil {
			return
		}
		if fi.Size() > maxFileSizeByte {
			skippedOversizedFiles++
			return
		}
		f, err := os.Open(safePath)
		if err != nil {
			return
		}
		defer f.Close()
		filesScanned++

		br := bufio.NewReaderSize(f, 64*1024)
		lineNo := 0
		for {
			line, readErr := br.ReadString('\n')
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				break
			}
			if line == "" && errors.Is(readErr, io.EOF) {
				break
			}
			lineNo++
			if len(line) > maxLineBytes {
				longLinesSkipped++
				if errors.Is(readErr, io.EOF) {
					break
				}
				continue
			}
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "#") {
				for _, rule := range active {
					if rule.Pattern.MatchString(line) && (rule.Exclude == nil || !rule.Exclude.MatchString(line)) {
						snip := redactSecretsInSnippet(trimmed)
						if len(snip) > 180 {
							snip = snip[:180]
						}
						findings = append(findings, map[string]any{
							"rule_id":             rule.ID,
							"cwe":                 rule.CWE,
							"severity":            rule.Severity,
							"confidence":          rule.Confidence,
							"title":               rule.Title,
							"file":                p,
							"line":                lineNo,
							"snippet":             snip,
							"suggested_cve_query": fmt.Sprintf("cve-intel-mcp:list_cwe_writeups(cwe_id=%q)", rule.CWE),
						})
						if len(findings) >= maxFindings {
							findingsTruncated = true
							return
						}
					}
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
		}
	}

	if !info.IsDir() {
		scanFile(resolvedPath)
	} else {
		_ = filepath.WalkDir(resolvedPath, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.IsDir() {
				if skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if filesScanned >= maxScanFiles {
				filesTruncated = true
				return filepath.SkipAll
			}
			if len(findings) >= maxFindings {
				findingsTruncated = true
				return filepath.SkipAll
			}
			scanFile(p)
			return nil
		})
	}

	return map[string]any{
		"workspace_root":          workspaceRoot,
		"target_path":             resolvedPath,
		"files_scanned":           filesScanned,
		"finding_count":           len(findings),
		"truncated":               findingsTruncated || filesTruncated,
		"findings_truncated":      findingsTruncated,
		"files_truncated":         filesTruncated,
		"skipped_oversized_files": skippedOversizedFiles,
		"long_lines_skipped":      longLinesSkipped,
		"findings":                findings,
	}, nil
}

func extractCookies(raw any) []string {
	switch v := raw.(type) {
	case string:
		var out []string
		for _, line := range strings.Split(v, "\n") {
			if s := strings.TrimSpace(line); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, elem := range v {
			if s := strings.TrimSpace(fmt.Sprintf("%v", elem)); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		if raw == nil {
			return nil
		}
		if s := strings.TrimSpace(fmt.Sprintf("%v", raw)); s != "" {
			return []string{s}
		}
		return nil
	}
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
			hdrOK := errH == nil && json.Unmarshal(hdrBytes, &hdr) == nil && hdr != nil
			payOK := errP == nil && json.Unmarshal(payBytes, &pay) == nil && pay != nil
			jwtDecoded = map[string]any{
				"header":          hdr,
				"payload":         pay,
				"header_decoded":  hdrOK,
				"payload_decoded": payOK,
				"signature_empty": parts[2] == "",
			}

			if !hdrOK {
				issues = append(issues, map[string]any{
					"category": "jwt",
					"severity": "INFO",
					"cwe":      "CWE-347",
					"detail":   "Failed to decode JWT header (malformed base64url or JSON)",
				})
			} else {
				algVal, hasAlg := hdr["alg"]
				alg := ""
				if s, ok := algVal.(string); ok {
					alg = strings.ToLower(strings.TrimSpace(s))
				}
				if !hasAlg || alg == "" || alg == "none" || parts[2] == "" {
					issues = append(issues, map[string]any{"category": "jwt", "severity": "CRITICAL", "cwe": "CWE-347", "detail": "Unsigned JWT or alg=none detected"})
				}
				for _, riskHdr := range []string{"jku", "x5u", "jwk"} {
					if _, ok := hdr[riskHdr]; ok {
						issues = append(issues, map[string]any{"category": "jwt", "severity": "HIGH", "cwe": "CWE-347", "detail": fmt.Sprintf("JWT header contains %q (check for SSRF or untrusted key injection)", riskHdr)})
					}
				}
				if kid, ok := hdr["kid"].(string); ok && (strings.Contains(kid, "..") || strings.Contains(kid, "'") || strings.Contains(kid, "/")) {
					issues = append(issues, map[string]any{"category": "jwt", "severity": "HIGH", "cwe": "CWE-22", "detail": "JWT kid header contains traversal or SQL metacharacters"})
				}
			}
			if !payOK {
				issues = append(issues, map[string]any{
					"category": "jwt",
					"severity": "INFO",
					"cwe":      "CWE-347",
					"detail":   "Failed to decode JWT payload (malformed base64url or JSON)",
				})
			} else if _, hasExp := pay["exp"]; !hasExp {
				issues = append(issues, map[string]any{"category": "jwt", "severity": "MEDIUM", "cwe": "CWE-613", "detail": "JWT payload missing exp claim"})
			}
		}
	}

	if len(headers) > 0 {
		norm := make(map[string]string, len(headers))
		var cookies []string
		for k, v := range headers {
			lk := strings.ToLower(strings.TrimSpace(k))
			if lk == "set-cookie" {
				cookies = append(cookies, extractCookies(v)...)
			} else {
				norm[lk] = fmt.Sprintf("%v", v)
			}
		}
		acao := strings.TrimSpace(norm["access-control-allow-origin"])
		acac := strings.ToLower(strings.TrimSpace(norm["access-control-allow-credentials"]))
		if acao == "*" && acac == "true" {
			issues = append(issues, map[string]any{"category": "cors", "severity": "HIGH", "cwe": "CWE-942", "detail": "CORS Access-Control-Allow-Origin: * paired with Allow-Credentials: true"})
		} else if acao == "null" && acac == "true" {
			issues = append(issues, map[string]any{"category": "cors", "severity": "HIGH", "cwe": "CWE-942", "detail": "CORS allows 'null' origin with credentials"})
		}
		if csp := norm["content-security-policy"]; csp == "" {
			issues = append(issues, map[string]any{"category": "headers", "severity": "LOW", "cwe": "CWE-693", "detail": "Missing Content-Security-Policy header"})
		} else if strings.Contains(csp, "unsafe-inline") && strings.Contains(csp, "unsafe-eval") {
			issues = append(issues, map[string]any{"category": "headers", "severity": "MEDIUM", "cwe": "CWE-693", "detail": "Weak CSP containing both unsafe-inline and unsafe-eval"})
		}
		for _, rawCookie := range cookies {
			segs := strings.Split(rawCookie, ";")
			cookieName := strings.TrimSpace(strings.SplitN(segs[0], "=", 2)[0])
			hasHttpOnly := false
			hasSecure := false
			for _, attr := range segs[1:] {
				tok := strings.ToLower(strings.TrimSpace(attr))
				if tok == "httponly" {
					hasHttpOnly = true
				} else if tok == "secure" {
					hasSecure = true
				}
			}
			if !hasHttpOnly {
				issues = append(issues, map[string]any{"category": "cookie", "severity": "MEDIUM", "cwe": "CWE-1004", "detail": fmt.Sprintf("Set-Cookie %q missing HttpOnly flag", cookieName)})
			}
			if !hasSecure {
				issues = append(issues, map[string]any{"category": "cookie", "severity": "MEDIUM", "cwe": "CWE-614", "detail": fmt.Sprintf("Set-Cookie %q missing Secure flag", cookieName)})
			}
		}
	}

	return map[string]any{
		"issue_count": len(issues),
		"issues":      issues,
		"jwt_decoded": jwtDecoded,
	}
}

func isNoisyURL(u string) bool {
	lu := strings.ToLower(u)
	for _, skip := range []string{
		"w3.org/", "schema.org/", "reactjs.org/", "nextjs.org/", "mozilla.org/",
		"fonts.googleapis.com/", "fonts.gstatic.com/", "purl.org/", "xmlns.com/",
		"creativecommons.org/", "github.com/facebook/", "fb.me/",
	} {
		if strings.Contains(lu, skip) {
			return true
		}
	}
	return false
}

func extractJSEndpoints(workspaceRoot, targetPath string, maxFiles int) (map[string]any, error) {
	if maxFiles <= 0 || maxFiles > maxScanFiles {
		maxFiles = 500
	}
	resolvedPath, err := pathguard.ResolveConfined(workspaceRoot, targetPath, true)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("stat target_path: %w", err)
	}

	jsExts := extSet(".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html", ".htm", ".json", ".map")
	apiPaths := map[string]bool{}
	absURLs := map[string]bool{}
	gqlOps := map[string]bool{}
	headers := map[string]bool{}
	pkgVersions := map[string]bool{}
	buildIDs := map[string]bool{}
	var secretHits []map[string]any
	filesScanned := 0
	filesTruncated := false
	skippedOversized := 0
	resultsTruncated := false

	processFile := func(p string) {
		if filesScanned >= maxFiles {
			filesTruncated = true
			return
		}
		safePath, err := pathguard.ResolveConfined(workspaceRoot, p, true)
		if err != nil {
			return
		}
		st, err := os.Stat(safePath)
		if err != nil || st.IsDir() {
			return
		}
		if st.Size() > 8<<20 {
			skippedOversized++
			return
		}
		raw, err := os.ReadFile(safePath)
		if err != nil {
			return
		}
		filesScanned++
		text := string(raw)

		for _, m := range jsAPIPathRe.FindAllStringSubmatch(text, 200) {
			if len(apiPaths) < 300 {
				apiPaths[m[1]] = true
			} else {
				resultsTruncated = true
			}
		}
		for _, u := range jsAbsURLRe.FindAllString(text, 200) {
			if !isNoisyURL(u) {
				if len(absURLs) < 200 {
					absURLs[u] = true
				} else {
					resultsTruncated = true
				}
			}
		}
		for _, m := range jsGraphQLOpRe.FindAllStringSubmatch(text, 100) {
			if len(gqlOps) < 100 {
				gqlOps[strings.ToLower(m[1])+" "+m[2]] = true
			} else {
				resultsTruncated = true
			}
		}
		for _, m := range jsHeaderRe.FindAllStringSubmatch(text, 100) {
			if len(headers) < 80 {
				headers[m[1]] = true
			} else {
				resultsTruncated = true
			}
		}
		for _, m := range jsNextBuildRe.FindAllStringSubmatch(text, 10) {
			buildIDs[m[1]] = true
		}
		for _, m := range jsPkgVersionRe.FindAllStringSubmatch(text, 50) {
			if len(pkgVersions) < 80 {
				pkgVersions[strings.ToLower(m[1])+"@"+m[2]] = true
			} else {
				resultsTruncated = true
			}
		}
		for _, m := range jsSecretRe.FindAllString(text, 10) {
			if len(secretHits) >= 50 {
				resultsTruncated = true
				break
			}
			secretHits = append(secretHits, map[string]any{
				"file":    p,
				"preview": redactSecretToken(m),
				"cwe":     "CWE-798",
			})
		}
	}

	if !info.IsDir() {
		processFile(resolvedPath)
	} else {
		_ = filepath.WalkDir(resolvedPath, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if filesScanned >= maxFiles {
				filesTruncated = true
				return fs.SkipAll
			}
			if !jsExts[strings.ToLower(filepath.Ext(p))] {
				return nil
			}
			processFile(p)
			return nil
		})
	}

	toSorted := func(m map[string]bool) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}

	pathsList := toSorted(apiPaths)
	urlsList := toSorted(absURLs)
	gqlList := toSorted(gqlOps)
	hdrList := toSorted(headers)
	pkgList := toSorted(pkgVersions)
	buildList := toSorted(buildIDs)

	return map[string]any{
		"workspace_root":          workspaceRoot,
		"target_path":             resolvedPath,
		"files_scanned":           filesScanned,
		"files_truncated":         filesTruncated,
		"results_truncated":       resultsTruncated,
		"skipped_oversized_files": skippedOversized,
		"api_paths":               pathsList,
		"absolute_urls":           urlsList,
		"graphql_ops":             gqlList,
		"custom_headers":          hdrList,
		"package_versions":        pkgList,
		"next_build_ids":          buildList,
		"secret_candidates":       secretHits,
		"summary": map[string]int{
			"api_paths":         len(pathsList),
			"absolute_urls":     len(urlsList),
			"graphql_ops":       len(gqlList),
			"custom_headers":    len(hdrList),
			"package_versions":  len(pkgList),
			"secret_candidates": len(secretHits),
		},
	}, nil
}

func buildServer(workspaceRoot string) *mcpserver.Server {
	srv := mcpserver.New("attack-surface-mcp", "0.5.0")

	srv.Register(mcpserver.Tool{
		Name:        "audit_openapi_spec",
		Description: "Audit an OpenAPI 3.x / Swagger 2.0 spec inside the configured workspace root for undeclared auth on writes (CWE-306), object ID paths (CWE-639), SSRF params (CWE-918), and mass-assignment fields (CWE-915).",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"spec_path": map[string]any{"type": "string", "description": "Path inside workspace root to an OpenAPI/Swagger .yaml or .json file"},
			},
			"required": []string{"spec_path"},
		},
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			p, _ := args["spec_path"].(string)
			return auditOpenAPISpec(workspaceRoot, strings.TrimSpace(p))
		},
	})

	srv.Register(mcpserver.Tool{
		Name:        "scan_source_sinks",
		Description: "Offline static sink and secret scan inside the configured workspace root across Go, Rust, Python, JS/TS, Java, and PHP.",
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
			return scanSourceSinks(workspaceRoot, strings.TrimSpace(p), maxF)
		},
	})

	srv.Register(mcpserver.Tool{
		Name:        "inspect_jwt_and_headers",
		Description: "Offline check of JWT header/claims (alg=none, jku/x5u/kid, missing exp) and HTTP response headers (CORS, CSP, per-cookie Set-Cookie flags).",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"jwt":     map[string]any{"type": "string", "description": "Optional JWT token to decode and inspect"},
				"headers": map[string]any{"type": "object", "description": "Optional map of HTTP response headers (Set-Cookie may be string or array)"},
			},
		},
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			jwtStr, _ := args["jwt"].(string)
			hdrs, _ := args["headers"].(map[string]any)
			return inspectJWTAndHeaders(jwtStr, hdrs), nil
		},
	})

	srv.Register(mcpserver.Tool{
		Name:        "extract_js_endpoints",
		Description: "Extract API routes, GraphQL ops, custom headers, Next.js buildIds, library versions, and redacted secret candidates from JS/HTML/JSON files inside the workspace root.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target_path": map[string]any{"type": "string", "description": "File or directory inside workspace root containing downloaded JS/HTML/JSON bundles"},
				"max_files":   map[string]any{"type": "integer", "default": 500},
			},
			"required": []string{"target_path"},
		},
		Handler: func(_ context.Context, args map[string]any) (any, error) {
			p, _ := args["target_path"].(string)
			maxF := 500
			if f, ok := args["max_files"].(float64); ok {
				maxF = int(f)
			}
			return extractJSEndpoints(workspaceRoot, strings.TrimSpace(p), maxF)
		},
	})

	return srv
}

func main() {
	transport := flag.String("transport", mcpserver.EnvOr("MCP_TRANSPORT", "stdio"), "stdio or http")
	host := flag.String("host", mcpserver.EnvOr("MCP_HOST", "127.0.0.1"), "HTTP bind host")
	port := flag.Int("port", 8904, "HTTP bind port")
	workspaceDir := flag.String("workspace-dir", mcpserver.EnvOr("ATTACK_SURFACE_ROOT", "."), "Confined root directory for file-reading tools")
	flag.Parse()

	absRoot, err := filepath.Abs(*workspaceDir)
	if err != nil {
		absRoot = *workspaceDir
	}
	fmt.Fprintf(os.Stderr, "[*] attack-surface-mcp workspace root: %s\n", absRoot)

	srv := buildServer(absRoot)
	if err := srv.Run(*transport, *host, *port); err != nil {
		fmt.Fprintf(os.Stderr, "attack-surface-mcp error: %v\n", err)
		os.Exit(1)
	}
}

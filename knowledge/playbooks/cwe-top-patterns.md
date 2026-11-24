# High-Signal CWE Research & Verification Playbooks

Use this index alongside `cve-intel-mcp:list_cwe_writeups(cwe_id)` to pair structural vulnerability classes with real-world Medium+ CVE writeups and patch diffs.

| CWE | Vulnerability Class | Primary Verification Focus | Typical Root-Cause Fix |
|---|---|---|---|
| **CWE-22** | Path Traversal / Arbitrary File Read-Write | Canonicalize resolved path (`realpath`) vs. allowed root directory; test encoded separators, symlinks, zip-slip archives | Strict prefix check after `os.path.realpath` + reject symlinks |
| **CWE-78 / CWE-77** | OS Command Injection | Trace untrusted strings into `shell=True`, `exec`, `popen`, or argument injection (`--option=`) | Use `execve` argv arrays (`shell=False`) + `--` end-of-options |
| **CWE-79** | Cross-Site Scripting (XSS) | Context-sensitive sinks (HTML, attribute, JS, URL, SVG, DOM `innerHTML`) | Context-aware auto-escaping + strict CSP + `DOMPurify` |
| **CWE-89** | SQL Injection | Dynamic query concatenation, `ORDER BY`/identifier interpolation, ORM raw clauses | Parameterized queries + strict allowlist for dynamic identifiers |
| **CWE-918** | Server-Side Request Forgery (SSRF) | HTTP clients, webhooks, PDF/image renderers, DNS rebinding, redirect chains | Resolve IP at connect time, block RFC1918/link-local/metadata IPs, disable or re-validate redirects |
| **CWE-287 / CWE-863** | Auth Bypass & Broken Authorization (BOLA/IDOR) | Missing object-ownership checks, JWT `alg`/kid/JWKS confusion, middleware path-matching differentials | Enforce centralized object-level policy on every handler + canonical path routing |
| **CWE-502** | Unsafe Deserialization | `pickle`, Java `ObjectInputStream`, PHP `unserialize`, YAML `unsafe_load`, gadget chains | Use safe data-only formats (JSON, `yaml.safe_load`) with strict schema validation |
| **CWE-362** | Race Condition (TOCTOU) | Multi-request concurrent state transitions (coupons, balance transfers, token reuse) | Atomic DB transactions (`SELECT ... FOR UPDATE`, unique constraints, idempotency keys) |

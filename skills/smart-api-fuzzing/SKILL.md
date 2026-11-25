---
name: smart-api-fuzzing
description: Run rate-limited OpenAPI and GraphQL fuzzing with upstream Schemathesis and Endava CATS routed through ARTEX's capture proxy for traffic binding.
---

# Smart API Fuzzing (Schemathesis + Endava CATS)

Use this when an authorized target exposes an OpenAPI/Swagger spec (2.0, 3.0, or 3.1), a GraphQL endpoint, or REST routes extracted from JS bundles (`attack-surface-mcp` -> `extract_js_endpoints`).

Combine context you gather (auth headers, realistic field values, or a small OpenAPI stub built from JS routes) with two upstream fuzzers installed in the environment:
- `schemathesis` (`schemathesis/schemathesis`): OpenAPI and GraphQL property-based + stateful fuzzer with automatic input shrinking.
- `cats` (`Endava/cats`): 179 built-in OpenAPI negative, boundary, header, HTTP method, auth, and stateful resource fuzzers.

## Before Running
- Verify the target host with `scope-guard-mcp:check_target_in_scope`.
- Cap request rates on live or rate-limited targets (`ARTEX_NOISE_PROFILE=quiet`):
  - `schemathesis`: `--rate-limit 2/s --workers 1 --max-examples 15`
  - `cats`: `--maxRequestsPerMinute 60` and a targeted `--fuzzers` / `--paths` subset
- Route traffic through ARTEX's capture proxy (`http://127.0.0.1:8788`) so configured request headers are injected and anomalies are captured for `traffic_search` and `bind_finding_traffic`.

## Getting a Spec
- If `/openapi.json`, `/swagger.json`, or `/v3/api-docs` is exposed, save it locally and run `mcp__attack-surface-mcp__audit_openapi_spec` first to pick high-value routes.
- If there is no published spec, extract routes with `mcp__attack-surface-mcp__extract_js_endpoints` and write a minimal OpenAPI 3.0 file (`/tmp/target_synth_openapi.json`) for the interesting endpoints and JSON bodies you observed.
- For GraphQL, point `schemathesis` at `/graphql` (if introspection is on) or a local SDL file.

## Running `schemathesis`
Good for GraphQL, OpenAPI 3.x stateful chains (`POST` -> `GET`/`PATCH`/`DELETE`), 5xx crashes, contract violations, and shrinking failing inputs to small reproducers:

```bash
schemathesis run /tmp/openapi.json \
  --url https://target.example.com \
  --proxy http://127.0.0.1:8788 \
  --tls-verify false \
  --header "Authorization: Bearer $TOKEN" \
  --rate-limit 3/s \
  --workers 1 \
  --max-examples 20 \
  --phases examples,coverage,fuzzing,stateful \
  --checks all \
  --report ndjson \
  --report-ndjson-path /tmp/st_report.ndjson

# GraphQL
schemathesis run https://target.example.com/graphql \
  --proxy http://127.0.0.1:8788 \
  --tls-verify false \
  --header "Authorization: Bearer $TOKEN" \
  --rate-limit 3/s \
  --workers 1 \
  --max-examples 20 \
  --report ndjson \
  --report-ndjson-path /tmp/st_gql.ndjson
```

Group failures in `/tmp/st_report.ndjson` with a short Python snippet by `(operation, check_name, status_code)` instead of pasting raw output into context.

## Running `cats`
Good for targeted negative/boundary/auth/extra-field checks across OpenAPI paths:

```bash
cats \
  --contract /tmp/openapi.json \
  --server https://target.example.com \
  --proxyHost 127.0.0.1 \
  --proxyPort 8788 \
  --insecure \
  -H "Authorization=Bearer $TOKEN" \
  --maxRequestsPerMinute 60 \
  --output /tmp/cats-report \
  --paths "/api/v1/records,/api/v1/users/{id}" \
  --fuzzers "BypassAuthentication,HttpMethods,ExtraFields,NullValuesInFields,ExtremePositiveNumbersInIntegerFields,ExtremeNegativeNumbersInIntegerFields,SpecialCharsInStringFields"
```

Useful helpers: `cats list --fuzzers`, `cats list --paths --contract /tmp/openapi.json`, and inspecting `/tmp/cats-report/cats-summary-report.json`.

## Triaging Anomalies
Do not file raw fuzzer failures as findings. A strict-schema mismatch or benign `400`/`422` is usually doc drift. Focus on real security impact (missing auth, cross-tenant reads/writes, mass assignment on privileged fields, injection, or stack traces leaking internals). Replay the minimized case plus a negative baseline through `curl -x http://127.0.0.1:8788 -k`, bind the captured `traffic_id`s via `traffic_refs` or `bind_finding_traffic`, and log a receipt in `scope-guard-mcp`.

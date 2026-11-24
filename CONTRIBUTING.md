# Contributing to ARTEX-Nexus

Thank you for helping build an open, evidence-driven cybersecurity research platform!

## Ways to Contribute
- **Report a CVE / Vulnerability Discovery:** Found a bug using ARTEX-Nexus? Add your publicly disclosed finding to [TROPHIES.md](TROPHIES.md) once patched/disclosed!
- **Add CWE Playbooks & Skills:** Expand `knowledge/playbooks/` or `skills/*/SKILL.md` with concrete verification methodologies and defensive remediation patterns.
- **Improve Rust & Go MCP Servers:** Add new data enrichers to `crates/nexus-sync`, query capabilities to `crates/cve-intel-mcp`, or security controls to `go/cmd/`.

## Local Development Setup

### Prerequisites
- Rust `1.88+` (`rustup`)
- Go `1.26+`
- Git (clone with `--recurse-submodules` to include `vendor/ARTEX`)

### Build, Lint & Test
```bash
# Rust checks & tests
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Go checks & race-detector tests
cd go
go vet ./...
go test -race -v ./...
```

### Pull Request Checklist
1. Zero warnings from `cargo clippy --workspace --all-targets -- -D warnings` and `go vet ./...`.
2. Unit or wire-level transport tests covering any new MCP tool, parser, or security boundary.
3. No hardcoded local paths, secrets, API tokens, private IPs, or undisclosed vulnerability details.
4. Keep `vendor/ARTEX` strictly as an upstream git submodule (contribute core ARTEX changes upstream to [`BaaRai/ARTEX`](https://github.com/BaaRai/ARTEX)).

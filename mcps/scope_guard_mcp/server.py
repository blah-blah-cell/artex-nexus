"""
scope-guard-mcp: Dual-transport (stdio + Streamable HTTP / SSE) MCP server for
programmatic scope enforcement (allow/deny domain, wildcard, CIDR validation)
and tamper-evident SHA-256 verification receipt & SARIF/Markdown reporting.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import ipaddress
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from mcps.compat import create_mcp_server, run_mcp_server

mcp = create_mcp_server("scope-guard-mcp")

_ACTIVE_SCOPE: dict[str, Any] = {
    "program": "unconfigured",
    "in_scope": [],
    "out_of_scope": [],
    "notes": "",
}
DEFAULT_RECEIPT_DIR = Path(os.environ.get("SCOPE_RECEIPT_DIR", "data/receipts"))


def _extract_host(target: str) -> str:
    raw = target.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        return (parsed.hostname or "").lower()
    if "/" in raw and not _is_cidr(raw):
        raw = raw.split("/", 1)[0]
    if ":" in raw and not _is_ip(raw):
        raw = raw.split(":", 1)[0]
    return raw.lower().strip(".")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return "/" in value
    except ValueError:
        return False


def _rule_matches(host: str, rule: str) -> bool:
    rule_norm = rule.strip().lower().rstrip(".")
    if not rule_norm:
        return False
    if _is_ip(host) and (_is_cidr(rule_norm) or _is_ip(rule_norm)):
        net = ipaddress.ip_network(rule_norm, strict=False)
        return ipaddress.ip_address(host) in net
    if rule_norm.startswith("*."):
        base = rule_norm[2:]
        return host == base or host.endswith("." + base)
    return fnmatch.fnmatch(host, rule_norm)


@mcp.tool()
def load_scope_policy(policy_path: str) -> dict[str, Any]:
    """Load an authorized engagement scope policy from a YAML or JSON file."""
    path = Path(policy_path)
    if not path.exists():
        return {"loaded": False, "error": f"Scope policy not found: {policy_path}"}

    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw) if path.suffix.lower() in (".yml", ".yaml") else json.loads(raw)
    if not isinstance(data, dict):
        return {"loaded": False, "error": "Scope policy must be a YAML/JSON mapping."}

    _ACTIVE_SCOPE["program"] = str(data.get("program") or path.stem)
    _ACTIVE_SCOPE["in_scope"] = [str(x).strip() for x in (data.get("in_scope") or []) if str(x).strip()]
    _ACTIVE_SCOPE["out_of_scope"] = [str(x).strip() for x in (data.get("out_of_scope") or []) if str(x).strip()]
    _ACTIVE_SCOPE["notes"] = str(data.get("notes") or "")
    return {"loaded": True, **_ACTIVE_SCOPE}


@mcp.tool()
def check_target_in_scope(target: str) -> dict[str, Any]:
    """Deterministically verify whether a domain, URL, or IP is within the loaded authorized scope."""
    host = _extract_host(target)
    if not host:
        return {"allowed": False, "target": target, "reason": "Empty or unparseable target host."}
    if not _ACTIVE_SCOPE["in_scope"]:
        return {
            "allowed": False,
            "target": target,
            "host": host,
            "reason": "No authorized scope policy loaded. Call load_scope_policy first.",
        }

    for deny_rule in _ACTIVE_SCOPE["out_of_scope"]:
        if _rule_matches(host, deny_rule):
            return {
                "allowed": False,
                "target": target,
                "host": host,
                "matched_rule": deny_rule,
                "reason": "Explicitly excluded by out_of_scope rule.",
            }

    for allow_rule in _ACTIVE_SCOPE["in_scope"]:
        if _rule_matches(host, allow_rule):
            return {
                "allowed": True,
                "target": target,
                "host": host,
                "matched_rule": allow_rule,
                "program": _ACTIVE_SCOPE["program"],
                "reason": "Matched authorized in_scope rule.",
            }

    return {
        "allowed": False,
        "target": target,
        "host": host,
        "reason": "Target did not match any authorized in_scope rule.",
    }


@mcp.tool()
def list_in_scope_assets() -> dict[str, Any]:
    """Return the currently loaded scope policy (program name, allowlist, and denylist)."""
    return dict(_ACTIVE_SCOPE)


@mcp.tool()
def record_evidence_receipt(
    finding_id: str,
    title: str,
    target: str,
    cwe: str,
    severity: str,
    cvss_vector: str,
    verification_command: str,
    observed_output_summary: str,
    remediation: str = "",
) -> dict[str, Any]:
    """Record a tamper-evident SHA-256 hashed verification receipt on disk."""
    receipt_dir = Path(os.environ.get("SCOPE_RECEIPT_DIR", str(DEFAULT_RECEIPT_DIR)))
    receipt_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "finding_id": finding_id.strip(),
        "program": _ACTIVE_SCOPE["program"],
        "title": title.strip(),
        "target": target.strip(),
        "cwe": cwe.upper().strip(),
        "severity": severity.upper().strip(),
        "cvss_vector": cvss_vector.strip(),
        "verification_command": verification_command.strip(),
        "observed_output_summary": observed_output_summary.strip(),
        "remediation": remediation.strip(),
        "recorded_at": datetime.now(UTC).isoformat(),
    }
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    payload["sha256"] = hashlib.sha256(canonical).hexdigest()

    safe_id = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in finding_id.strip())
    out_file = receipt_dir / f"{safe_id}.json"
    out_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"recorded": True, "path": str(out_file), "sha256": payload["sha256"]}


@mcp.tool()
def export_report(report_format: str = "markdown") -> dict[str, Any]:
    """Export all recorded verification receipts as a clean Markdown or SARIF 2.1.0 report."""
    receipt_dir = Path(os.environ.get("SCOPE_RECEIPT_DIR", str(DEFAULT_RECEIPT_DIR)))
    receipts: list[dict[str, Any]] = []
    if receipt_dir.exists():
        for p in sorted(receipt_dir.glob("*.json")):
            try:
                receipts.append(json.loads(p.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue

    fmt = report_format.lower().strip()
    if fmt == "sarif":
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {"driver": {"name": "artex-nexus-scope-guard", "version": "0.1.0"}},
                    "results": [
                        {
                            "ruleId": r.get("cwe", "CWE-UNKNOWN"),
                            "level": "error" if r.get("severity") in ("CRITICAL", "HIGH") else "warning",
                            "message": {"text": f"{r.get('title')} — {r.get('observed_output_summary')}"},
                            "properties": {
                                "finding_id": r.get("finding_id"),
                                "target": r.get("target"),
                                "cvss_vector": r.get("cvss_vector"),
                                "sha256": r.get("sha256"),
                            },
                        }
                        for r in receipts
                    ],
                }
            ],
        }
        return {"format": "sarif", "count": len(receipts), "content": json.dumps(sarif, indent=2)}

    lines = [f"# Security Verification Report ({_ACTIVE_SCOPE['program']})", ""]
    for r in receipts:
        lines.extend(
            [
                f"## [{r.get('finding_id')}] {r.get('title')}",
                f"- **Severity:** {r.get('severity')} (`{r.get('cvss_vector')}`)",
                f"- **CWE:** {r.get('cwe')}",
                f"- **Target:** `{r.get('target')}`",
                f"- **Verification:** `{r.get('verification_command')}`",
                f"- **Observed Evidence:** {r.get('observed_output_summary')}",
                f"- **Remediation:** {r.get('remediation') or 'Pending'}",
                f"- **Receipt SHA-256:** `{r.get('sha256')}`",
                "",
            ]
        )
    return {"format": "markdown", "count": len(receipts), "content": "\n".join(lines)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run scope-guard-mcp server")
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse", "streamable-http"),
        default=os.environ.get("MCP_TRANSPORT", "stdio"),
    )
    parser.add_argument("--host", default=os.environ.get("MCP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("MCP_PORT", "8903")))
    args = parser.parse_args()

    run_mcp_server(mcp, transport=args.transport, host=args.host, port=args.port)


if __name__ == "__main__":
    main()

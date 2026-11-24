"""Compatibility helpers supporting both mcp v2 (MCPServer) and mcp v1 (FastMCP)."""

from __future__ import annotations

from typing import Any

try:
    from mcp.server.mcpserver import MCPServer as _ServerClass  # type: ignore

    IS_MCP_V2 = True
except ImportError:
    from mcp.server.fastmcp import FastMCP as _ServerClass  # type: ignore

    IS_MCP_V2 = False


def create_mcp_server(name: str) -> Any:
    return _ServerClass(name)


def run_mcp_server(server: Any, transport: str, host: str, port: int) -> None:
    if hasattr(server, "settings"):
        server.settings.host = host
        server.settings.port = port
        server.run(transport=transport)
    elif transport == "stdio":
        server.run(transport="stdio")
    else:
        server.run(transport=transport, host=host, port=port)

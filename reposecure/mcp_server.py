"""REPOSECURE MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from reposecure.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-reposecure[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-reposecure[mcp]'")
        return 1
    app = FastMCP("reposecure")

    @app.tool()
    def reposecure_scan(target: str) -> str:
        """One-shot repo security posture grade (secrets/CI/branch rules/deps). Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0

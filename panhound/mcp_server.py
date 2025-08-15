"""PANHOUND MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from panhound.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-panhound[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-panhound[mcp]'")
        return 1
    app = FastMCP("panhound")

    @app.tool()
    def panhound_scan(target: str) -> str:
        """Scans code, logs, fixtures, and S3 buckets for leaked PANs (Luhn-validated card numbers) and CVVs before they hit prod.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0

"""PANHOUND MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json
import os

from panhound.core import scan_paths, scan_text, findings_to_dicts


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-panhound[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install the MCP extra: pip install 'cognis-panhound[mcp]'",
              flush=True)
        return 1
    app = FastMCP("panhound")

    @app.tool()
    def panhound_scan(target: str) -> str:
        """Scan a file path, directory, or literal text for leaked PANs
        (Luhn-validated card numbers) and CVVs. Returns JSON findings."""
        if not target:
            return json.dumps({"error": "target must not be empty"})
        if os.path.exists(target):
            findings = scan_paths([target])
        else:
            # treat as literal text (e.g. a log snippet)
            findings = scan_text(target, path="<text>")
        return json.dumps({"findings": findings_to_dicts(findings)})

    app.run()
    return 0

"""ENTROPYSCAN MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import sys

from entropyscan.core import scan, to_json


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-entropyscan[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore[import]
    except ImportError:
        print(
            "Install the MCP extra: pip install 'cognis-entropyscan[mcp]'",
            file=sys.stderr,
        )
        return 1
    app = FastMCP("entropyscan")

    @app.tool()
    def entropyscan_scan(target: str) -> str:
        """Flag high-entropy regions in files. Returns JSON findings."""
        try:
            return to_json(scan(target))
        except (FileNotFoundError, ValueError, OSError) as exc:
            return to_json({"error": str(exc), "path": target})

    app.run()
    return 0

"""ENTROPYSCAN MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from entropyscan.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-entropyscan[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-entropyscan[mcp]'")
        return 1
    app = FastMCP("entropyscan")

    @app.tool()
    def entropyscan_scan(target: str) -> str:
        """Flag packed/encrypted/high-entropy regions in files. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0

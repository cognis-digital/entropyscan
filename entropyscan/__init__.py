"""entropyscan — part of the Cognis Neural Suite."""
from entropyscan.core import (  # noqa: F401
    TOOL_NAME,
    TOOL_VERSION,
    shannon_entropy,
    classify,
    scan_bytes,
    scan_file,
    scan,
    to_json,
    BlockResult,
    ScanReport,
    DEFAULT_BLOCK_SIZE,
    MAX_BYTES_DEFAULT,
    SEVERITY_ORDER,
)

__version__ = TOOL_VERSION

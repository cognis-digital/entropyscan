"""ENTROPYSCAN - flag packed/encrypted/high-entropy regions in files.

A defensive/forensics CLI in the spirit of binwalk's entropy analysis:
slide a window across a file, compute Shannon entropy per block, and surface
the regions that look compressed, encrypted, or packed.

Standard library only. Zero install. Analysis on artifacts you own.
"""
from .core import (
    BlockResult,
    ScanReport,
    scan_file,
    scan_bytes,
    shannon_entropy,
    classify,
    SEVERITY_ORDER,
)

TOOL_NAME = "entropyscan"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "BlockResult",
    "ScanReport",
    "scan_file",
    "scan_bytes",
    "shannon_entropy",
    "classify",
    "SEVERITY_ORDER",
]

"""Core entropy-scanning engine for ENTROPYSCAN.

Shannon entropy is measured in bits-per-byte (0.0 .. 8.0). Random/encrypted
or strongly-compressed data trends toward 8.0; structured data (code, text,
tables, padding) sits well below. We slide a fixed-size window across the
file, score each block, and classify regions by severity.
"""
from __future__ import annotations

import math
import os
from dataclasses import dataclass, field, asdict
from typing import Iterable, List, Optional

# --- tool identity (single source of truth) ---
TOOL_NAME = "entropyscan"


def _read_version() -> str:
    """Resolve the version from the repo VERSION file, then packaging metadata,
    then a safe default. Keeps the CLI banner in sync with the release tag."""
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (
        os.path.join(here, "..", "VERSION"),
        os.path.join(here, "VERSION"),
    ):
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                v = fh.read().strip()
            if v:
                return v
        except OSError:
            continue
    try:  # installed wheel
        from importlib.metadata import version, PackageNotFoundError
        try:
            return version("cognis-entropyscan")
        except PackageNotFoundError:
            pass
    except Exception:
        pass
    return "0.4.0"


TOOL_VERSION = _read_version()

# Entropy thresholds in bits/byte. Tuned to match common forensic practice:
# >7.5 is the classic "encrypted/compressed" heuristic used by binwalk et al.
CRITICAL_THRESHOLD = 7.5   # almost certainly encrypted/compressed/packed
HIGH_THRESHOLD = 6.8       # likely compressed/obfuscated
MEDIUM_THRESHOLD = 5.5     # mixed / suspicious
# below MEDIUM is considered low (plain structured data)

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

DEFAULT_BLOCK_SIZE = 4096
MAX_BYTES_DEFAULT = 256 * 1024 * 1024  # 256 MiB safety cap


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy of ``data`` in bits per byte (0.0 .. 8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / n
            entropy -= p * math.log2(p)
    return entropy


def classify(entropy: float) -> str:
    """Map an entropy value to a severity label."""
    if entropy >= CRITICAL_THRESHOLD:
        return "critical"
    if entropy >= HIGH_THRESHOLD:
        return "high"
    if entropy >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"


@dataclass
class BlockResult:
    index: int
    offset: int
    size: int
    entropy: float
    severity: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanReport:
    path: str
    size: int
    block_size: int
    bytes_scanned: int
    blocks: List[BlockResult] = field(default_factory=list)
    truncated: bool = False

    # --- derived metrics ---
    @property
    def mean_entropy(self) -> float:
        if not self.blocks:
            return 0.0
        return sum(b.entropy for b in self.blocks) / len(self.blocks)

    @property
    def max_entropy(self) -> float:
        return max((b.entropy for b in self.blocks), default=0.0)

    @property
    def min_entropy(self) -> float:
        return min((b.entropy for b in self.blocks), default=0.0)

    @property
    def overall_severity(self) -> str:
        worst = "low"
        for b in self.blocks:
            if SEVERITY_ORDER[b.severity] > SEVERITY_ORDER[worst]:
                worst = b.severity
        return worst

    def severity_counts(self) -> dict:
        counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for b in self.blocks:
            counts[b.severity] += 1
        return counts

    def flagged_blocks(self, min_severity: str = "high") -> List[BlockResult]:
        floor = SEVERITY_ORDER[min_severity]
        return [b for b in self.blocks if SEVERITY_ORDER[b.severity] >= floor]

    def regions(self, min_severity: str = "high") -> List[dict]:
        """Coalesce consecutive flagged blocks into contiguous regions."""
        floor = SEVERITY_ORDER[min_severity]
        out: List[dict] = []
        cur: Optional[dict] = None
        for b in self.blocks:
            if SEVERITY_ORDER[b.severity] >= floor:
                if cur is None:
                    cur = {
                        "start": b.offset,
                        "end": b.offset + b.size,
                        "max_entropy": b.entropy,
                        "severity": b.severity,
                        "blocks": 1,
                    }
                else:
                    cur["end"] = b.offset + b.size
                    cur["blocks"] += 1
                    if b.entropy > cur["max_entropy"]:
                        cur["max_entropy"] = b.entropy
                    if SEVERITY_ORDER[b.severity] > SEVERITY_ORDER[cur["severity"]]:
                        cur["severity"] = b.severity
            else:
                if cur is not None:
                    out.append(cur)
                    cur = None
        if cur is not None:
            out.append(cur)
        return out

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size": self.size,
            "block_size": self.block_size,
            "bytes_scanned": self.bytes_scanned,
            "truncated": self.truncated,
            "mean_entropy": round(self.mean_entropy, 4),
            "max_entropy": round(self.max_entropy, 4),
            "min_entropy": round(self.min_entropy, 4),
            "overall_severity": self.overall_severity,
            "severity_counts": self.severity_counts(),
            "blocks": [b.to_dict() for b in self.blocks],
        }


def scan_bytes(
    data: bytes,
    *,
    path: str = "<bytes>",
    block_size: int = DEFAULT_BLOCK_SIZE,
) -> ScanReport:
    """Scan an in-memory buffer and return a :class:`ScanReport`."""
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    blocks: List[BlockResult] = []
    n = len(data)
    idx = 0
    offset = 0
    while offset < n:
        chunk = data[offset:offset + block_size]
        ent = shannon_entropy(chunk)
        blocks.append(
            BlockResult(
                index=idx,
                offset=offset,
                size=len(chunk),
                entropy=round(ent, 4),
                severity=classify(ent),
            )
        )
        idx += 1
        offset += block_size
    return ScanReport(
        path=path,
        size=n,
        block_size=block_size,
        bytes_scanned=n,
        blocks=blocks,
        truncated=False,
    )


def scan_file(
    path: str,
    *,
    block_size: int = DEFAULT_BLOCK_SIZE,
    max_bytes: int = MAX_BYTES_DEFAULT,
) -> ScanReport:
    """Stream a file from disk and compute per-block entropy."""
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    total_size = os.path.getsize(path)
    blocks: List[BlockResult] = []
    idx = 0
    offset = 0
    scanned = 0
    truncated = False
    with open(path, "rb") as fh:
        while True:
            if scanned >= max_bytes:
                truncated = offset < total_size
                break
            to_read = min(block_size, max_bytes - scanned)
            chunk = fh.read(to_read)
            if not chunk:
                break
            ent = shannon_entropy(chunk)
            blocks.append(
                BlockResult(
                    index=idx,
                    offset=offset,
                    size=len(chunk),
                    entropy=round(ent, 4),
                    severity=classify(ent),
                )
            )
            idx += 1
            offset += len(chunk)
            scanned += len(chunk)
    return ScanReport(
        path=path,
        size=total_size,
        block_size=block_size,
        bytes_scanned=scanned,
        blocks=blocks,
        truncated=truncated,
    )


def scan(target: str, *, block_size: int = DEFAULT_BLOCK_SIZE,
         max_bytes: int = MAX_BYTES_DEFAULT) -> ScanReport:
    """Convenience alias for :func:`scan_file` (used by the MCP server/SDK)."""
    return scan_file(target, block_size=block_size, max_bytes=max_bytes)


def to_json(report: "ScanReport", *, min_severity: str = "high") -> str:
    """Serialize a :class:`ScanReport` to the canonical JSON string.

    Mirrors the CLI's ``--format json`` payload so SDK/MCP consumers and the
    command line speak exactly the same shape.
    """
    import json as _json
    payload = report.to_dict()
    payload["tool"] = TOOL_NAME
    payload["version"] = TOOL_VERSION
    payload["min_severity"] = min_severity
    payload["flagged_regions"] = report.regions(min_severity)
    payload["flagged"] = bool(report.regions(min_severity))
    return _json.dumps(payload, indent=2)


__all__ = [
    "TOOL_NAME", "TOOL_VERSION",
    "CRITICAL_THRESHOLD", "HIGH_THRESHOLD", "MEDIUM_THRESHOLD",
    "SEVERITY_ORDER", "DEFAULT_BLOCK_SIZE", "MAX_BYTES_DEFAULT",
    "shannon_entropy", "classify", "BlockResult", "ScanReport",
    "scan_bytes", "scan_file", "scan", "to_json",
]

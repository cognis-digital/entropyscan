"""Command-line interface for ENTROPYSCAN.

Subcommand:
    scan PATH [--block-size N] [--min-severity LEVEL] [--format {table,json,html}]
              [--output FILE] [--max-bytes N]

Exit codes:
    0  scan succeeded, nothing met the flag threshold
    1  one or more regions met/exceeded --min-severity (findings)
    2  usage / runtime error (missing file, bad args, etc.)
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    DEFAULT_BLOCK_SIZE,
    MAX_BYTES_DEFAULT,
    SEVERITY_ORDER,
    ScanReport,
    scan_file,
)

SEVERITY_COLORS = {
    "low": "#2e7d32",
    "medium": "#f9a825",
    "high": "#ef6c00",
    "critical": "#c62828",
}


def _bar(entropy: float, width: int = 20) -> str:
    filled = int(round((entropy / 8.0) * width))
    filled = max(0, min(width, filled))
    return "#" * filled + "-" * (width - filled)


def render_table(report: ScanReport, min_severity: str) -> str:
    lines: List[str] = []
    lines.append(f"ENTROPYSCAN {TOOL_VERSION} - {report.path}")
    lines.append(
        f"size={report.size}B  block={report.block_size}B  "
        f"blocks={len(report.blocks)}  scanned={report.bytes_scanned}B"
        + ("  [TRUNCATED]" if report.truncated else "")
    )
    lines.append(
        f"entropy  mean={report.mean_entropy:.3f}  max={report.max_entropy:.3f}  "
        f"min={report.min_entropy:.3f}  overall={report.overall_severity.upper()}"
    )
    counts = report.severity_counts()
    lines.append(
        "counts   "
        + "  ".join(f"{k}={counts[k]}" for k in ("low", "medium", "high", "critical"))
    )
    lines.append("")

    regions = report.regions(min_severity)
    if regions:
        lines.append(f"Flagged regions (>= {min_severity}):")
        lines.append(f"  {'range':<24}{'sev':<10}{'maxH':<8}blocks")
        for r in regions:
            rng = f"0x{r['start']:08x}-0x{r['end']:08x}"
            lines.append(
                f"  {rng:<24}{r['severity']:<10}{r['max_entropy']:<8.3f}{r['blocks']}"
            )
        lines.append("")
    else:
        lines.append(f"No regions at or above '{min_severity}'.")
        lines.append("")

    lines.append("Block map:")
    lines.append(f"  {'offset':<12}{'H(bits)':<10}{'sev':<10}profile")
    for b in report.blocks:
        lines.append(
            f"  0x{b.offset:08x}  {b.entropy:<8.3f}  {b.severity:<8}  "
            f"[{_bar(b.entropy)}]"
        )
    return "\n".join(lines)


_SARIF_LEVEL = {
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}


def render_sarif(report: ScanReport, min_severity: str) -> str:
    """Render flagged regions as SARIF 2.1.0 (code-scanning compatible).

    Each coalesced high-entropy region becomes one result, located by byte
    range so GitHub code-scanning / any SARIF viewer can ingest it.
    """
    regions = report.regions(min_severity)
    results = []
    for i, r in enumerate(regions):
        results.append({
            "ruleId": "entropyscan/high-entropy-region",
            "level": _SARIF_LEVEL.get(r["severity"], "warning"),
            "message": {
                "text": (
                    f"High-entropy region ({r['severity']}, "
                    f"max {r['max_entropy']:.3f} bits/byte over "
                    f"{r['blocks']} block(s)) at bytes "
                    f"{r['start']}-{r['end']}. Indicates packed, encrypted, "
                    f"or compressed content."
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": report.path},
                    "region": {
                        "byteOffset": r["start"],
                        "byteLength": r["end"] - r["start"],
                    },
                }
            }],
            "properties": {
                "severity": r["severity"],
                "maxEntropy": round(r["max_entropy"], 4),
                "blocks": r["blocks"],
            },
            "partialFingerprints": {
                "regionIndex": str(i),
                "byteRange": f"{r['start']}-{r['end']}",
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": "https://github.com/cognis-digital/entropyscan",
                    "rules": [{
                        "id": "entropyscan/high-entropy-region",
                        "name": "HighEntropyRegion",
                        "shortDescription": {
                            "text": "Packed/encrypted/high-entropy region"
                        },
                        "fullDescription": {
                            "text": (
                                "A contiguous region whose Shannon entropy "
                                "meets or exceeds the configured severity "
                                "threshold, indicating compressed, encrypted, "
                                "or packed content."
                            )
                        },
                        "helpUri": "https://github.com/cognis-digital/entropyscan",
                        "defaultConfiguration": {"level": "error"},
                    }],
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def render_json(report: ScanReport, min_severity: str) -> str:
    payload = report.to_dict()
    payload["tool"] = TOOL_NAME
    payload["version"] = TOOL_VERSION
    payload["min_severity"] = min_severity
    payload["flagged_regions"] = report.regions(min_severity)
    payload["flagged"] = bool(report.regions(min_severity))
    return json.dumps(payload, indent=2)


def render_html(report: ScanReport, min_severity: str) -> str:
    counts = report.severity_counts()
    regions = report.regions(min_severity)
    esc = html.escape
    overall = report.overall_severity

    region_rows = ""
    if regions:
        for r in regions:
            color = SEVERITY_COLORS[r["severity"]]
            region_rows += (
                "<tr>"
                f"<td class='mono'>0x{r['start']:08x} &ndash; 0x{r['end']:08x}</td>"
                f"<td><span class='badge' style='background:{color}'>"
                f"{esc(r['severity'].upper())}</span></td>"
                f"<td>{r['max_entropy']:.3f}</td>"
                f"<td>{r['blocks']}</td>"
                "</tr>"
            )
    else:
        region_rows = (
            "<tr><td colspan='4' class='muted'>No regions at or above "
            f"'{esc(min_severity)}'.</td></tr>"
        )

    block_rows = ""
    for b in report.blocks:
        color = SEVERITY_COLORS[b.severity]
        pct = max(0.0, min(100.0, (b.entropy / 8.0) * 100.0))
        block_rows += (
            "<tr>"
            f"<td class='mono'>0x{b.offset:08x}</td>"
            f"<td>{b.entropy:.3f}</td>"
            f"<td><span class='badge' style='background:{color}'>"
            f"{esc(b.severity.upper())}</span></td>"
            f"<td class='barcell'><div class='bar'><div class='fill' "
            f"style='width:{pct:.1f}%;background:{color}'></div></div></td>"
            "</tr>"
        )

    overall_color = SEVERITY_COLORS[overall]
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ENTROPYSCAN report - {esc(report.path)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         margin: 0; padding: 2rem; background: #0f1115; color: #e6e6e6; }}
  h1 {{ font-size: 1.4rem; margin: 0 0 .25rem; }}
  .sub {{ color: #9aa0a6; font-size: .85rem; margin-bottom: 1.5rem; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; }}
  .card {{ background: #1a1d24; border: 1px solid #2a2f3a; border-radius: 10px;
          padding: 1rem 1.25rem; min-width: 120px; }}
  .card .k {{ font-size: .7rem; text-transform: uppercase; letter-spacing: .05em;
             color: #9aa0a6; }}
  .card .v {{ font-size: 1.5rem; font-weight: 600; margin-top: .25rem; }}
  table {{ width: 100%; border-collapse: collapse; background: #1a1d24;
           border-radius: 10px; overflow: hidden; margin-bottom: 1.5rem; }}
  th, td {{ padding: .5rem .75rem; text-align: left; border-bottom: 1px solid #2a2f3a;
           font-size: .85rem; }}
  th {{ background: #20242e; color: #c8cdd6; font-weight: 600; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
  .badge {{ color: #fff; padding: .1rem .5rem; border-radius: 999px;
            font-size: .7rem; font-weight: 700; }}
  .muted {{ color: #9aa0a6; }}
  .barcell {{ width: 50%; }}
  .bar {{ background: #2a2f3a; border-radius: 4px; height: 12px; overflow: hidden; }}
  .fill {{ height: 100%; }}
  h2 {{ font-size: 1rem; margin: 1.5rem 0 .5rem; }}
  .pill {{ display:inline-block; color:#fff; padding:.15rem .6rem;
           border-radius:999px; font-weight:700; background:{overall_color}; }}
</style></head>
<body>
  <h1>ENTROPYSCAN report</h1>
  <div class="sub mono">{esc(report.path)} &mdash; {report.size:,} bytes &mdash; "
  f"block {report.block_size} B {'(truncated)' if report.truncated else ''}</div>
  <div class="cards">
    <div class="card"><div class="k">Overall</div>
      <div class="v"><span class="pill">{esc(overall.upper())}</span></div></div>
    <div class="card"><div class="k">Mean H</div><div class="v">{report.mean_entropy:.3f}</div></div>
    <div class="card"><div class="k">Max H</div><div class="v">{report.max_entropy:.3f}</div></div>
    <div class="card"><div class="k">Blocks</div><div class="v">{len(report.blocks)}</div></div>
    <div class="card"><div class="k">Critical</div><div class="v">{counts['critical']}</div></div>
    <div class="card"><div class="k">High</div><div class="v">{counts['high']}</div></div>
  </div>

  <h2>Flagged regions (&ge; {esc(min_severity)})</h2>
  <table>
    <thead><tr><th>Range</th><th>Severity</th><th>Max H</th><th>Blocks</th></tr></thead>
    <tbody>{region_rows}</tbody>
  </table>

  <h2>Block entropy map</h2>
  <table>
    <thead><tr><th>Offset</th><th>H (bits/byte)</th><th>Severity</th><th>Profile</th></tr></thead>
    <tbody>{block_rows}</tbody>
  </table>
  <div class="sub">Generated by {esc(TOOL_NAME)} {esc(TOOL_VERSION)}. "
  f"High Shannon entropy (&rarr;8.0 bits/byte) suggests compressed, encrypted, or packed data.</div>
</body></html>"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Flag packed/encrypted/high-entropy regions in files you own.",
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan a file for high-entropy regions.")
    scan.add_argument("path", help="File to analyze.")
    scan.add_argument(
        "--block-size", type=int, default=DEFAULT_BLOCK_SIZE,
        help=f"Window size in bytes (default {DEFAULT_BLOCK_SIZE}).",
    )
    scan.add_argument(
        "--min-severity", choices=list(SEVERITY_ORDER), default="high",
        help="Severity that counts as a finding / triggers exit 1 (default high).",
    )
    scan.add_argument(
        "--format", choices=["table", "json", "html", "sarif"], default="table",
        help="Output format (default table). 'html' writes a shareable report; "
             "'sarif' emits SARIF 2.1.0 for code-scanning / CI.",
    )
    scan.add_argument(
        "--output", "-o", default=None,
        help="Write report to FILE instead of stdout.",
    )
    scan.add_argument(
        "--max-bytes", type=int, default=MAX_BYTES_DEFAULT,
        help="Cap bytes read from the file (safety limit).",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    try:
        report = scan_file(
            args.path,
            block_size=args.block_size,
            max_bytes=args.max_bytes,
        )
    except FileNotFoundError:
        print(f"{TOOL_NAME}: error: no such file: {args.path}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"{TOOL_NAME}: error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        out = render_json(report, args.min_severity)
    elif args.format == "sarif":
        out = render_sarif(report, args.min_severity)
    elif args.format == "html":
        out = render_html(report, args.min_severity)
    else:
        out = render_table(report, args.min_severity)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(out)
        except OSError as exc:
            print(f"{TOOL_NAME}: error: {exc}", file=sys.stderr)
            return 2
        print(f"{TOOL_NAME}: wrote {args.format} report to {args.output}",
              file=sys.stderr)
    else:
        print(out)

    flagged = bool(report.regions(args.min_severity))
    return 1 if flagged else 0


if __name__ == "__main__":
    raise SystemExit(main())

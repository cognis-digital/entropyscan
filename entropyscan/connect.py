"""Native cognis-connect emit for entropyscan — forward findings to any platform.

Maps entropyscan's JSON output to the canonical `Finding` and forwards it via
`cognis-connect` (STIX/TAXII, MISP, Sigma, Splunk, Elastic, Slack/Discord, webhook, or a
`/v1` brief). cognis-connect is a soft dependency:
    pip install "git+https://github.com/cognis-digital/cognis-connect.git"

Usage:
    entropyscan ... --format json | entropyscan-emit --to stix
    entropyscan-emit --to slack --url $WEBHOOK --dry-run < findings.json
"""

from __future__ import annotations

import argparse
import json
import sys

SOURCE = "entropyscan"


def map_record(rec: dict) -> dict:
    """Tool-specific mapping (fleet-contributed, validated; safe-fallback)."""
    try:
        out = dict(rec)
        out.pop('block', None)
        out.pop('blocks', None)
        out.pop('path', None)
        out.pop('size', None)
        out.pop('block_size', None)
        out.pop('bytes_scanned', None)
        out.pop('truncated', None)
        out.pop('mean_entropy', None)
        out.pop('max_entropy', None)
        out.pop('min_entropy', None)
        out.pop('ov', None)
        out['title'] = f"High Entropy Region in {rec.get('path', 'unknown')}"
        out['severity'] = 'high'
        out['type'] = 'entropy'
        out['description'] = f"Detected high entropy region with value {rec.get('max_entropy', 0.0):.3f}"
        out['tags'] = ['entropy', 'high']
        out['ipv4'] = rec.get('ipv4')
        out['domain'] = rec.get('domain')
        out['url'] = rec.get('url')
        out['sha256'] = rec.get('sha256')
        out['cve'] = rec.get('cve')
        out['imo'] = rec.get('imo')
        out['mmsi'] = rec.get('mmsi')
        out['lat'] = rec.get('lat')
        out['lon'] = rec.get('lon')
        return out
    except Exception:
        return rec


def _findings(text: str):
    from cognis_connect.findings import normalize, load
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return load(text, source=SOURCE)
    if isinstance(data, dict):
        data = data.get("findings") or data.get("results") or data.get("watchlist") or [data]
    return [normalize(map_record(r), source=SOURCE) if isinstance(r, dict) else r for r in data]


def emit_main(argv=None) -> int:
    p = argparse.ArgumentParser(prog=f"{SOURCE}-emit",
                                description=f"forward {SOURCE} JSON findings to a platform via cognis-connect")
    p.add_argument("--to", required=True,
                   choices=["stix", "taxii", "misp", "sigma", "splunk", "elastic",
                            "slack", "discord", "webhook", "brief", "findings"])
    p.add_argument("input", nargs="?", default="-", help="findings JSON file (default: stdin)")
    p.add_argument("--url", default=None)
    p.add_argument("--token", default=None)
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args(argv)
    try:
        from cognis_connect import misp, notify, sigma, siem, stix, edgemesh
    except ImportError:
        print("needs cognis-connect: pip install "
              "git+https://github.com/cognis-digital/cognis-connect.git", file=sys.stderr)
        return 1
    text = sys.stdin.read() if a.input == "-" else open(a.input, encoding="utf-8").read()
    fs = _findings(text)
    try:
        if a.to == "stix":
            print(json.dumps(stix.to_bundle(fs), indent=2))
        elif a.to == "taxii":
            print(json.dumps(stix.push_taxii(fs, a.url, token=a.token, dry_run=a.dry_run), indent=2))
        elif a.to == "misp":
            print(json.dumps(misp.push(fs, a.url, a.token or "", dry_run=a.dry_run) if a.url
                             else misp.to_event(fs), indent=2))
        elif a.to == "sigma":
            print(sigma.to_rules(fs))
        elif a.to == "splunk":
            print(json.dumps(siem.send_splunk(fs, a.url, a.token or "", dry_run=a.dry_run), indent=2))
        elif a.to == "elastic":
            print(json.dumps(siem.send_elastic(fs, a.url, token=a.token, dry_run=a.dry_run), indent=2))
        elif a.to == "slack":
            print(json.dumps(notify.send_slack(fs, a.url, dry_run=a.dry_run), indent=2))
        elif a.to == "discord":
            print(json.dumps(notify.send_discord(fs, a.url, dry_run=a.dry_run), indent=2))
        elif a.to == "webhook":
            print(json.dumps(siem.send_webhook(fs, a.url, token=a.token, dry_run=a.dry_run), indent=2))
        elif a.to == "brief":
            print(edgemesh.summarize(fs, base=a.url))
        elif a.to == "findings":
            from cognis_connect.findings import dump
            print(dump(fs))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(emit_main())

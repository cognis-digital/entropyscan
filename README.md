<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=ENTROPYSCAN&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="ENTROPYSCAN"/>

# ENTROPYSCAN

### Flag packed/encrypted/high-entropy regions in files

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Flag+packedencryptedhighentropy+regions+in+files;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-entropyscan.svg?color=6b46c1)](https://pypi.org/project/cognis-entropyscan/) [![CI](https://github.com/cognis-digital/entropyscan/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/entropyscan/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*Part of the Cognis Neural Suite.*

</div>

```bash
pip install cognis-entropyscan
entropyscan scan suspicious.bin     # → flagged high-entropy regions in seconds
```

> **What it does, precisely.** `entropyscan` slides a fixed-size window across a
> file and measures the **Shannon entropy** of each block in *bits per byte*
> (0.0 → 8.0). Random, encrypted, compressed, or packed data trends toward 8.0;
> structured data (code, text, tables, zero-padding) sits well below. Blocks are
> classified `low / medium / high / critical`, consecutive flagged blocks are
> coalesced into **byte-offset regions**, and the result is emitted as a table,
> JSON, a shareable HTML report, or **SARIF 2.1.0** for code-scanning. It is
> **passive and offline** — it reads a file you point it at and never opens a
> network connection.


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ entropyscan-emit --version
entropyscan 0.4.0
```

```console
$ entropyscan-emit --help
usage: entropyscan [-h] [--version] {scan,mcp} ...

Flag packed/encrypted/high-entropy regions in files you own.

positional arguments:
  {scan,mcp}
    scan      Scan a file for high-entropy regions.
    mcp       Run the MCP stdio server (exposes scan() as an MCP tool).
              Requires the optional 'mcp' extra.

options:
  -h, --help  show this help message and exit
  --version   show program's version number and exit
```

> Blocks above are real `entropyscan` output — reproduce them from a clone.

**Sample result format** _(illustrative values — run on your own data for real findings):_

```
{
"feed": {
"type": "STIX",
"data": [
{
"id": "12345",
"created_by_ref": "user1",
"modified_by_ref": "user2",
"created": "2023-02-15T14:30:00Z",
"modified": "2023-02-15T14:30:01Z",
"feed_name": "My Feed",
"spec_version": "2.0",
"objects": [
{
"id": "obj1",
"type": "indicator",
"name": "Example Indicator",
"description": "This is an example indicator.",
"created_by_ref": "user1",
"modified_by_ref": "user2",
"created": "2023-02-15T14:30:00Z",
"modified": "2023-02-15T14:30:01Z",
"labels": ["example", "test"],
"observables": [
{
"type": "url",
"value": "https://www.example.com"
}
]
}
]
}
]
}
```

<!-- cognis:example:end -->

## Usage — step by step

1. **Install** the CLI:

   ```bash
   pipx install "git+https://github.com/cognis-digital/entropyscan.git"
   ```

2. **Scan** a file for high-entropy regions (packed/encrypted/embedded-secret indicators) — the primary command:

   ```bash
   entropyscan scan suspicious.bin
   ```

3. **Tune sensitivity** — adjust the analysis window and the severity that counts as a finding:

   ```bash
   entropyscan scan suspicious.bin --block-size 4096 --min-severity medium
   ```

4. **Read the output** — `entropyscan` exits `1` when flagged regions are found (else `0`). Emit JSON or write a shareable HTML report:

   ```bash
   entropyscan scan suspicious.bin --format json  -o report.json
   entropyscan scan suspicious.bin --format html  -o report.html
   entropyscan scan suspicious.bin --format sarif -o report.sarif   # code-scanning
   ```

5. **Automate in CI** — gate artifacts on high-entropy content:

   ```bash
   entropyscan scan build/artifact.bin --min-severity high
   # exit 1 => high-entropy region detected => job fails
   ```

## Contents

- [Why entropyscan?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Demos](#demos) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Scope & safety](#scope) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why entropyscan?

Flag packed/encrypted/high-entropy regions in files — without standing up heavyweight infrastructure.

`entropyscan` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ **Per-block Shannon entropy** (bits/byte, 0–8) with a sliding window (`--block-size`)
- ✅ **Four-level severity** (`low / medium / high / critical`) with forensic-standard thresholds (5.5 / 6.8 / 7.5)
- ✅ **Region coalescing** — consecutive flagged blocks merged into byte-offset regions
- ✅ Output as **table · JSON · self-contained HTML report · SARIF 2.1.0** (GitHub code-scanning ready)
- ✅ **CI-friendly exit codes** (`0` clean / `1` finding / `2` error) gated by `--min-severity`
- ✅ **Streaming + safety cap** (`--max-bytes`) — handles large files without loading them whole
- ✅ 10 real-use-case [demos](#demos), each **verified by the test suite** to fire (or not) as documented
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer · **air-gapped** (stdlib only, no network)
- ✅ Real, CI-built ports in **Python, JavaScript/Node, Go, and Rust** (`ports/`) — each mirrors `scan` and shares the JSON shape + exit codes

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-entropyscan
entropyscan --version
entropyscan scan suspicious.bin                       # human-readable table
entropyscan scan suspicious.bin --format json         # machine-readable
entropyscan scan suspicious.bin --min-severity high   # CI gate (exit 1 on finding)
```

**CLI surface (one subcommand, `scan`):**

| Flag | Default | Meaning |
|---|---|---|
| `path` | — | File to analyze (positional) |
| `--block-size N` | `4096` | Window size in bytes |
| `--min-severity {low,medium,high,critical}` | `high` | Severity that counts as a finding / triggers exit `1` |
| `--format {table,json,html,sarif}` | `table` | Output format |
| `--output, -o FILE` | stdout | Write the report to a file |
| `--max-bytes N` | `268435456` | Cap bytes read (safety limit) |

**Exit codes:** `0` = clean · `1` = a region met/exceeded `--min-severity` · `2` = usage/IO error.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

Real output against the bundled `demos/04-packed-elf/sample.bin` (a UPX-style
packed executable: low-entropy stub followed by a compressed body):

```text
$ entropyscan scan demos/04-packed-elf/sample.bin
ENTROPYSCAN 0.4.0 - demos/04-packed-elf/sample.bin
size=24934B  block=4096B  blocks=7  scanned=24934B
entropy  mean=7.833  max=7.965  min=7.466  overall=CRITICAL
counts   low=0  medium=0  high=1  critical=6

Flagged regions (>= high):
  range                   sev       maxH    blocks
  0x00000000-0x00006166   critical  7.965   7

Block map:
  offset      H(bits)   sev       profile
  0x00000000  7.584     critical  [###################-]
  0x00001000  7.954     critical  [####################]
  ...
```

The same scan as JSON (truncated) — note the byte-offset `flagged_regions` and
the per-block map that downstream tooling can ingest:

```text
$ entropyscan scan demos/04-packed-elf/sample.bin --format json
{
  "tool": "entropyscan",
  "version": "0.4.0",
  "path": "demos/04-packed-elf/sample.bin",
  "size": 24934,
  "mean_entropy": 7.8328,
  "max_entropy": 7.9646,
  "overall_severity": "critical",
  "severity_counts": { "low": 0, "medium": 0, "high": 1, "critical": 6 },
  "min_severity": "high",
  "flagged": true,
  "flagged_regions": [
    { "start": 0, "end": 24934, "max_entropy": 7.9646, "severity": "critical", "blocks": 7 }
  ],
  "blocks": [ { "index": 0, "offset": 0, "size": 4096, "entropy": 7.5841, "severity": "critical" }, ... ]
}
```

A clean text artifact (`demos/08-clean-release/artifact.txt`) produces
`overall=LOW`, no flagged regions, and exit code `0`.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="demos"></a>
## Demos — real triage scenarios

Each folder under [`demos/`](demos/) is a self-contained, **authorized-use**
scenario: a realistic input file in the tool's real input format plus a
`SCENARIO.md` that explains where the data came from, the exact command to
run, what to expect, and how to act on the finding. Every demo input is
synthetic and seeded (no real malware, hashes, or credentials), and each one
is verified by the test suite to actually produce its documented result.

| Demo | Scenario | Fires at `high`? |
|---|---|:---:|
| [`01-basic`](demos/01-basic/) | Firmware blob with a packed tail | ✅ |
| [`02-clean`](demos/02-clean/) | Plain text — negative control | — |
| [`03-mixed`](demos/03-mixed/) | Mixed low/high regions | ✅ |
| [`04-packed-elf`](demos/04-packed-elf/) | UPX-style packed executable (stub + compressed body) | ✅ |
| [`05-office-macro`](demos/05-office-macro/) | OLE2 document hiding a compressed macro stream | ✅ |
| [`06-pcap-tls`](demos/06-pcap-tls/) | Packet capture with an encrypted exfil flow | ✅ |
| [`07-leaked-secret`](demos/07-leaked-secret/) | Config bundle that leaked a binary keystore | ✅ |
| [`08-clean-release`](demos/08-clean-release/) | Clean release artifact — negative control | — |
| [`09-stego-carrier`](demos/09-stego-carrier/) | Image with data hidden past `IEND` | ✅ |
| [`10-memory-dump`](demos/10-memory-dump/) | Process dump with an injected high-entropy region | ✅ |

```bash
# Regenerate every demo input deterministically
python demos/_make_all.py

# Run one and read the result
python -m entropyscan scan demos/04-packed-elf/sample.bin
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[target / manifest] --> P[entropyscan<br/>checks + rules]
  P --> OUT[findings (JSON / SARIF)]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`entropyscan` is interoperable with every popular way of using AI:

- **MCP server** — `entropyscan mcp` exposes `scan()` as an MCP tool over stdio (install the extra: `pip install "cognis-entropyscan[mcp]"`) for Claude Desktop, Cursor, Cognis.Studio, and the [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet)
- **OpenAI-compatible / JSON** — pipe `entropyscan scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis entropyscan** | typical tools |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust), CI-built | ✅ | ❌ |
| Passive / offline / air-gap-ready | ✅ | varies |
| Open license | ✅ COCL | varies |
<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`entropyscan mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/entropyscan.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/entropyscan.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/entropyscan.git" # uv
pip install cognis-entropyscan                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/entropyscan:latest --help        # Docker
brew install cognis-digital/tap/entropyscan                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/entropyscan/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/entropyscan` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools


**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `entropyscan` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`entropyscan` composes with the Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

<a name="scope"></a>
## Scope, safety & air-gap

`entropyscan` is a **defensive, authorized-use** analysis tool.

- **Passive and offline by design.** It reads a single local file you point it
  at and computes statistics. It performs **no active scanning**, opens **no
  network connections**, sends **no telemetry**, and executes nothing from the
  files it inspects. The Python core and all ports depend only on their
  language standard library.
- **Air-gap / edge friendly.** Because there are no network calls and no
  external data dependencies, `entropyscan` runs unchanged on a fully
  disconnected host. `pip install` from a local wheel (or clone the repo and run
  `python -m entropyscan`), and the polyglot ports compile to a single static
  binary you can copy onto an isolated machine.
- **High entropy is a signal, not a verdict.** A flagged region means the bytes
  are statistically indistinguishable from random — which is *expected* for
  legitimately compressed or encrypted content (archives, media, TLS, signed
  blobs). Treat findings as triage leads, confirm with format-aware tooling, and
  only analyze artifacts you are **authorized** to inspect.
- **No fabricated intelligence.** Demo inputs are synthetic, seeded, and contain
  no real malware, hashes, or credentials. The tool ships no CVE/vuln database
  and makes no threat-intel claims of its own.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>

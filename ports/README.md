# Ports of entropyscan

The **same entropy-scanning engine**, ported across languages so you can drop
`entropyscan` into any stack or ship a single static binary. Every port mirrors
the Python reference CLI:

```
entropyscan scan FILE [--block-size N] [--min-severity low|medium|high|critical] [--format table|json]
```

All ports compute Shannon entropy per fixed-size window (bits/byte, 0..8),
classify each block (`low` < 5.5 ≤ `medium` < 6.8 ≤ `high` < 7.5 ≤ `critical`),
coalesce flagged blocks into byte-offset **regions**, and emit the same JSON
shape (`tool`, `version`, `path`, `severity_counts`, `flagged_regions`, …).
They share the reference exit-code contract:

| Exit | Meaning |
|---|---|
| `0` | clean — nothing met `--min-severity` |
| `1` | one or more regions met/exceeded `--min-severity` (finding) |
| `2` | usage / IO error |

All ports are **passive and offline**: they read a single local file and never
open a network socket.

| Language | Path | Build / Run | Tests |
|---|---|---|---|
| Python (reference) | [`../entropyscan/`](../entropyscan/) | `entropyscan scan file.bin` | `pytest` |
| JavaScript / Node | [`javascript/`](javascript/) | `node ports/javascript/index.js scan file.bin` | `node --test` |
| Go | [`go/`](go/) | `cd ports/go && go run . scan ../../file.bin` | `go test ./...` |
| Rust | [`rust/`](rust/) | `cd ports/rust && cargo run -- scan ../../file.bin` | `cargo test` |

### Verified in CI

Every port is built and tested on each push by
[`.github/workflows/ports.yml`](../.github/workflows/ports.yml) — Node
(`node --test`), Go (`go vet` + `go test` + `go build`), and Rust
(`cargo test` + `cargo build --release`). These are real, compiling programs
with their own unit tests, not stubs.

### Example (any port)

```bash
$ node ports/javascript/index.js scan ../../demos/04-packed-elf/sample.bin --format json
{
  "tool": "entropyscan",
  "version": "0.4.0",
  "overall_severity": "critical",
  "flagged": true,
  "flagged_regions": [ { "start": 4096, "end": 16384, "severity": "critical", ... } ],
  ...
}
```

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see
[../CONTRIBUTING.md](../CONTRIBUTING.md).

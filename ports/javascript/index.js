#!/usr/bin/env node
// entropyscan — JavaScript/Node port of the Cognis entropy scanner.
//
// Zero third-party dependencies (Node stdlib only). Mirrors the Python
// reference CLI: slide a fixed-size window over a file, score each block by
// Shannon entropy (bits/byte, 0..8), classify by severity, coalesce flagged
// blocks into regions, emit table or JSON. Passive/offline only — reads a
// local file and never touches the network.
//
//   node index.js scan FILE [--block-size N] [--min-severity LEVEL] [--format table|json]
//
// Exit codes: 0 = clean, 1 = finding at/above --min-severity, 2 = usage/IO error.
import { readFileSync } from "fs";

export const TOOL_NAME = "entropyscan";
export const TOOL_VERSION = "0.4.0";
const CRITICAL = 7.5, HIGH = 6.8, MEDIUM = 5.5, DEFAULT_BLOCK = 4096;
const SEV_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };

export function shannonEntropy(buf) {
  if (!buf || buf.length === 0) return 0.0;
  const counts = new Array(256).fill(0);
  for (let i = 0; i < buf.length; i++) counts[buf[i]]++;
  const n = buf.length;
  let ent = 0.0;
  for (const c of counts) {
    if (c) {
      const p = c / n;
      ent -= p * Math.log2(p);
    }
  }
  return ent;
}

export function classify(e) {
  if (e >= CRITICAL) return "critical";
  if (e >= HIGH) return "high";
  if (e >= MEDIUM) return "medium";
  return "low";
}

const round4 = (f) => Math.round(f * 10000) / 10000;

export function scanBytes(buf, path = "<bytes>", blockSize = DEFAULT_BLOCK) {
  const bs = blockSize > 0 ? blockSize : DEFAULT_BLOCK;
  const blocks = [];
  const n = buf.length;
  let idx = 0;
  for (let offset = 0; offset < n; offset += bs) {
    const chunk = buf.subarray(offset, Math.min(offset + bs, n));
    const e = shannonEntropy(chunk);
    blocks.push({ index: idx++, offset, size: chunk.length, entropy: round4(e), severity: classify(e) });
  }
  return makeReport(blocks, path, n, bs, n);
}

export function scanFile(path, blockSize = DEFAULT_BLOCK) {
  const buf = readFileSync(path);
  return scanBytes(buf, path, blockSize);
}

function makeReport(blocks, path, size, blockSize, scanned) {
  const counts = { low: 0, medium: 0, high: 0, critical: 0 };
  let mean = 0, max = 0, min = blocks.length ? 8.0 : 0.0, overall = "low";
  for (const b of blocks) {
    counts[b.severity]++;
    mean += b.entropy;
    if (b.entropy > max) max = b.entropy;
    if (b.entropy < min) min = b.entropy;
    if (SEV_ORDER[b.severity] > SEV_ORDER[overall]) overall = b.severity;
  }
  mean = blocks.length ? round4(mean / blocks.length) : 0.0;
  const report = {
    tool: TOOL_NAME, version: TOOL_VERSION, path, size,
    block_size: blockSize, bytes_scanned: scanned, truncated: false,
    mean_entropy: mean, max_entropy: round4(max), min_entropy: round4(min),
    overall_severity: overall, severity_counts: counts, blocks,
  };
  report.regions = (minSeverity) => regionsOf(blocks, minSeverity);
  return report;
}

export function regionsOf(blocks, minSeverity) {
  const floor = SEV_ORDER[minSeverity];
  const out = [];
  let cur = null;
  for (const b of blocks) {
    if (SEV_ORDER[b.severity] >= floor) {
      if (!cur) {
        cur = { start: b.offset, end: b.offset + b.size, max_entropy: b.entropy, severity: b.severity, blocks: 1 };
      } else {
        cur.end = b.offset + b.size;
        cur.blocks++;
        if (b.entropy > cur.max_entropy) cur.max_entropy = b.entropy;
        if (SEV_ORDER[b.severity] > SEV_ORDER[cur.severity]) cur.severity = b.severity;
      }
    } else if (cur) {
      out.push(cur);
      cur = null;
    }
  }
  if (cur) out.push(cur);
  return out;
}

function renderTable(report, minSeverity) {
  const c = report.severity_counts;
  const lines = [
    `${TOOL_NAME} ${TOOL_VERSION} - ${report.path}`,
    `size=${report.size}B block=${report.block_size}B blocks=${report.blocks.length} scanned=${report.bytes_scanned}B`,
    `entropy mean=${report.mean_entropy.toFixed(3)} max=${report.max_entropy.toFixed(3)} min=${report.min_entropy.toFixed(3)} overall=${report.overall_severity}`,
    `counts  low=${c.low} medium=${c.medium} high=${c.high} critical=${c.critical}`,
  ];
  const regions = report.regions(minSeverity);
  if (regions.length) {
    lines.push(`flagged regions (>= ${minSeverity}):`);
    for (const r of regions) {
      lines.push(`  0x${r.start.toString(16).padStart(8, "0")}-0x${r.end.toString(16).padStart(8, "0")} ${r.severity} maxH=${r.max_entropy.toFixed(3)} blocks=${r.blocks}`);
    }
  } else {
    lines.push(`no regions at or above '${minSeverity}'.`);
  }
  return lines.join("\n");
}

function renderJson(report, minSeverity) {
  const regions = report.regions(minSeverity);
  const { regions: _fn, ...rest } = report;
  return JSON.stringify({ ...rest, min_severity: minSeverity, flagged: regions.length > 0, flagged_regions: regions }, null, 2);
}

export function run(argv) {
  if (argv[0] === "--version") {
    console.log(`${TOOL_NAME} ${TOOL_VERSION}`);
    return 0;
  }
  if (argv.length < 2 || argv[0] !== "scan") {
    process.stderr.write(`usage: ${TOOL_NAME} scan FILE [--block-size N] [--min-severity LEVEL] [--format table|json]\n`);
    return 2;
  }
  const path = argv[1];
  let blockSize = DEFAULT_BLOCK, minSeverity = "high", format = "table";
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === "--block-size") blockSize = parseInt(argv[++i], 10) || DEFAULT_BLOCK;
    else if (argv[i] === "--min-severity") minSeverity = argv[++i];
    else if (argv[i] === "--format") format = argv[++i];
  }
  if (!(minSeverity in SEV_ORDER)) {
    process.stderr.write(`${TOOL_NAME}: error: bad --min-severity '${minSeverity}'\n`);
    return 2;
  }
  let report;
  try {
    report = scanFile(path, blockSize);
  } catch (e) {
    process.stderr.write(`${TOOL_NAME}: error: ${e.message}\n`);
    return 2;
  }
  const flagged = report.regions(minSeverity).length > 0;
  console.log(format === "json" ? renderJson(report, minSeverity) : renderTable(report, minSeverity));
  return flagged ? 1 : 0;
}

const isMain = import.meta.url === `file://${process.argv[1]}` ||
  (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/")));
if (isMain) {
  process.exit(run(process.argv.slice(2)));
}

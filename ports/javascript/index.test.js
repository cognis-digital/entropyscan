// Smoke tests for the Node port. Run with: node --test
import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  shannonEntropy,
  classify,
  scanBytes,
  scanFile,
  regionsOf,
  run,
  TOOL_NAME,
} from "./index.js";

test("zero entropy for all-zero buffer", () => {
  assert.equal(shannonEntropy(Buffer.alloc(4096)), 0.0);
});

test("empty buffer is zero entropy", () => {
  assert.equal(shannonEntropy(Buffer.alloc(0)), 0.0);
});

test("uniform byte distribution approaches 8.0", () => {
  const data = Buffer.alloc(256 * 16);
  for (let i = 0; i < data.length; i++) data[i] = i % 256;
  assert.ok(Math.abs(shannonEntropy(data) - 8.0) < 1e-6);
});

test("classify thresholds", () => {
  assert.equal(classify(0.0), "low");
  assert.equal(classify(6.0), "medium");
  assert.equal(classify(7.0), "high");
  assert.equal(classify(7.9), "critical");
});

test("scanBytes block count", () => {
  const r = scanBytes(Buffer.from("A".repeat(1000)), "t.bin", 256);
  assert.equal(r.blocks.length, 4);
  assert.equal(r.bytes_scanned, 1000);
});

test("detects high-entropy region", () => {
  const parts = [Buffer.from("A".repeat(1024))];
  const rnd = Buffer.alloc(8192);
  for (let i = 0; i < rnd.length; i++) rnd[i] = (i * 167 + 13) % 256;
  parts.push(rnd);
  const r = scanBytes(Buffer.concat(parts), "mixed.bin", 4096);
  assert.ok(r.regions("high").length >= 1);
  assert.equal(r.overall_severity, "critical");
});

test("regionsOf coalesces consecutive flagged blocks", () => {
  const blocks = [
    { offset: 0, size: 10, entropy: 7.9, severity: "critical" },
    { offset: 10, size: 10, entropy: 7.0, severity: "high" },
    { offset: 20, size: 10, entropy: 1.0, severity: "low" },
  ];
  const regs = regionsOf(blocks, "high");
  assert.equal(regs.length, 1);
  assert.equal(regs[0].blocks, 2);
  assert.equal(regs[0].severity, "critical");
});

test("scanFile and run exit codes", () => {
  const clean = join(tmpdir(), "es_clean.bin");
  writeFileSync(clean, Buffer.alloc(4096));
  const r = scanFile(clean, 1024);
  assert.equal(r.size, 4096);
  assert.equal(run(["scan", clean, "--block-size", "1024", "--format", "json"]), 0);
  rmSync(clean);
  assert.equal(run(["scan", "/no/such/file/xyz.bin"]), 2);
  assert.equal(run(["--version"]), 0);
  assert.equal(TOOL_NAME, "entropyscan");
});

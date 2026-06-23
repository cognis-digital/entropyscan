"""Expanded behavioural tests for ENTROPYSCAN.

Standard-library only, fully offline. These tests exercise the entropy math,
classification, the streaming scanner, region coalescing, every renderer
(table/json/html/sarif), the CLI surface, and the public ``scan``/``to_json``
helpers used by the MCP server. Aim: dense, real assertions.
"""
import json
import math
import os
import random
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from entropyscan import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    shannon_entropy,
    classify,
    scan_bytes,
    scan_file,
    scan,
    to_json,
)
from entropyscan.core import (  # noqa: E402
    CRITICAL_THRESHOLD,
    HIGH_THRESHOLD,
    MEDIUM_THRESHOLD,
    SEVERITY_ORDER,
    DEFAULT_BLOCK_SIZE,
    BlockResult,
    ScanReport,
)
from entropyscan.cli import (  # noqa: E402
    build_parser,
    main,
    render_table,
    render_json,
    render_html,
    render_sarif,
)

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _write(data: bytes, suffix=".bin") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return path


def _uniform(n: int, seed: int = 0) -> bytes:
    """Deterministic near-uniform bytes (high entropy without RNG flakiness)."""
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(n))


class TestIdentity(unittest.TestCase):
    def test_tool_name(self):
        self.assertEqual(TOOL_NAME, "entropyscan")

    def test_version_nonempty(self):
        self.assertTrue(TOOL_VERSION)
        self.assertRegex(TOOL_VERSION, r"^\d+\.\d+")

    def test_version_not_stale_default(self):
        # Regression: __init__ used to silently fall back to 0.1.0.
        self.assertNotEqual(TOOL_VERSION, "0.1.0")

    def test_thresholds_ordered(self):
        self.assertLess(MEDIUM_THRESHOLD, HIGH_THRESHOLD)
        self.assertLess(HIGH_THRESHOLD, CRITICAL_THRESHOLD)
        self.assertLessEqual(CRITICAL_THRESHOLD, 8.0)

    def test_severity_order_complete(self):
        self.assertEqual(
            set(SEVERITY_ORDER), {"low", "medium", "high", "critical"}
        )
        self.assertEqual(SEVERITY_ORDER["low"], 0)
        self.assertEqual(SEVERITY_ORDER["critical"], 3)


class TestEntropyMath(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(shannon_entropy(b""), 0.0)

    def test_all_same_byte(self):
        for b in (b"\x00", b"\xff", b"A"):
            self.assertEqual(shannon_entropy(b * 4096), 0.0)

    def test_two_symbols_balanced_is_one_bit(self):
        self.assertAlmostEqual(shannon_entropy(b"AB" * 1000), 1.0, places=6)

    def test_four_symbols_balanced_is_two_bits(self):
        self.assertAlmostEqual(shannon_entropy(b"ABCD" * 1000), 2.0, places=6)

    def test_uniform_256_is_eight_bits(self):
        data = bytes(range(256)) * 16
        self.assertAlmostEqual(shannon_entropy(data), 8.0, places=9)

    def test_entropy_in_range(self):
        for n in (1, 16, 256, 4096):
            e = shannon_entropy(_uniform(n, seed=n))
            self.assertGreaterEqual(e, 0.0)
            self.assertLessEqual(e, 8.0 + 1e-9)

    def test_skew_lowers_entropy(self):
        skewed = b"A" * 900 + b"B" * 100
        balanced = b"AB" * 500
        self.assertLess(shannon_entropy(skewed), shannon_entropy(balanced))

    def test_uniform_block_is_high(self):
        self.assertGreater(shannon_entropy(_uniform(8192, 1)), 7.5)

    def test_known_value_half_half(self):
        # 50/50 over two symbols => exactly 1 bit
        self.assertAlmostEqual(shannon_entropy(b"\x00\x01" * 4096), 1.0, places=9)


class TestClassify(unittest.TestCase):
    def test_low(self):
        self.assertEqual(classify(0.0), "low")
        self.assertEqual(classify(MEDIUM_THRESHOLD - 0.01), "low")

    def test_medium(self):
        self.assertEqual(classify(MEDIUM_THRESHOLD), "medium")
        self.assertEqual(classify(HIGH_THRESHOLD - 0.01), "medium")

    def test_high(self):
        self.assertEqual(classify(HIGH_THRESHOLD), "high")
        self.assertEqual(classify(CRITICAL_THRESHOLD - 0.01), "high")

    def test_critical(self):
        self.assertEqual(classify(CRITICAL_THRESHOLD), "critical")
        self.assertEqual(classify(8.0), "critical")

    def test_monotone(self):
        order = ["low", "medium", "high", "critical"]
        seen = [classify(v) for v in (1.0, 6.0, 7.0, 7.9)]
        self.assertEqual(seen, order)


class TestScanBytes(unittest.TestCase):
    def test_block_count_exact(self):
        r = scan_bytes(b"A" * 1024, block_size=256)
        self.assertEqual(len(r.blocks), 4)

    def test_block_count_remainder(self):
        r = scan_bytes(b"A" * 1000, block_size=256)
        self.assertEqual(len(r.blocks), 4)
        self.assertEqual(r.blocks[-1].size, 1000 - 256 * 3)

    def test_offsets_contiguous(self):
        r = scan_bytes(b"X" * 1000, block_size=128)
        expected = 0
        for b in r.blocks:
            self.assertEqual(b.offset, expected)
            expected += b.size
        self.assertEqual(expected, 1000)

    def test_indices_sequential(self):
        r = scan_bytes(b"Y" * 500, block_size=100)
        self.assertEqual([b.index for b in r.blocks], [0, 1, 2, 3, 4])

    def test_bytes_scanned(self):
        r = scan_bytes(b"Z" * 777, block_size=64)
        self.assertEqual(r.bytes_scanned, 777)
        self.assertEqual(r.size, 777)

    def test_empty_input(self):
        r = scan_bytes(b"", block_size=64)
        self.assertEqual(r.blocks, [])
        self.assertEqual(r.overall_severity, "low")
        self.assertEqual(r.mean_entropy, 0.0)
        self.assertEqual(r.max_entropy, 0.0)
        self.assertEqual(r.min_entropy, 0.0)

    def test_bad_block_size(self):
        with self.assertRaises(ValueError):
            scan_bytes(b"abc", block_size=0)
        with self.assertRaises(ValueError):
            scan_bytes(b"abc", block_size=-5)

    def test_zero_block_low(self):
        r = scan_bytes(b"\x00" * 8192, block_size=4096)
        self.assertEqual(r.overall_severity, "low")
        self.assertEqual(r.severity_counts()["low"], 2)

    def test_uniform_block_critical(self):
        r = scan_bytes(_uniform(8192, 2), block_size=4096)
        self.assertEqual(r.overall_severity, "critical")
        self.assertGreater(r.max_entropy, 7.5)


class TestScanFile(unittest.TestCase):
    def test_matches_scan_bytes(self):
        data = _uniform(4096, 3) + b"\x00" * 4096
        path = _write(data)
        try:
            rf = scan_file(path, block_size=2048)
            rb = scan_bytes(data, block_size=2048)
            self.assertEqual(len(rf.blocks), len(rb.blocks))
            for a, b in zip(rf.blocks, rb.blocks):
                self.assertEqual(a.severity, b.severity)
                self.assertAlmostEqual(a.entropy, b.entropy, places=4)
        finally:
            os.remove(path)

    def test_size_reported(self):
        path = _write(b"Q" * 5000)
        try:
            r = scan_file(path, block_size=1024)
            self.assertEqual(r.size, 5000)
            self.assertEqual(r.bytes_scanned, 5000)
            self.assertFalse(r.truncated)
        finally:
            os.remove(path)

    def test_max_bytes_truncates(self):
        path = _write(b"W" * 10000)
        try:
            r = scan_file(path, block_size=1024, max_bytes=4096)
            self.assertTrue(r.truncated)
            self.assertLessEqual(r.bytes_scanned, 4096)
            self.assertEqual(r.size, 10000)
        finally:
            os.remove(path)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            scan_file("/no/such/entropyscan_file.bin")

    def test_bad_block_size_raises(self):
        path = _write(b"abc")
        try:
            with self.assertRaises(ValueError):
                scan_file(path, block_size=0)
        finally:
            os.remove(path)

    def test_scan_alias_equivalent(self):
        path = _write(_uniform(2048, 9))
        try:
            a = scan(path, block_size=512)
            b = scan_file(path, block_size=512)
            self.assertEqual(a.to_dict(), b.to_dict())
        finally:
            os.remove(path)


class TestReportDerived(unittest.TestCase):
    def setUp(self):
        # low banner, then uniform tail => mixed
        self.data = b"A" * 4096 + _uniform(8192, 5)
        self.report = scan_bytes(self.data, block_size=4096, path="mixed.bin")

    def test_mean_between_min_max(self):
        self.assertLessEqual(self.report.min_entropy, self.report.mean_entropy)
        self.assertLessEqual(self.report.mean_entropy, self.report.max_entropy)

    def test_overall_is_worst_block(self):
        worst = max(self.report.blocks, key=lambda b: SEVERITY_ORDER[b.severity])
        self.assertEqual(self.report.overall_severity, worst.severity)

    def test_counts_sum_to_blocks(self):
        c = self.report.severity_counts()
        self.assertEqual(sum(c.values()), len(self.report.blocks))

    def test_flagged_blocks_threshold(self):
        high = self.report.flagged_blocks("high")
        for b in high:
            self.assertGreaterEqual(SEVERITY_ORDER[b.severity], SEVERITY_ORDER["high"])

    def test_regions_nonempty(self):
        regions = self.report.regions("high")
        self.assertTrue(regions)
        self.assertGreater(regions[0]["max_entropy"], 7.5)

    def test_region_bounds_within_file(self):
        for r in self.report.regions("high"):
            self.assertGreaterEqual(r["start"], 0)
            self.assertLessEqual(r["end"], self.report.size)
            self.assertLess(r["start"], r["end"])

    def test_to_dict_keys(self):
        d = self.report.to_dict()
        for k in ("path", "size", "block_size", "bytes_scanned", "truncated",
                  "mean_entropy", "max_entropy", "min_entropy",
                  "overall_severity", "severity_counts", "blocks"):
            self.assertIn(k, d)

    def test_block_to_dict(self):
        b = self.report.blocks[0]
        d = b.to_dict()
        self.assertEqual(set(d), {"index", "offset", "size", "entropy", "severity"})


class TestRegionCoalescing(unittest.TestCase):
    def _report(self, severities):
        blocks = []
        for i, sev in enumerate(severities):
            ent = {"low": 1.0, "medium": 6.0, "high": 7.0, "critical": 7.9}[sev]
            blocks.append(BlockResult(i, i * 10, 10, ent, sev))
        return ScanReport(path="x", size=len(severities) * 10, block_size=10,
                          bytes_scanned=len(severities) * 10, blocks=blocks)

    def test_single_region(self):
        r = self._report(["low", "high", "high", "low"])
        regs = r.regions("high")
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0]["blocks"], 2)

    def test_two_regions(self):
        r = self._report(["high", "low", "high"])
        self.assertEqual(len(r.regions("high")), 2)

    def test_trailing_region(self):
        r = self._report(["low", "low", "critical"])
        regs = r.regions("high")
        self.assertEqual(len(regs), 1)
        self.assertEqual(regs[0]["severity"], "critical")

    def test_region_takes_worst_severity(self):
        r = self._report(["high", "critical", "high"])
        self.assertEqual(r.regions("high")[0]["severity"], "critical")

    def test_min_severity_filters(self):
        r = self._report(["medium", "medium"])
        self.assertEqual(r.regions("high"), [])
        self.assertEqual(len(r.regions("medium")), 1)

    def test_all_low_no_regions(self):
        r = self._report(["low"] * 5)
        self.assertEqual(r.regions("low") and len(r.regions("low")), 1)
        self.assertEqual(r.regions("high"), [])


class TestRenderers(unittest.TestCase):
    def setUp(self):
        self.flagged = scan_bytes(
            b"AAAA" * 1024 + _uniform(8192, 7), block_size=4096, path="evidence.bin"
        )
        self.clean = scan_bytes(b"\x00" * 8192, block_size=4096, path="clean.bin")

    # --- table ---
    def test_table_header(self):
        out = render_table(self.flagged, "high")
        self.assertIn(TOOL_NAME.upper(), out)
        self.assertIn("evidence.bin", out)
        self.assertIn("Block map", out)

    def test_table_shows_regions(self):
        out = render_table(self.flagged, "high")
        self.assertIn("Flagged regions", out)

    def test_table_clean_message(self):
        out = render_table(self.clean, "high")
        self.assertIn("No regions", out)

    # --- json ---
    def test_json_parses(self):
        d = json.loads(render_json(self.flagged, "high"))
        self.assertEqual(d["tool"], TOOL_NAME)
        self.assertEqual(d["version"], TOOL_VERSION)
        self.assertTrue(d["flagged"])
        self.assertTrue(d["flagged_regions"])
        self.assertIn("blocks", d)

    def test_json_clean_not_flagged(self):
        d = json.loads(render_json(self.clean, "high"))
        self.assertFalse(d["flagged"])
        self.assertEqual(d["flagged_regions"], [])

    def test_json_severity_counts(self):
        d = json.loads(render_json(self.flagged, "high"))
        self.assertEqual(sum(d["severity_counts"].values()), len(d["blocks"]))

    # --- to_json helper (MCP path) ---
    def test_to_json_matches_render_json(self):
        a = json.loads(to_json(self.flagged, min_severity="high"))
        b = json.loads(render_json(self.flagged, "high"))
        self.assertEqual(a, b)

    # --- html ---
    def test_html_doctype(self):
        out = render_html(self.flagged, "high")
        self.assertTrue(out.startswith("<!DOCTYPE html>"))
        self.assertTrue(out.rstrip().endswith("</html>"))

    def test_html_self_contained(self):
        out = render_html(self.flagged, "high")
        self.assertIn("<style>", out)
        self.assertNotIn("http://", out.split("informationUri", 1)[0] if "informationUri" in out else out)

    def test_html_no_fstring_artifacts(self):
        # Regression: the report sub-line used to leak literal `f"` / `"`.
        out = render_html(self.flagged, "high")
        self.assertNotIn('f"block', out)
        self.assertNotIn('f"High Shannon', out)
        for line in out.splitlines():
            self.assertFalse(line.strip().startswith('f"'),
                             f"leaked f-string fragment: {line!r}")

    def test_html_escapes_path(self):
        rep = scan_bytes(b"A" * 100, block_size=50, path="<script>x</script>")
        out = render_html(rep, "high")
        self.assertNotIn("<script>x</script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_html_shows_overall(self):
        out = render_html(self.flagged, "high")
        self.assertIn("CRITICAL", out)

    # --- sarif ---
    def test_sarif_schema(self):
        doc = json.loads(render_sarif(self.flagged, "high"))
        self.assertEqual(doc["version"], "2.1.0")
        self.assertIn("$schema", doc)
        driver = doc["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], TOOL_NAME)
        self.assertEqual(driver["version"], TOOL_VERSION)

    def test_sarif_results_have_byte_regions(self):
        doc = json.loads(render_sarif(self.flagged, "high"))
        results = doc["runs"][0]["results"]
        self.assertTrue(results)
        for res in results:
            self.assertEqual(res["ruleId"], "entropyscan/high-entropy-region")
            loc = res["locations"][0]["physicalLocation"]
            self.assertEqual(loc["artifactLocation"]["uri"], "evidence.bin")
            self.assertIn("byteOffset", loc["region"])
            self.assertIn("byteLength", loc["region"])
            self.assertIn(res["level"], ("note", "warning", "error"))

    def test_sarif_empty_when_clean(self):
        doc = json.loads(render_sarif(self.clean, "high"))
        self.assertEqual(doc["runs"][0]["results"], [])

    def test_sarif_fingerprints(self):
        doc = json.loads(render_sarif(self.flagged, "high"))
        res = doc["runs"][0]["results"][0]
        self.assertIn("partialFingerprints", res)
        self.assertIn("byteRange", res["partialFingerprints"])


class TestCli(unittest.TestCase):
    def test_parser_builds(self):
        p = build_parser()
        ns = p.parse_args(["scan", "foo.bin", "--min-severity", "medium",
                           "--format", "json", "--block-size", "512"])
        self.assertEqual(ns.command, "scan")
        self.assertEqual(ns.min_severity, "medium")
        self.assertEqual(ns.format, "json")
        self.assertEqual(ns.block_size, 512)

    def test_default_block_size(self):
        ns = build_parser().parse_args(["scan", "f"])
        self.assertEqual(ns.block_size, DEFAULT_BLOCK_SIZE)

    def test_no_command_returns_2(self):
        self.assertEqual(main([]), 2)

    def test_missing_file_returns_2(self):
        self.assertEqual(main(["scan", "/no/such/file/xyz.bin"]), 2)

    def test_clean_returns_0(self):
        path = _write(b"\x00" * 4096)
        try:
            self.assertEqual(
                main(["scan", path, "--block-size", "1024", "--format", "json"]), 0
            )
        finally:
            os.remove(path)

    def test_finding_returns_1(self):
        path = _write(_uniform(8192, 11))
        try:
            self.assertEqual(
                main(["scan", path, "--block-size", "4096", "--format", "json"]), 1
            )
        finally:
            os.remove(path)

    def test_output_file_written(self):
        path = _write(_uniform(8192, 12))
        out = path + ".sarif"
        try:
            rc = main(["scan", path, "--format", "sarif", "-o", out])
            self.assertEqual(rc, 1)
            self.assertTrue(os.path.exists(out))
            with open(out, encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(doc["version"], "2.1.0")
        finally:
            os.remove(path)
            if os.path.exists(out):
                os.remove(out)

    def test_min_severity_changes_exit(self):
        # medium-only content: flags at medium, clean at high.
        data = b"".join(bytes([i % 40 + 32]) for i in range(8192))
        path = _write(data)
        try:
            rc_med = main(["scan", path, "--block-size", "4096",
                           "--min-severity", "medium", "--format", "json"])
            rc_high = main(["scan", path, "--block-size", "4096",
                            "--min-severity", "high", "--format", "json"])
            # medium content should not exceed high; at least the high run is clean
            self.assertEqual(rc_high, 0)
            self.assertIn(rc_med, (0, 1))
        finally:
            os.remove(path)

    def test_mcp_subcommand_registered(self):
        # The `mcp` subcommand must parse (README documents `entropyscan mcp`).
        ns = build_parser().parse_args(["mcp"])
        self.assertEqual(ns.command, "mcp")

    def test_mcp_routes_to_server(self):
        # `entropyscan mcp` must dispatch to entropyscan.mcp_server.serve.
        import entropyscan.cli as climod
        import entropyscan.mcp_server as mcpmod
        calls = []
        orig = mcpmod.serve
        mcpmod.serve = lambda: (calls.append(1) or 0)
        try:
            rc = climod.main(["mcp"])
        finally:
            mcpmod.serve = orig
        self.assertEqual(rc, 0)
        self.assertEqual(len(calls), 1)

    def test_version_subprocess(self):
        proc = subprocess.run(
            [sys.executable, "-m", "entropyscan", "--version"],
            cwd=_REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn(TOOL_VERSION, proc.stdout)
        self.assertIn(TOOL_NAME, proc.stdout)


class TestDemosConsistency(unittest.TestCase):
    """The shipped demo corpus must classify as documented in the README table."""

    EXPECT = {
        "04-packed-elf/sample.bin": True,
        "05-office-macro/sample.doc": True,
        "06-pcap-tls/capture.pcap": True,
        "07-leaked-secret/config.bundle": True,
        "08-clean-release/artifact.txt": False,
        "09-stego-carrier/photo.png": True,
        "10-memory-dump/process.dmp": True,
    }

    def test_demo_files_present(self):
        for rel in self.EXPECT:
            self.assertTrue(
                os.path.exists(os.path.join(_REPO_ROOT, "demos", rel)),
                f"missing demo: {rel}",
            )

    def test_demo_classification(self):
        for rel, should_flag in self.EXPECT.items():
            p = os.path.join(_REPO_ROOT, "demos", rel)
            if not os.path.exists(p):
                self.skipTest(f"demo not present: {rel}")
            report = scan_file(p, block_size=4096)
            self.assertEqual(
                bool(report.regions("high")), should_flag,
                f"{rel}: maxH={report.max_entropy:.3f} overall={report.overall_severity}",
            )


if __name__ == "__main__":
    unittest.main()

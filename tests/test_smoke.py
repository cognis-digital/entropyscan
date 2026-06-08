"""Smoke tests for ENTROPYSCAN (standard library / no network)."""
import os
import json
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
)
from entropyscan.cli import main, render_html, render_json, render_table  # noqa: E402


def _mixed_file() -> str:
    rng = random.Random(7)
    banner = b"HEADER-TEXT-AAAA " * 64
    padding = b"\x00" * 1024
    payload = bytes(rng.randrange(256) for _ in range(4096))
    fd, path = tempfile.mkstemp(suffix=".bin")
    with os.fdopen(fd, "wb") as fh:
        fh.write(banner + padding + payload)
    return path


class TestEntropy(unittest.TestCase):
    def test_zero_entropy(self):
        self.assertEqual(shannon_entropy(b"\x00" * 4096), 0.0)

    def test_empty(self):
        self.assertEqual(shannon_entropy(b""), 0.0)

    def test_max_entropy_all_bytes(self):
        data = bytes(range(256)) * 16
        self.assertAlmostEqual(shannon_entropy(data), 8.0, places=6)

    def test_random_is_high(self):
        rng = random.Random(1)
        data = bytes(rng.randrange(256) for _ in range(8192))
        self.assertGreater(shannon_entropy(data), 7.5)

    def test_classify_bounds(self):
        self.assertEqual(classify(0.0), "low")
        self.assertEqual(classify(6.0), "medium")
        self.assertEqual(classify(7.0), "high")
        self.assertEqual(classify(7.9), "critical")


class TestScan(unittest.TestCase):
    def test_scan_bytes_block_count(self):
        report = scan_bytes(b"A" * 1000, block_size=256)
        self.assertEqual(len(report.blocks), 4)  # 256*3 + 232
        self.assertEqual(report.bytes_scanned, 1000)

    def test_detects_high_entropy_region(self):
        path = _mixed_file()
        try:
            from entropyscan import scan_file
            report = scan_file(path, block_size=256)
            self.assertEqual(report.overall_severity, "critical")
            regions = report.regions("high")
            self.assertTrue(regions)
            self.assertGreater(regions[-1]["max_entropy"], 7.5)
        finally:
            os.remove(path)

    def test_to_dict_roundtrip(self):
        report = scan_bytes(b"hello world" * 100, block_size=128)
        d = report.to_dict()
        self.assertIn("blocks", d)
        self.assertEqual(d["block_size"], 128)


class TestRenderers(unittest.TestCase):
    def setUp(self):
        self.report = scan_bytes(
            bytes(range(256)) * 8 + b"\x00" * 256, block_size=128, path="t.bin"
        )

    def test_table(self):
        out = render_table(self.report, "high")
        self.assertIn("ENTROPYSCAN", out)
        self.assertIn("Block map", out)

    def test_json_valid(self):
        out = render_json(self.report, "high")
        parsed = json.loads(out)
        self.assertEqual(parsed["tool"], TOOL_NAME)
        self.assertIn("blocks", parsed)

    def test_html_selfcontained(self):
        out = render_html(self.report, "high")
        self.assertTrue(out.startswith("<!DOCTYPE html>"))
        self.assertIn("<style>", out)
        self.assertIn("ENTROPYSCAN report", out)


class TestCli(unittest.TestCase):
    def test_exit_1_on_finding(self):
        path = _mixed_file()
        try:
            rc = main(["scan", path, "--block-size", "256", "--format", "json"])
            self.assertEqual(rc, 1)
        finally:
            os.remove(path)

    def test_exit_0_low_entropy(self):
        fd, path = tempfile.mkstemp(suffix=".bin")
        with os.fdopen(fd, "wb") as fh:
            fh.write(b"\x00" * 4096)
        try:
            rc = main(["scan", path, "--block-size", "256", "--format", "json"])
            self.assertEqual(rc, 0)
        finally:
            os.remove(path)

    def test_missing_file_exit_2(self):
        rc = main(["scan", "/no/such/file/xyz.bin"])
        self.assertEqual(rc, 2)

    def test_module_version(self):
        proc = subprocess.run(
            [sys.executable, "-m", "entropyscan", "--version"],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn(TOOL_VERSION, proc.stdout)


if __name__ == "__main__":
    unittest.main()

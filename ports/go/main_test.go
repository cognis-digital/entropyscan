package main

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestShannonEntropyZero(t *testing.T) {
	if e := shannonEntropy(make([]byte, 4096)); e != 0.0 {
		t.Fatalf("all-zero entropy = %v, want 0", e)
	}
}

func TestShannonEntropyEmpty(t *testing.T) {
	if e := shannonEntropy([]byte{}); e != 0.0 {
		t.Fatalf("empty entropy = %v, want 0", e)
	}
}

func TestShannonEntropyMax(t *testing.T) {
	data := make([]byte, 256*16)
	for i := range data {
		data[i] = byte(i % 256)
	}
	if e := shannonEntropy(data); math.Abs(e-8.0) > 1e-6 {
		t.Fatalf("uniform entropy = %v, want 8.0", e)
	}
}

func TestClassifyBounds(t *testing.T) {
	cases := map[float64]string{0.0: "low", 6.0: "medium", 7.0: "high", 7.9: "critical"}
	for in, want := range cases {
		if got := classify(in); got != want {
			t.Fatalf("classify(%v) = %s, want %s", in, got, want)
		}
	}
}

func TestScanBytesBlockCount(t *testing.T) {
	data := make([]byte, 1000)
	for i := range data {
		data[i] = 'A'
	}
	r := ScanBytes(data, "t.bin", 256)
	if len(r.Blocks) != 4 {
		t.Fatalf("blocks = %d, want 4", len(r.Blocks))
	}
	if r.BytesScanned != 1000 {
		t.Fatalf("scanned = %d, want 1000", r.BytesScanned)
	}
}

func TestRegionsDetectHighEntropy(t *testing.T) {
	// "AAAA" banner (low) followed by deterministic uniform bytes (critical).
	data := []byte{}
	for i := 0; i < 1024; i++ {
		data = append(data, 'A')
	}
	for i := 0; i < 8192; i++ {
		data = append(data, byte((i*167+13)%256))
	}
	r := ScanBytes(data, "mixed.bin", 4096)
	r.Regions = r.computeRegions("high")
	if len(r.Regions) == 0 {
		t.Fatalf("expected at least one flagged region")
	}
	if r.Overall != "critical" {
		t.Fatalf("overall = %s, want critical", r.Overall)
	}
}

func TestScanFileRoundtrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sample.bin")
	data := make([]byte, 2048)
	for i := range data {
		data[i] = byte((i * 91) % 256)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := scanFile(p, 512, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Size != 2048 {
		t.Fatalf("size = %d, want 2048", r.Size)
	}
	if len(r.Blocks) != 4 {
		t.Fatalf("blocks = %d, want 4", len(r.Blocks))
	}
}

func TestRunExitCodes(t *testing.T) {
	dir := t.TempDir()
	clean := filepath.Join(dir, "clean.bin")
	if err := os.WriteFile(clean, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	if rc := run([]string{"scan", clean, "--block-size", "1024", "--format", "json"}); rc != 0 {
		t.Fatalf("clean exit = %d, want 0", rc)
	}
	if rc := run([]string{"scan", "/no/such/file"}); rc != 2 {
		t.Fatalf("missing-file exit = %d, want 2", rc)
	}
	if rc := run([]string{"--version"}); rc != 0 {
		t.Fatalf("version exit = %d, want 0", rc)
	}
}

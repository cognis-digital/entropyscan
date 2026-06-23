// entropyscan — Go port of the Cognis entropy scanner.
//
// Single static binary, zero third-party dependencies. Mirrors the Python
// reference CLI: slide a fixed-size window across a file, score each block by
// Shannon entropy (bits/byte, 0..8), classify by severity, coalesce flagged
// blocks into regions, and emit table or JSON. Passive/offline only — it
// reads a local file and never touches the network.
//
//	go run . scan FILE [--block-size N] [--min-severity LEVEL] [--format table|json]
//
// Exit codes match the reference: 0 = clean, 1 = finding at/above
// --min-severity, 2 = usage/IO error.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
)

const (
	toolName        = "entropyscan"
	toolVersion     = "0.4.0"
	criticalThresh  = 7.5
	highThresh      = 6.8
	mediumThresh    = 5.5
	defaultBlock    = 4096
)

var severityOrder = map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}

// shannonEntropy returns the Shannon entropy of data in bits per byte (0..8).
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	ent := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			ent -= p * math.Log2(p)
		}
	}
	return ent
}

func classify(e float64) string {
	switch {
	case e >= criticalThresh:
		return "critical"
	case e >= highThresh:
		return "high"
	case e >= mediumThresh:
		return "medium"
	default:
		return "low"
	}
}

func round4(f float64) float64 { return math.Round(f*10000) / 10000 }

// Block is one scored window.
type Block struct {
	Index    int     `json:"index"`
	Offset   int     `json:"offset"`
	Size     int     `json:"size"`
	Entropy  float64 `json:"entropy"`
	Severity string  `json:"severity"`
}

// Region is a run of consecutive flagged blocks.
type Region struct {
	Start      int     `json:"start"`
	End        int     `json:"end"`
	MaxEntropy float64 `json:"max_entropy"`
	Severity   string  `json:"severity"`
	Blocks     int     `json:"blocks"`
}

// Report is the full scan result.
type Report struct {
	Tool         string         `json:"tool"`
	Version      string         `json:"version"`
	Path         string         `json:"path"`
	Size         int            `json:"size"`
	BlockSize    int            `json:"block_size"`
	BytesScanned int            `json:"bytes_scanned"`
	Truncated    bool           `json:"truncated"`
	MeanEntropy  float64        `json:"mean_entropy"`
	MaxEntropy   float64        `json:"max_entropy"`
	MinEntropy   float64        `json:"min_entropy"`
	Overall      string         `json:"overall_severity"`
	Counts       map[string]int `json:"severity_counts"`
	Blocks       []Block        `json:"blocks"`
	MinSeverity  string         `json:"min_severity"`
	Regions      []Region       `json:"flagged_regions"`
	Flagged      bool           `json:"flagged"`
}

// ScanBytes scores an in-memory buffer.
func ScanBytes(data []byte, path string, blockSize int) *Report {
	if blockSize <= 0 {
		blockSize = defaultBlock
	}
	blocks := []Block{}
	n := len(data)
	idx := 0
	for offset := 0; offset < n; offset += blockSize {
		end := offset + blockSize
		if end > n {
			end = n
		}
		chunk := data[offset:end]
		e := shannonEntropy(chunk)
		blocks = append(blocks, Block{idx, offset, len(chunk), round4(e), classify(e)})
		idx++
	}
	return finalize(blocks, path, n, blockSize, n, false)
}

func finalize(blocks []Block, path string, size, blockSize, scanned int, truncated bool) *Report {
	counts := map[string]int{"low": 0, "medium": 0, "high": 0, "critical": 0}
	mean, mx, mn := 0.0, 0.0, math.Inf(1)
	overall := "low"
	for _, b := range blocks {
		counts[b.Severity]++
		mean += b.Entropy
		if b.Entropy > mx {
			mx = b.Entropy
		}
		if b.Entropy < mn {
			mn = b.Entropy
		}
		if severityOrder[b.Severity] > severityOrder[overall] {
			overall = b.Severity
		}
	}
	if len(blocks) > 0 {
		mean /= float64(len(blocks))
	} else {
		mn = 0.0
	}
	return &Report{
		Tool: toolName, Version: toolVersion, Path: path, Size: size,
		BlockSize: blockSize, BytesScanned: scanned, Truncated: truncated,
		MeanEntropy: round4(mean), MaxEntropy: round4(mx), MinEntropy: round4(mn),
		Overall: overall, Counts: counts, Blocks: blocks,
	}
}

// computeRegions coalesces consecutive blocks at/above minSeverity.
func (r *Report) computeRegions(minSeverity string) []Region {
	floor := severityOrder[minSeverity]
	out := []Region{}
	var cur *Region
	for _, b := range r.Blocks {
		if severityOrder[b.Severity] >= floor {
			if cur == nil {
				cur = &Region{b.Offset, b.Offset + b.Size, b.Entropy, b.Severity, 1}
			} else {
				cur.End = b.Offset + b.Size
				cur.Blocks++
				if b.Entropy > cur.MaxEntropy {
					cur.MaxEntropy = b.Entropy
				}
				if severityOrder[b.Severity] > severityOrder[cur.Severity] {
					cur.Severity = b.Severity
				}
			}
		} else if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

func scanFile(path string, blockSize, maxBytes int) (*Report, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	if blockSize <= 0 {
		blockSize = defaultBlock
	}
	blocks := []Block{}
	buf := make([]byte, blockSize)
	idx, offset, scanned := 0, 0, 0
	truncated := false
	for {
		if maxBytes > 0 && scanned >= maxBytes {
			truncated = offset < int(fi.Size())
			break
		}
		toRead := blockSize
		if maxBytes > 0 && maxBytes-scanned < toRead {
			toRead = maxBytes - scanned
		}
		nr, rerr := io.ReadFull(fh, buf[:toRead])
		if nr > 0 {
			chunk := buf[:nr]
			e := shannonEntropy(chunk)
			blocks = append(blocks, Block{idx, offset, nr, round4(e), classify(e)})
			idx++
			offset += nr
			scanned += nr
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
	}
	return finalize(blocks, path, int(fi.Size()), blockSize, scanned, truncated), nil
}

func renderTable(r *Report) string {
	s := fmt.Sprintf("%s %s - %s\n", toolName, toolVersion, r.Path)
	s += fmt.Sprintf("size=%dB block=%dB blocks=%d scanned=%dB\n", r.Size, r.BlockSize, len(r.Blocks), r.BytesScanned)
	s += fmt.Sprintf("entropy mean=%.3f max=%.3f min=%.3f overall=%s\n", r.MeanEntropy, r.MaxEntropy, r.MinEntropy, r.Overall)
	keys := []string{"low", "medium", "high", "critical"}
	s += "counts  "
	for _, k := range keys {
		s += fmt.Sprintf(" %s=%d", k, r.Counts[k])
	}
	s += "\n"
	if len(r.Regions) > 0 {
		s += fmt.Sprintf("flagged regions (>= %s):\n", r.MinSeverity)
		for _, rg := range r.Regions {
			s += fmt.Sprintf("  0x%08x-0x%08x %-9s maxH=%.3f blocks=%d\n", rg.Start, rg.End, rg.Severity, rg.MaxEntropy, rg.Blocks)
		}
	} else {
		s += fmt.Sprintf("no regions at or above '%s'.\n", r.MinSeverity)
	}
	return s
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s scan FILE [--block-size N] [--min-severity low|medium|high|critical] [--format table|json]\n", toolName)
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) >= 1 && (args[0] == "--version" || args[0] == "-V") {
		fmt.Printf("%s %s\n", toolName, toolVersion)
		return 0
	}
	if len(args) < 2 || args[0] != "scan" {
		usage()
		return 2
	}
	path := args[1]
	blockSize := defaultBlock
	minSeverity := "high"
	format := "table"
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--block-size":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &blockSize)
			}
		case "--min-severity":
			i++
			if i < len(args) {
				minSeverity = args[i]
			}
		case "--format":
			i++
			if i < len(args) {
				format = args[i]
			}
		}
	}
	if _, ok := severityOrder[minSeverity]; !ok {
		usage()
		return 2
	}
	report, err := scanFile(path, blockSize, 256*1024*1024)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: error: %v\n", toolName, err)
		return 2
	}
	report.MinSeverity = minSeverity
	report.Regions = report.computeRegions(minSeverity)
	report.Flagged = len(report.Regions) > 0
	if format == "json" {
		b, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Print(renderTable(report))
	}
	if report.Flagged {
		return 1
	}
	return 0
}

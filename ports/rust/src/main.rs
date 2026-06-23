//! entropyscan — Rust port of the Cognis entropy scanner.
//!
//! Fast single binary, zero third-party crates (std only). Mirrors the Python
//! reference CLI: slide a fixed-size window over a file, score each block by
//! Shannon entropy (bits/byte, 0..8), classify by severity, coalesce flagged
//! blocks into regions, and emit table or JSON. Passive/offline only — reads a
//! local file, never opens a socket.
//!
//! `entropyscan scan FILE [--block-size N] [--min-severity LEVEL] [--format table|json]`
//!
//! Exit codes: 0 = clean, 1 = finding at/above --min-severity, 2 = usage/IO error.

use std::env;
use std::fs::File;
use std::io::Read;
use std::process::exit;

const TOOL_NAME: &str = "entropyscan";
const TOOL_VERSION: &str = "0.4.0";
const CRITICAL: f64 = 7.5;
const HIGH: f64 = 6.8;
const MEDIUM: f64 = 5.5;
const DEFAULT_BLOCK: usize = 4096;

fn sev_order(s: &str) -> i32 {
    match s {
        "low" => 0,
        "medium" => 1,
        "high" => 2,
        "critical" => 3,
        _ => -1,
    }
}

/// Shannon entropy of `data` in bits per byte (0..8).
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut ent = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / n;
            ent -= p * p.log2();
        }
    }
    ent
}

fn classify(e: f64) -> &'static str {
    if e >= CRITICAL {
        "critical"
    } else if e >= HIGH {
        "high"
    } else if e >= MEDIUM {
        "medium"
    } else {
        "low"
    }
}

fn round4(f: f64) -> f64 {
    (f * 10000.0).round() / 10000.0
}

struct Block {
    offset: usize,
    size: usize,
    entropy: f64,
    severity: &'static str,
}

struct Region {
    start: usize,
    end: usize,
    max_entropy: f64,
    severity: String,
    blocks: usize,
}

struct Report {
    path: String,
    size: usize,
    block_size: usize,
    bytes_scanned: usize,
    blocks: Vec<Block>,
}

fn scan_bytes(data: &[u8], path: &str, block_size: usize) -> Report {
    let bs = if block_size == 0 { DEFAULT_BLOCK } else { block_size };
    let mut blocks = Vec::new();
    let n = data.len();
    let mut offset = 0;
    while offset < n {
        let end = (offset + bs).min(n);
        let chunk = &data[offset..end];
        let e = shannon_entropy(chunk);
        blocks.push(Block {
            offset,
            size: chunk.len(),
            entropy: round4(e),
            severity: classify(e),
        });
        offset += bs;
    }
    Report {
        path: path.to_string(),
        size: n,
        block_size: bs,
        bytes_scanned: n,
        blocks,
    }
}

impl Report {
    fn mean(&self) -> f64 {
        if self.blocks.is_empty() {
            return 0.0;
        }
        let s: f64 = self.blocks.iter().map(|b| b.entropy).sum();
        round4(s / self.blocks.len() as f64)
    }
    fn max(&self) -> f64 {
        self.blocks.iter().map(|b| b.entropy).fold(0.0, f64::max)
    }
    fn min(&self) -> f64 {
        if self.blocks.is_empty() {
            return 0.0;
        }
        self.blocks.iter().map(|b| b.entropy).fold(8.0, f64::min)
    }
    fn overall(&self) -> &'static str {
        let mut worst = "low";
        for b in &self.blocks {
            if sev_order(b.severity) > sev_order(worst) {
                worst = b.severity;
            }
        }
        worst
    }
    fn counts(&self) -> [(&'static str, usize); 4] {
        let mut c = [("low", 0usize), ("medium", 0), ("high", 0), ("critical", 0)];
        for b in &self.blocks {
            for entry in c.iter_mut() {
                if entry.0 == b.severity {
                    entry.1 += 1;
                }
            }
        }
        c
    }
    fn regions(&self, min_severity: &str) -> Vec<Region> {
        let floor = sev_order(min_severity);
        let mut out: Vec<Region> = Vec::new();
        let mut cur: Option<Region> = None;
        for b in &self.blocks {
            if sev_order(b.severity) >= floor {
                match cur.as_mut() {
                    None => {
                        cur = Some(Region {
                            start: b.offset,
                            end: b.offset + b.size,
                            max_entropy: b.entropy,
                            severity: b.severity.to_string(),
                            blocks: 1,
                        });
                    }
                    Some(r) => {
                        r.end = b.offset + b.size;
                        r.blocks += 1;
                        if b.entropy > r.max_entropy {
                            r.max_entropy = b.entropy;
                        }
                        if sev_order(b.severity) > sev_order(&r.severity) {
                            r.severity = b.severity.to_string();
                        }
                    }
                }
            } else if let Some(r) = cur.take() {
                out.push(r);
            }
        }
        if let Some(r) = cur.take() {
            out.push(r);
        }
        out
    }
}

fn scan_file(path: &str, block_size: usize) -> std::io::Result<Report> {
    let mut f = File::open(path)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;
    Ok(scan_bytes(&data, path, block_size))
}

fn render_table(r: &Report, min_severity: &str) -> String {
    let mut s = String::new();
    s.push_str(&format!("{} {} - {}\n", TOOL_NAME, TOOL_VERSION, r.path));
    s.push_str(&format!(
        "size={}B block={}B blocks={} scanned={}B\n",
        r.size,
        r.block_size,
        r.blocks.len(),
        r.bytes_scanned
    ));
    s.push_str(&format!(
        "entropy mean={:.3} max={:.3} min={:.3} overall={}\n",
        r.mean(),
        r.max(),
        r.min(),
        r.overall()
    ));
    s.push_str("counts ");
    for (k, v) in r.counts() {
        s.push_str(&format!(" {}={}", k, v));
    }
    s.push('\n');
    let regions = r.regions(min_severity);
    if regions.is_empty() {
        s.push_str(&format!("no regions at or above '{}'.\n", min_severity));
    } else {
        s.push_str(&format!("flagged regions (>= {}):\n", min_severity));
        for rg in &regions {
            s.push_str(&format!(
                "  0x{:08x}-0x{:08x} {:<9} maxH={:.3} blocks={}\n",
                rg.start, rg.end, rg.severity, rg.max_entropy, rg.blocks
            ));
        }
    }
    s
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn render_json(r: &Report, min_severity: &str) -> String {
    let regions = r.regions(min_severity);
    let mut blocks_json = String::from("[");
    for (i, b) in r.blocks.iter().enumerate() {
        if i > 0 {
            blocks_json.push(',');
        }
        blocks_json.push_str(&format!(
            "{{\"index\":{},\"offset\":{},\"size\":{},\"entropy\":{},\"severity\":\"{}\"}}",
            i, b.offset, b.size, b.entropy, b.severity
        ));
    }
    blocks_json.push(']');
    let mut reg_json = String::from("[");
    for (i, rg) in regions.iter().enumerate() {
        if i > 0 {
            reg_json.push(',');
        }
        reg_json.push_str(&format!(
            "{{\"start\":{},\"end\":{},\"max_entropy\":{},\"severity\":\"{}\",\"blocks\":{}}}",
            rg.start, rg.end, rg.max_entropy, rg.severity, rg.blocks
        ));
    }
    reg_json.push(']');
    let counts = r.counts();
    format!(
        "{{\"tool\":\"{}\",\"version\":\"{}\",\"path\":\"{}\",\"size\":{},\"block_size\":{},\
\"bytes_scanned\":{},\"mean_entropy\":{},\"max_entropy\":{},\"min_entropy\":{},\
\"overall_severity\":\"{}\",\"severity_counts\":{{\"low\":{},\"medium\":{},\"high\":{},\"critical\":{}}},\
\"min_severity\":\"{}\",\"flagged\":{},\"flagged_regions\":{},\"blocks\":{}}}",
        TOOL_NAME, TOOL_VERSION, json_escape(&r.path), r.size, r.block_size, r.bytes_scanned,
        r.mean(), r.max(), r.min(), r.overall(),
        counts[0].1, counts[1].1, counts[2].1, counts[3].1,
        min_severity, !regions.is_empty(), reg_json, blocks_json
    )
}

fn run(args: &[String]) -> i32 {
    if args.first().map(|s| s.as_str()) == Some("--version") {
        println!("{} {}", TOOL_NAME, TOOL_VERSION);
        return 0;
    }
    if args.len() < 2 || args[0] != "scan" {
        eprintln!(
            "usage: {} scan FILE [--block-size N] [--min-severity LEVEL] [--format table|json]",
            TOOL_NAME
        );
        return 2;
    }
    let path = &args[1];
    let mut block_size = DEFAULT_BLOCK;
    let mut min_severity = String::from("high");
    let mut format = String::from("table");
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--block-size" => {
                i += 1;
                if i < args.len() {
                    block_size = args[i].parse().unwrap_or(DEFAULT_BLOCK);
                }
            }
            "--min-severity" => {
                i += 1;
                if i < args.len() {
                    min_severity = args[i].clone();
                }
            }
            "--format" => {
                i += 1;
                if i < args.len() {
                    format = args[i].clone();
                }
            }
            _ => {}
        }
        i += 1;
    }
    if sev_order(&min_severity) < 0 {
        eprintln!("{}: error: bad --min-severity '{}'", TOOL_NAME, min_severity);
        return 2;
    }
    let report = match scan_file(path, block_size) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}: error: {}", TOOL_NAME, e);
            return 2;
        }
    };
    let flagged = !report.regions(&min_severity).is_empty();
    if format == "json" {
        println!("{}", render_json(&report, &min_severity));
    } else {
        print!("{}", render_table(&report, &min_severity));
    }
    if flagged {
        1
    } else {
        0
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    exit(run(&args));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_entropy() {
        assert_eq!(shannon_entropy(&[0u8; 4096]), 0.0);
    }

    #[test]
    fn empty_entropy() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn max_entropy() {
        let mut data = Vec::new();
        for _ in 0..16 {
            for b in 0u16..256 {
                data.push(b as u8);
            }
        }
        assert!((shannon_entropy(&data) - 8.0).abs() < 1e-6);
    }

    #[test]
    fn classify_bounds() {
        assert_eq!(classify(0.0), "low");
        assert_eq!(classify(6.0), "medium");
        assert_eq!(classify(7.0), "high");
        assert_eq!(classify(7.9), "critical");
    }

    #[test]
    fn block_count() {
        let data = vec![b'A'; 1000];
        let r = scan_bytes(&data, "t.bin", 256);
        assert_eq!(r.blocks.len(), 4);
        assert_eq!(r.bytes_scanned, 1000);
    }

    #[test]
    fn detects_region() {
        let mut data = vec![b'A'; 1024];
        for i in 0..8192usize {
            data.push(((i * 167 + 13) % 256) as u8);
        }
        let r = scan_bytes(&data, "mixed.bin", 4096);
        assert!(!r.regions("high").is_empty());
        assert_eq!(r.overall(), "critical");
    }

    #[test]
    fn json_contains_tool() {
        let data = vec![b'A'; 256];
        let r = scan_bytes(&data, "t.bin", 128);
        let j = render_json(&r, "high");
        assert!(j.contains("\"tool\":\"entropyscan\""));
        assert!(j.contains("\"flagged\""));
    }

    #[test]
    fn run_clean_exits_zero() {
        let dir = env::temp_dir();
        let p = dir.join("entropyscan_rs_clean.bin");
        std::fs::write(&p, vec![0u8; 4096]).unwrap();
        let rc = run(&[
            "scan".into(),
            p.to_string_lossy().into_owned(),
            "--block-size".into(),
            "1024".into(),
            "--format".into(),
            "json".into(),
        ]);
        let _ = std::fs::remove_file(&p);
        assert_eq!(rc, 0);
    }

    #[test]
    fn run_missing_file_exits_two() {
        assert_eq!(run(&["scan".into(), "/no/such/file/xyz.bin".into()]), 2);
    }

    #[test]
    fn run_version_exits_zero() {
        assert_eq!(run(&["--version".into()]), 0);
    }
}

use crate::parsing::{parse_record, record_summary};
use crate::stats::compute_stats_full;
use flate2::read::GzDecoder;
use rayon::prelude::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::warn;

type RecordKey = (String, i64);

pub struct DataStore {
    pub records: Vec<Value>,
    pub index: HashMap<RecordKey, usize>,
    pub duplicate_groups: HashMap<RecordKey, Vec<Value>>,
    pub duplicates_removed: usize,
    pub parse_errors: usize,
    pub files_loaded: usize,
    pub cve_count: usize,
    // Precomputed at startup — cheap Arc clone, no serialisation on each request
    summaries: Arc<Vec<Value>>,
    stats: Arc<Value>,
    duplicates_data: Arc<Value>,
}

pub type SharedStore = Arc<RwLock<DataStore>>;

// ── ANSI helpers (mirrors main.rs, used for per-stage output) ────────────────
fn cli_step(icon: &str, msg: &str) {
    eprintln!("  \x1b[38;5;245m│\x1b[0m  {icon}  \x1b[38;5;255m{msg}\x1b[0m");
}
fn cli_ok(label: &str, detail: &str) {
    eprintln!("  \x1b[38;5;245m│\x1b[0m  \x1b[38;5;82m✓\x1b[0m  \x1b[38;5;255m{label}\x1b[0m  \x1b[38;5;245m{detail}\x1b[0m");
}

impl DataStore {
    /// Called from main — same as load() but prints verbose progress to stderr.
    pub fn load_verbose(data_dir: &Path) -> Self {
        Self::load_inner(data_dir, true)
    }

    pub fn load(data_dir: &Path) -> Self {
        Self::load_inner(data_dir, false)
    }

    fn load_inner(data_dir: &Path, verbose: bool) -> Self {
        let t0 = std::time::Instant::now();

        // ── 1. Discover files ──────────────────────────────────────────────
        let files = if data_dir.exists() {
            collect_data_files(data_dir)
        } else {
            warn!("Data directory {:?} not found — starting with empty store", data_dir);
            vec![]
        };
        let files_loaded = files.len();

        // ── 2. Parse files in parallel (rayon) ────────────────────────────
        let file_results: Vec<(Vec<Value>, usize, String, u128)> = files
            .par_iter()
            .map(|path| {
                let t = std::time::Instant::now();
                let (records, errors) = load_file(path);
                let name = path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                (records, errors, name, t.elapsed().as_millis())
            })
            .collect();

        let mut raw: Vec<Value> = Vec::new();
        let mut parse_errors = 0usize;
        for (records, errors, name, ms) in &file_results {
            if verbose {
                cli_step("📄", &format!("\x1b[38;5;245m{name}\x1b[0m  \x1b[38;5;208m{}\x1b[0m\x1b[38;5;245m records  ({ms} ms)\x1b[0m", records.len()));
            }
            raw.extend(records.clone());
            parse_errors += errors;
        }
        if parse_errors > 0 {
            warn!("{} line(s) failed to parse", parse_errors);
        }

        if verbose {
            cli_ok("Parsing complete",
                &format!("\x1b[38;5;208m{}\x1b[0m\x1b[38;5;245m raw records  ({:.2?})\x1b[0m", raw.len(), t0.elapsed()));
        }

        // ── 3. Deduplicate by (ip_str, port) keeping newest ───────────────
        let t1 = std::time::Instant::now();
        let mut groups: HashMap<RecordKey, Vec<Value>> = HashMap::with_capacity(raw.len());
        for r in raw {
            let ip = r.get("ip_str").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let port = r.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
            groups.entry((ip, port)).or_default().push(r);
        }

        let mut index: HashMap<RecordKey, usize> = HashMap::with_capacity(groups.len());
        let mut records: Vec<Value> = Vec::with_capacity(groups.len());

        for (key, occ) in &groups {
            let best = occ.iter().max_by(|a, b| {
                let ta = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
                let tb = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
                ta.cmp(tb)
            }).unwrap();
            let idx = records.len();
            records.push(best.clone());
            index.insert(key.clone(), idx);
        }

        let total_before: usize = groups.values().map(|v| v.len()).sum();
        let duplicates_removed = total_before - records.len();
        let duplicate_groups: HashMap<RecordKey, Vec<Value>> = groups
            .into_iter()
            .filter(|(_, v)| v.len() > 1)
            .collect();

        if verbose {
            cli_ok("Deduplication",
                &format!("\x1b[38;5;208m{}\x1b[0m\x1b[38;5;245m unique  ·  {duplicates_removed} removed  ({:.2?})\x1b[0m",
                    records.len(), t1.elapsed()));
        }

        // ── 4-6. Summaries, stats, duplicate report — all three in parallel ──
        let t2 = std::time::Instant::now();
        if verbose { cli_step("⚙️ ", "Pre-computing summaries · statistics · duplicate report…"); }
        let (summaries, (stats, duplicates_data)) = rayon::join(
            || records.par_iter().map(|r| record_summary(r)).collect::<Vec<Value>>(),
            || rayon::join(
                || compute_stats_full(&records, duplicates_removed),
                || build_duplicates(&duplicate_groups, duplicates_removed),
            ),
        );
        let cve_count = stats.get("vulns").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
        if verbose {
            cli_ok("Pre-compute complete",
                &format!("\x1b[38;5;208m{}\x1b[0m\x1b[38;5;245m summaries · \x1b[0m\x1b[38;5;208m{cve_count}\x1b[0m\x1b[38;5;245m CVEs · \x1b[0m\x1b[38;5;208m{}\x1b[0m\x1b[38;5;245m dup groups  ({:.2?})\x1b[0m",
                    summaries.len(), duplicate_groups.len(), t2.elapsed()));
        }

        DataStore {
            records,
            index,
            duplicate_groups,
            duplicates_removed,
            parse_errors,
            files_loaded,
            cve_count,
            summaries: Arc::new(summaries),
            stats: Arc::new(stats),
            duplicates_data: Arc::new(duplicates_data),
        }
    }

    pub fn get_detail(&self, ip: &str, port: i64) -> Option<&Value> {
        self.index.get(&(ip.to_string(), port)).map(|&i| &self.records[i])
    }

    pub fn summaries(&self) -> Arc<Vec<Value>> { self.summaries.clone() }
    pub fn stats(&self) -> Arc<Value> { self.stats.clone() }
    pub fn duplicates(&self) -> Arc<Value> { self.duplicates_data.clone() }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn build_duplicates(
    duplicate_groups: &HashMap<RecordKey, Vec<Value>>,
    duplicates_removed: usize,
) -> Value {
    let mut groups: Vec<Value> = duplicate_groups.iter().map(|((ip_str, port), occ)| {
        let kept = occ.iter().max_by(|a, b| {
            let ta = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
            let tb = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
            ta.cmp(tb)
        }).unwrap();

        let mut sorted_occ: Vec<&Value> = occ.iter().collect();
        sorted_occ.sort_by(|a, b| {
            let ta = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
            let tb = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
            tb.cmp(ta)
        });

        let occurrences: Vec<Value> = sorted_occ.iter().map(|r| {
            let vulns = r.get("vulns").and_then(|v| v.as_array()).map(|a| a.as_slice()).unwrap_or(&[]);
            let max_cvss = vulns.iter()
                .filter_map(|v| v.get("cvss").and_then(|c| c.as_f64()))
                .fold(0.0_f64, f64::max);
            let http = r.get("http");
            let is_kept = std::ptr::eq(*r, kept);
            let loc = r.get("location").unwrap_or(&Value::Null);
            json!({
                "source": r.get("_source").and_then(|v| v.as_str()),
                "timestamp": r.get("timestamp"),
                "kept": is_kept,
                "org": r.get("org").and_then(|v| v.as_str())
                    .or_else(|| r.get("isp").and_then(|v| v.as_str())),
                "country_code": loc.get("country_code"),
                "vulns_count": vulns.len(),
                "max_cvss": max_cvss,
                "http_status": http.and_then(|h| h.get("status")).and_then(|v| if v.is_null() { None } else { Some(v) }),
                "title": http.and_then(|h| h.get("title")).and_then(|v| if v.is_null() { None } else { Some(v) }),
                "has_ssl": r.get("ssl").map(|v| !v.is_null()).unwrap_or(false),
            })
        }).collect();

        json!({
            "ip_str": ip_str,
            "port": port,
            "count": occ.len(),
            "occurrences": occurrences,
        })
    }).collect();

    groups.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()));

    json!({
        "groups": groups,
        "group_count": duplicate_groups.len(),
        "duplicates_removed": duplicates_removed,
    })
}

fn collect_data_files(data_dir: &Path) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    let mut files = Vec::new();

    for ext in &["json.gz", "gz", "json"] {
        if let Ok(entries) = std::fs::read_dir(data_dir) {
            let mut batch: Vec<PathBuf> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.is_file()
                        && !p.file_name().map(|n| n.to_string_lossy().starts_with('.')).unwrap_or(true)
                        && p.to_string_lossy().ends_with(ext)
                        && seen.insert(p.clone())
                })
                .collect();
            batch.sort();
            files.extend(batch);
        }
    }
    files
}

fn load_file(path: &Path) -> (Vec<Value>, usize) {
    let mut records = Vec::new();
    let mut errors = 0usize;

    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            warn!("Could not open {}: {}", path.display(), e);
            return (records, errors);
        }
    };

    let reader: Box<dyn Read> = if path.extension().map(|e| e == "gz").unwrap_or(false) {
        Box::new(GzDecoder::new(file))
    } else {
        Box::new(file)
    };

    let fname = path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    for line in BufReader::new(reader).lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => { errors += 1; continue; }
        };
        let line = line.trim();
        if line.is_empty() { continue; }

        match serde_json::from_str::<Value>(line) {
            Ok(raw) => {
                let mut rec = parse_record(&raw);
                if let Some(obj) = rec.as_object_mut() {
                    obj.insert("_source".to_string(), Value::String(fname.clone()));
                }
                records.push(rec);
            }
            Err(_) => { errors += 1; }
        }
    }

    (records, errors)
}

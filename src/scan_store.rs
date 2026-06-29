use anyhow::Result;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::warn;

const HISTORY_LIMIT: usize = 10;

pub struct ScanStore {
    path: PathBuf,
    data: Mutex<HashMap<String, Value>>,
}

impl ScanStore {
    pub fn new(path: &Path) -> Self {
        let data = Self::read_file(path).unwrap_or_default();
        ScanStore {
            path: path.to_path_buf(),
            data: Mutex::new(data),
        }
    }

    fn read_file(path: &Path) -> Result<HashMap<String, Value>> {
        let content = std::fs::read_to_string(path)?;
        let map: HashMap<String, Value> = serde_json::from_str(&content)?;
        Ok(map)
    }

    fn write_file(&self, data: &HashMap<String, Value>) {
        let tmp = self.path.with_extension("json.tmp");
        let content = match serde_json::to_string(data) {
            Ok(s) => s,
            Err(e) => { warn!("Could not serialize scan results: {}", e); return; }
        };
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&tmp, &content) {
            warn!("Could not write scan results: {}", e);
            return;
        }
        if let Err(e) = std::fs::rename(&tmp, &self.path) {
            warn!("Could not rename scan results: {}", e);
        }
    }

    pub fn count(&self) -> usize {
        self.data.lock().len()
    }

    pub fn all(&self) -> Value {
        let data = self.data.lock();
        serde_json::to_value(&*data).unwrap_or(json!({}))
    }

    pub fn record(&self, results: Vec<Value>) -> Vec<Value> {
        let mut data = self.data.lock();
        let mut out = Vec::new();

        for r in results {
            let ip = r.get("ip").and_then(|v| v.as_str()).unwrap_or("");
            let port = r.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
            let key = format!("{}:{}", ip, port);

            let prev = data.get(&key).cloned().unwrap_or(json!({}));
            let mut history = prev.get("history")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            let hist_entry = json!({
                "scanned_at": r.get("scanned_at"),
                "http_status": r.get("http_status"),
                "http_ok": r.get("http_ok"),
                "tcp_open": r.get("tcp_open"),
                "http_ms": r.get("http_ms"),
            });

            history.insert(0, hist_entry);
            history.truncate(HISTORY_LIMIT);

            let first_seen = prev.get("first_seen")
                .and_then(|v| v.as_str())
                .or_else(|| r.get("scanned_at").and_then(|v| v.as_str()))
                .map(|s| s.to_string())
                .unwrap_or_default();

            let mut entry = r.clone();
            if let Some(obj) = entry.as_object_mut() {
                obj.insert("history".to_string(), Value::Array(history));
                obj.insert("first_seen".to_string(), Value::String(first_seen));
            }

            data.insert(key, entry.clone());
            out.push(entry);
        }

        self.write_file(&data);
        out
    }
}

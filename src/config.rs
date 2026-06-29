use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub host: String,
    pub port: u16,
    pub scan_store: PathBuf,
    pub scan_workers: usize,
    pub scan_connect_timeout_secs: f64,
    pub scan_read_timeout_secs: f64,
    pub scan_max_targets: usize,
}

impl Default for Config {
    fn default() -> Self {
        let data_dir = PathBuf::from(env::var("DATA_DIR").unwrap_or_else(|_| "data".into()));
        let scan_store = PathBuf::from(
            env::var("SCAN_STORE")
                .unwrap_or_else(|_| data_dir.join(".scan_results.json").to_string_lossy().into_owned()),
        );
        Config {
            data_dir,
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5000),
            scan_store,
            scan_workers: env::var("SCAN_WORKERS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(16),
            scan_connect_timeout_secs: env::var("SCAN_CONNECT_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4.0),
            scan_read_timeout_secs: env::var("SCAN_READ_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(6.0),
            scan_max_targets: env::var("SCAN_MAX_TARGETS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
        }
    }
}

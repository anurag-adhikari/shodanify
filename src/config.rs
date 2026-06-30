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
        let data_dir = env::var("DATA_DIR").map(PathBuf::from).unwrap_or_else(|_| {
            // Prefer a "data" folder next to the running executable so the app
            // works regardless of the current working directory (e.g. on Windows
            // where double-clicking an exe sets CWD to the exe's own directory).
            // Fall back to a CWD-relative "data" if neither exists.
            let cwd_data = PathBuf::from("data");
            let exe_data = env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("data")));
            if cwd_data.exists() {
                cwd_data
            } else if let Some(p) = exe_data.filter(|p| p.exists()) {
                p
            } else {
                cwd_data
            }
        });
        let scan_store = PathBuf::from(
            env::var("SCAN_STORE")
                .unwrap_or_else(|_| data_dir.join(".scan_results.json").to_string_lossy().into_owned()),
        );
        Config {
            data_dir,
            host: env::var("HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            port: env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8080),
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
                .unwrap_or(10_000),
        }
    }
}

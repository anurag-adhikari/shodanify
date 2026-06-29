mod activity;
mod config;
mod filter;
mod parsing;
mod report;
mod routes;
mod scan_store;
mod scanner;
mod stats;
mod store;

use activity::ActivityLog;
use config::Config;
use routes::{AppState, build_router};
use scan_store::ScanStore;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

// ── ANSI helpers ─────────────────────────────────────────────────────────────
const RESET: &str = "\x1b[0m";
const BOLD:  &str = "\x1b[1m";
const DIM:   &str = "\x1b[2m";

const ORANGE: &str = "\x1b[38;5;208m";
const CYAN:   &str = "\x1b[38;5;87m";
const GREEN:  &str = "\x1b[38;5;82m";
const YELLOW: &str = "\x1b[38;5;226m";
const RED:    &str = "\x1b[38;5;196m";
const GREY:   &str = "\x1b[38;5;245m";
const WHITE:  &str = "\x1b[38;5;255m";

// ── Live activity display ─────────────────────────────────────────────────────

const BLOCK_LINES: usize = 9; // header(1) + sep(1) + 5 rows + blank(1) + footer(1)
const SPINNER: [char; 4] = ['⠋', '⠙', '⠴', '⠦'];

async fn activity_display_loop(log: ActivityLog) {
    let mut printed = false;
    let mut tick: usize = 0;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let entries = log.recent(5);
        if entries.is_empty() && !printed { continue; }

        let spin = SPINNER[tick % SPINNER.len()];
        tick += 1;

        // Move cursor up to overwrite the previous block.
        if printed {
            eprint!("\x1b[{}A\x1b[0J", BLOCK_LINES);
        }

        eprintln!("  {GREY}│{RESET}");
        eprintln!("  {GREY}│  {DIM}Activity{RESET}");
        eprintln!("  {GREY}│  ─────────────────────────────────────────────────────────────{RESET}");

        // Pad to always have 5 rows so block height is constant.
        let pad = 5usize.saturating_sub(entries.len());
        for _ in 0..pad {
            eprintln!("  {GREY}│{RESET}");
        }
        for a in &entries {
            let (icon, detail) = match &a.status {
                activity::Status::Running => (
                    format!("{CYAN}{spin}{RESET}"),
                    format!("{WHITE}{}…{RESET}  {DIM}{}{RESET}", a.description, a.elapsed_str()),
                ),
                activity::Status::Done(result) => (
                    format!("{GREEN}✓{RESET}"),
                    format!("{GREY}{}{RESET}  {DIM}{}{RESET}", result, a.elapsed_str()),
                ),
            };
            let kind_w = format!("{ORANGE}{:<7}{RESET}", a.kind);
            eprintln!("  {GREY}│{RESET}  {icon}  {DIM}{}{RESET}  {kind_w}  {detail}", a.time);
        }

        eprintln!("  {GREY}│{RESET}");
        eprint!("  {GREY}╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌{RESET}");

        printed = true;
    }
}

// ── Startup helpers ───────────────────────────────────────────────────────────

fn step(icon: &str, label: &str) {
    eprintln!("  {GREY}│{RESET}  {icon}  {WHITE}{label}{RESET}");
}

fn step_ok(label: &str, detail: &str) {
    eprintln!("  {GREY}│{RESET}  {GREEN}✓{RESET}  {WHITE}{label}{RESET}  {GREY}{detail}{RESET}");
}

fn step_warn(label: &str, detail: &str) {
    eprintln!("  {GREY}│{RESET}  {YELLOW}⚠{RESET}  {WHITE}{label}{RESET}  {GREY}{detail}{RESET}");
}

#[tokio::main]
async fn main() {
    // Pretty startup banner — logs go to stderr so they don't interfere with
    // any stdout piping; tracing (for request logs) stays on stderr too.
    eprintln!();
    eprintln!("  {ORANGE}{BOLD}███████╗██╗  ██╗ ██████╗ ██████╗  █████╗ ███╗   ██╗██╗███████╗██╗   ██╗{RESET}");
    eprintln!("  {ORANGE}{BOLD}██╔════╝██║  ██║██╔═══██╗██╔══██╗██╔══██╗████╗  ██║██║██╔════╝╚██╗ ██╔╝{RESET}");
    eprintln!("  {ORANGE}{BOLD}███████╗███████║██║   ██║██║  ██║███████║██╔██╗ ██║██║█████╗   ╚████╔╝ {RESET}");
    eprintln!("  {ORANGE}{BOLD}╚════██║██╔══██║██║   ██║██║  ██║██╔══██║██║╚██╗██║██║██╔══╝    ╚██╔╝  {RESET}");
    eprintln!("  {ORANGE}{BOLD}███████║██║  ██║╚██████╔╝██████╔╝██║  ██║██║ ╚████║██║██║        ██║   {RESET}");
    eprintln!("  {ORANGE}{BOLD}╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝        ╚═╝   {RESET}");
    eprintln!("  {GREY}Shodan data explorer  ·  {DIM}v{}{RESET}", env!("CARGO_PKG_VERSION"));
    eprintln!("  {GREY}╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌{RESET}");
    eprintln!();

    // Suppress the default tracing formatter — we'll print our own lines.
    // Request/error logs still flow through tracing but at WARN level only.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .without_time()
        .with_target(false)
        .with_level(false)
        .init();

    let config = Config::default();

    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let template_path = project_root.join("templates").join("index.html");
    let static_dir = project_root.join("static");

    // ── Load data ──────────────────────────────────────────────────────────
    eprintln!("  {GREY}│{RESET}");
    step("📂", &format!("Loading data from  {CYAN}{}{RESET}", config.data_dir.display()));
    eprintln!("  {GREY}│{RESET}");

    let t0 = std::time::Instant::now();
    let data_store = store::DataStore::load_verbose(&config.data_dir);
    let elapsed = t0.elapsed();

    eprintln!("  {GREY}│{RESET}");
    step_ok("Data loaded",
        &format!("{ORANGE}{BOLD}{}{RESET}{GREY} records · {RESET}{ORANGE}{}{RESET}{GREY} unique CVEs · {RESET}{ORANGE}{}{RESET}{GREY} files  ({:.2?}){RESET}",
            data_store.records.len(),
            data_store.cve_count,
            data_store.files_loaded,
            elapsed,
        ));

    if data_store.duplicates_removed > 0 {
        step_warn("Duplicates removed", &format!("{}", data_store.duplicates_removed));
    }
    if data_store.parse_errors > 0 {
        step_warn("Parse errors", &format!("{}", data_store.parse_errors));
    }

    // ── Scan history ───────────────────────────────────────────────────────
    let scan_store = ScanStore::new(&config.scan_store);
    let scan_count = scan_store.count();
    if scan_count > 0 {
        step_ok("Scan history", &format!("{ORANGE}{}{RESET}{GREY} previous results loaded{RESET}", scan_count));
    } else {
        step("💡", &format!("{GREY}No scan history yet — use the Targets tab to start scanning{RESET}"));
    }

    eprintln!("  {GREY}│{RESET}");

    // ── Build server ───────────────────────────────────────────────────────
    let activity = ActivityLog::new();

    let state = AppState {
        store: Arc::new(RwLock::new(data_store)),
        scan_store: Arc::new(scan_store),
        config: Arc::new(config.clone()),
        template_path,
        activity: activity.clone(),
    };

    // Spawn background task that refreshes the live activity block on stderr.
    tokio::spawn(activity_display_loop(activity));

    let mut app = build_router(state);

    if static_dir.exists() {
        use tower_http::services::ServeDir;
        app = app.nest_service("/static", ServeDir::new(&static_dir));
    }

    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .expect("Invalid HOST:PORT");

    let url = format!("http://{}", addr);
    eprintln!("  {GREY}│{RESET}  {GREEN}{BOLD}🚀 Ready!{RESET}  Open  {CYAN}{BOLD}{url}{RESET}");
    eprintln!("  {GREY}│{RESET}  {GREY}Press Ctrl+C to stop{RESET}");
    eprintln!("  {GREY}│{RESET}");
    eprintln!();

    let listener = tokio::net::TcpListener::bind(addr).await.expect("Failed to bind");
    axum::serve(listener, app).await.expect("Server error");
}

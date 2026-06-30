# Shodanify — AI Context

## What this is

A **local web dashboard** for browsing and analysing Shodan bulk export files. Written in **Rust** (rewritten from an earlier Python/Flask prototype — the old Python files are deleted but still referenced in git history and in the README which is now stale).

Drop `.json.gz` or `.json` Shodan NDJSON exports into `data/`, run the server, and get a searchable, filterable, live-scanning UI.

## Stack

- **Language**: Rust (edition 2021), binary name `shodanify`
- **Web framework**: Axum 0.7 + Tokio async runtime
- **Parallelism**: Rayon for CPU-bound data loading; Tokio for async I/O (scanning)
- **Serialisation**: serde_json — records are stored as raw `serde_json::Value`
- **HTTP client** (for scanning): reqwest with rustls-tls, invalid-cert accepted
- **Frontend**: Single-page HTML at `templates/index.html` — served from disk on every request so edits are live without a restart. Uses Alpine.js + Tailwind from CDN.
- **Static assets**: `static/` dir served at `/static` if it exists

## Source layout

| File | Purpose |
|------|---------|
| `src/main.rs` | Entry point: banner, config, data load, server start, live activity display loop |
| `src/config.rs` | `Config` struct — all values from env vars with defaults |
| `src/store.rs` | `DataStore`: load files in parallel (rayon), dedup by `(ip_str, port)` keeping newest timestamp, precompute summaries/stats/duplicates as `Arc<Value>` |
| `src/parsing.rs` | `parse_record` normalises raw Shodan JSON; `record_summary` builds the lightweight row object; `INFRA_DOMAINS` list used to classify infra vs. real websites |
| `src/stats.rs` | `compute_stats_full` — aggregates CVEs, ports, orgs, countries, tech, severity etc. |
| `src/scanner.rs` | `scan_targets`: async TCP check + rDNS + HTTP(S) probe with scheme auto-detection and fallback |
| `src/scan_store.rs` | Persists scan results to `data/.scan_results.json` (or `SCAN_STORE` env) |
| `src/filter.rs` | `FilterParams` + `apply` — server-side filtering/pagination used by `/api/hosts` |
| `src/report.rs` | `generate` — produces a standalone HTML report for an org or the whole dataset |
| `src/activity.rs` | `ActivityLog` — a small in-memory ring of recent ops displayed on stderr |
| `src/routes.rs` | All HTTP routes wired here |
| `templates/index.html` | The entire frontend SPA |

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Serves `templates/index.html` |
| GET | `/api/records` | All record summaries (precomputed `Arc`) |
| GET | `/api/records/:ip/:port` | Full detail for one record |
| GET | `/api/stats` | Aggregated statistics |
| GET | `/api/duplicates` | Duplicate groups |
| GET | `/api/infra-domains` | Sorted list of infra domain patterns |
| GET | `/api/scans` | Persisted scan history |
| POST | `/api/hosts` | Filtered/paginated host list (`FilterParams` JSON body) |
| POST | `/api/scan` | Run live scans against selected targets |
| POST | `/api/report` | Generate and download HTML report |
| POST | `/api/reload` | Hot-reload data from disk |

## Configuration (env vars)

| Var | Default | Description |
|-----|---------|-------------|
| `DATA_DIR` | `data` | Directory with `.json.gz` / `.json` files |
| `HOST` | `0.0.0.0` | Bind host |
| `PORT` | `5000` | Bind port |
| `SCAN_STORE` | `data/.scan_results.json` | Scan result persistence path |
| `SCAN_WORKERS` | `16` | Concurrent scan workers |
| `SCAN_CONNECT_TIMEOUT` | `4.0` | TCP connect timeout (seconds) |
| `SCAN_READ_TIMEOUT` | `6.0` | HTTP read timeout (seconds) |
| `SCAN_MAX_TARGETS` | `300` | Max targets per scan request |

## Build & run

```bash
cargo build --release          # produces target/release/shodanify
./target/release/shodanify     # or: bash run.sh
```

Data directory must exist at startup or the store starts empty (a warning is logged).

## Data flow

1. **Load**: `collect_data_files` finds `.json.gz` > `.gz` > `.json` in `DATA_DIR`
2. **Parse**: each file parsed in parallel via rayon; lines are NDJSON; gzip auto-detected by extension
3. **Dedup**: single-pass HashMap keyed on `(ip_str, port)`, newest timestamp wins; losers tracked for duplicate report
4. **Precompute**: summaries + stats + duplicate report all computed via `rayon::join` and stored as `Arc<Value>` — serialised once, cheaply cloned per request
5. **Serve**: Axum routes read `SharedStore` (`Arc<RwLock<DataStore>>`); reload replaces the inner value

## Key design decisions

- Records kept as raw `serde_json::Value` throughout — no typed struct, avoids schema churn as Shodan adds fields
- Summaries/stats precomputed at load time and arc-cloned on each request — no per-request serialisation cost
- Scanner accepts invalid TLS certs by design (Shodan hosts are often misconfigured)
- Scheme auto-detection: known ports (80, 8080 → HTTP; 443, 8443 → HTTPS); ambiguous ports try HTTPS first, fall back to HTTP on TLS handshake mismatch
- Frontend reloaded from disk on every request — no restart needed when editing `templates/index.html`

## What the frontend shows

Five tabs driven entirely by the REST API above:
1. **Overview** — summary stats cards + charts
2. **Hosts** — paginated, sortable table with global search/filter. Filters are sticky across all tabs.
3. **Vulns** — CVE list ranked by CVSS with per-CVE host list
4. **Tech** — fingerprinted technology breakdown
5. **Analytics** — scatter/heatmap/donut/histogram charts; clicking a segment applies a cross-tab facet filter
6. **Targets** — live-scan tab: TCP + HTTP health check, org/infra separation, CSV export, per-org HTML report download

# Shodanify

A fast, local web dashboard for browsing and analysing **Shodan bulk export files**. Drop your `.json.gz` exports into the `data/` folder, run the binary, and get a searchable, filterable, live-scanning view of every host, vulnerability, and technology in the dataset.

Built in **Rust** — loads and deduplicates tens of thousands of records in seconds, then serves them from an in-memory store with gzip compression on every response.

---

## Features

- **Overview** — at-a-glance stats: total records, unique IPs, CVE count, country breakdown, severity distribution, top ports / orgs / tech
- **Hosts table** — sortable, filterable list of every host with IP, port, org, location, detected tech stack, CVE count, and CVSS score. Search and filters are global and persist across all tabs
- **Vulnerability view** — all CVEs across the dataset ranked by CVSS, filterable by severity and verification status, with per-CVE affected host list including hostnames. CVEs are sortable by CVSS and EPSS
- **Technology view** — every fingerprinted technology with version info and host count
- **Analytics view** — risk-landscape scatter, port×severity correlation heatmap, severity/TLS donuts, CVSS histogram, most-exposed orgs, tech adoption and a scan timeline. Click any chart segment to apply a cross-tab facet filter that affects every other view simultaneously
- **Targets view** — live website health checks: TCP reachability, HTTP/HTTPS status, page description, redirects, page title, response time, and reverse DNS — all scanned in parallel with a configurable worker/thread count and a **stop** control to abort a run mid-scan. Sortable columns and persisted results so you always know when a target was last checked. Real organisation websites are separated from cloud/VPS infrastructure (by domain pattern and TLS cert), with an editable infrastructure-domain list. Export the current view as **CSV**, a standalone **per-organisation HTML report**, or a self-contained **Quick Export** security report (collapsible host summary, detailed findings, and a linked CVE annex — all searchable and paginated client-side)
- **Host detail modal** — click any host to drill into full detail across five tabs:
  - **Info** — location, ASN, org/ISP, hostnames, domains, cloud provider, CPE identifiers
  - **HTTP** — status code, server header, page title, detected components
  - **SSL** — certificate subject/issuer, validity window, cipher suite, supported TLS versions, JARM fingerprint, SHA-256/SHA-1 fingerprints
  - **Vulns** — per-host CVE list with CVSS, EPSS score, description, and references
  - **Raw** — complete raw banner data returned by Shodan

---

## Requirements

- **Rust toolchain** (stable) — only needed to build from source. The release binary has no runtime dependencies.
- A modern browser (Chrome, Firefox, Edge). The frontend loads Tailwind CSS and Alpine.js from CDN, so it needs internet access on first load.

---

## Installation

### Windows

```powershell
# 1. Install Rust if you don't have it (https://rustup.rs)
winget install Rustlang.Rustup

# 2. Clone and build
git clone https://github.com/youruser/shodanify.git
cd shodanify
cargo build --release

# 3. Run
.\target\release\shodanify.exe
```

Or download a pre-built binary from the [Releases](../../releases) page, place it in the project root, and run it directly.

### macOS

```bash
# 1. Install Rust if you don't have it
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# 2. Clone and build
git clone https://github.com/youruser/shodanify.git
cd shodanify
cargo build --release

# 3. Run
./target/release/shodanify
```

### Linux

```bash
# 1. Install Rust if you don't have it
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# 2. Install OpenSSL dev headers (needed by reqwest)
# Debian/Ubuntu:
sudo apt install pkg-config libssl-dev
# Fedora/RHEL:
sudo dnf install pkg-config openssl-devel
# Arch:
sudo pacman -S pkg-config openssl

# 3. Clone and build
git clone https://github.com/youruser/shodanify.git
cd shodanify
cargo build --release

# 4. Run
./target/release/shodanify
```

---

## Adding your Shodan data

Shodan bulk exports are gzip-compressed NDJSON files — one JSON object per line. Place them in the `data/` directory:

```
shodanify/
└── data/
    ├── export-2024-01-15.json.gz
    ├── export-2024-02-03.json.gz
    └── another-search.json
```

Both `.json.gz` (gzip) and plain `.json` files are supported. All files in the folder are loaded in parallel at startup and deduplicated by `(ip, port)` — the most recent scan wins.

To export from the Shodan CLI:

```bash
shodan download --limit 10000 my-export 'org:"Acme Corp"'
# produces my-export.json.gz — move it to data/
```

---

## Running

```bash
# Default: binds 127.0.0.1:8080, reads data from ./data
./target/release/shodanify          # Linux / macOS
.\target\release\shodanify.exe      # Windows
```

Then open [http://localhost:8080](http://localhost:8080).

> The `data/` directory is resolved relative to the current working directory first, then relative to the executable's own folder — so double-clicking the binary on Windows works as long as a `data/` folder sits next to it.

### Configuration

All options are set via environment variables — no config file needed:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATA_DIR` | `data` | Directory containing your Shodan export files |
| `HOST` | `127.0.0.1` | Interface to bind |
| `PORT` | `8080` | Port to listen on |
| `SCAN_STORE` | `data/.scan_results.json` | Where scan results are persisted |
| `SCAN_WORKERS` | `16` | Default concurrent connections during live scans (the Targets tab can override this per scan) |
| `SCAN_CONNECT_TIMEOUT` | `4.0` | TCP connect timeout in seconds |
| `SCAN_READ_TIMEOUT` | `6.0` | HTTP read timeout in seconds |
| `SCAN_MAX_TARGETS` | `10000` | Maximum targets per scan request |

**Examples:**

```bash
# Linux / macOS
PORT=9000 DATA_DIR=/mnt/exports ./target/release/shodanify

# Windows (PowerShell)
$env:PORT="9000"; $env:DATA_DIR="D:\exports"; .\target\release\shodanify.exe
```

---

## Reloading data without restarting

Click the **Reload** button in the top-right corner of the UI. The server will re-scan the `data/` folder, pick up any new files, and hot-swap the in-memory store — no restart needed.

---

## Project structure

```
shodanify/
├── src/
│   ├── main.rs         # Entry point, startup banner, server init
│   ├── config.rs       # Config struct (all from env vars)
│   ├── store.rs        # Data loading, dedup, precomputed summaries
│   ├── parsing.rs      # Shodan JSON normalisation, record summaries
│   ├── stats.rs        # Aggregated statistics computation
│   ├── filter.rs       # Server-side filtering and pagination
│   ├── scanner.rs      # Async TCP + HTTP/HTTPS health checks
│   ├── scan_store.rs   # Scan result persistence
│   ├── report.rs       # HTML report generation
│   ├── routes.rs       # Axum HTTP routes
│   └── activity.rs     # Live activity log (stderr display)
├── templates/
│   └── index.html      # Single-page frontend (Alpine.js + Tailwind)
├── data/               # Put your Shodan export files here (git-ignored)
├── Cargo.toml
└── run.sh
```

---

## API

The frontend is driven entirely by a JSON API you can also query directly:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/records` | All records (summary fields only) |
| GET | `/api/records/:ip/:port` | Full detail for a single host |
| GET | `/api/stats` | Aggregated stats — top ports, countries, CVEs, tech |
| GET | `/api/duplicates` | IP:port collisions across files — kept vs superseded scans |
| GET | `/api/scans` | All persisted health-check results |
| GET | `/api/infra-domains` | Cloud/hosting domain patterns used to classify infrastructure |
| POST | `/api/hosts` | Filtered + paginated host list. Body: `FilterParams` JSON |
| POST | `/api/scan` | Run live TCP/HTTP checks. Body: `{ "targets": [{ "ip": "1.2.3.4", "port": 443 }] }` |
| POST | `/api/report` | Generate and download a standalone HTML report |
| POST | `/api/reload` | Hot-reload all files from `DATA_DIR` |

> **Active scanning note:** the Targets view makes outbound TCP/HTTP requests to hosts in your data to check whether they are reachable. It sends a single request per target, identifies itself with a `Shodanify-Healthcheck` User-Agent, and only contacts `ip:port` pairs already present in your loaded dataset. Only use it on hosts you are authorised to assess.

---

## Data format

Shodan exports are newline-delimited JSON. Each line is a host record:

```jsonc
{
  "ip_str": "1.2.3.4",
  "port": 443,
  "org": "Acme Corp",
  "hostnames": ["mail.acme.com"],
  "location": { "country_code": "AU", "city": "Sydney" },
  "ssl": { "cert": { "subject": {}, "expires": "20261231000000Z" } },
  "http": { "title": "Login", "server": "nginx/1.24.0", "components": {} },
  "vulns": { "CVE-2021-44228": { "cvss": 10.0, "verified": true } }
}
```

---

## License

MIT

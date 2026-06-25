# Shodanify

A local web dashboard for browsing and analysing Shodan bulk export files. Drop your `.json.gz` exports into the `data/` folder, run the server, and get a searchable, filterable view of every host, vulnerability, and technology in the dataset.

![Shodanify dashboard](https://i.imgur.com/placeholder.png)

---

## Features

- **Overview dashboard** — at-a-glance stats: total records, unique IPs, CVE count, country breakdown, severity distribution, top ports/orgs/tech
- **Hosts table** — sortable and filterable list of every host with IP, port, org, location, detected tech stack, CVE count, and CVSS score
- **Vulnerability view** — all CVEs across the dataset ranked by CVSS, filterable by severity and verification status, with per-CVE affected host list including hostnames
- **Technology view** — every fingerprinted technology with version info and host count
- **Analytics view** — risk-landscape scatter, port×severity correlation heatmap, severity/TLS donuts, CVSS histogram, most-exposed orgs, tech adoption and a scan timeline. Click any chart segment to apply a cross-tab facet that filters every view at once
- **Targets view** — live website health checks for the web-facing hosts: TCP reachability, HTTP status, redirects, page title, response time and reverse DNS, scanned in parallel. Results are persisted with a last-scanned timestamp so you know when each target was last checked. Real organisation websites are separated from cloud/VPS infrastructure (by domain and TLS cert), with an editable infrastructure-domain list. Export the current view as **CSV** or generate a printable **per-organisation PDF report** of exposed sites, live status and CVEs
- **Host detail modal** — click any host to drill into full detail across five tabs:
  - **Info** — location, ASN, org/ISP, hostnames, domains, cloud provider, CPE identifiers
  - **HTTP** — status code, server header, page title, detected components
  - **SSL** — certificate subject/issuer, validity window, cipher suite, supported TLS versions, JARM fingerprint, SHA-256/SHA-1 fingerprints
  - **Vulns** — per-host CVE list with CVSS, EPSS score, description, and references
  - **Raw** — raw banner data returned by Shodan

---

## Requirements

- Python 3.8+
- pip

The only runtime dependency is Flask. Everything else (Tailwind CSS, Alpine.js) is loaded from CDN, so the browser needs internet access on first load.

---

## Installation

```bash
git clone https://github.com/youruser/shodanify.git
cd shodanify
pip install -r requirements.txt
```

Or with a virtual environment (recommended):

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## Adding your Shodan data

Shodan bulk exports come as gzip-compressed NDJSON files — one JSON object per line. Place them in the `data/` directory:

```
shodanify/
└── data/
    ├── export-2024-01-15.json.gz
    ├── export-2024-02-03.json.gz
    └── another-search.json.gz
```

Both `.json.gz` (gzip) and plain `.json` files are supported. The app reads all files in the folder on startup and caches them in memory.

To export from Shodan CLI:

```bash
shodan download --limit 1000 my-export 'org:"Acme Corp"'
# produces my-export.json.gz — move it to data/
```

---

## Running

```bash
python3 app.py
```

Then open [http://localhost:5000](http://localhost:5000) in your browser.

The server starts on `0.0.0.0:5000` by default, so it is also reachable on your local network.

To use a different port or data directory:

```bash
PORT=8080 DATA_DIR=/path/to/exports python3 app.py
```

> **Note:** This uses Flask's built-in development server, which is fine for local use. Do not expose it publicly without putting it behind a proper WSGI server (gunicorn, uWSGI) and a firewall.

---

## Reloading data without restarting

Once the server is running, click the **Reload** button in the top-right corner of the UI. It will re-scan the `data/` folder and pick up any new files you've dropped in, without needing a server restart.

---

## Project structure

```
shodanify/
├── app.py              # Flask backend — parsing, caching, API routes
├── templates/
│   └── index.html      # Single-page frontend (Tailwind CSS + Alpine.js)
├── data/               # Put your Shodan export files here (git-ignored)
├── requirements.txt
└── .gitignore
```

---

## API

The frontend talks to a small JSON API if you want to query it directly:

| Endpoint | Method | Description |
|---|---|---|
| `/api/records` | GET | All records (summary fields) |
| `/api/records/<ip>/<port>` | GET | Full detail for a single host |
| `/api/stats` | GET | Aggregated stats, top ports/countries/CVEs/tech |
| `/api/duplicates` | GET | IP:port collisions across files — kept vs superseded scans |
| `/api/scans` | GET | All persisted health-check results, keyed by `ip:port` |
| `/api/infra-domains` | GET | Default cloud/hosting domains used to classify infrastructure |
| `/api/scan` | POST | Run live TCP/HTTP health checks for a batch of targets (concurrent). Body: `{ "targets": [{ "ip": "1.2.3.4", "port": 443 }] }`. Only scans targets present in the loaded dataset |
| `/api/reload` | POST | Flush cache and reload all files from `data/` |

> **Active scanning note:** the Targets view makes outbound TCP/HTTP requests to the hosts in your data to check whether their sites are up. It sends a single request per target, identifies itself with a `Shodanify-Healthcheck` User-Agent, and only contacts `ip:port` pairs already present in your dataset. Use it on hosts you are authorised to assess.

---

## Data format

Shodan exports are newline-delimited JSON. Each line is a host record with fields like:

```jsonc
{
  "ip_str": "1.2.3.4",
  "port": 443,
  "org": "Acme Corp",
  "hostnames": ["mail.acme.com"],
  "location": { "country_code": "AU", "city": "Sydney", ... },
  "ssl": { "cert": { "subject": {...}, "expires": "20261231000000Z" }, ... },
  "http": { "title": "Login", "server": "nginx/1.24.0", "components": {...} },
  "vulns": { "CVE-2021-44228": { "cvss": 10.0, "verified": true, ... } }
}
```

---

## License

MIT

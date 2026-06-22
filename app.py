from flask import Flask, render_template, jsonify
from pathlib import Path
from collections import defaultdict
import json, gzip, os

app = Flask(__name__)
DATA_DIR = Path(os.environ.get("DATA_DIR", "data"))

_records_cache = None
_stats_cache = None
_duplicates_removed = 0


# Parsing helpers

def _cert_date(s):
    if not s:
        return None
    try:
        from datetime import datetime
        return datetime.strptime(s, "%Y%m%d%H%M%SZ").isoformat() + "Z"
    except Exception:
        return s


def _cvss_severity(score):
    try:
        score = float(score or 0)
    except (TypeError, ValueError):
        return "none"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _parse_ssl(ssl):
    if not ssl:
        return None
    cert = ssl.get("cert") or {}
    subj = cert.get("subject") or {}
    iss = cert.get("issuer") or {}
    fp = cert.get("fingerprint") or {}
    return {
        "subject_cn": subj.get("CN") or subj.get("O"),
        "subject": subj,
        "issuer_cn": iss.get("CN") or iss.get("O"),
        "issuer": iss,
        "issued": _cert_date(cert.get("issued")),
        "expires": _cert_date(cert.get("expires")),
        "expired": cert.get("expired", False),
        "sig_alg": cert.get("sig_alg"),
        "serial": str(cert.get("serial", "")),
        "sha256": fp.get("sha256"),
        "sha1": fp.get("sha1"),
        "versions": ssl.get("versions") or [],
        "cipher": ssl.get("cipher"),
        "jarm": ssl.get("jarm"),
        "alpn": ssl.get("alpn") or [],
    }


def _parse_http(http):
    if not http:
        return None
    components = http.get("components") or {}
    tech = []
    for name, info in components.items():
        info = info or {}
        tech.append({
            "name": name,
            "categories": info.get("categories") or [],
            "versions": info.get("versions") or [],
        })
    return {
        "status": http.get("status"),
        "title": http.get("title"),
        "server": http.get("server"),
        "location": http.get("location"),
        "host": http.get("host"),
        "components": tech,
        "robots": http.get("robots"),
        "html_preview": (http.get("html") or "")[:3000],
    }


def _parse_vulns(raw):
    result = []
    for cve_id, info in (raw or {}).items():
        info = info or {}
        cvss = float(info.get("cvss") or info.get("cvss_v2") or 0)
        result.append({
            "cve": cve_id,
            "cvss": cvss,
            "cvss_v2": info.get("cvss_v2"),
            "cvss_version": info.get("cvss_version"),
            "severity": _cvss_severity(cvss),
            "epss": info.get("epss", 0),
            "ranking_epss": info.get("ranking_epss", 0),
            "verified": info.get("verified", False),
            "summary": info.get("summary", ""),
            "references": (info.get("references") or [])[:8],
        })
    result.sort(key=lambda x: x["cvss"], reverse=True)
    return result


def _parse_record(r):
    loc = r.get("location") or {}
    shodan = r.get("_shodan") or {}
    vulns = _parse_vulns(r.get("vulns"))
    http = _parse_http(r.get("http"))
    ssl = _parse_ssl(r.get("ssl"))
    return {
        "ip_str": r.get("ip_str", ""),
        "ip": r.get("ip"),
        "port": r.get("port"),
        "transport": r.get("transport", "tcp"),
        "isp": r.get("isp"),
        "org": r.get("org"),
        "asn": r.get("asn"),
        "os": r.get("os"),
        "product": r.get("product"),
        "version": r.get("version"),
        "hostnames": r.get("hostnames") or [],
        "domains": r.get("domains") or [],
        "timestamp": r.get("timestamp"),
        "tags": r.get("tags") or [],
        "cpe": r.get("cpe23") or r.get("cpe") or [],
        "location": {
            "city": loc.get("city"),
            "region": loc.get("region_code"),
            "country_code": loc.get("country_code"),
            "country_name": loc.get("country_name"),
            "lat": loc.get("latitude"),
            "lon": loc.get("longitude"),
        },
        "cloud": r.get("cloud"),
        "http": http,
        "ssl": ssl,
        "vulns": vulns,
        "data": (r.get("data") or "")[:3000],
        "shodan_module": shodan.get("module"),
        "shodan_id": shodan.get("id"),
    }


# Data loading and in-memory caching

def load_records(force=False):
    global _records_cache, _stats_cache, _duplicates_removed
    if _records_cache is not None and not force:
        return _records_cache

    raw = []
    if DATA_DIR.exists():
        for pattern, opener in [("*.json.gz", gzip.open), ("*.json", open)]:
            for path in sorted(DATA_DIR.glob(pattern)):
                try:
                    kwargs = {"mode": "rt", "encoding": "utf-8"}
                    if pattern == "*.json":
                        kwargs = {"encoding": "utf-8"}
                    with opener(path, **kwargs) as fh:
                        for line in fh:
                            line = line.strip()
                            if line:
                                try:
                                    raw.append(_parse_record(json.loads(line)))
                                except Exception:
                                    pass
                except Exception:
                    pass

    # Deduplicate by (ip_str, port), keeping the record with the newest timestamp
    seen: dict = {}
    for r in raw:
        key = (r["ip_str"], r["port"])
        existing = seen.get(key)
        if existing is None:
            seen[key] = r
        else:
            # Prefer the record with a later timestamp
            ts_new = r["timestamp"] or ""
            ts_old = existing["timestamp"] or ""
            if ts_new > ts_old:
                seen[key] = r

    records = list(seen.values())
    _duplicates_removed = len(raw) - len(records)
    _records_cache = records
    _stats_cache = None
    return records


def compute_stats(records):
    global _stats_cache
    if _stats_cache is not None:
        return _stats_cache

    ips = set()
    ports = defaultdict(int)
    countries: dict = {}
    orgs = defaultdict(int)
    cve_map: dict = {}
    tech_map: dict = {}
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}

    for r in records:
        ips.add(r["ip_str"])
        if r["port"]:
            ports[r["port"]] += 1

        loc = r["location"]
        cc = loc.get("country_code") or "XX"
        cn = loc.get("country_name") or "Unknown"
        if cc not in countries:
            countries[cc] = {"code": cc, "name": cn, "count": 0}
        countries[cc]["count"] += 1

        org = r["org"] or r["isp"] or "Unknown"
        orgs[org] += 1

        for v in r["vulns"]:
            cid = v["cve"]
            sev[v["severity"]] += 1
            if cid not in cve_map:
                cve_map[cid] = {
                    "cve": cid,
                    "max_cvss": v["cvss"],
                    "severity": v["severity"],
                    "verified": v["verified"],
                    "summary": v["summary"],
                    "epss": v.get("epss", 0),
                    "hosts": [],
                }
            entry = cve_map[cid]
            if v["cvss"] > entry["max_cvss"]:
                entry["max_cvss"] = v["cvss"]
                entry["severity"] = v["severity"]
                entry["summary"] = v["summary"]
            if v["verified"]:
                entry["verified"] = True
            entry["hosts"].append({
                "ip": r["ip_str"],
                "port": r["port"],
                "hostname": r["hostnames"][0] if r["hostnames"] else None,
            })

        if r["http"]:
            for t in r["http"]["components"]:
                nm = t["name"]
                if nm not in tech_map:
                    tech_map[nm] = {"name": nm, "count": 0, "categories": t["categories"], "versions": set()}
                tech_map[nm]["count"] += 1
                for ver in t["versions"]:
                    tech_map[nm]["versions"].add(ver)

    top_ports = [{"port": k, "count": v} for k, v in sorted(ports.items(), key=lambda x: x[1], reverse=True)][:12]
    top_countries = sorted(countries.values(), key=lambda x: x["count"], reverse=True)[:15]
    top_orgs = [{"org": k, "count": v} for k, v in sorted(orgs.items(), key=lambda x: x[1], reverse=True)][:10]
    top_vulns = sorted(cve_map.values(), key=lambda x: x["max_cvss"], reverse=True)[:50]
    for tv in top_vulns:
        tv["host_count"] = len(tv["hosts"])
        tv["hosts"] = tv["hosts"][:10]

    tech_list = []
    for t in tech_map.values():
        tech_list.append({**t, "versions": sorted(t["versions"])})
    tech_list.sort(key=lambda x: x["count"], reverse=True)

    _stats_cache = {
        "total_records": len(records),
        "duplicates_removed": _duplicates_removed,
        "unique_ips": len(ips),
        "unique_ports": len(ports),
        "unique_countries": len(countries),
        "unique_cves": len(cve_map),
        "total_vuln_instances": sum(sev.values()),
        "severity": sev,
        "top_ports": top_ports,
        "top_countries": top_countries,
        "top_orgs": top_orgs,
        "top_vulns": top_vulns,
        "tech": tech_list,
    }
    return _stats_cache


# Routes

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/records")
def api_records():
    records = load_records()
    result = []
    for r in records:
        result.append({
            "ip_str": r["ip_str"],
            "port": r["port"],
            "transport": r["transport"],
            "org": r["org"],
            "isp": r["isp"],
            "os": r["os"],
            "product": r["product"],
            "version": r["version"],
            "hostname": r["hostnames"][0] if r["hostnames"] else None,
            "hostnames": r["hostnames"],
            "country_code": r["location"]["country_code"],
            "country_name": r["location"]["country_name"],
            "city": r["location"]["city"],
            "timestamp": r["timestamp"],
            "vulns_count": len(r["vulns"]),
            "max_cvss": max((v["cvss"] for v in r["vulns"]), default=0),
            "http_title": r["http"]["title"] if r["http"] else None,
            "http_status": r["http"]["status"] if r["http"] else None,
            "tech": [t["name"] for t in r["http"]["components"]] if r["http"] else [],
            "has_ssl": r["ssl"] is not None,
            "ssl_cn": r["ssl"]["subject_cn"] if r["ssl"] else None,
            "ssl_expired": r["ssl"]["expired"] if r["ssl"] else None,
            "tags": r["tags"],
            "cloud": r["cloud"],
            "asn": r["asn"],
        })
    return jsonify(result)


@app.route("/api/records/<path:ip_str>/<int:port>")
def api_record_detail(ip_str, port):
    for r in load_records():
        if r["ip_str"] == ip_str and r["port"] == port:
            return jsonify(r)
    return jsonify({"error": "not found"}), 404


@app.route("/api/stats")
def api_stats():
    return jsonify(compute_stats(load_records()))


@app.route("/api/reload", methods=["POST"])
def api_reload():
    records = load_records(force=True)
    return jsonify({"status": "ok", "count": len(records)})


if __name__ == "__main__":
    load_records()
    app.run(debug=True, host="0.0.0.0", port=5000)

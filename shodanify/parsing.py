"""Pure functions that normalise raw Shodan banner records.

Everything here is side-effect free and independently testable.
"""
from datetime import datetime


def cert_date(s):
    """Convert a Shodan cert timestamp (``YYYYMMDDHHMMSSZ``) to ISO-8601."""
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y%m%d%H%M%SZ").isoformat() + "Z"
    except (ValueError, TypeError):
        return s


def cvss_severity(score):
    """Bucket a CVSS score into a severity label."""
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


def parse_ssl(ssl):
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
        "issued": cert_date(cert.get("issued")),
        "expires": cert_date(cert.get("expires")),
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


def parse_http(http):
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


def parse_vulns(raw):
    result = []
    for cve_id, info in (raw or {}).items():
        info = info or {}
        cvss = float(info.get("cvss") or info.get("cvss_v2") or 0)
        result.append({
            "cve": cve_id,
            "cvss": cvss,
            "cvss_v2": info.get("cvss_v2"),
            "cvss_version": info.get("cvss_version"),
            "severity": cvss_severity(cvss),
            "epss": info.get("epss", 0),
            "ranking_epss": info.get("ranking_epss", 0),
            "verified": info.get("verified", False),
            "summary": info.get("summary", ""),
            "references": (info.get("references") or [])[:8],
        })
    result.sort(key=lambda x: x["cvss"], reverse=True)
    return result


def parse_record(r):
    """Normalise a single raw Shodan record into the internal shape."""
    loc = r.get("location") or {}
    shodan = r.get("_shodan") or {}
    http = parse_http(r.get("http"))
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
        "ssl": parse_ssl(r.get("ssl")),
        "vulns": parse_vulns(r.get("vulns")),
        "data": (r.get("data") or "")[:3000],
        "shodan_module": shodan.get("module"),
        "shodan_id": shodan.get("id"),
    }


def record_summary(r):
    """The lightweight projection served by ``GET /api/records``."""
    http = r["http"]
    ssl = r["ssl"]
    return {
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
        "cves": [v["cve"] for v in r["vulns"]],
        "verified_cves": sum(1 for v in r["vulns"] if v["verified"]),
        "http_title": http["title"] if http else None,
        "http_status": http["status"] if http else None,
        "tech": [t["name"] for t in http["components"]] if http else [],
        "has_ssl": ssl is not None,
        "ssl_cn": ssl["subject_cn"] if ssl else None,
        "ssl_expired": ssl["expired"] if ssl else None,
        "tags": r["tags"],
        "cloud": r["cloud"],
        "asn": r["asn"],
    }

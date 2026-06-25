"""Pure functions that normalise raw Shodan banner records.

Everything here is side-effect free and independently testable.
"""
from datetime import datetime

# Auto-generated PTR / hosting domains. A host whose only domain is one of
# these is generic cloud/VPS infrastructure rather than an organisation's
# website. Matched as an exact domain or a parent suffix.
INFRA_DOMAINS = {
    "amazonaws.com", "compute.amazonaws.com", "compute-1.amazonaws.com",
    "cloudfront.net", "elasticbeanstalk.com",
    "googleusercontent.com", "bc.googleusercontent.com", "1e100.net",
    "cloudapp.azure.com", "cloudapp.net", "azure.com", "azurewebsites.net",
    "oraclecloud.com", "oraclevcn.com",
    "vultrusercontent.com", "linodeusercontent.com", "members.linode.com",
    "digitalocean.com", "your-server.de", "hetzner.com", "hetzner.de",
    "contabo.net", "contabo.host", "ovh.net", "ovh.com", "ovh.ca",
    "scaleway.com", "online.net", "leaseweb.com", "leaseweb.net",
    "choopa.com", "constant.com", "as-hosting.de", "secureserver.net",
    "hostwindsdns.com", "ramnode.com", "quadranet.com", "colocrossing.com",
    "frantech.ca", "servers.com", "dedicated.com", "ip-pool.com",
    "akamaitechnologies.com", "cloudflare.com", "t-ipconnect.de",
}


def _is_infra_domain(d):
    d = (d or "").lower().strip(".")
    return any(d == x or d.endswith("." + x) for x in INFRA_DOMAINS)


def _looks_like_domain(s):
    """True for things like ``acme.com.au`` but not IPs or single labels."""
    s = (s or "").lower().strip()
    if not s or " " in s or "." not in s:
        return False
    return s.rsplit(".", 1)[-1].isalpha()


def classify_site(domains, ssl_cn):
    """Decide whether a host is a real organisation website.

    Returns ``(is_site, primary_domain)``. ``is_site`` is True when there is a
    registrable domain (from Shodan's ``domains`` or the TLS certificate CN)
    that is not a cloud/hosting provider's auto-generated domain.
    """
    candidates = [d for d in (domains or []) if _looks_like_domain(d)]
    if ssl_cn:
        cn = ssl_cn.lower().lstrip("*").strip(".")
        if cn.startswith("www."):
            cn = cn[4:]
        if _looks_like_domain(cn):
            candidates.append(cn)
    real = [d for d in dict.fromkeys(candidates) if not _is_infra_domain(d)]
    if not real:
        return False, None
    # Prefer the most "apex" domain (fewest labels, then shortest).
    primary = sorted(real, key=lambda d: (d.count("."), len(d)))[0]
    return True, primary


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
    ssl = parse_ssl(r.get("ssl"))
    domains = r.get("domains") or []
    is_site, primary_domain = classify_site(domains, ssl.get("subject_cn") if ssl else None)
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
        "domains": domains,
        "is_site": is_site,
        "primary_domain": primary_domain,
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
        "domains": r["domains"],
        "is_site": r["is_site"],
        "primary_domain": r["primary_domain"],
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

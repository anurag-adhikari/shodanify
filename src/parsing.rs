use serde_json::{json, Value};
use std::collections::HashSet;

fn truncate_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        s
    } else {
        let mut idx = max_bytes;
        while idx > 0 && !s.is_char_boundary(idx) {
            idx -= 1;
        }
        &s[..idx]
    }
}

pub static INFRA_DOMAINS: &[&str] = &[
    "amazonaws.com",
    "compute.amazonaws.com",
    "compute-1.amazonaws.com",
    "cloudfront.net",
    "elasticbeanstalk.com",
    "googleusercontent.com",
    "bc.googleusercontent.com",
    "1e100.net",
    "cloudapp.azure.com",
    "cloudapp.net",
    "azure.com",
    "azurewebsites.net",
    "oraclecloud.com",
    "oraclevcn.com",
    "vultrusercontent.com",
    "linodeusercontent.com",
    "members.linode.com",
    "digitalocean.com",
    "your-server.de",
    "hetzner.com",
    "hetzner.de",
    "contabo.net",
    "contabo.host",
    "ovh.net",
    "ovh.com",
    "ovh.ca",
    "scaleway.com",
    "online.net",
    "leaseweb.com",
    "leaseweb.net",
    "choopa.com",
    "constant.com",
    "as-hosting.de",
    "secureserver.net",
    "hostwindsdns.com",
    "ramnode.com",
    "quadranet.com",
    "colocrossing.com",
    "frantech.ca",
    "servers.com",
    "dedicated.com",
    "ip-pool.com",
    "akamaitechnologies.com",
    "cloudflare.com",
    "t-ipconnect.de",
];

fn is_infra_domain(d: &str) -> bool {
    let d = d.to_lowercase();
    let d = d.trim_matches('.');
    INFRA_DOMAINS.iter().any(|x| d == *x || d.ends_with(&format!(".{}", x)))
}

// Technical subdomain names that indicate server/service endpoints, not human-facing websites.
static TECHNICAL_SUBS: &[&str] = &[
    "api", "apis", "mail", "smtp", "pop", "pop3", "imap", "ftp", "sftp", "ssh",
    "ns", "ns1", "ns2", "ns3", "ns4", "mx", "cpanel", "whm", "webmail", "autodiscover",
    "cdn", "dev", "staging", "stage", "test", "sandbox", "uat", "qa", "demo",
    "beta", "alpha", "admin", "manage", "panel", "dashboard", "monitor", "status",
    "health", "backup", "archive", "cache", "proxy", "gateway", "vpn", "citrix",
    "remote", "rdp", "assets", "static", "media", "img", "images", "files",
    "downloads", "upload", "uploads", "internal", "intranet", "corp", "local",
    "waf", "sso", "auth", "oauth", "oidc", "idp", "mgmt", "management",
];

/// Estimates the number of labels that form the public TLD.
/// For 2-level country-code TLDs like .co.nz, .com.au, .edu.au → returns 2.
/// For .com, .org, .net, .io, etc. → returns 1.
fn tld_depth(labels: &[&str]) -> usize {
    let n = labels.len();
    if n < 3 { return 1; }
    let last = labels[n - 1];
    let second_last = labels[n - 2];
    // 2-level TLD: last is a 2-char country code AND second-last is a short (2-4 char) SLD
    // e.g. co.nz, com.au, edu.au, gov.au, net.au, org.nz, ac.nz, co.uk …
    if last.len() == 2 && last.chars().all(|c| c.is_ascii_alphabetic())
        && second_last.len() <= 4 && second_last.chars().all(|c| c.is_ascii_alphabetic())
    {
        return 2;
    }
    1
}

/// Returns true if this domain should be classified as infra because:
///   (a) it has more than 1 effective subdomain level above the registered domain, OR
///   (b) it has exactly 1 subdomain that is a known technical/service name (or contains one).
///
/// Examples filtered OUT: api.wiseops.wiseway.co.nz, cpanel.userdomain.com,
///   smartchoice.eresearch.unimelb.edu.au, archive-dev.ada.edu.au
///
/// Examples KEPT: inside.freightmatch.com.au, www.draytek.com, print.unihubsg.org
pub fn is_subdomain_infra(domain: &str) -> bool {
    let d = domain.trim_matches('.');
    let labels: Vec<&str> = d.split('.').collect();
    let n = labels.len();
    if n < 2 { return false; }

    let tld = tld_depth(&labels);
    let registered_depth = tld + 1; // TLD labels + 1 for the registered name
    let subdomain_count = (n as isize - registered_depth as isize).max(0) as usize;

    // Rule (a): more than 1 subdomain level
    if subdomain_count > 1 { return true; }

    // Rule (b): the single subdomain is a known service/server name
    if subdomain_count == 1 {
        let sub = labels[0].to_lowercase();
        // Check the whole subdomain and each dash-segment
        let parts: Vec<&str> = sub.split('-').collect();
        if TECHNICAL_SUBS.contains(&sub.as_str()) { return true; }
        if parts.iter().any(|p| TECHNICAL_SUBS.contains(p)) { return true; }
    }

    false
}

/// Returns true when the domain's leading labels encode an IP address — e.g.:
///   "115.9.160.203.isphone.com.au"   → 4 consecutive numeric labels
///   "203-196-40-164.static.dsl.net.au" → first label has 3+ dash-separated octets
///   "cpe-120-148-33-130.vb07.vic..."   → first label has 3+ dash-separated numbers
///   "35.130.247.43.static.as24516.net" → 4 leading numeric labels
pub fn has_numeric_hostname_prefix(domain: &str) -> bool {
    let d = domain.trim_matches('.');
    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() < 2 { return false; }

    // Rule 1: first label contains 3+ dash-separated numeric parts (IP-with-dashes or CPE)
    let first = labels[0];
    let dash_numeric = first.split('-')
        .filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        .count();
    if dash_numeric >= 3 { return true; }

    // Rule 2: 3 or more consecutive leading labels are all-digit (IP octets as dots)
    let leading_numeric = labels.iter()
        .take_while(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_digit()))
        .count();
    if leading_numeric >= 3 { return true; }

    false
}

fn looks_like_domain(s: &str) -> bool {
    let s = s.to_lowercase();
    let s = s.trim();
    if s.is_empty() || s.contains(' ') || !s.contains('.') {
        return false;
    }
    s.rsplit('.').next().map(|tld| tld.chars().all(|c| c.is_ascii_alphabetic())).unwrap_or(false)
}

pub fn classify_site(domains: &[String], ssl_cn: Option<&str>, hostname: Option<&str>) -> (bool, Option<String>) {
    // If the primary hostname itself encodes an IP address or is a technical service
    // endpoint, it's infra — regardless of what domains Shodan extracted from the cert
    // (those are stripped-down parent domains and won't trigger the check themselves).
    if let Some(h) = hostname {
        if has_numeric_hostname_prefix(h) || is_subdomain_infra(h) {
            return (false, None);
        }
    }
    let mut candidates: Vec<String> = domains
        .iter()
        .filter(|d| looks_like_domain(d))
        .map(|d| d.to_lowercase())
        .collect();

    if let Some(cn) = ssl_cn {
        let mut cn = cn.to_lowercase();
        cn = cn.trim_start_matches('*').trim_matches('.').to_string();
        if cn.starts_with("www.") {
            cn = cn[4..].to_string();
        }
        if looks_like_domain(&cn) {
            candidates.push(cn);
        }
    }

    // Deduplicate while preserving order
    let mut seen = HashSet::new();
    candidates.retain(|d| seen.insert(d.clone()));

    let real: Vec<String> = candidates.into_iter()
        .filter(|d| !is_infra_domain(d) && !has_numeric_hostname_prefix(d) && !is_subdomain_infra(d))
        .collect();
    if real.is_empty() {
        return (false, None);
    }

    // Prefer apex domain (fewest dots, then shortest)
    let primary = real
        .iter()
        .min_by_key(|d| (d.matches('.').count(), d.len()))
        .cloned();

    (true, primary)
}

pub fn cert_date(s: &str) -> String {
    // Shodan format: "YYYYMMDDHHMMSSZ" → ISO-8601
    if s.len() < 14 {
        return s.to_string();
    }
    let year = &s[0..4];
    let month = &s[4..6];
    let day = &s[6..8];
    let hour = &s[8..10];
    let min = &s[10..12];
    let sec = &s[12..14];
    format!("{}-{}-{}T{}:{}:{}Z", year, month, day, hour, min, sec)
}

pub fn cvss_severity(score: f64) -> &'static str {
    if score >= 9.0 {
        "critical"
    } else if score >= 7.0 {
        "high"
    } else if score >= 4.0 {
        "medium"
    } else if score > 0.0 {
        "low"
    } else {
        "none"
    }
}

pub fn parse_ssl(ssl: &Value) -> Option<Value> {
    if ssl.is_null() {
        return None;
    }
    let cert = ssl.get("cert").and_then(|v| if v.is_null() { None } else { Some(v) }).unwrap_or(&Value::Null);
    let subj = cert.get("subject").and_then(|v| if v.is_null() { None } else { Some(v) }).unwrap_or(&Value::Null);
    let iss = cert.get("issuer").and_then(|v| if v.is_null() { None } else { Some(v) }).unwrap_or(&Value::Null);
    let fp = cert.get("fingerprint").and_then(|v| if v.is_null() { None } else { Some(v) }).unwrap_or(&Value::Null);

    let subject_cn = subj.get("CN").or_else(|| subj.get("O")).and_then(|v| v.as_str()).map(|s| s.to_string());
    let issuer_cn = iss.get("CN").or_else(|| iss.get("O")).and_then(|v| v.as_str()).map(|s| s.to_string());

    let issued = cert.get("issued").and_then(|v| v.as_str()).map(|s| cert_date(s));
    let expires = cert.get("expires").and_then(|v| v.as_str()).map(|s| cert_date(s));
    let expired = cert.get("expired").and_then(|v| v.as_bool()).unwrap_or(false);

    let versions: Vec<Value> = ssl.get("versions")
        .and_then(|v| v.as_array())
        .map(|a| a.clone())
        .unwrap_or_default();

    Some(json!({
        "subject_cn": subject_cn,
        "subject": subj,
        "issuer_cn": issuer_cn,
        "issuer": iss,
        "issued": issued,
        "expires": expires,
        "expired": expired,
        "sig_alg": cert.get("sig_alg").and_then(|v| v.as_str()),
        "serial": cert.get("serial").map(|v| v.to_string()).unwrap_or_default(),
        "sha256": fp.get("sha256").and_then(|v| v.as_str()),
        "sha1": fp.get("sha1").and_then(|v| v.as_str()),
        "versions": versions,
        "cipher": ssl.get("cipher"),
        "jarm": ssl.get("jarm").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "alpn": ssl.get("alpn").and_then(|v| v.as_array()).map(|a| a.clone()).unwrap_or_default(),
    }))
}

pub fn parse_http(http: &Value) -> Option<Value> {
    if http.is_null() {
        return None;
    }
    let components_raw = http.get("components").and_then(|v| v.as_object());
    let tech: Vec<Value> = if let Some(comps) = components_raw {
        comps.iter().map(|(name, info)| {
            let info = if info.is_null() { &Value::Null } else { info };
            json!({
                "name": name,
                "categories": info.get("categories").and_then(|v| v.as_array()).map(|a| a.clone()).unwrap_or_default(),
                "versions": info.get("versions").and_then(|v| v.as_array()).map(|a| a.clone()).unwrap_or_default(),
            })
        }).collect()
    } else {
        vec![]
    };

    let html_raw = http.get("html").and_then(|v| v.as_str()).unwrap_or("");
    let html_preview = truncate_str(html_raw, 3000);

    Some(json!({
        "status": http.get("status"),
        "title": http.get("title").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "server": http.get("server").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "location": http.get("location").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "host": http.get("host").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "components": tech,
        "robots": http.get("robots").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "html_preview": html_preview,
    }))
}

pub fn parse_vulns(raw: &Value) -> Vec<Value> {
    let obj = match raw.as_object() {
        Some(o) => o,
        None => return vec![],
    };

    let mut result: Vec<Value> = obj.iter().map(|(cve_id, info)| {
        let info = if info.is_null() { &Value::Null } else { info };
        let cvss = info.get("cvss").or_else(|| info.get("cvss_v2"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let severity = cvss_severity(cvss);
        let refs: Vec<Value> = info.get("references")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().take(8).cloned().collect())
            .unwrap_or_default();

        json!({
            "cve": cve_id,
            "cvss": cvss,
            "cvss_v2": info.get("cvss_v2").and_then(|v| if v.is_null() { None } else { Some(v) }),
            "cvss_version": info.get("cvss_version").and_then(|v| if v.is_null() { None } else { Some(v) }),
            "severity": severity,
            "epss": info.get("epss").and_then(|v| v.as_f64()).unwrap_or(0.0),
            "ranking_epss": info.get("ranking_epss").and_then(|v| v.as_f64()).unwrap_or(0.0),
            "verified": info.get("verified").and_then(|v| v.as_bool()).unwrap_or(false),
            "summary": info.get("summary").and_then(|v| v.as_str()).unwrap_or(""),
            "references": refs,
        })
    }).collect();

    result.sort_by(|a, b| {
        let ca = a["cvss"].as_f64().unwrap_or(0.0);
        let cb = b["cvss"].as_f64().unwrap_or(0.0);
        cb.partial_cmp(&ca).unwrap_or(std::cmp::Ordering::Equal)
    });
    result
}

/// Parse a raw Shodan record JSON into our internal normalized shape.
pub fn parse_record(r: &Value) -> Value {
    let loc = r.get("location").and_then(|v| if v.is_null() { None } else { Some(v) }).unwrap_or(&Value::Null);
    let shodan = r.get("_shodan").and_then(|v| if v.is_null() { None } else { Some(v) }).unwrap_or(&Value::Null);

    let http = r.get("http").map(|v| parse_http(v)).flatten();
    let ssl = r.get("ssl").map(|v| parse_ssl(v)).flatten();

    let domains: Vec<String> = r.get("domains")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    let ssl_cn = ssl.as_ref()
        .and_then(|s| s.get("subject_cn"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Primary hostname — first entry in the hostnames array
    let primary_hostname = r.get("hostnames")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let (is_site, primary_domain) = classify_site(&domains, ssl_cn.as_deref(), primary_hostname.as_deref());

    let vulns = r.get("vulns").map(|v| parse_vulns(v)).unwrap_or_default();

    let data_raw = r.get("data").and_then(|v| v.as_str()).unwrap_or("");
    let data = truncate_str(data_raw, 3000);

    let hostnames: Vec<Value> = r.get("hostnames")
        .and_then(|v| v.as_array())
        .map(|a| a.clone())
        .unwrap_or_default();

    let tags: Vec<Value> = r.get("tags")
        .and_then(|v| v.as_array())
        .map(|a| a.clone())
        .unwrap_or_default();

    let cpe: Vec<Value> = r.get("cpe23").or_else(|| r.get("cpe"))
        .and_then(|v| v.as_array())
        .map(|a| a.clone())
        .unwrap_or_default();

    json!({
        "ip_str": r.get("ip_str").and_then(|v| v.as_str()).unwrap_or(""),
        "ip": r.get("ip"),
        "port": r.get("port"),
        "transport": r.get("transport").and_then(|v| v.as_str()).unwrap_or("tcp"),
        "isp": r.get("isp").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "org": r.get("org").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "asn": r.get("asn").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "os": r.get("os").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "product": r.get("product").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "version": r.get("version").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "hostnames": hostnames,
        "domains": domains,
        "is_site": is_site,
        "primary_domain": primary_domain,
        "timestamp": r.get("timestamp").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "tags": tags,
        "cpe": cpe,
        "location": {
            "city": loc.get("city").and_then(|v| if v.is_null() { None } else { Some(v) }),
            "region": loc.get("region_code").and_then(|v| if v.is_null() { None } else { Some(v) }),
            "country_code": loc.get("country_code").and_then(|v| if v.is_null() { None } else { Some(v) }),
            "country_name": loc.get("country_name").and_then(|v| if v.is_null() { None } else { Some(v) }),
            "lat": loc.get("latitude").and_then(|v| if v.is_null() { None } else { Some(v) }),
            "lon": loc.get("longitude").and_then(|v| if v.is_null() { None } else { Some(v) }),
        },
        "cloud": r.get("cloud").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "http": http,
        "ssl": ssl,
        "vulns": vulns,
        "data": data,
        "shodan_module": shodan.get("module").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "shodan_id": shodan.get("id").and_then(|v| if v.is_null() { None } else { Some(v) }),
    })
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn cvss_severity_boundaries() {
        // Boundaries are inclusive at the lower edge of each band.
        assert_eq!(cvss_severity(10.0), "critical");
        assert_eq!(cvss_severity(9.0), "critical");
        assert_eq!(cvss_severity(8.9), "high");
        assert_eq!(cvss_severity(7.0), "high");
        assert_eq!(cvss_severity(6.9), "medium");
        assert_eq!(cvss_severity(4.0), "medium");
        assert_eq!(cvss_severity(3.9), "low");
        assert_eq!(cvss_severity(0.1), "low");
        assert_eq!(cvss_severity(0.0), "none");
    }

    #[test]
    fn cert_date_converts_shodan_format() {
        assert_eq!(cert_date("20261231000000Z"), "2026-12-31T00:00:00Z");
        assert_eq!(cert_date("20240115093000"), "2024-01-15T09:30:00Z");
        // Too short to parse → returned unchanged.
        assert_eq!(cert_date("2026"), "2026");
    }

    #[test]
    fn infra_domains_are_detected() {
        // Apex and subdomains of a known infra domain classify as infra.
        assert!(is_infra_domain("amazonaws.com"));
        assert!(is_infra_domain("ec2-1-2-3-4.compute-1.amazonaws.com"));
        assert!(is_infra_domain("AMAZONAWS.COM")); // case-insensitive
        assert!(!is_infra_domain("acme.com"));
    }

    #[test]
    fn subdomain_infra_rules() {
        // Rule (a): more than one subdomain level above the registered domain.
        assert!(is_subdomain_infra("a.b.example.com"));
        assert!(is_subdomain_infra("api.wiseops.wiseway.co.nz"));
        // Rule (b): single technical/service subdomain.
        assert!(is_subdomain_infra("api.example.com"));
        assert!(is_subdomain_infra("cpanel.userdomain.com"));
        assert!(is_subdomain_infra("archive-dev.ada.edu.au")); // dash segment matches
        // Kept (real sites): single non-technical subdomain or apex.
        assert!(!is_subdomain_infra("www.draytek.com"));
        assert!(!is_subdomain_infra("inside.freightmatch.com.au"));
        assert!(!is_subdomain_infra("example.com"));
    }

    #[test]
    fn numeric_hostname_prefixes() {
        assert!(has_numeric_hostname_prefix("115.9.160.203.isphone.com.au"));
        assert!(has_numeric_hostname_prefix("203-196-40-164.static.dsl.net.au"));
        assert!(has_numeric_hostname_prefix("cpe-120-148-33-130.vb07.vic.example.net"));
        assert!(!has_numeric_hostname_prefix("www.example.com"));
        assert!(!has_numeric_hostname_prefix("mail.acme.org"));
    }

    #[test]
    fn classify_site_picks_apex_real_domain() {
        let domains = vec!["www.example.com".to_string(), "example.com".to_string()];
        let (is_site, primary) = classify_site(&domains, None, Some("www.example.com"));
        assert!(is_site);
        assert_eq!(primary.as_deref(), Some("example.com"));
    }

    #[test]
    fn classify_site_rejects_infra_and_numeric() {
        // Pure infra domain.
        let (is_site, primary) = classify_site(&["amazonaws.com".to_string()], None, None);
        assert!(!is_site);
        assert!(primary.is_none());

        // Numeric hostname prefix forces infra regardless of extracted domains.
        let (is_site, _) = classify_site(
            &["example.com".to_string()],
            None,
            Some("203-196-40-164.static.dsl.net.au"),
        );
        assert!(!is_site);
    }

    #[test]
    fn parse_vulns_sorts_by_cvss_and_falls_back_to_v2() {
        let raw = json!({
            "CVE-2020-0001": { "cvss": 4.5, "verified": false },
            "CVE-2021-44228": { "cvss": 10.0, "verified": true, "summary": "Log4Shell" },
            "CVE-2019-0002": { "cvss_v2": 7.5 } // no cvss → falls back to cvss_v2
        });
        let out = parse_vulns(&raw);
        assert_eq!(out.len(), 3);
        // Sorted by CVSS descending.
        assert_eq!(out[0]["cve"], "CVE-2021-44228");
        assert_eq!(out[0]["severity"], "critical");
        assert_eq!(out[0]["verified"], true);
        // v2 fallback applied.
        let v2 = out.iter().find(|v| v["cve"] == "CVE-2019-0002").unwrap();
        assert_eq!(v2["cvss"].as_f64(), Some(7.5));
        assert_eq!(v2["severity"], "high");
    }

    #[test]
    fn parse_vulns_handles_non_object() {
        assert!(parse_vulns(&json!([])).is_empty());
        assert!(parse_vulns(&Value::Null).is_empty());
    }

    #[test]
    fn parse_record_normalises_core_fields() {
        let raw = json!({
            "ip_str": "1.2.3.4",
            "port": 443,
            "org": "Acme Corp",
            "hostnames": ["www.acme.com"],
            "domains": ["acme.com"],
            "location": { "country_code": "AU", "country_name": "Australia", "city": "Sydney" },
            "vulns": { "CVE-2021-44228": { "cvss": 10.0, "verified": true } }
        });
        let rec = parse_record(&raw);
        assert_eq!(rec["ip_str"], "1.2.3.4");
        assert_eq!(rec["port"], 443);
        assert_eq!(rec["transport"], "tcp"); // defaulted
        assert_eq!(rec["is_site"], true);
        assert_eq!(rec["primary_domain"], "acme.com");
        assert_eq!(rec["location"]["country_code"], "AU");
        assert_eq!(rec["vulns"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn record_summary_rolls_up_vulns() {
        let raw = json!({
            "ip_str": "1.2.3.4",
            "port": 443,
            "hostnames": ["www.acme.com"],
            "vulns": [
                { "cve": "CVE-A", "cvss": 5.0, "verified": false },
                { "cve": "CVE-B", "cvss": 9.8, "verified": true }
            ]
        });
        let sum = record_summary(&raw);
        assert_eq!(sum["vulns_count"], 2);
        assert_eq!(sum["max_cvss"].as_f64(), Some(9.8));
        assert_eq!(sum["verified_cves"], 1);
        assert_eq!(sum["hostname"], "www.acme.com");
        assert_eq!(sum["cves"].as_array().unwrap().len(), 2);
    }
}

/// Lightweight summary projection for the GET /api/records list endpoint.
pub fn record_summary(r: &Value) -> Value {
    let http = r.get("http");
    let ssl = r.get("ssl");
    let vulns = r.get("vulns").and_then(|v| v.as_array()).map(|a| a.as_slice()).unwrap_or(&[]);

    let vulns_count = vulns.len();
    let max_cvss = vulns.iter()
        .filter_map(|v| v.get("cvss").and_then(|c| c.as_f64()))
        .fold(0.0_f64, f64::max);
    let cves: Vec<Value> = vulns.iter()
        .filter_map(|v| v.get("cve").cloned())
        .collect();
    let verified_cves = vulns.iter()
        .filter(|v| v.get("verified").and_then(|b| b.as_bool()).unwrap_or(false))
        .count();

    let http_title = http.and_then(|h| h.get("title")).and_then(|v| if v.is_null() { None } else { Some(v) });
    let http_status = http.and_then(|h| h.get("status")).and_then(|v| if v.is_null() { None } else { Some(v) });
    let tech: Vec<Value> = http
        .and_then(|h| h.get("components"))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|t| t.get("name").cloned()).collect())
        .unwrap_or_default();

    let has_ssl = ssl.map(|s| !s.is_null()).unwrap_or(false);
    let ssl_cn = if has_ssl { ssl.and_then(|s| s.get("subject_cn")).and_then(|v| if v.is_null() { None } else { Some(v) }) } else { None };
    let ssl_expired = if has_ssl { ssl.and_then(|s| s.get("expired")).and_then(|v| if v.is_null() { None } else { Some(v) }) } else { None };

    let hostnames = r.get("hostnames").and_then(|v| v.as_array());
    let hostname = hostnames.and_then(|a| a.first()).and_then(|v| if v.is_null() { None } else { Some(v) });
    let location = r.get("location").unwrap_or(&Value::Null);

    json!({
        "ip_str": r.get("ip_str"),
        "port": r.get("port"),
        "transport": r.get("transport"),
        "org": r.get("org").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "isp": r.get("isp").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "os": r.get("os").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "product": r.get("product").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "version": r.get("version").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "hostname": hostname,
        "hostnames": r.get("hostnames").and_then(|v| v.as_array()).map(|a| Value::Array(a.clone())).unwrap_or(Value::Array(vec![])),
        "domains": r.get("domains").and_then(|v| v.as_array()).map(|a| Value::Array(a.clone())).unwrap_or(Value::Array(vec![])),
        "is_site": r.get("is_site").and_then(|v| v.as_bool()).unwrap_or(false),
        "primary_domain": r.get("primary_domain").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "country_code": location.get("country_code").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "country_name": location.get("country_name").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "city": location.get("city").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "timestamp": r.get("timestamp").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "vulns_count": vulns_count,
        "max_cvss": max_cvss,
        "cves": cves,
        "verified_cves": verified_cves,
        "http_title": http_title,
        "http_status": http_status,
        "tech": tech,
        "has_ssl": has_ssl,
        "ssl_cn": ssl_cn,
        "ssl_expired": ssl_expired,
        "tags": r.get("tags").and_then(|v| v.as_array()).map(|a| Value::Array(a.clone())).unwrap_or(Value::Array(vec![])),
        "cloud": r.get("cloud").and_then(|v| if v.is_null() { None } else { Some(v) }),
        "asn": r.get("asn").and_then(|v| if v.is_null() { None } else { Some(v) }),
    })
}

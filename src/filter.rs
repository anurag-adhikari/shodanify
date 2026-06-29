use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::HashMap;

#[derive(Deserialize, Default, Clone)]
pub struct FacetFilter {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

#[derive(Deserialize, Default, Clone)]
pub struct FilterParams {
    pub page: Option<usize>,
    pub per_page: Option<usize>,
    // Host-tab search / filter bar (all AND'd)
    pub search: Option<String>,
    pub port: Option<i64>,
    pub country: Option<String>,
    pub severity: Option<String>,
    #[serde(default)] pub has_cve: bool,
    #[serde(default)] pub verified_cve: bool,
    #[serde(default)] pub has_ssl: bool,
    #[serde(default)] pub ssl_expired: bool,
    // Cross-tab facet chips: OR within same type, AND across types
    #[serde(default)] pub facets: Vec<FacetFilter>,
    // Only return web-accessible hosts (for targets tab)
    #[serde(default)] pub is_web: bool,
    // Sort
    pub sort_by: Option<String>,
    pub sort_dir: Option<String>,
}

#[derive(Serialize)]
pub struct PageResponse {
    pub records: Vec<Value>,
    pub total: usize,           // all records (no filter)
    pub filtered_total: usize,  // after applying all filters
    pub page: usize,
    pub per_page: usize,
    pub filtered_cve_ids: Vec<String>,              // all CVE IDs in the filtered set
    pub filtered_tech_counts: HashMap<String, usize>, // tech name → host count in filtered set
}

fn sev_name(cvss: f64) -> &'static str {
    if cvss >= 9.0 { "critical" }
    else if cvss >= 7.0 { "high" }
    else if cvss >= 4.0 { "medium" }
    else if cvss > 0.0  { "low" }
    else                { "none" }
}

fn str_field<'a>(r: &'a Value, key: &str) -> &'a str {
    r.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

fn facet_matches(r: &Value, kind: &str, value: &str) -> bool {
    match kind {
        "severity" => sev_name(r.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0)) == value,
        "port"     => r.get("port").and_then(|v| v.as_i64()).map(|p| p.to_string()) == Some(value.to_string()),
        "country"  => str_field(r, "country_code") == value,
        "org"      => {
            let org = str_field(r, "org");
            let isp = str_field(r, "isp");
            (if org.is_empty() { if isp.is_empty() { "Unknown" } else { isp } } else { org }) == value
        }
        "tech"     => r.get("tech").and_then(|v| v.as_array())
                       .map(|a| a.iter().any(|t| t.as_str() == Some(value))).unwrap_or(false),
        "cve"      => r.get("cves").and_then(|v| v.as_array())
                       .map(|a| a.iter().any(|c| c.as_str() == Some(value))).unwrap_or(false),
        "ssl"      => {
            let has = r.get("has_ssl").and_then(|v| v.as_bool()).unwrap_or(false);
            let exp = r.get("ssl_expired").and_then(|v| v.as_bool()).unwrap_or(false);
            let state = if has { if exp { "expired" } else { "valid" } } else { "none" };
            state == value
        }
        "site"     => {
            let is_site = r.get("is_site").and_then(|v| v.as_bool()).unwrap_or(false);
            match value {
                "website" => is_site,
                "infra"   => !is_site,
                _         => true,
            }
        }
        _ => true,
    }
}

pub fn apply<'a>(summaries: &'a [Value], params: &FilterParams, total: usize)
    -> PageResponse
{
    let page     = params.page.unwrap_or(0);
    let per_page = params.per_page.unwrap_or(25).clamp(1, 10_000);
    let search   = params.search.as_deref().unwrap_or("").trim().to_lowercase();
    let sort_by  = params.sort_by.as_deref().unwrap_or("max_cvss");
    let sort_asc = params.sort_dir.as_deref() == Some("asc");

    // Group facets by type for OR-within / AND-across logic
    let mut facet_map: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
    for f in &params.facets {
        facet_map.entry(f.kind.as_str()).or_default().push(f.value.as_str());
    }

    // ── Apply filters ──────────────────────────────────────────────────────
    let mut filtered: Vec<&Value> = summaries.iter().filter(|r| {
        // Port filter
        if let Some(p) = params.port {
            if r.get("port").and_then(|v| v.as_i64()).unwrap_or(0) != p { return false; }
        }
        // Country filter
        if let Some(ref c) = params.country {
            if !c.is_empty() && str_field(r, "country_code") != c.as_str() { return false; }
        }
        // Severity filter
        if let Some(ref s) = params.severity {
            if !s.is_empty() && sev_name(r.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0)) != s.as_str() { return false; }
        }
        // Boolean filters
        if params.has_cve      && r.get("vulns_count").and_then(|v| v.as_i64()).unwrap_or(0) == 0 { return false; }
        if params.verified_cve {
            let vc = r.get("verified_cves").and_then(|v| v.as_i64())
                .or_else(|| r.get("verified_cves_count").and_then(|v| v.as_i64()))
                .unwrap_or(0);
            if vc == 0 { return false; }
        }
        if params.has_ssl    && !r.get("has_ssl").and_then(|v| v.as_bool()).unwrap_or(false)    { return false; }
        if params.ssl_expired && !r.get("ssl_expired").and_then(|v| v.as_bool()).unwrap_or(false) { return false; }
        // Web targets filter: must have HTTP data, SSL, or be on a web port
        if params.is_web {
            let web_ports = [80i64, 443, 8080, 8443, 8000, 8888, 9443, 3000, 5000];
            let port = r.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
            let has_http = r.get("http_status").is_some();
            let has_ssl  = r.get("has_ssl").and_then(|v| v.as_bool()).unwrap_or(false);
            if !has_http && !has_ssl && !web_ports.contains(&port) { return false; }
        }
        // Facets: OR within type, AND across types
        for (kind, vals) in &facet_map {
            if !vals.iter().any(|v| facet_matches(r, kind, v)) { return false; }
        }
        // Search
        if !search.is_empty() {
            let ip    = str_field(r, "ip_str").to_lowercase();
            let hn    = str_field(r, "hostname").to_lowercase();
            let org   = str_field(r, "org").to_lowercase();
            let isp   = str_field(r, "isp").to_lowercase();
            let title = str_field(r, "http_title").to_lowercase();
            let cves: String = r.get("cves").and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|c| c.as_str()).collect::<Vec<_>>().join(" ").to_lowercase())
                .unwrap_or_default();
            if !ip.contains(&search) && !hn.contains(&search) && !org.contains(&search)
                && !isp.contains(&search) && !title.contains(&search) && !cves.contains(&search)
            { return false; }
        }
        true
    }).collect();

    let filtered_total = filtered.len();

    // ── Collect CVE IDs and tech counts (only when actually filtered) ───────
    // When unfiltered, the global stats endpoint already has these — skip the
    // expensive full-scan so the default page loads in ~10ms instead of ~100ms.
    let is_filtered = filtered_total < total || !search.is_empty();
    let mut filtered_cve_ids: Vec<String> = Vec::new();
    let mut filtered_tech_counts: HashMap<String, usize> = HashMap::new();
    if is_filtered {
        let mut cve_set = std::collections::HashSet::new();
        for r in &filtered {
            if let Some(arr) = r.get("cves").and_then(|v| v.as_array()) {
                for c in arr { if let Some(s) = c.as_str() { cve_set.insert(s.to_string()); } }
            }
            if let Some(arr) = r.get("tech").and_then(|v| v.as_array()) {
                for t in arr { if let Some(s) = t.as_str() { *filtered_tech_counts.entry(s.to_string()).or_insert(0) += 1; } }
            }
        }
        filtered_cve_ids = cve_set.into_iter().collect();
    }

    // ── Sort ───────────────────────────────────────────────────────────────
    filtered.sort_by(|a, b| {
        let ord = match sort_by {
            "port" => {
                let pa = a.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
                let pb = b.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
                pa.cmp(&pb)
            }
            "ip_str" => str_field(a, "ip_str").cmp(str_field(b, "ip_str")),
            "timestamp" => str_field(b, "timestamp").cmp(str_field(a, "timestamp")),
            "vulns_count" => {
                let va = a.get("vulns_count").and_then(|v| v.as_i64()).unwrap_or(0);
                let vb = b.get("vulns_count").and_then(|v| v.as_i64()).unwrap_or(0);
                vb.cmp(&va)
            }
            "org" => {
                let oa = if str_field(a, "org").is_empty() { str_field(a, "isp") } else { str_field(a, "org") };
                let ob = if str_field(b, "org").is_empty() { str_field(b, "isp") } else { str_field(b, "org") };
                oa.cmp(ob)
            }
            "country_name" => str_field(a, "country_name").cmp(str_field(b, "country_name")),
            _ /* max_cvss */ => {
                let ca = a.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let cb = b.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0);
                cb.partial_cmp(&ca).unwrap_or(Ordering::Equal)
            }
        };
        if sort_asc { ord.reverse() } else { ord }
    });

    // ── Paginate ───────────────────────────────────────────────────────────
    let start = (page * per_page).min(filtered_total);
    let end   = (start + per_page).min(filtered_total);
    let records = filtered[start..end].iter().map(|r| (*r).clone()).collect();

    PageResponse { records, total, filtered_total, page, per_page, filtered_cve_ids, filtered_tech_counts }
}

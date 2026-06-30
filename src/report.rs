use crate::stats::compute_stats_full;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Deserialize)]
pub struct ReportMeta {
    pub title: Option<String>,
    pub org: Option<String>,
    pub analyst: Option<String>,
    pub classification: Option<String>,
    pub notes: Option<String>,
}

#[derive(Deserialize)]
pub struct ReportConfig {
    pub meta: ReportMeta,
    /// Ordered list of enabled section IDs (e.g. ["cover","exec","metrics",...])
    pub sections: Vec<String>,
    /// "ip:port" strings for the host set to report on (from the browser's filtered view)
    pub filtered_keys: Vec<String>,
    /// When true, exclude hosts with zero CVEs from website/host listings
    #[serde(default)]
    pub only_with_cves: bool,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Truncate a string to at most `max_bytes` bytes, always on a char boundary.
fn truncate_chars(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes { return s; }
    let cut = s.char_indices()
        .take_while(|(i, _)| *i < max_bytes)
        .last()
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0);
    &s[..cut]
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}

fn esc_opt(v: Option<&str>) -> String {
    esc(v.unwrap_or(""))
}

// ── Colour helpers ──────────────────────────────────────────────────────────

fn cvss_color(cvss: f64) -> &'static str {
    if cvss >= 9.0 { "#dc2626" }
    else if cvss >= 7.0 { "#ea580c" }
    else if cvss >= 4.0 { "#ca8a04" }
    else if cvss > 0.0  { "#2563eb" }
    else                { "#64748b" }
}

fn sev_label(cvss: f64) -> &'static str {
    if cvss >= 9.0 { "CRITICAL" }
    else if cvss >= 7.0 { "HIGH" }
    else if cvss >= 4.0 { "MEDIUM" }
    else if cvss > 0.0  { "LOW" }
    else                { "NONE" }
}

fn sev_name(cvss: f64) -> &'static str {
    if cvss >= 9.0 { "critical" }
    else if cvss >= 7.0 { "high" }
    else if cvss >= 4.0 { "medium" }
    else if cvss > 0.0  { "low" }
    else                { "none" }
}

// ── Shared CSS ──────────────────────────────────────────────────────────────

fn report_css() -> &'static str {
    r#"*{box-sizing:border-box;margin:0;padding:0}
body{font:13px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;color:#1e293b;background:#f8fafc;print-color-adjust:exact;-webkit-print-color-adjust:exact}
.page{max-width:900px;margin:0 auto;padding:40px 48px}
@media print{.noprint{display:none!important}.page{padding:20px 28px}.pagebreak{page-break-before:always}}
h1{font-size:28px;font-weight:800;color:#0f172a;line-height:1.2}
h2{font-size:16px;font-weight:700;color:#0f172a;margin:32px 0 12px;padding-bottom:6px;border-bottom:2px solid #e2e8f0}
h3{font-size:13px;font-weight:700;color:#334155;margin:18px 0 8px}
p{margin:6px 0;color:#475569}
.sub{font-size:11px;color:#94a3b8}
.mono{font-family:ui-monospace,monospace;font-size:11px}
a{color:#ea580c;text-decoration:none}a:hover{text-decoration:underline}
table{width:100%;border-collapse:collapse;margin:10px 0;font-size:12px}
th{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.04em;color:#64748b;border-bottom:2px solid #e2e8f0;padding:7px 10px;background:#f1f5f9}
td{padding:7px 10px;border-bottom:1px solid #e2e8f0;vertical-align:top}
tr:hover td{background:#f8fafc}
.badge{display:inline-block;padding:2px 8px;border-radius:99px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.04em}
.badge.critical{background:#fee2e2;color:#991b1b}.badge.high{background:#ffedd5;color:#9a3412}
.badge.medium{background:#fef9c3;color:#854d0e}.badge.low{background:#dbeafe;color:#1e40af}.badge.none{background:#f1f5f9;color:#475569}
.badge.up{background:#dcfce7;color:#166534}.badge.down{background:#fee2e2;color:#991b1b}.badge.warn{background:#fef9c3;color:#854d0e}.badge.open,.badge.unscanned{background:#f1f5f9;color:#64748b}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.card{flex:1;min-width:120px;background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:14px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.card .num{font-size:26px;font-weight:800;display:block;line-height:1.1}.card .lbl{font-size:10px;color:#94a3b8;display:block;margin-top:2px}
.card.red .num{color:#dc2626}.card.orange .num{color:#ea580c}.card.green .num{color:#16a34a}.card.blue .num{color:#2563eb}
.cve-bar{display:inline-block;height:6px;border-radius:3px;vertical-align:middle;margin-left:4px}
details.site-card{border:1px solid #e2e8f0;border-radius:10px;margin-bottom:8px;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.05)}
summary{display:flex;flex-wrap:wrap;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;list-style:none}
summary::-webkit-details-marker{display:none}summary::before{content:'▸';color:#94a3b8;font-size:11px;margin-right:2px}
details[open] summary::before{content:'▾'}summary:hover{background:#f8fafc}details[open] summary{border-bottom:1px solid #f1f5f9}
.body{padding:6px 16px 16px}.body table{margin:4px 0}
.site-name{font-size:14px;font-weight:700;color:#0f172a}.meta{font-size:11px;color:#64748b}
.ok{font-size:12px;font-weight:600;color:#16a34a;margin:8px 0}
.cover{min-height:100vh;display:flex;flex-direction:column;justify-content:center;padding:80px 0}
.cover-class{display:inline-block;padding:4px 14px;border-radius:6px;font-size:11px;font-weight:700;letter-spacing:.1em;background:#fee2e2;color:#991b1b;margin-bottom:32px}
.cover h1{font-size:38px;margin-bottom:12px}.cover .org{font-size:20px;color:#475569;margin-bottom:40px}
.cover-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;max-width:420px;margin-top:32px;font-size:12px}
.cover-grid dt{color:#94a3b8}.cover-grid dd{font-weight:600;color:#1e293b}
.bar-wrap{display:flex;align-items:center;gap:8px}.bar-bg{flex:1;height:6px;background:#e2e8f0;border-radius:3px;overflow:hidden}.bar-fill{height:100%;border-radius:3px}
.toc{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:20px 24px;margin:24px 0}.toc h3{margin:0 0 10px}.toc ol{padding-left:20px}.toc li{padding:2px 0;color:#475569;font-size:12px}
.sticky-bar{position:sticky;top:0;background:#fff;border-bottom:1px solid #e2e8f0;padding:8px 0;z-index:5;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
input.flt{flex:1;min-width:180px;font:inherit;padding:6px 10px;border:1px solid #e2e8f0;border-radius:6px;font-size:12px}
button.ctrl{font:inherit;font-size:11px;padding:5px 12px;border:1px solid #e2e8f0;border-radius:6px;background:#f8fafc;cursor:pointer}"#
}

fn report_js() -> &'static str {
    r#"<script>
function filterSites(q){q=q.trim().toLowerCase();var n=0;document.querySelectorAll('details.site-card').forEach(function(d){var m=!q||d.dataset.name.indexOf(q)>-1;d.style.display=m?'':'none';if(m)n++;});var el=document.getElementById('sc');if(el)el.textContent=n;}
function setAll(open){document.querySelectorAll('details.site-card').forEach(function(d){if(d.style.display!=='none')d.open=open});}
window.addEventListener('beforeprint',function(){setAll(true);});
</script>"#
}

// ── Main entry point ────────────────────────────────────────────────────────

pub fn generate(
    config: &ReportConfig,
    all_records: &[Value],
    record_index: &HashMap<(String, i64), usize>,
    scan_store: &crate::scan_store::ScanStore,
) -> String {
    // ── Resolve filtered records ───────────────────────────────────────────
    let key_set: HashSet<&str> = config.filtered_keys.iter().map(|s| s.as_str()).collect();
    let records: Vec<&Value> = if key_set.is_empty() {
        all_records.iter().collect()
    } else {
        config.filtered_keys.iter().filter_map(|k| {
            let mut parts = k.splitn(2, ':');
            let ip = parts.next()?;
            let port: i64 = parts.next()?.parse().ok()?;
            record_index.get(&(ip.to_string(), port)).map(|&i| &all_records[i])
        }).collect()
    };

    // ── Compute stats for this filtered set ───────────────────────────────
    let owned: Vec<Value> = records.iter().map(|r| (*r).clone()).collect();
    let stats = compute_stats_full(&owned, 0);

    let vulns = stats.get("vulns").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let scans = scan_store.all();

    let meta = &config.meta;
    let classification = meta.classification.as_deref().unwrap_or("CONFIDENTIAL");
    let title = meta.title.as_deref().unwrap_or("Security Assessment Report");

    let total_hosts = records.len();
    let unique_ips: HashSet<&str> = records.iter().filter_map(|r| r.get("ip_str")?.as_str()).collect();

    // Precompute common stats
    let critical_hosts = records.iter().filter(|r| r.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0) >= 9.0).count();
    let high_hosts = records.iter().filter(|r| { let c = r.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0); c >= 7.0 && c < 9.0 }).count();
    let hosts_with_cve = records.iter().filter(|r| r.get("vulns_count").and_then(|v| v.as_i64()).unwrap_or(0) > 0).count();
    let verified_cves: Vec<&Value> = vulns.iter().filter(|v| v.get("verified").and_then(|b| b.as_bool()).unwrap_or(false)).collect();

    // Build vmap: CVE id → vuln info
    let vmap: HashMap<&str, &Value> = vulns.iter()
        .filter_map(|v| v.get("cve")?.as_str().map(|c| (c, v)))
        .collect();

    // Identify website targets
    let web_ports: HashSet<i64> = [80, 443, 8080, 8443, 8000, 8888, 9443, 3000, 5000].iter().cloned().collect();
    let sites: Vec<&Value> = records.iter().copied().filter(|r| {
        r.get("is_site").and_then(|v| v.as_bool()).unwrap_or(false)
        || r.get("has_ssl").and_then(|v| v.as_bool()).unwrap_or(false)
        || r.get("http_status").is_some()
        || r.get("port").and_then(|v| v.as_i64()).map(|p| web_ports.contains(&p)).unwrap_or(false)
    }).collect();

    // ── Build sections ─────────────────────────────────────────────────────
    let mut sec_num = 0usize;
    let mut toc_items = Vec::new();
    let mut parts = Vec::new();

    for sec_id in &config.sections {
        let n = {
            if sec_id != "cover" { sec_num += 1; }
            sec_num
        };

        match sec_id.as_str() {
            "cover" => {
                toc_items.push(format!("<li><a href=\"#scover\">Cover</a></li>"));
                parts.push(format!(r#"<div class="cover pagebreak" id="scover">
  <span class="cover-class">{cls}</span>
  <h1>{title}</h1>
  <div class="org">{org}</div>
  <p style="color:#64748b;font-size:13px">{notes}</p>
  <dl class="cover-grid">
    <dt>Total hosts</dt><dd>{total}</dd>
    <dt>Unique CVEs</dt><dd>{cves}</dd>
    <dt>Prepared by</dt><dd>{analyst}</dd>
    <dt>Classification</dt><dd>{cls}</dd>
  </dl>
</div>"#,
                    cls = esc(classification),
                    title = esc(title),
                    org = esc_opt(meta.org.as_deref()),
                    notes = esc_opt(meta.notes.as_deref()),
                    total = total_hosts,
                    cves = vulns.len(),
                    analyst = esc(meta.analyst.as_deref().unwrap_or("Shodanify")),
                ));
            }

            "exec" => {
                let top_cve = vulns.first();
                let spread_cve = vulns.iter().max_by_key(|v| v.get("host_count").and_then(|x| x.as_i64()).unwrap_or(0));
                let top_cve_html = top_cve.map(|v| {
                    let cve = esc(v.get("cve").and_then(|x| x.as_str()).unwrap_or(""));
                    let cvss = v.get("max_cvss").and_then(|x| x.as_f64()).unwrap_or(0.0);
                    let sev = v.get("severity").and_then(|x| x.as_str()).unwrap_or("unknown").to_uppercase();
                    let hc = v.get("host_count").and_then(|x| x.as_i64()).unwrap_or(0);
                    let summary = v.get("summary").and_then(|x| x.as_str()).unwrap_or("");
                    let short = if summary.len() > 200 { &summary[..200] } else { summary };
                    format!("<p style=\"margin-top:10px\">Highest-severity vulnerability: <strong>{cve}</strong> (CVSS {cvss:.1}, {sev}), affecting <strong>{hc} host{s}</strong>. {desc}</p>",
                        s = if hc != 1 { "s" } else { "" },
                        desc = esc(short),
                    )
                }).unwrap_or_default();
                let spread_html = match (top_cve, spread_cve) {
                    (Some(tc), Some(sc)) if !std::ptr::eq(tc, sc) => {
                        let cve = esc(sc.get("cve").and_then(|x| x.as_str()).unwrap_or(""));
                        let cvss = sc.get("max_cvss").and_then(|x| x.as_f64()).unwrap_or(0.0);
                        let hc = sc.get("host_count").and_then(|x| x.as_i64()).unwrap_or(0);
                        format!("<p>Most widespread vulnerability: <strong>{cve}</strong> (CVSS {cvss:.1}), on <strong>{hc} host{s}</strong>.</p>",
                            s = if hc != 1 { "s" } else { "" })
                    }
                    _ => String::new(),
                };
                toc_items.push(format!("<li><a href=\"#sexec\">{n}. Executive Summary</a></li>"));
                parts.push(format!(r#"<div id="sexec" class="pagebreak">
  <h2>{n}. Executive Summary</h2>
  <p>This report presents findings from a Shodan-based reconnaissance assessment{org_clause}. A total of <strong>{total} hosts</strong> were analysed across <strong>{ips} unique IP address{ip_s}</strong>.</p>
  <p style="margin-top:10px"><strong>{with_cve} hosts ({pct}%)</strong> carry at least one known vulnerability. Of these, <strong>{critical} host{cs}</strong> are exposed to critical-severity vulnerabilities (CVSS ≥ 9.0) and <strong>{high} host{hs}</strong> to high-severity issues. <strong>{verified} verified exploit{vs}</strong> confirmed in the wild.</p>
  {top_cve_html}
  {spread_html}
  {notes_html}
</div>"#,
                    org_clause = meta.org.as_deref().map(|o| format!(" of <strong>{}</strong>", esc(o))).unwrap_or_default(),
                    total = total_hosts,
                    ips = unique_ips.len(),
                    ip_s = if unique_ips.len() != 1 { "es" } else { "" },
                    with_cve = hosts_with_cve,
                    pct = if total_hosts > 0 { hosts_with_cve * 100 / total_hosts } else { 0 },
                    critical = critical_hosts,
                    cs = if critical_hosts != 1 { "s" } else { "" },
                    high = high_hosts,
                    hs = if high_hosts != 1 { "s" } else { "" },
                    verified = verified_cves.len(),
                    vs = if verified_cves.len() != 1 { "s" } else { "" },
                    top_cve_html = top_cve_html,
                    spread_html = spread_html,
                    notes_html = meta.notes.as_deref().map(|no| format!("<p style=\"margin-top:10px;color:#475569\"><em>Scope: {}</em></p>", esc(no))).unwrap_or_default(),
                ));
            }

            "metrics" => {
                let sev_map = stats.get("severity").and_then(|v| v.as_object()).cloned().unwrap_or_default();
                let sev_total: i64 = sev_map.values().filter_map(|v| v.as_i64()).sum();
                let unique_ports = stats.get("unique_ports").and_then(|v| v.as_i64()).unwrap_or(0);
                let rows: String = ["critical","high","medium","low","none"].iter().map(|sv| {
                    let cnt = sev_map.get(*sv).and_then(|v| v.as_i64()).unwrap_or(0);
                    let pct = if sev_total > 0 { cnt * 100 / sev_total } else { 0 };
                    format!("<tr><td><span class=\"badge {sv}\">{su}</span></td><td>{cnt}</td><td>{pct}%</td></tr>",
                        su = sv.to_uppercase())
                }).collect();
                toc_items.push(format!("<li><a href=\"#smetrics\">{n}. Headline Metrics</a></li>"));
                parts.push(format!(r#"<div id="smetrics">
  <h2>{n}. Headline Metrics</h2>
  <div class="cards">
    <div class="card"><span class="num">{total}</span><span class="lbl">Total hosts</span></div>
    <div class="card"><span class="num">{ips}</span><span class="lbl">Unique IPs</span></div>
    <div class="card red"><span class="num">{critical}</span><span class="lbl">Critical hosts</span></div>
    <div class="card orange"><span class="num">{high}</span><span class="lbl">High-risk hosts</span></div>
    <div class="card"><span class="num">{with_cve}</span><span class="lbl">Hosts with CVEs</span></div>
    <div class="card"><span class="num">{cve_count}</span><span class="lbl">Unique CVEs</span></div>
    <div class="card green"><span class="num">{verified}</span><span class="lbl">Verified exploits</span></div>
    <div class="card blue"><span class="num">{ports}</span><span class="lbl">Distinct ports</span></div>
  </div>
  <h3>CVE Severity Breakdown</h3>
  <table><thead><tr><th>Severity</th><th>CVE instances</th><th>% of total</th></tr></thead><tbody>{rows}</tbody></table>
</div>"#,
                    total = total_hosts,
                    ips = unique_ips.len(),
                    critical = critical_hosts,
                    high = high_hosts,
                    with_cve = hosts_with_cve,
                    cve_count = vulns.len(),
                    verified = verified_cves.len(),
                    ports = unique_ports,
                    rows = rows,
                ));
            }

            "top_cvss" => {
                let top: Vec<&Value> = vulns.iter().take(20).collect();
                let max_hc = top.iter().filter_map(|v| v.get("host_count")?.as_i64()).max().unwrap_or(1) as f64;
                let rows: String = top.iter().map(|v| {
                    let cve = v.get("cve").and_then(|x| x.as_str()).unwrap_or("");
                    let cvss = v.get("max_cvss").and_then(|x| x.as_f64()).unwrap_or(0.0);
                    let sev = v.get("severity").and_then(|x| x.as_str()).unwrap_or("none");
                    let hc = v.get("host_count").and_then(|x| x.as_i64()).unwrap_or(0);
                    let epss = v.get("epss").and_then(|x| x.as_f64()).map(|e| format!("{:.2}%", e*100.0)).unwrap_or_else(|| "—".to_string());
                    let ver = v.get("verified").and_then(|x| x.as_bool()).unwrap_or(false);
                    let summary = v.get("summary").and_then(|x| x.as_str()).unwrap_or("");
                    let short = if summary.len() > 200 { &summary[..200] } else { summary };
                    let bar_w = (hc as f64 / max_hc * 60.0) as i32;
                    format!("<tr><td class=\"mono\"><a href=\"https://nvd.nist.gov/vuln/detail/{cve}\" target=\"_blank\" rel=\"noopener\">{cve}</a></td><td style=\"color:{col};font-weight:700\">{cvss:.1}</td><td><span class=\"badge {sev}\">{sev_up}</span></td><td><span style=\"font-weight:600\">{hc}</span><span class=\"cve-bar\" style=\"width:{bar_w}px;background:{col}\"></span></td><td class=\"mono\">{epss}</td><td style=\"color:{vc};font-weight:600\">{ver_l}</td><td style=\"max-width:280px;color:#475569\">{desc}…</td></tr>",
                        col = cvss_color(cvss), sev_up = sev.to_uppercase(), vc = if ver { "#16a34a" } else { "#94a3b8" }, ver_l = if ver { "✓ Yes" } else { "No" }, desc = esc(short))
                }).collect();
                toc_items.push(format!("<li><a href=\"#stop_cvss\">{n}. Top Vulnerabilities by CVSS</a></li>"));
                parts.push(format!("<div id=\"stop_cvss\" class=\"pagebreak\"><h2>{n}. Top Vulnerabilities by CVSS Score</h2><p class=\"sub\">Up to 20 highest-CVSS vulnerabilities.</p><table><thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>Hosts</th><th>EPSS</th><th>Verified</th><th>Description</th></tr></thead><tbody>{rows}</tbody></table></div>"));
            }

            "top_spread" => {
                let mut spread: Vec<&Value> = vulns.iter().collect();
                spread.sort_by_key(|v| std::cmp::Reverse(v.get("host_count").and_then(|x| x.as_i64()).unwrap_or(0)));
                let spread = &spread[..spread.len().min(15)];
                let max_hc = spread.iter().filter_map(|v| v.get("host_count")?.as_i64()).max().unwrap_or(1) as f64;
                let rows: String = spread.iter().map(|v| {
                    let cve = v.get("cve").and_then(|x| x.as_str()).unwrap_or("");
                    let cvss = v.get("max_cvss").and_then(|x| x.as_f64()).unwrap_or(0.0);
                    let sev = v.get("severity").and_then(|x| x.as_str()).unwrap_or("none");
                    let hc = v.get("host_count").and_then(|x| x.as_i64()).unwrap_or(0);
                    let pct = if total_hosts > 0 { hc * 100 / total_hosts as i64 } else { 0 };
                    let bar = (hc as f64 / max_hc * 100.0) as i32;
                    let summary = v.get("summary").and_then(|x| x.as_str()).unwrap_or("");
                    let short = truncate_chars(summary, 180);
                    format!("<tr><td class=\"mono\"><a href=\"https://nvd.nist.gov/vuln/detail/{cve}\" target=\"_blank\" rel=\"noopener\">{cve}</a></td><td style=\"font-weight:700\">{hc}</td><td><div class=\"bar-wrap\"><div class=\"bar-bg\"><div class=\"bar-fill\" style=\"width:{bar}%;background:{col}\"></div></div><span style=\"font-size:10px;color:#94a3b8\">{pct}%</span></div></td><td style=\"color:{col};font-weight:700\">{cvss:.1}</td><td><span class=\"badge {sev}\">{su}</span></td><td style=\"color:#475569\">{desc}</td></tr>",
                        col = cvss_color(cvss), su = sev.to_uppercase(), desc = esc(short))
                }).collect();
                toc_items.push(format!("<li><a href=\"#stop_spread\">{n}. Widest-Spread Vulnerabilities</a></li>"));
                parts.push(format!("<div id=\"stop_spread\"><h2>{n}. Widest-Spread Vulnerabilities</h2><p class=\"sub\">CVEs sorted by number of affected hosts.</p><table><thead><tr><th>CVE</th><th>Hosts</th><th>Coverage</th><th>CVSS</th><th>Severity</th><th>Description</th></tr></thead><tbody>{rows}</tbody></table></div>"));
            }

            "top_verified" => {
                let rows: String = if verified_cves.is_empty() {
                    "<p style=\"color:#16a34a;font-weight:600\">✓ No verified exploitable vulnerabilities identified.</p>".to_string()
                } else {
                    let header = "<table><thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>Hosts</th><th>EPSS</th><th>Description</th></tr></thead><tbody>";
                    let body: String = verified_cves.iter().map(|v| {
                        let cve = v.get("cve").and_then(|x| x.as_str()).unwrap_or("");
                        let cvss = v.get("max_cvss").and_then(|x| x.as_f64()).unwrap_or(0.0);
                        let sev = v.get("severity").and_then(|x| x.as_str()).unwrap_or("none");
                        let hc = v.get("host_count").and_then(|x| x.as_i64()).unwrap_or(0);
                        let epss = v.get("epss").and_then(|x| x.as_f64()).map(|e| format!("{:.2}%", e*100.0)).unwrap_or_else(|| "—".to_string());
                        let summary = v.get("summary").and_then(|x| x.as_str()).unwrap_or("");
                        let short = if summary.len() > 200 { &summary[..200] } else { summary };
                        format!("<tr><td class=\"mono\"><a href=\"https://nvd.nist.gov/vuln/detail/{cve}\" target=\"_blank\" rel=\"noopener\">{cve}</a></td><td style=\"color:{col};font-weight:700\">{cvss:.1}</td><td><span class=\"badge {sev}\">{su}</span></td><td>{hc}</td><td class=\"mono\">{epss}</td><td style=\"color:#475569\">{desc}</td></tr>",
                            col = cvss_color(cvss), su = sev.to_uppercase(), desc = esc(short))
                    }).collect();
                    format!("{header}{body}</tbody></table>")
                };
                toc_items.push(format!("<li><a href=\"#stop_verified\">{n}. Verified / Exploitable Vulnerabilities</a></li>"));
                parts.push(format!("<div id=\"stop_verified\"><h2>{n}. Verified / Exploitable Vulnerabilities</h2><p class=\"sub\">CVEs with confirmed exploitation in the wild — highest remediation priority.</p>{rows}</div>"));
            }

            "websites" => {
                let mut site_sorted: Vec<&Value> = sites.clone();
                if config.only_with_cves {
                    site_sorted.retain(|r| r.get("vulns_count").and_then(|v| v.as_i64()).unwrap_or(0) > 0);
                }
                // Primary: highest max_cvss. Secondary: most CVEs.
                site_sorted.sort_by(|a, b| {
                    let ca = a.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let cb = b.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    cb.partial_cmp(&ca).unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| {
                            let va = a.get("vulns_count").and_then(|v| v.as_i64()).unwrap_or(0);
                            let vb = b.get("vulns_count").and_then(|v| v.as_i64()).unwrap_or(0);
                            vb.cmp(&va)
                        })
                });
                let scans_val = scans.as_object().cloned().unwrap_or_default();
                let sites_up = site_sorted.iter().filter(|t| {
                    let key = format!("{}:{}", t.get("ip_str").and_then(|v| v.as_str()).unwrap_or(""), t.get("port").and_then(|v| v.as_i64()).unwrap_or(0));
                    scans_val.get(&key).and_then(|s| s.get("http_ok")).and_then(|v| v.as_bool()).unwrap_or(false)
                }).count();
                let sites_down = site_sorted.iter().filter(|t| {
                    let key = format!("{}:{}", t.get("ip_str").and_then(|v| v.as_str()).unwrap_or(""), t.get("port").and_then(|v| v.as_i64()).unwrap_or(0));
                    let s = scans_val.get(&key);
                    s.map(|sc| sc.get("http_ok").and_then(|v| v.as_bool()).unwrap_or(true) == false && sc.get("tcp_open").and_then(|v| v.as_bool()).unwrap_or(true) == false).unwrap_or(false)
                }).count();
                let scanned = site_sorted.iter().filter(|t| {
                    let key = format!("{}:{}", t.get("ip_str").and_then(|v| v.as_str()).unwrap_or(""), t.get("port").and_then(|v| v.as_i64()).unwrap_or(0));
                    scans_val.contains_key(&key)
                }).count();
                let with_cves = site_sorted.iter().filter(|t| t.get("vulns_count").and_then(|v| v.as_i64()).unwrap_or(0) > 0).count();

                let site_html: String = site_sorted.iter().map(|t| {
                    let ip = t.get("ip_str").and_then(|v| v.as_str()).unwrap_or("");
                    let port = t.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
                    let key = format!("{ip}:{port}");
                    let hostname = t.get("hostname").and_then(|v| v.as_str()).unwrap_or(ip);
                    let scheme = if t.get("has_ssl").and_then(|v| v.as_bool()).unwrap_or(false) || port == 443 { "https" } else { "http" };
                    let is_default = (scheme == "https" && port == 443) || (scheme == "http" && port == 80);
                    let url = if is_default { format!("{scheme}://{hostname}") } else { format!("{scheme}://{hostname}:{port}") };
                    let org = t.get("org").and_then(|v| v.as_str()).unwrap_or("Unknown");
                    let vulns_count = t.get("vulns_count").and_then(|v| v.as_i64()).unwrap_or(0);
                    let max_cvss = t.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let cve_list: Vec<&str> = t.get("cves").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|c| c.as_str()).collect()).unwrap_or_default();

                    let sc = scans_val.get(&key);
                    let (status_badge, status_label) = if let Some(sc) = sc {
                        let ok = sc.get("http_ok").and_then(|v| v.as_bool()).unwrap_or(false);
                        let tcp = sc.get("tcp_open").and_then(|v| v.as_bool()).unwrap_or(false);
                        if ok { ("up", "Up") } else if tcp { ("warn", "TCP open") } else { ("down", "Down") }
                    } else { ("unscanned", "Unscanned") };

                    let scan_meta = sc.map(|sc| {
                        let status = sc.get("http_status").and_then(|v| v.as_i64()).map(|s| format!("<span>HTTP {s}</span>")).unwrap_or_default();
                        let title_s = sc.get("title").and_then(|v| v.as_str()).map(|t| format!("<span>Title: <em>{}</em></span>", esc(t))).unwrap_or_default();
                        let ms = sc.get("http_ms").and_then(|v| v.as_i64()).map(|m| format!("<span>Response: {m}ms</span>")).unwrap_or_default();
                        let redir = sc.get("redirected").and_then(|v| v.as_bool()).unwrap_or(false);
                        let redir_s = if redir { sc.get("final_url").and_then(|v| v.as_str()).map(|u| format!("<span>↳ {}</span>", esc(u))).unwrap_or_default() } else { String::new() };
                        format!("{status}{title_s}{ms}{redir_s}")
                    }).unwrap_or_default();

                    let cve_table = if cve_list.is_empty() {
                        "<p class=\"ok\">✓ No known vulnerabilities for this website.</p>".to_string()
                    } else {
                        let mut cve_rows: Vec<&Value> = cve_list.iter().filter_map(|c| vmap.get(*c).copied()).collect();
                        cve_rows.sort_by(|a, b| b.get("max_cvss").and_then(|v| v.as_f64()).partial_cmp(&a.get("max_cvss").and_then(|v| v.as_f64())).unwrap_or(std::cmp::Ordering::Equal));
                        let rows: String = cve_rows.iter().map(|c| {
                            let cve = c.get("cve").and_then(|v| v.as_str()).unwrap_or("");
                            let cvss = c.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0);
                            let sev = c.get("severity").and_then(|v| v.as_str()).unwrap_or("none");
                            let ver = c.get("verified").and_then(|v| v.as_bool()).unwrap_or(false);
                            let epss = c.get("epss").and_then(|v| v.as_f64()).map(|e| format!("{:.2}%", e*100.0)).unwrap_or_else(|| "—".to_string());
                            let summary = c.get("summary").and_then(|v| v.as_str()).unwrap_or("");
                            let short = truncate_chars(summary, 240);
                            format!("<tr><td class=\"mono\"><a href=\"https://nvd.nist.gov/vuln/detail/{cve}\" target=\"_blank\" rel=\"noopener\">{cve}</a></td><td style=\"color:{col};font-weight:700\">{cvss:.1}</td><td><span class=\"badge {sev}\">{su}</span></td><td style=\"color:{vc};font-weight:600\">{vl}</td><td class=\"mono\">{epss}</td><td style=\"color:#475569\">{desc}</td></tr>",
                                col = cvss_color(cvss), su = sev.to_uppercase(), vc = if ver { "#16a34a" } else { "#94a3b8" }, vl = if ver { "✓" } else { "No" }, desc = esc(short))
                        }).collect();
                        format!("<table><thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>Verified</th><th>EPSS</th><th>Description</th></tr></thead><tbody>{rows}</tbody></table>")
                    };

                    let vuln_badge = if vulns_count > 0 {
                        format!("<span class=\"meta\"><strong style=\"color:{col}\">{vulns_count} CVE{s}</strong> · max CVSS {max_cvss:.1}</span>", col = cvss_color(max_cvss), s = if vulns_count != 1 { "s" } else { "" })
                    } else {
                        "<span style=\"color:#16a34a;font-size:11px;font-weight:600\">No known CVEs</span>".to_string()
                    };

                    let display_host = if hostname == ip { format!("{ip}:{port}") } else { hostname.to_string() };
                    let data_name = format!("{} {}:{} {}", hostname, ip, port, org).to_lowercase();
                    format!(r#"<details class="site-card" data-name="{dn}">
  <summary>
    <span class="site-name">{hn}</span>
    <span class="meta mono" style="color:#94a3b8;font-size:10px">{ip}:{port}</span>
    <span class="meta">{org_e}</span>
    <span class="badge {status_badge}">{status_label}</span>
    {vuln_badge}
  </summary>
  <div class="body">
    <div style="display:flex;flex-wrap:wrap;gap:16px;margin:8px 0 10px;font-size:11px;color:#64748b">
      <span>🔗 <a href="{url}" target="_blank" rel="noopener">{url}</a></span>
      <span style="color:#94a3b8">{ip}:{port}</span>
      {scan_meta}
    </div>
    {cve_table}
  </div>
</details>"#,
                        dn = esc(&data_name),
                        hn = esc(&display_host), org_e = esc(org), url = esc(&url),
                    )
                }).collect();

                toc_items.push(format!("<li><a href=\"#swebsites\">{n}. Website Status &amp; CVE Detail</a></li>"));
                parts.push(format!(r#"<div id="swebsites" class="pagebreak">
  <h2>{n}. Website Status &amp; CVE Detail</h2>
  <div class="cards" style="margin-bottom:16px">
    <div class="card"><span class="num">{total}</span><span class="lbl">Total websites</span></div>
    <div class="card green"><span class="num">{up}</span><span class="lbl">Confirmed up</span></div>
    <div class="card red"><span class="num">{down}</span><span class="lbl">Unreachable</span></div>
    <div class="card"><span class="num">{sc}</span><span class="lbl">Actively scanned</span></div>
    <div class="card orange"><span class="num">{wc}</span><span class="lbl">With CVEs</span></div>
  </div>
  <div class="sticky-bar noprint">
    <input class="flt" id="site-flt" placeholder="Filter by site, IP, org or CVE…" oninput="filterSites(this.value)">
    <button class="ctrl" onclick="setAll(true)">Expand all</button>
    <button class="ctrl" onclick="setAll(false)">Collapse all</button>
    <button class="ctrl" onclick="window.print()">Print / PDF</button>
    <span id="sc" style="font-size:11px;color:#94a3b8">{total}</span> shown
  </div>
  {site_html}
</div>"#,
                    total = site_sorted.len(), up = sites_up, down = sites_down, sc = scanned, wc = with_cves,
                    site_html = if site_html.is_empty() { "<p style=\"color:#64748b\">No website targets in current filter.</p>".to_string() } else { site_html },
                ));
            }

            "orgs" => {
                let mut org_map: HashMap<&str, (usize, f64, i64)> = HashMap::new(); // name → (hosts, max_cvss, total_cves)
                for r in &records {
                    let org = r.get("org").and_then(|v| v.as_str())
                        .or_else(|| r.get("isp").and_then(|v| v.as_str()))
                        .unwrap_or("Unknown");
                    let e = org_map.entry(org).or_insert((0, 0.0, 0));
                    e.0 += 1;
                    let cvss = r.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    if cvss > e.1 { e.1 = cvss; }
                    e.2 += r.get("vulns_count").and_then(|v| v.as_i64()).unwrap_or(0);
                }
                let mut orgs: Vec<(&str, usize, f64, i64)> = org_map.into_iter().map(|(n, (h, c, v))| (n, h, c, v)).collect();
                orgs.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal).then(b.1.cmp(&a.1)));
                let rows: String = orgs.iter().take(30).map(|(name, hosts, cvss, cves)| {
                    format!("<tr><td style=\"font-weight:600\">{}</td><td>{hosts}</td><td style=\"color:{col};font-weight:700\">{cvss_s}</td><td>{sev_badge}</td><td>{cves}</td></tr>",
                        esc(name),
                        col = cvss_color(*cvss),
                        cvss_s = if *cvss > 0.0 { format!("{cvss:.1}") } else { "—".to_string() },
                        sev_badge = if *cvss > 0.0 { format!("<span class=\"badge {}\">{}</span>", sev_name(*cvss), sev_label(*cvss)) } else { "—".to_string() },
                    )
                }).collect();
                toc_items.push(format!("<li><a href=\"#sorgs\">{n}. Organisation Breakdown</a></li>"));
                parts.push(format!("<div id=\"sorgs\"><h2>{n}. Organisation Breakdown</h2><p class=\"sub\">Top 30 organisations by maximum CVE severity.</p><table><thead><tr><th>Organisation</th><th>Hosts</th><th>Max CVSS</th><th>Severity</th><th>Total CVE instances</th></tr></thead><tbody>{rows}</tbody></table></div>"));
            }

            "ports" => {
                let ports = stats.get("top_ports").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                let max_p = ports.iter().filter_map(|p| p.get("count")?.as_i64()).max().unwrap_or(1) as f64;
                let rows: String = ports.iter().map(|p| {
                    let port = p.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
                    let count = p.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
                    let pct = if total_hosts > 0 { count * 100 / total_hosts as i64 } else { 0 };
                    let bar = (count as f64 / max_p * 100.0) as i32;
                    format!("<tr><td class=\"mono\" style=\"font-weight:700\">:{port}</td><td>{count}</td><td><div class=\"bar-wrap\"><div class=\"bar-bg\"><div class=\"bar-fill\" style=\"width:{bar}%;background:#ea580c\"></div></div></div></td><td>{pct}%</td></tr>")
                }).collect();
                toc_items.push(format!("<li><a href=\"#sports\">{n}. Port Exposure</a></li>"));
                parts.push(format!("<div id=\"sports\"><h2>{n}. Port Exposure Summary</h2><table><thead><tr><th>Port</th><th>Hosts</th><th>Coverage</th><th>% of fleet</th></tr></thead><tbody>{rows}</tbody></table></div>"));
            }

            "tech" => {
                let tech = stats.get("tech").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                let max_t = tech.iter().filter_map(|t| t.get("count")?.as_i64()).max().unwrap_or(1) as f64;
                let rows: String = tech.iter().map(|t| {
                    let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                    let count = t.get("count").and_then(|v| v.as_i64()).unwrap_or(0);
                    let pct = if total_hosts > 0 { count * 100 / total_hosts as i64 } else { 0 };
                    let bar = (count as f64 / max_t * 100.0) as i32;
                    format!("<tr><td style=\"font-weight:600\">{}</td><td>{count}</td><td><div class=\"bar-wrap\"><div class=\"bar-bg\"><div class=\"bar-fill\" style=\"width:{bar}%;background:#f97316\"></div></div></div></td><td>{pct}%</td></tr>", esc(name))
                }).collect();
                toc_items.push(format!("<li><a href=\"#stech\">{n}. Technology Stack</a></li>"));
                parts.push(format!("<div id=\"stech\"><h2>{n}. Technology Stack</h2><table><thead><tr><th>Technology</th><th>Hosts</th><th>Adoption</th><th>% of fleet</th></tr></thead><tbody>{rows}</tbody></table></div>"));
            }

            "ssl" => {
                let ssl_hosts = records.iter().filter(|r| r.get("has_ssl").and_then(|v| v.as_bool()).unwrap_or(false)).count();
                let no_ssl = total_hosts - ssl_hosts;
                let expired = records.iter().filter(|r| r.get("ssl_expired").and_then(|v| v.as_bool()).unwrap_or(false)).count();
                toc_items.push(format!("<li><a href=\"#sssl\">{n}. TLS / Certificate Posture</a></li>"));
                parts.push(format!(r#"<div id="sssl"><h2>{n}. TLS / Certificate Posture</h2>
  <div class="cards">
    <div class="card green"><span class="num">{ssl_hosts}</span><span class="lbl">Hosts with TLS</span></div>
    <div class="card red"><span class="num">{no_ssl}</span><span class="lbl">No TLS</span></div>
    <div class="card red"><span class="num">{expired}</span><span class="lbl">Expired certs</span></div>
  </div>
  <table><thead><tr><th>Status</th><th>Hosts</th><th>% of fleet</th></tr></thead><tbody>
    <tr><td style="color:#16a34a;font-weight:600">Valid TLS</td><td>{valid}</td><td>{vp}%</td></tr>
    <tr><td style="color:#dc2626;font-weight:600">Expired certificate</td><td>{expired}</td><td>{ep}%</td></tr>
    <tr><td style="color:#94a3b8;font-weight:600">No TLS</td><td>{no_ssl}</td><td>{np}%</td></tr>
  </tbody></table>
</div>"#,
                    valid = ssl_hosts.saturating_sub(expired),
                    vp = if total_hosts > 0 { (ssl_hosts.saturating_sub(expired)) * 100 / total_hosts } else { 0 },
                    ep = if total_hosts > 0 { expired * 100 / total_hosts } else { 0 },
                    np = if total_hosts > 0 { no_ssl * 100 / total_hosts } else { 0 },
                ));
            }

            "infra" => {
                let mut infra: Vec<&Value> = records.iter().copied().filter(|r| {
                    !r.get("is_site").and_then(|v| v.as_bool()).unwrap_or(false) &&
                    (r.get("has_ssl").and_then(|v| v.as_bool()).unwrap_or(false)
                     || r.get("http_status").is_some()
                     || r.get("port").and_then(|v| v.as_i64()).map(|p| web_ports.contains(&p)).unwrap_or(false))
                }).collect();
                if config.only_with_cves {
                    infra.retain(|r| r.get("vulns_count").and_then(|v| v.as_i64()).unwrap_or(0) > 0);
                }
                infra.sort_by(|a, b| {
                    let ca = a.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let cb = b.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    cb.partial_cmp(&ca).unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| {
                            let va = a.get("vulns_count").and_then(|v| v.as_i64()).unwrap_or(0);
                            let vb = b.get("vulns_count").and_then(|v| v.as_i64()).unwrap_or(0);
                            vb.cmp(&va)
                        })
                });
                let rows: String = infra.iter().take(200).map(|r| {
                    let ip = r.get("ip_str").and_then(|v| v.as_str()).unwrap_or("");
                    let port = r.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
                    let host = r.get("hostnames").and_then(|v| v.as_array()).and_then(|a| a.first()).and_then(|v| v.as_str()).unwrap_or("");
                    let org = r.get("org").and_then(|v| v.as_str()).or_else(|| r.get("isp").and_then(|v| v.as_str())).unwrap_or("—");
                    let cves = r.get("vulns_count").and_then(|v| v.as_i64()).unwrap_or(0);
                    let cvss = r.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let fw = if cvss > 0.0 { 700 } else { 400 };
                    let cvss_s = if cvss > 0.0 { format!("{cvss:.1}") } else { "—".to_string() };
                    let cves_s = if cves > 0 { cves.to_string() } else { "—".to_string() };
                    // Hostname primary; IP shown underneath
                    let primary = if host.is_empty() { esc(ip) } else { esc(host) };
                    let secondary = if host.is_empty() { String::new() } else { format!("<br><span style=\"color:#94a3b8;font-size:10px\" class=\"mono\">{}</span>", esc(ip)) };
                    format!("<tr><td>{primary}{secondary}</td><td>{port}</td><td>{}</td><td>{cves_s}</td><td style=\"color:{col};font-weight:{fw}\">{cvss_s}</td></tr>",
                        esc(org), col = cvss_color(cvss))
                }).collect();
                toc_items.push(format!("<li><a href=\"#sinfra\">{n}. Infrastructure Hosts</a></li>"));
                parts.push(format!("<div id=\"sinfra\" class=\"pagebreak\"><h2>{n}. Infrastructure Hosts</h2><p class=\"sub\">Cloud and VPS hosts not classified as organisation websites. Showing up to 200.</p><table><thead><tr><th>Hostname / IP</th><th>Port</th><th>Org</th><th>CVEs</th><th>Max CVSS</th></tr></thead><tbody>{rows}</tbody></table></div>"));
            }

            "all_hosts" => {
                let mut sorted: Vec<&Value> = records.iter().copied().collect();
                if config.only_with_cves {
                    sorted.retain(|r| r.get("vulns_count").and_then(|v| v.as_i64()).unwrap_or(0) > 0);
                }
                sorted.sort_by(|a, b| {
                    let ca = a.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let cb = b.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    cb.partial_cmp(&ca).unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| {
                            let va = a.get("vulns_count").and_then(|v| v.as_i64()).unwrap_or(0);
                            let vb = b.get("vulns_count").and_then(|v| v.as_i64()).unwrap_or(0);
                            vb.cmp(&va)
                        })
                });
                let rows: String = sorted.iter().take(500).map(|r| {
                    let ip = r.get("ip_str").and_then(|v| v.as_str()).unwrap_or("");
                    let port = r.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
                    let hostname = r.get("hostnames").and_then(|v| v.as_array()).and_then(|a| a.first()).and_then(|v| v.as_str()).unwrap_or("");
                    let org = r.get("org").and_then(|v| v.as_str()).or_else(|| r.get("isp").and_then(|v| v.as_str())).unwrap_or("—");
                    let country = r.get("country_name").and_then(|v| v.as_str()).or_else(|| r.get("country_code").and_then(|v| v.as_str())).unwrap_or("—");
                    let cves = r.get("vulns_count").and_then(|v| v.as_i64()).unwrap_or(0);
                    let cvss = r.get("max_cvss").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let ts = r.get("timestamp").and_then(|v| v.as_str()).map(|t| &t[..t.len().min(10)]).unwrap_or("—");
                    let fw = if cvss > 0.0 { 700 } else { 400 };
                    let cvss_s = if cvss > 0.0 { format!("{cvss:.1}") } else { "—".to_string() };
                    let cves_s = if cves > 0 { cves.to_string() } else { "—".to_string() };
                    let sev_badge = if cvss > 0.0 { format!("<span class=\"badge {}\">{}</span>", sev_name(cvss), sev_label(cvss)) } else { "—".to_string() };
                    let col = cvss_color(cvss);
                    // Hostname primary, IP as secondary line
                    let primary = if hostname.is_empty() { esc(ip) } else { esc(hostname) };
                    let secondary = if hostname.is_empty() { String::new() } else { format!("<br><span style=\"color:#94a3b8;font-size:10px\" class=\"mono\">{ip}:{port}</span>") };
                    format!("<tr><td>{primary}{secondary}</td><td>{port}</td><td style=\"font-size:11px\">{}</td><td style=\"font-size:11px\">{}</td><td>{cves_s}</td><td style=\"color:{col};font-weight:{fw}\">{cvss_s}</td><td>{sev_badge}</td><td style=\"font-size:10px;color:#94a3b8\">{ts}</td></tr>",
                        esc(org), esc(country))
                }).collect();
                toc_items.push(format!("<li><a href=\"#sall_hosts\">{n}. Full Host Listing</a></li>"));
                parts.push(format!("<div id=\"sall_hosts\" class=\"pagebreak\"><h2>{n}. Full Host Listing</h2><p class=\"sub\">All hosts sorted by highest CVE severity, then most CVEs. Capped at 500 rows.</p><table><thead><tr><th>Hostname / IP</th><th>Port</th><th>Org</th><th>Country</th><th>CVEs</th><th>Max CVSS</th><th>Severity</th><th>Scanned</th></tr></thead><tbody>{rows}</tbody></table></div>"));
            }

            "cve_ref" => {
                let rows: String = vulns.iter().map(|v| {
                    let cve = v.get("cve").and_then(|x| x.as_str()).unwrap_or("");
                    let cvss = v.get("max_cvss").and_then(|x| x.as_f64()).unwrap_or(0.0);
                    let sev = v.get("severity").and_then(|x| x.as_str()).unwrap_or("none");
                    let hc = v.get("host_count").and_then(|x| x.as_i64()).unwrap_or(0);
                    let epss = v.get("epss").and_then(|x| x.as_f64()).map(|e| format!("{:.2}%", e*100.0)).unwrap_or_else(|| "—".to_string());
                    let ver = v.get("verified").and_then(|x| x.as_bool()).unwrap_or(false);
                    let summary = v.get("summary").and_then(|x| x.as_str()).unwrap_or("");
                    let short = truncate_chars(summary, 180);
                    format!("<tr><td class=\"mono\" style=\"white-space:nowrap\"><a href=\"https://nvd.nist.gov/vuln/detail/{cve}\" target=\"_blank\" rel=\"noopener\">{cve}</a></td><td style=\"color:{col};font-weight:700\">{cvss:.1}</td><td><span class=\"badge {sev}\">{su}</span></td><td>{hc}</td><td class=\"mono\">{epss}</td><td style=\"color:{vc}\">{vl}</td><td style=\"color:#475569;font-size:11px\">{desc}</td></tr>",
                        col = cvss_color(cvss), su = sev.to_uppercase(), vc = if ver { "#16a34a" } else { "#94a3b8" }, vl = if ver { "✓" } else { "" }, desc = esc(short))
                }).collect();
                toc_items.push(format!("<li><a href=\"#scve_ref\">{n}. Appendix: CVE Reference</a></li>"));
                parts.push(format!("<div id=\"scve_ref\" class=\"pagebreak\"><h2>{n}. Appendix: CVE Reference Table</h2><p class=\"sub\">All {} unique CVEs identified, sorted by CVSS score.</p><table><thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>Hosts</th><th>EPSS</th><th>Verified</th><th>Summary</th></tr></thead><tbody>{rows}</tbody></table></div>", vulns.len()));
            }

            _ => {}
        }
    }

    let toc_html = format!("<div class=\"toc noprint\"><h3>Contents</h3><ol>{}</ol></div>", toc_items.join(""));
    let footer = format!("<div class=\"sub\" style=\"margin-top:48px;padding-top:12px;border-top:1px solid #e2e8f0;text-align:center\">Generated by Shodanify · {}</div>", esc(classification));

    format!(r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{title}</title>
<style>{css}</style></head><body>
<div class="page">{toc}{body}{footer}</div>
{js}</body></html>"#,
        title = esc(title),
        css = report_css(),
        toc = toc_html,
        body = parts.join("\n"),
        footer = footer,
        js = report_js(),
    )
}

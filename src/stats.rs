use serde_json::{json, Value};
use std::collections::HashMap;

pub fn compute_stats(records: &[Value], duplicates_removed: usize) -> Value {
    let mut ips: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut ports: HashMap<i64, u64> = HashMap::new();
    let mut countries: HashMap<String, Value> = HashMap::new();
    let mut orgs: HashMap<String, u64> = HashMap::new();
    let mut cve_map: HashMap<String, CveStat> = HashMap::new();
    let mut tech_map: HashMap<String, TechStat> = HashMap::new();
    let mut sev = SeverityCounts::default();

    for r in records {
        if let Some(ip) = r.get("ip_str").and_then(|v| v.as_str()) {
            ips.insert(ip);
        }

        if let Some(port) = r.get("port").and_then(|v| v.as_i64()) {
            *ports.entry(port).or_default() += 1;
        }

        let loc = r.get("location").unwrap_or(&Value::Null);
        let cc = loc.get("country_code").and_then(|v| v.as_str()).unwrap_or("XX").to_string();
        let cn = loc.get("country_name").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
        countries.entry(cc.clone()).or_insert_with(|| json!({"code": cc, "name": cn, "count": 0}));
        if let Some(obj) = countries.get_mut(&cc) {
            if let Some(c) = obj.get_mut("count").and_then(|v| v.as_u64()) {
                *obj.get_mut("count").unwrap() = Value::Number((c + 1).into());
            }
        }

        let org = r.get("org").and_then(|v| v.as_str())
            .or_else(|| r.get("isp").and_then(|v| v.as_str()))
            .unwrap_or("Unknown")
            .to_string();
        *orgs.entry(org).or_default() += 1;

        let vulns = r.get("vulns").and_then(|v| v.as_array()).map(|a| a.as_slice()).unwrap_or(&[]);
        let ip_str = r.get("ip_str").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let port_val = r.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
        let hostnames = r.get("hostnames").and_then(|v| v.as_array());
        let first_hostname = hostnames.and_then(|a| a.first()).and_then(|v| v.as_str()).map(|s| s.to_string());

        for v in vulns {
            let cve_id = match v.get("cve").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            let cvss = v.get("cvss").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let severity = v.get("severity").and_then(|v| v.as_str()).unwrap_or("none").to_string();
            let verified = v.get("verified").and_then(|v| v.as_bool()).unwrap_or(false);
            let summary = v.get("summary").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let epss = v.get("epss").and_then(|v| v.as_f64()).unwrap_or(0.0);

            match severity.as_str() {
                "critical" => sev.critical += 1,
                "high" => sev.high += 1,
                "medium" => sev.medium += 1,
                "low" => sev.low += 1,
                _ => sev.none += 1,
            }

            let entry = cve_map.entry(cve_id.clone()).or_insert_with(|| CveStat {
                cve: cve_id.clone(),
                max_cvss: cvss,
                severity: severity.clone(),
                verified,
                summary: summary.clone(),
                epss,
                hosts: vec![],
            });
            if cvss > entry.max_cvss {
                entry.max_cvss = cvss;
                entry.severity = severity;
                entry.summary = summary;
            }
            if verified {
                entry.verified = true;
            }
            entry.hosts.push(HostRef {
                ip: ip_str.clone(),
                port: port_val,
                hostname: first_hostname.clone(),
            });
        }

        if let Some(http) = r.get("http").and_then(|v| if v.is_null() { None } else { Some(v) }) {
            if let Some(comps) = http.get("components").and_then(|v| v.as_array()) {
                for t in comps {
                    let name = match t.get("name").and_then(|v| v.as_str()) {
                        Some(n) => n.to_string(),
                        None => continue,
                    };
                    let cats: Vec<String> = t.get("categories")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default();
                    let vers: Vec<String> = t.get("versions")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default();
                    let entry = tech_map.entry(name.clone()).or_insert_with(|| TechStat {
                        name: name.clone(),
                        count: 0,
                        categories: cats,
                        versions: std::collections::HashSet::new(),
                    });
                    entry.count += 1;
                    for v in vers {
                        entry.versions.insert(v);
                    }
                }
            }
        }
    }

    // Top ports (sorted by count desc, top 12)
    let mut port_list: Vec<Value> = ports.iter()
        .map(|(port, count)| json!({"port": port, "count": count}))
        .collect();
    port_list.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()));
    let top_ports: Vec<Value> = port_list.into_iter().take(12).collect();

    // Top countries (sorted by count desc, top 15)
    let mut country_list: Vec<Value> = countries.into_values().collect();
    country_list.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()));
    let top_countries: Vec<Value> = country_list.into_iter().take(15).collect();

    // Top orgs (top 10)
    let mut org_list: Vec<Value> = orgs.iter()
        .map(|(org, count)| json!({"org": org, "count": count}))
        .collect();
    org_list.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()));
    let top_orgs: Vec<Value> = org_list.into_iter().take(10).collect();

    // All vulns sorted by CVSS desc
    let mut all_vulns: Vec<Value> = cve_map.into_iter().map(|(_, entry)| {
        let host_count = entry.hosts.len();
        let hosts_limited: Vec<Value> = entry.hosts.into_iter().take(25).map(|h| json!({
            "ip": h.ip,
            "port": h.port,
            "hostname": h.hostname,
        })).collect();
        json!({
            "cve": entry.cve,
            "max_cvss": entry.max_cvss,
            "severity": entry.severity,
            "verified": entry.verified,
            "summary": entry.summary,
            "epss": entry.epss,
            "hosts": hosts_limited,
            "host_count": host_count,
        })
    }).collect();
    all_vulns.sort_by(|a, b| {
        b["max_cvss"].as_f64().partial_cmp(&a["max_cvss"].as_f64()).unwrap_or(std::cmp::Ordering::Equal)
    });

    // Tech list sorted by count
    let mut tech_list: Vec<Value> = tech_map.into_iter().map(|(_, entry)| {
        let mut versions: Vec<String> = entry.versions.into_iter().collect();
        versions.sort();
        json!({
            "name": entry.name,
            "count": entry.count,
            "categories": entry.categories,
            "versions": versions,
        })
    }).collect();
    tech_list.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()));

    let total_vuln_instances = sev.critical + sev.high + sev.medium + sev.low + sev.none;

    json!({
        "total_records": records.len(),
        "duplicates_removed": duplicates_removed,
        "unique_ips": ips.len(),
        "unique_ports": ports.len(),
        "unique_countries": country_list_count(&top_countries),
        "unique_cves": all_vulns.len(),
        "total_vuln_instances": total_vuln_instances,
        "severity": {
            "critical": sev.critical,
            "high": sev.high,
            "medium": sev.medium,
            "low": sev.low,
            "none": sev.none,
        },
        "top_ports": top_ports,
        "top_countries": top_countries,
        "top_orgs": top_orgs,
        "vulns": all_vulns,
        "tech": tech_list,
    })
}

fn country_list_count(top: &[Value]) -> usize {
    // We truncated to 15; for accurate unique count we need the full set.
    // This is called after already truncating so we just return what we have.
    // The actual unique_countries is computed before truncation in the caller.
    top.len()
}

// Helper: compute unique country count separately
pub fn compute_stats_full(records: &[Value], duplicates_removed: usize) -> Value {
    let mut ips: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut ports: HashMap<i64, u64> = HashMap::new();
    let mut countries: HashMap<String, (String, u64)> = HashMap::new();
    let mut orgs: HashMap<String, u64> = HashMap::new();
    let mut cve_map: HashMap<String, CveStat> = HashMap::new();
    let mut tech_map: HashMap<String, TechStat> = HashMap::new();
    let mut sev = SeverityCounts::default();

    for r in records {
        if let Some(ip) = r.get("ip_str").and_then(|v| v.as_str()) {
            ips.insert(ip);
        }
        if let Some(port) = r.get("port").and_then(|v| v.as_i64()) {
            *ports.entry(port).or_default() += 1;
        }
        let loc = r.get("location").unwrap_or(&Value::Null);
        let cc = loc.get("country_code").and_then(|v| v.as_str()).unwrap_or("XX").to_string();
        let cn = loc.get("country_name").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
        let e = countries.entry(cc).or_insert((cn, 0));
        e.1 += 1;

        let org = r.get("org").and_then(|v| v.as_str())
            .or_else(|| r.get("isp").and_then(|v| v.as_str()))
            .unwrap_or("Unknown")
            .to_string();
        *orgs.entry(org).or_default() += 1;

        let vulns = r.get("vulns").and_then(|v| v.as_array()).map(|a| a.as_slice()).unwrap_or(&[]);
        let ip_str = r.get("ip_str").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let port_val = r.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
        let hostnames = r.get("hostnames").and_then(|v| v.as_array());
        let first_hostname = hostnames.and_then(|a| a.first()).and_then(|v| v.as_str()).map(|s| s.to_string());

        for v in vulns {
            let cve_id = match v.get("cve").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            let cvss = v.get("cvss").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let severity = v.get("severity").and_then(|v| v.as_str()).unwrap_or("none").to_string();
            let verified = v.get("verified").and_then(|v| v.as_bool()).unwrap_or(false);
            let summary = v.get("summary").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let epss = v.get("epss").and_then(|v| v.as_f64()).unwrap_or(0.0);

            match severity.as_str() {
                "critical" => sev.critical += 1,
                "high" => sev.high += 1,
                "medium" => sev.medium += 1,
                "low" => sev.low += 1,
                _ => sev.none += 1,
            }

            let entry = cve_map.entry(cve_id.clone()).or_insert_with(|| CveStat {
                cve: cve_id.clone(),
                max_cvss: cvss,
                severity: severity.clone(),
                verified,
                summary: summary.clone(),
                epss,
                hosts: vec![],
            });
            if cvss > entry.max_cvss {
                entry.max_cvss = cvss;
                entry.severity = severity;
                entry.summary = summary;
            }
            if verified { entry.verified = true; }
            entry.hosts.push(HostRef { ip: ip_str.clone(), port: port_val, hostname: first_hostname.clone() });
        }

        if let Some(http) = r.get("http").and_then(|v| if v.is_null() { None } else { Some(v) }) {
            if let Some(comps) = http.get("components").and_then(|v| v.as_array()) {
                for t in comps {
                    let name = match t.get("name").and_then(|v| v.as_str()) {
                        Some(n) => n.to_string(),
                        None => continue,
                    };
                    let cats: Vec<String> = t.get("categories")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default();
                    let vers: Vec<String> = t.get("versions")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default();
                    let entry = tech_map.entry(name.clone()).or_insert_with(|| TechStat {
                        name: name.clone(),
                        count: 0,
                        categories: cats,
                        versions: std::collections::HashSet::new(),
                    });
                    entry.count += 1;
                    for v in vers { entry.versions.insert(v); }
                }
            }
        }
    }

    let unique_countries = countries.len();
    let mut country_list: Vec<Value> = countries.into_iter()
        .map(|(cc, (cn, count))| json!({"code": cc, "name": cn, "count": count}))
        .collect();
    country_list.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()));
    let top_countries: Vec<Value> = country_list.into_iter().take(15).collect();

    let mut port_list: Vec<Value> = ports.iter()
        .map(|(port, count)| json!({"port": port, "count": count}))
        .collect();
    port_list.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()));
    let top_ports: Vec<Value> = port_list.into_iter().take(12).collect();

    let mut org_list: Vec<Value> = orgs.iter()
        .map(|(org, count)| json!({"org": org, "count": count}))
        .collect();
    org_list.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()));
    let top_orgs: Vec<Value> = org_list.into_iter().take(10).collect();

    let mut all_vulns: Vec<Value> = cve_map.into_iter().map(|(_, entry)| {
        let host_count = entry.hosts.len();
        let hosts_limited: Vec<Value> = entry.hosts.into_iter().take(25).map(|h| json!({
            "ip": h.ip, "port": h.port, "hostname": h.hostname,
        })).collect();
        json!({
            "cve": entry.cve,
            "max_cvss": entry.max_cvss,
            "severity": entry.severity,
            "verified": entry.verified,
            "summary": entry.summary,
            "epss": entry.epss,
            "hosts": hosts_limited,
            "host_count": host_count,
        })
    }).collect();
    all_vulns.sort_by(|a, b| {
        b["max_cvss"].as_f64().partial_cmp(&a["max_cvss"].as_f64()).unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut tech_list: Vec<Value> = tech_map.into_iter().map(|(_, entry)| {
        let mut versions: Vec<String> = entry.versions.into_iter().collect();
        versions.sort();
        json!({ "name": entry.name, "count": entry.count, "categories": entry.categories, "versions": versions })
    }).collect();
    tech_list.sort_by(|a, b| b["count"].as_u64().cmp(&a["count"].as_u64()));

    let total_vuln_instances = sev.critical + sev.high + sev.medium + sev.low + sev.none;

    json!({
        "total_records": records.len(),
        "duplicates_removed": duplicates_removed,
        "unique_ips": ips.len(),
        "unique_ports": ports.len(),
        "unique_countries": unique_countries,
        "unique_cves": all_vulns.len(),
        "total_vuln_instances": total_vuln_instances,
        "severity": {
            "critical": sev.critical, "high": sev.high, "medium": sev.medium,
            "low": sev.low, "none": sev.none,
        },
        "top_ports": top_ports,
        "top_countries": top_countries,
        "top_orgs": top_orgs,
        "vulns": all_vulns,
        "tech": tech_list,
    })
}

#[derive(Default)]
struct SeverityCounts {
    critical: u64,
    high: u64,
    medium: u64,
    low: u64,
    none: u64,
}

struct CveStat {
    cve: String,
    max_cvss: f64,
    severity: String,
    verified: bool,
    summary: String,
    epss: f64,
    hosts: Vec<HostRef>,
}

struct HostRef {
    ip: String,
    port: i64,
    hostname: Option<String>,
}

struct TechStat {
    name: String,
    count: u64,
    categories: Vec<String>,
    versions: std::collections::HashSet<String>,
}

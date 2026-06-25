"""Aggregate statistics computed over the full record set."""
from collections import defaultdict


def compute_stats(records, duplicates_removed=0):
    ips = set()
    ports = defaultdict(int)
    countries = {}
    orgs = defaultdict(int)
    cve_map = {}
    tech_map = {}
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
            entry = cve_map.get(cid)
            if entry is None:
                entry = cve_map[cid] = {
                    "cve": cid,
                    "max_cvss": v["cvss"],
                    "severity": v["severity"],
                    "verified": v["verified"],
                    "summary": v["summary"],
                    "epss": v.get("epss", 0),
                    "hosts": [],
                }
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
                tm = tech_map.get(nm)
                if tm is None:
                    tm = tech_map[nm] = {"name": nm, "count": 0,
                                         "categories": t["categories"], "versions": set()}
                tm["count"] += 1
                tm["versions"].update(t["versions"])

    top_ports = [{"port": k, "count": v}
                 for k, v in sorted(ports.items(), key=lambda x: x[1], reverse=True)][:12]
    top_countries = sorted(countries.values(), key=lambda x: x["count"], reverse=True)[:15]
    top_orgs = [{"org": k, "count": v}
                for k, v in sorted(orgs.items(), key=lambda x: x[1], reverse=True)][:10]
    # Full CVE list (sorted by severity) so the vulnerabilities tab can search
    # and filter across every CVE, not just the worst 50.
    all_vulns = sorted(cve_map.values(), key=lambda x: x["max_cvss"], reverse=True)
    for tv in all_vulns:
        tv["host_count"] = len(tv["hosts"])
        tv["hosts"] = tv["hosts"][:25]

    tech_list = [{**t, "versions": sorted(t["versions"])} for t in tech_map.values()]
    tech_list.sort(key=lambda x: x["count"], reverse=True)

    return {
        "total_records": len(records),
        "duplicates_removed": duplicates_removed,
        "unique_ips": len(ips),
        "unique_ports": len(ports),
        "unique_countries": len(countries),
        "unique_cves": len(cve_map),
        "total_vuln_instances": sum(sev.values()),
        "severity": sev,
        "top_ports": top_ports,
        "top_countries": top_countries,
        "top_orgs": top_orgs,
        "vulns": all_vulns,
        "tech": tech_list,
    }

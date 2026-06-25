from shodanify.parsing import (
    cvss_severity, cert_date, parse_record, record_summary, classify_site,
)


def test_classify_site():
    # Real org domain → a site
    assert classify_site(["acme.com.au"], None) == (True, "acme.com.au")
    # Cloud PTR only → infrastructure
    assert classify_site(["amazonaws.com"], None) == (False, None)
    assert classify_site(["vultrusercontent.com"], None) == (False, None)
    # Real domain wins even when a cloud domain is also present
    assert classify_site(["amazonaws.com", "acme.com"], None)[0] is True
    # TLS cert CN reveals the real site when no real hostname exists
    assert classify_site(["amazonaws.com"], "www.acme.io") == (True, "acme.io")
    # Self-signed cert with an IP / single-label CN is not a domain
    assert classify_site([], "1.2.3.4") == (False, None)
    assert classify_site([], "localhost") == (False, None)
    # Prefer the apex domain over a deeper one
    assert classify_site(["acme.com", "shop.acme.com"], None)[1] == "acme.com"


def test_cvss_severity_buckets():
    assert cvss_severity(9.8) == "critical"
    assert cvss_severity(7.0) == "high"
    assert cvss_severity(4.0) == "medium"
    assert cvss_severity(0.1) == "low"
    assert cvss_severity(0) == "none"
    assert cvss_severity(None) == "none"
    assert cvss_severity("bad") == "none"


def test_cert_date():
    assert cert_date("20261231000000Z") == "2026-12-31T00:00:00Z"
    assert cert_date(None) is None
    assert cert_date("garbage") == "garbage"


def test_parse_record_and_summary():
    raw = {
        "ip_str": "1.2.3.4", "port": 443, "org": "Acme",
        "hostnames": ["a.acme.com"],
        "location": {"country_code": "AU", "country_name": "Australia"},
        "http": {"title": "Login", "status": 200, "components": {"nginx": {}}},
        "vulns": {"CVE-2021-44228": {"cvss": 10.0, "verified": True}},
    }
    r = parse_record(raw)
    assert r["ip_str"] == "1.2.3.4"
    assert r["vulns"][0]["severity"] == "critical"

    s = record_summary(r)
    assert s["hostname"] == "a.acme.com"
    assert s["max_cvss"] == 10.0
    assert s["vulns_count"] == 1
    assert s["tech"] == ["nginx"]

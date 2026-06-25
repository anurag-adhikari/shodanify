"""Active, lightweight health checks for targets in the dataset.

For each target this performs a single TCP connect (reachability + latency),
one HTTP(S) GET (status, redirects, server, page title, timing) and a reverse
DNS lookup. It is deliberately minimal — one request per target — and
identifies itself with a clear User-Agent. Stdlib only.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import re
import socket
import ssl
import time
import urllib.error
import urllib.request

USER_AGENT = "Shodanify-Healthcheck/1.0 (+defensive security outreach)"
HTTPS_PORTS = {443, 8443, 9443, 4443, 10443}
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _scheme(port):
    return "https" if port in HTTPS_PORTS else "http"


def _build_url(host, port, scheme):
    default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    return f"{scheme}://{host}" + ("" if default else f":{port}")


def _tcp_check(ip, port, timeout):
    start = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True, round((time.monotonic() - start) * 1000)
    except OSError:
        return False, None


def _reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return None


def _http_check(host, port, timeout):
    scheme = _scheme(port)
    url = _build_url(host, port, scheme)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we want a status even from self-signed certs
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(20000).decode("utf-8", "ignore")
            ms = round((time.monotonic() - start) * 1000)
            final = resp.geturl()
            m = _TITLE_RE.search(body)
            return {
                "http_status": resp.status,
                "http_ok": 200 <= resp.status < 400,
                "server": resp.headers.get("Server"),
                "title": (m.group(1).strip()[:200] if m else None),
                "final_url": final,
                "redirected": final.rstrip("/") != url.rstrip("/"),
                "http_ms": ms,
                "scheme": scheme,
                "url": url,
            }
    except urllib.error.HTTPError as e:
        # A 4xx/5xx is still a live web server — record the code.
        return {
            "http_status": e.code,
            "http_ok": False,
            "server": (e.headers.get("Server") if e.headers else None),
            "title": None,
            "final_url": url,
            "redirected": False,
            "http_ms": round((time.monotonic() - start) * 1000),
            "scheme": scheme,
            "url": url,
        }
    except (urllib.error.URLError, ssl.SSLError, socket.timeout, OSError) as e:
        return {
            "http_status": None,
            "http_ok": False,
            "server": None,
            "title": None,
            "final_url": None,
            "redirected": False,
            "http_ms": None,
            "scheme": scheme,
            "url": url,
            "http_error": str(getattr(e, "reason", e))[:160],
        }


def check_target(ip, port, hostname=None, connect_timeout=4, read_timeout=6):
    """Run TCP + HTTP + rDNS checks for one target. Never raises."""
    host_for_http = hostname or ip
    tcp_open, tcp_ms = _tcp_check(ip, port, connect_timeout)
    result = {
        "ip": ip,
        "port": port,
        "hostname": hostname,
        "rdns": _reverse_dns(ip),
        "tcp_open": tcp_open,
        "tcp_ms": tcp_ms,
        "scanned_at": _now(),
    }
    if tcp_open:
        result.update(_http_check(host_for_http, port, read_timeout))
    else:
        result.update({"http_status": None, "http_ok": False, "scheme": _scheme(port),
                       "url": _build_url(host_for_http, port, _scheme(port))})
    return result


def scan_targets(targets, workers=16, connect_timeout=4, read_timeout=6):
    """Scan many targets concurrently. ``targets`` is a list of
    ``(ip, port, hostname)`` tuples. Returns a list of result dicts."""
    targets = list(targets)
    if not targets:
        return []

    def _run(t):
        ip, port, hostname = t
        return check_target(ip, port, hostname, connect_timeout, read_timeout)

    with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as pool:
        return list(pool.map(_run, targets))

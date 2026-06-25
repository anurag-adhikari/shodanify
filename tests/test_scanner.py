import http.server
import socket
import threading

from shodanify.scanner import check_target, _build_url, _scheme
from shodanify.scan_store import ScanStore


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"<html><head><title>Hello Co</title></head></html>")

    def log_message(self, *a):
        pass


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_check_target_live_http():
    port = _free_port()
    srv = http.server.HTTPServer(("127.0.0.1", port), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = check_target("127.0.0.1", port, connect_timeout=2, read_timeout=2)
        assert r["tcp_open"] is True
        assert r["http_status"] == 200
        assert r["http_ok"] is True
        assert r["title"] == "Hello Co"
        assert r["scanned_at"].endswith("Z")
    finally:
        srv.shutdown()


def test_check_target_unreachable():
    port = _free_port()  # nothing listening
    r = check_target("127.0.0.1", port, connect_timeout=1, read_timeout=1)
    assert r["tcp_open"] is False
    assert r["http_status"] is None
    assert r["http_ok"] is False


def test_scheme_and_url():
    assert _scheme(443) == "https"
    assert _scheme(8080) == "http"
    assert _build_url("ex.com", 443, "https") == "https://ex.com"
    assert _build_url("ex.com", 8443, "https") == "https://ex.com:8443"
    assert _build_url("ex.com", 80, "http") == "http://ex.com"


def test_scan_store_history(tmp_path):
    store = ScanStore(tmp_path / "scans.json")
    store.record([{"ip": "1.1.1.1", "port": 80, "scanned_at": "2024-01-01T00:00:00Z",
                   "http_status": 200, "http_ok": True, "tcp_open": True, "http_ms": 10}])
    out = store.record([{"ip": "1.1.1.1", "port": 80, "scanned_at": "2024-01-02T00:00:00Z",
                         "http_status": 500, "http_ok": False, "tcp_open": True, "http_ms": 20}])
    entry = out[0]
    assert entry["http_status"] == 500
    assert len(entry["history"]) == 2
    assert entry["history"][0]["http_status"] == 500  # newest first
    assert entry["first_seen"] == "2024-01-01T00:00:00Z"
    # persisted across instances
    assert ScanStore(tmp_path / "scans.json").all()["1.1.1.1:80"]["http_status"] == 500

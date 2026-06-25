"""HTTP routes. The JSON contract is unchanged from the original app."""
from flask import Blueprint, current_app, jsonify, render_template, request

from .scanner import scan_targets

bp = Blueprint("main", __name__)


def _store():
    return current_app.config["DATA_STORE"]


def _scans():
    return current_app.config["SCAN_STORE_OBJ"]


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/api/records")
def api_records():
    return jsonify(_store().summaries())


@bp.route("/api/records/<path:ip_str>/<int:port>")
def api_record_detail(ip_str, port):
    record = _store().get_detail(ip_str, port)
    if record is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(record)


@bp.route("/api/stats")
def api_stats():
    return jsonify(_store().stats())


@bp.route("/api/duplicates")
def api_duplicates():
    return jsonify(_store().duplicates())


@bp.route("/api/scans")
def api_scans():
    """All persisted scan results, keyed by ip:port."""
    return jsonify(_scans().all())


@bp.route("/api/scan", methods=["POST"])
def api_scan():
    """Run live health checks for a batch of targets, concurrently.

    Only targets that exist in the loaded dataset are scanned — this keeps the
    endpoint from being used as an arbitrary scan/SSRF proxy.
    """
    cfg = current_app.config
    payload = request.get_json(silent=True) or {}
    requested = payload.get("targets") or []
    index = _store().index

    targets, skipped = [], 0
    for t in requested:
        try:
            ip, port = t["ip"], int(t["port"])
        except (KeyError, TypeError, ValueError):
            skipped += 1
            continue
        if (ip, port) not in index:
            skipped += 1
            continue
        hostname = t.get("hostname")
        if not hostname:
            rec = index.get((ip, port))
            hostname = rec["hostnames"][0] if rec and rec["hostnames"] else None
        targets.append((ip, port, hostname))

    if len(targets) > cfg["SCAN_MAX_TARGETS"]:
        return jsonify({"error": f"too many targets (max {cfg['SCAN_MAX_TARGETS']})"}), 400

    results = scan_targets(
        targets,
        workers=cfg["SCAN_WORKERS"],
        connect_timeout=cfg["SCAN_CONNECT_TIMEOUT"],
        read_timeout=cfg["SCAN_READ_TIMEOUT"],
    )
    stored = _scans().record(results)
    return jsonify({"results": stored, "scanned": len(stored), "skipped": skipped})


@bp.route("/api/reload", methods=["POST"])
def api_reload():
    store = _store().load()
    return jsonify({
        "status": "ok",
        "count": len(store.records),
        "files_loaded": store.files_loaded,
        "duplicates_removed": store.duplicates_removed,
        "parse_errors": store.parse_errors,
    })

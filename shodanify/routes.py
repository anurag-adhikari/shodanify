"""HTTP routes. The JSON contract is unchanged from the original app."""
from flask import Blueprint, current_app, jsonify, render_template

bp = Blueprint("main", __name__)


def _store():
    return current_app.config["DATA_STORE"]


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

"""Shodanify application factory."""
import gzip
import logging
from pathlib import Path

from flask import Flask, request

from .config import Config
from .routes import bp
from .store import DataStore

_GZIP_MIN_BYTES = 1024


def _gzip_response(response):
    """Compress large JSON payloads when the client accepts gzip.

    The records/stats endpoints return big, highly compressible JSON; gzipping
    them cuts transfer size by ~10x at negligible CPU cost.
    """
    accept = request.headers.get("Accept-Encoding", "")
    if (
        "gzip" not in accept.lower()
        or response.direct_passthrough
        or response.status_code >= 300
        or "Content-Encoding" in response.headers
        or not response.mimetype == "application/json"
        or response.content_length is not None and response.content_length < _GZIP_MIN_BYTES
    ):
        return response
    data = gzip.compress(response.get_data(), compresslevel=6)
    response.set_data(data)
    response.headers["Content-Encoding"] = "gzip"
    response.headers["Content-Length"] = len(data)
    response.headers.setdefault("Vary", "Accept-Encoding")
    return response


def create_app(config=Config):
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    # templates/ and static/ live at the project root, one level above the package.
    root = Path(__file__).resolve().parent.parent
    app = Flask(
        __name__,
        template_folder=str(root / "templates"),
        static_folder=str(root / "static"),
    )
    app.config.from_object(config)
    # Pick up template edits without a restart during local development.
    app.config["TEMPLATES_AUTO_RELOAD"] = True

    store = DataStore(config.DATA_DIR, workers=config.LOAD_WORKERS).load()
    app.config["DATA_STORE"] = store

    app.register_blueprint(bp)
    app.after_request(_gzip_response)
    return app

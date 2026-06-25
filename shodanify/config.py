"""Runtime configuration, sourced from environment variables."""
from pathlib import Path
import os


def _as_bool(value, default=False):
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    DATA_DIR = Path(os.environ.get("DATA_DIR", "data"))
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", "5000"))
    # Debug must be opt-in: it exposes the Werkzeug code-execution console.
    DEBUG = _as_bool(os.environ.get("FLASK_DEBUG"), default=False)
    # Worker threads used to load/parse data files in parallel.
    LOAD_WORKERS = int(os.environ.get("LOAD_WORKERS", "0")) or None

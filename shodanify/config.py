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

    # Active health-check scanner.
    # Dotfile so the data loader (which ignores dotfiles) won't read it back.
    SCAN_STORE = Path(os.environ.get("SCAN_STORE", str(DATA_DIR / ".scan_results.json")))
    SCAN_WORKERS = int(os.environ.get("SCAN_WORKERS", "16"))
    SCAN_CONNECT_TIMEOUT = float(os.environ.get("SCAN_CONNECT_TIMEOUT", "4"))
    SCAN_READ_TIMEOUT = float(os.environ.get("SCAN_READ_TIMEOUT", "6"))
    SCAN_MAX_TARGETS = int(os.environ.get("SCAN_MAX_TARGETS", "300"))

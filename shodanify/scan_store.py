"""Persistent store for scan results, keyed by ``ip:port``.

Each entry holds the latest scan plus a short rolling history so the UI can
show when a target was last checked and how its status has changed. Backed by
a single JSON file; writes are serialised with a lock.
"""
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
import json
import logging

log = logging.getLogger(__name__)

_HISTORY_LIMIT = 10


class ScanStore:
    def __init__(self, path):
        self.path = Path(path)
        self._lock = Lock()
        self._data = self._read()

    def _read(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def _write(self):
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh)
            tmp.replace(self.path)
        except OSError as exc:
            log.warning("Could not persist scan results: %s", exc)

    def all(self):
        return self._data

    def record(self, results):
        """Persist a batch of scan results and return them with history."""
        out = []
        with self._lock:
            for r in results:
                key = f"{r['ip']}:{r['port']}"
                prev = self._data.get(key, {})
                history = prev.get("history", [])
                history = ([{
                    "scanned_at": r["scanned_at"],
                    "http_status": r.get("http_status"),
                    "http_ok": r.get("http_ok"),
                    "tcp_open": r.get("tcp_open"),
                    "http_ms": r.get("http_ms"),
                }] + history)[:_HISTORY_LIMIT]
                entry = {**r, "history": history,
                         "first_seen": prev.get("first_seen", r["scanned_at"])}
                self._data[key] = entry
                out.append(entry)
            self._write()
        return out

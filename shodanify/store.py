"""In-memory data store: loads, dedups, indexes and caches Shodan records.

A single :class:`DataStore` instance owns all derived state. Everything is
computed once at load time and cached, so the API routes are just lookups.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import gzip
import json
import logging

from .parsing import parse_record, record_summary
from .stats import compute_stats

log = logging.getLogger(__name__)


def _open(path):
    """Return a text-mode file handle, transparently gunzipping ``.gz``."""
    if path.suffix == ".gz":
        return gzip.open(path, mode="rt", encoding="utf-8")
    return open(path, mode="rt", encoding="utf-8")


def _iter_data_files(data_dir):
    """Yield every supported data file exactly once.

    Matches ``*.gz`` (any gzipped export, not only ``*.json.gz``) and plain
    ``*.json``. The previous implementation only matched ``*.json.gz`` and so
    silently ignored files named e.g. ``Shodan1.gz``.
    """
    seen = set()
    for pattern in ("*.json.gz", "*.gz", "*.json"):
        for path in data_dir.glob(pattern):
            if path.is_file() and path not in seen:
                seen.add(path)
                yield path


def _load_file(path):
    """Parse one file. Returns ``(records, parse_errors)``; never raises."""
    records, errors = [], 0
    try:
        with _open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(parse_record(json.loads(line)))
                except Exception:
                    errors += 1
    except OSError as exc:
        log.warning("Could not read %s: %s", path.name, exc)
    return records, errors


class DataStore:
    def __init__(self, data_dir, workers=None):
        self.data_dir = Path(data_dir)
        self.workers = workers
        self.records = []
        self.index = {}            # (ip_str, port) -> record
        self.duplicates_removed = 0
        self.parse_errors = 0
        self.files_loaded = 0
        self._summaries = None     # cached GET /api/records payload
        self._stats = None         # cached GET /api/stats payload

    def load(self):
        files = sorted(_iter_data_files(self.data_dir)) if self.data_dir.exists() else []
        raw = []
        self.parse_errors = 0
        if files:
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                for records, errors in pool.map(_load_file, files):
                    raw.extend(records)
                    self.parse_errors += errors
        self.files_loaded = len(files)

        # Deduplicate by (ip_str, port), keeping the newest timestamp.
        index = {}
        for r in raw:
            key = (r["ip_str"], r["port"])
            existing = index.get(key)
            if existing is None or (r["timestamp"] or "") > (existing["timestamp"] or ""):
                index[key] = r

        self.index = index
        self.records = list(index.values())
        self.duplicates_removed = len(raw) - len(self.records)
        self._summaries = None
        self._stats = None
        log.info("Loaded %d records from %d file(s) — %d dupes, %d parse errors",
                 len(self.records), self.files_loaded, self.duplicates_removed,
                 self.parse_errors)
        return self

    def get_detail(self, ip_str, port):
        """O(1) host lookup (was a full scan of every record)."""
        return self.index.get((ip_str, port))

    def summaries(self):
        if self._summaries is None:
            self._summaries = [record_summary(r) for r in self.records]
        return self._summaries

    def stats(self):
        if self._stats is None:
            self._stats = compute_stats(self.records, self.duplicates_removed)
        return self._stats

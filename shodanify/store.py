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
            # Skip dotfiles (e.g. the scanner's .scan_results.json) and re-matches.
            if path.is_file() and not path.name.startswith(".") and path not in seen:
                seen.add(path)
                yield path


def _load_file(path):
    """Parse one file. Returns ``(records, parse_errors)``; never raises.

    Each record is tagged with ``_source`` (the originating filename) so the
    duplicates view can show where each copy came from.
    """
    records, errors = [], 0
    try:
        with _open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = parse_record(json.loads(line))
                    rec["_source"] = path.name
                    records.append(rec)
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
        self.duplicate_groups = {}
        self.duplicates_removed = 0
        self.parse_errors = 0
        self.files_loaded = 0
        self._summaries = None     # cached GET /api/records payload
        self._stats = None         # cached GET /api/stats payload
        self._duplicates = None    # cached GET /api/duplicates payload

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

        # Group every occurrence by (ip_str, port) so we can both deduplicate
        # (keep the newest) and retain the full set for the duplicates view.
        groups = {}
        for r in raw:
            groups.setdefault((r["ip_str"], r["port"]), []).append(r)

        index = {}
        for key, occ in groups.items():
            index[key] = max(occ, key=lambda r: r["timestamp"] or "")

        self.index = index
        self.records = list(index.values())
        self.duplicate_groups = {k: v for k, v in groups.items() if len(v) > 1}
        self.duplicates_removed = len(raw) - len(self.records)
        self._summaries = None
        self._stats = None
        self._duplicates = None
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

    def duplicates(self):
        """Groups where the same IP:port appeared in more than one record.

        The newest occurrence is flagged ``kept`` (it is the one served
        everywhere else); the rest were dropped during deduplication.
        """
        if self._duplicates is None:
            groups = []
            for (ip_str, port), occ in self.duplicate_groups.items():
                kept = max(occ, key=lambda r: r["timestamp"] or "")
                occurrences = sorted(
                    occ, key=lambda r: r["timestamp"] or "", reverse=True
                )
                groups.append({
                    "ip_str": ip_str,
                    "port": port,
                    "count": len(occ),
                    "occurrences": [{
                        "source": r.get("_source"),
                        "timestamp": r["timestamp"],
                        "kept": r is kept,
                        "org": r["org"] or r["isp"],
                        "country_code": r["location"]["country_code"],
                        "vulns_count": len(r["vulns"]),
                        "max_cvss": max((v["cvss"] for v in r["vulns"]), default=0),
                        "http_status": r["http"]["status"] if r["http"] else None,
                        "title": r["http"]["title"] if r["http"] else None,
                        "has_ssl": r["ssl"] is not None,
                    } for r in occurrences],
                })
            groups.sort(key=lambda g: g["count"], reverse=True)
            self._duplicates = {
                "groups": groups,
                "group_count": len(groups),
                "duplicates_removed": self.duplicates_removed,
            }
        return self._duplicates

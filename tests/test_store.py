import gzip
import json

from shodanify.store import DataStore


def _write(path, records, gz=False):
    payload = "\n".join(json.dumps(r) for r in records)
    if gz:
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            fh.write(payload)
    else:
        path.write_text(payload, encoding="utf-8")


def _rec(ip, port, ts):
    return {"ip_str": ip, "port": port, "timestamp": ts, "location": {}}


def test_loads_bare_gz_files(tmp_path):
    # Regression: ``*.gz`` (not just ``*.json.gz``) must be picked up.
    _write(tmp_path / "Shodan1.gz", [_rec("1.1.1.1", 80, "2024-01-01")], gz=True)
    _write(tmp_path / "Shodan2.json.gz", [_rec("2.2.2.2", 443, "2024-01-01")], gz=True)
    _write(tmp_path / "plain.json", [_rec("3.3.3.3", 22, "2024-01-01")])

    store = DataStore(tmp_path).load()
    assert store.files_loaded == 3
    assert {r["ip_str"] for r in store.records} == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}


def test_dedup_keeps_newest(tmp_path):
    _write(tmp_path / "a.json", [_rec("1.1.1.1", 80, "2024-01-01")])
    _write(tmp_path / "b.json", [_rec("1.1.1.1", 80, "2024-06-01")])
    store = DataStore(tmp_path).load()
    assert len(store.records) == 1
    assert store.duplicates_removed == 1
    assert store.get_detail("1.1.1.1", 80)["timestamp"] == "2024-06-01"


def test_parse_errors_counted(tmp_path):
    (tmp_path / "bad.json").write_text('{"ip_str":"1.1.1.1","port":80}\nNOT JSON\n')
    store = DataStore(tmp_path).load()
    assert store.parse_errors == 1
    assert len(store.records) == 1


def test_duplicates_payload(tmp_path):
    _write(tmp_path / "old.json", [_rec("1.1.1.1", 80, "2024-01-01")])
    _write(tmp_path / "new.json", [_rec("1.1.1.1", 80, "2024-06-01")])
    _write(tmp_path / "uniq.json", [_rec("2.2.2.2", 80, "2024-01-01")])
    dup = DataStore(tmp_path).load().duplicates()
    assert dup["group_count"] == 1
    assert dup["duplicates_removed"] == 1
    group = dup["groups"][0]
    assert group["ip_str"] == "1.1.1.1" and group["count"] == 2
    kept = [o for o in group["occurrences"] if o["kept"]]
    assert len(kept) == 1 and kept[0]["timestamp"] == "2024-06-01"
    assert {o["source"] for o in group["occurrences"]} == {"old.json", "new.json"}


def test_ignores_dotfiles(tmp_path):
    # The scanner persists .scan_results.json into the data dir; the loader
    # must not read dotfiles back in as records.
    _write(tmp_path / "real.json", [_rec("1.1.1.1", 80, "2024")])
    (tmp_path / ".scan_results.json").write_text('{"1.1.1.1:80": {"http_status": 200}}')
    store = DataStore(tmp_path).load()
    assert store.files_loaded == 1
    assert len(store.records) == 1


def test_no_double_count(tmp_path):
    # A *.json.gz file matches two glob patterns but must load once.
    _write(tmp_path / "x.json.gz", [_rec("9.9.9.9", 1, "2024")], gz=True)
    store = DataStore(tmp_path).load()
    assert store.files_loaded == 1

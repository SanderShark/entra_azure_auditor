import json
import os
import stat

from entra_auditor.toolkit import audit_log


def test_secrets_are_scrubbed_from_the_log(tmp_path):
    path = tmp_path / "log.jsonl"
    audit_log.record({"action": "x", "requests": [{"json": {"newPassword": "SECRET", "ok": 1}}], "token": "t"}, path=path)
    text = path.read_text()
    assert "SECRET" not in text
    entry = json.loads(text)
    assert entry["token"] == "***"
    assert entry["requests"][0]["json"] == {"newPassword": "***", "ok": 1}


def test_log_file_is_owner_only(tmp_path):
    path = tmp_path / "log.jsonl"
    audit_log.record({"action": "x"}, path=path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_entries_append_and_read_back_newest_last(tmp_path):
    path = tmp_path / "log.jsonl"
    for name in ("a", "b", "c"):
        audit_log.record({"action": name}, path=path)
    assert [e["action"] for e in audit_log.read_recent(2, path)] == ["b", "c"]
    assert "ts" in audit_log.read_recent(1, path)[0]


def test_reading_a_missing_log_is_empty(tmp_path):
    assert audit_log.read_recent(5, tmp_path / "nope.jsonl") == []


def test_corrupt_lines_are_skipped(tmp_path):
    path = tmp_path / "log.jsonl"
    path.write_text('{"action": "ok"}\nnot json\n')
    assert [e["action"] for e in audit_log.read_recent(5, path)] == ["ok"]


def test_default_path_honours_the_environment(isolated_env):
    assert audit_log.default_log_path() == isolated_env.log

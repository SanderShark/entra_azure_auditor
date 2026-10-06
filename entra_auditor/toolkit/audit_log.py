"""Local, append-only record of every change the toolkit makes (who, what, to whom, result).

JSON Lines in ``~/.entra_auditor/actions.jsonl`` (override: ``AUDITOR_ACTION_LOG``), created
owner-only. Secrets are never written: passwords are redacted before the plan reaches here,
and ``_scrub`` is a second line of defence for known secret-looking keys.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SECRET_KEYS = {"newpassword", "password", "secret", "client_secret", "token", "access_token",
                "refresh_token"}


def default_log_path() -> Path:
    override = os.environ.get("AUDITOR_ACTION_LOG")
    return Path(override).expanduser() if override else Path.home() / ".entra_auditor" / "actions.jsonl"


def _scrub(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: "***" if str(k).lower() in _SECRET_KEYS else _scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


def record(entry: dict[str, Any], path: Path | None = None) -> Path:
    path = Path(path) if path else default_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps({"ts": datetime.now(timezone.utc).isoformat(), **_scrub(entry)},
                      ensure_ascii=False, default=str)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    return path


def read_recent(n: int = 20, path: Path | None = None) -> list[dict[str, Any]]:
    path = Path(path) if path else default_log_path()
    if not path.exists():
        return []
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines()[-n:]:
        try:
            entries.append(json.loads(line))
        except ValueError:
            continue
    return entries

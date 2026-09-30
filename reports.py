"""Reports and local run storage.

Writers
    write_json(run, path)             complete run: summary, inventory, findings, CA policies
    write_findings_csv(run, path)     one row per finding (spreadsheet-friendly)
    write_policies_csv(run, path)     one row per Conditional Access policy, in plain language
    write_reports(run, dir, formats)  the above with consistent file names

Run store (JSON files in ``~/.entra_auditor/runs`` or ``$AUDITOR_RUNS_DIR``)
    save_run / list_runs / resolve_run / load_run
    This is what the CLI browses. The PostgreSQL layer will replace it later.

Security notes
    * Reports describe your tenant's weaknesses, so files are created owner-only (0600)
      and written atomically.
    * CSV cells that start with = + - @ are prefixed with an apostrophe so a finding
      title or a display name can't execute as a spreadsheet formula (CSV injection).
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable

from pydantic import BaseModel

from .engine import AuditRun

SCHEMA_VERSION = 1
SUPPORTED_FORMATS = ("json", "csv")

FINDING_COLUMNS = [
    "severity", "check_id", "resource_type", "resource_name", "resource_id",
    "title", "remediation", "evidence", "fingerprint",
]
POLICY_COLUMNS = [
    "policy_id", "name", "state", "action", "summary", "applies_to", "excluded",
    "applications", "conditions", "requirements", "session_controls", "tags", "concerns",
]


# --------------------------------------------------------------------------- #
# Low-level helpers
# --------------------------------------------------------------------------- #

def _write_private(path: Path, text: str) -> None:
    """Atomic write, owner-only permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    os.replace(tmp, path)


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: object) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def _to_csv(columns: list[str], rows: Iterable[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([_csv_safe(row.get(c)) for c in columns])
    return buffer.getvalue()


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-") or "tenant"


def base_name(run: AuditRun) -> str:
    """e.g. ``entra-audit-<tenant>-20260929T101500Z``"""
    return f"entra-audit-{_slug(run.tenant_id)}-{run.started_at:%Y%m%dT%H%M%SZ}"


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #

def run_to_dict(run: AuditRun) -> dict:
    data = run.model_dump(mode="json")
    return {
        "schema_version": SCHEMA_VERSION,
        "summary": run.summary().model_dump(mode="json"),
        **data,
    }


def render_json(run: AuditRun) -> str:
    return json.dumps(run_to_dict(run), indent=2, ensure_ascii=False) + "\n"


def write_json(run: AuditRun, path: Path) -> Path:
    _write_private(Path(path), render_json(run))
    return Path(path)


# --------------------------------------------------------------------------- #
# CSV
# --------------------------------------------------------------------------- #

def findings_rows(run: AuditRun) -> list[dict]:
    return [
        {
            "severity": f.severity,
            "check_id": f.check_id,
            "resource_type": f.resource_type,
            "resource_name": f.resource_name or "",
            "resource_id": f.resource_id,
            "title": f.title,
            "remediation": f.remediation,
            "evidence": json.dumps(f.evidence, ensure_ascii=False, default=str, separators=(",", ":")),
            "fingerprint": f.fingerprint,
        }
        for f in run.findings
    ]


def policies_rows(run: AuditRun) -> list[dict]:
    rows = []
    for p in run.policies:
        ex = p.exclusions
        excluded = []
        if ex.users:
            excluded.append("users: " + ", ".join(u.label for u in ex.users))
        if ex.groups:
            excluded.append("groups: " + ", ".join(g.label for g in ex.groups))
        if ex.roles:
            excluded.append("roles: " + ", ".join(r.label for r in ex.roles))
        if ex.guests_or_external:
            excluded.append("guests/external users")
        if ex.applications:
            excluded.append("apps: " + ", ".join(a.label for a in ex.applications))
        rows.append({
            "policy_id": p.policy_id,
            "name": p.name,
            "state": p.state,
            "action": p.action,
            "summary": p.summary,
            "applies_to": "; ".join(p.users),
            "excluded": " | ".join(excluded),
            "applications": "; ".join(p.applications),
            "conditions": "; ".join(p.conditions),
            "requirements": (f" {p.requirement_logic.upper()} ".join(p.requirements)
                             if p.requirement_logic else "; ".join(p.requirements)),
            "session_controls": "; ".join(p.session_controls),
            "tags": ", ".join(t.value for t in p.tags),
            "concerns": " | ".join(f"[{c.severity}] {c.text}" for c in p.concerns),
        })
    return rows


def render_findings_csv(run: AuditRun) -> str:
    return _to_csv(FINDING_COLUMNS, findings_rows(run))


def render_policies_csv(run: AuditRun) -> str:
    return _to_csv(POLICY_COLUMNS, policies_rows(run))


def write_findings_csv(run: AuditRun, path: Path) -> Path:
    _write_private(Path(path), render_findings_csv(run))
    return Path(path)


def write_policies_csv(run: AuditRun, path: Path) -> Path:
    _write_private(Path(path), render_policies_csv(run))
    return Path(path)


# --------------------------------------------------------------------------- #
# All formats at once
# --------------------------------------------------------------------------- #

def write_reports(
    run: AuditRun, directory: Path, formats: Iterable[str] = SUPPORTED_FORMATS
) -> list[Path]:
    """Write the requested formats into ``directory``; returns the paths written.

    ``csv`` produces a findings file, plus a policies file when the run has CA policies.
    """
    formats = [f.strip().lower() for f in formats]
    bad = [f for f in formats if f not in SUPPORTED_FORMATS]
    if bad:
        raise ValueError(f"Unsupported format(s): {', '.join(bad)}. Use: {', '.join(SUPPORTED_FORMATS)}")

    directory, stem = Path(directory), base_name(run)
    written: list[Path] = []
    if "json" in formats:
        written.append(write_json(run, directory / f"{stem}.json"))
    if "csv" in formats:
        written.append(write_findings_csv(run, directory / f"{stem}-findings.csv"))
        if run.policies:
            written.append(write_policies_csv(run, directory / f"{stem}-policies.csv"))
    return written


# --------------------------------------------------------------------------- #
# Local run store
# --------------------------------------------------------------------------- #

def default_runs_dir() -> Path:
    override = os.environ.get("AUDITOR_RUNS_DIR")
    return Path(override) if override else Path.home() / ".entra_auditor" / "runs"


class RunInfo(BaseModel):
    """Cheap listing entry (read from the JSON header without full validation)."""
    path: Path
    id: str
    tenant_id: str
    started_at: datetime
    status: str
    total_findings: int
    highest_severity: str | None = None


def save_run(run: AuditRun, directory: Path | None = None) -> Path:
    directory = directory or default_runs_dir()
    path = directory / f"{run.started_at:%Y%m%dT%H%M%SZ}-{run.id[:8]}.json"
    return write_json(run, path)


def list_runs(directory: Path | None = None) -> list[RunInfo]:
    """Saved runs, newest first. Unreadable files are skipped."""
    directory = directory or default_runs_dir()
    infos: list[RunInfo] = []
    for path in sorted(directory.glob("*.json"), reverse=True) if directory.exists() else []:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            summary = data.get("summary", {})
            infos.append(RunInfo(
                path=path, id=data["id"], tenant_id=data["tenant_id"],
                started_at=data["started_at"], status=data["status"],
                total_findings=summary.get("total", len(data.get("findings", []))),
                highest_severity=summary.get("highest_severity"),
            ))
        except (OSError, ValueError, KeyError):
            continue
    return sorted(infos, key=lambda i: i.started_at, reverse=True)


def load_run(path: Path) -> AuditRun:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema_version", 1) > SCHEMA_VERSION:
        raise ValueError(f"{path} was written by a newer version of this tool")
    data.pop("schema_version", None)
    data.pop("summary", None)  # derived, not stored on the model
    return AuditRun.model_validate(data)


def resolve_run(ref: str | None, directory: Path | None = None) -> Path:
    """Turn ``latest`` / ``previous`` / a run-id prefix / a file path into a run file.

    ``None`` means latest.
    """
    ref = ref or "latest"
    candidate = Path(ref)
    if candidate.suffix == ".json" and candidate.exists():
        return candidate

    runs = list_runs(directory)
    if not runs:
        raise FileNotFoundError("No saved runs found. Run `auditor run` first.")
    if ref == "latest":
        return runs[0].path
    if ref == "previous":
        if len(runs) < 2:
            raise FileNotFoundError("Only one saved run; there is no previous run.")
        return runs[1].path
    matches = [r for r in runs if r.id.startswith(ref)]
    if len(matches) == 1:
        return matches[0].path
    raise FileNotFoundError(
        f"No run matches '{ref}'." if not matches else f"'{ref}' is ambiguous ({len(matches)} runs match)."
    )
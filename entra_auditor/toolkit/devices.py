"""Device recovery secrets: BitLocker recovery keys and Windows LAPS local-administrator passwords.

Both are secrets with the same rule as passwords: shown to the operator once, never logged or saved. The
local action log records THAT a secret was read (who, which device, which key), never the secret; Entra's
own audit log records it too (reading a BitLocker key with ``$select=key`` creates a KeyManagement entry).

Endpoints (Microsoft Graph v1.0):
    GET /informationProtection/bitlocker/recoveryKeys?$filter=deviceId eq '{deviceId}'     (no key returned)
    GET /informationProtection/bitlocker/recoveryKeys/{keyId}?$select=key                  (the key; audited)
        delegated BitlockerKey.Read.All; Cloud Device Administrator, Helpdesk Administrator, Intune
        Administrator, Security Administrator/Reader, Global Reader, or the device's registered owner
    GET /directory/deviceLocalCredentials/{deviceId}?$select=credentials
        delegated DeviceLocalCredential.Read.All; Cloud Device Administrator or Intune Administrator
``deviceId`` is the device's hardware/registration id (DeviceSummary.device_id), NOT its object id.

Neither permission is in the default toolkit scopes (requesting an unconsented scope breaks sign-in for
everything): an admin consents them on the app registration; a refusal here explains what is missing.

NOT VERIFIED AGAINST A LIVE TENANT (built from the Graph docs and tested against a fake). The list-by-device
filter was not re-checked in the docs this session. See CLAUDE.md.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel

from ..graph.client import GraphError, GraphNotFoundError, GraphPermissionError
from . import audit_log
from .models import DeviceSummary
from .odata import literal, segment

BITLOCKER_PATH = "/informationProtection/bitlocker/recoveryKeys"
LAPS_PATH = "/directory/deviceLocalCredentials"
VOLUMES = {"1": "operating system drive", "2": "fixed data drive", "3": "removable drive",
           "operatingsystemvolume": "operating system drive", "fixeddatavolume": "fixed data drive",
           "removabledatavolume": "removable drive"}
BITLOCKER_HINT = ("Needs the delegated permission BitlockerKey.Read.All on the app registration (admin consent) and "
                  "a role such as Cloud Device Administrator or Helpdesk Administrator.")
LAPS_HINT = ("Needs the delegated permission DeviceLocalCredential.Read.All on the app registration (admin consent) "
             "and the Cloud Device Administrator or Intune Administrator role.")


class DeviceSecretError(Exception):
    """A recovery secret couldn't be read; ``hint`` says what to check."""

    def __init__(self, message: str, hint: str = ""):
        super().__init__(message)
        self.hint = hint


class RecoveryKey(BaseModel):
    """A BitLocker key's identity. The key itself is never held here."""
    id: str
    created: Optional[datetime] = None
    volume: str = "unknown drive"

    @property
    def label(self) -> str:
        when = f"{self.created:%Y-%m-%d}" if self.created else "unknown date"
        return f"{self.volume}, backed up {when} (key id {self.id})"


class LapsCredential(BaseModel):
    account: str
    password: str
    backed_up: Optional[datetime] = None


def _unwrap(body: dict[str, Any]) -> dict[str, Any]:
    """Graph documents these two responses wrapped in a "value" object; accept both shapes."""
    inner = body.get("value")
    return inner if isinstance(inner, dict) else body


def _hardware_id(device: DeviceSummary) -> str:
    if not device.device_id:
        raise DeviceSecretError(f"{device.label} has no device id, so its recovery secrets can't be looked up.")
    return device.device_id


def _record(action: str, device: DeviceSummary, actor: str, status: str, log_path: Any, **extra: Any) -> None:
    try:
        audit_log.record({"actor": actor, "action": action, "title": action.replace("device.", "").replace("_", " "),
                          "target": {"type": "device", "id": device.id, "name": device.label},
                          "status": status, **extra}, path=log_path)
    except OSError:
        pass        # a logging problem must not hide a recovery key from someone locked out


def list_bitlocker_keys(graph: Any, device: DeviceSummary) -> list[RecoveryKey]:
    """The recovery keys backed up for a device (identities only), newest first."""
    try:
        items = graph.get_all(BITLOCKER_PATH, filter=f"deviceId eq {literal(_hardware_id(device))}")
    except GraphPermissionError as exc:
        raise DeviceSecretError("You aren't allowed to list BitLocker keys.", BITLOCKER_HINT) from exc
    keys = [RecoveryKey(id=str(i["id"]), created=i.get("createdDateTime"),
                        volume=VOLUMES.get(str(i.get("volumeType", "")).lower(), "unknown drive")) for i in items]
    return sorted(keys, key=lambda k: (k.created is None, -(k.created.timestamp() if k.created else 0)))


def reveal_bitlocker_key(graph: Any, device: DeviceSummary, key: RecoveryKey, *, actor: str = "",
                         log_path: Any = None) -> str:
    """The recovery key itself. Entra audits this read; so does the local action log (without the key)."""
    try:
        value = str(_unwrap(graph.get(f"{BITLOCKER_PATH}/{segment(key.id)}", select=["key"])).get("key") or "")
    except GraphError as exc:
        _record("device.reveal_bitlocker_key", device, actor, "denied" if isinstance(exc, GraphPermissionError)
                else "failed", log_path, key_id=key.id)
        if isinstance(exc, GraphPermissionError):
            raise DeviceSecretError("You aren't allowed to read this BitLocker key.", BITLOCKER_HINT) from exc
        raise DeviceSecretError(f"The BitLocker key couldn't be read: {exc}") from exc
    _record("device.reveal_bitlocker_key", device, actor, "ok" if value else "failed", log_path, key_id=key.id)
    if not value:
        raise DeviceSecretError("Graph answered without the key.", BITLOCKER_HINT)
    return value


def _decode(encoded: str) -> str:
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DeviceSecretError("The LAPS password came back in a form that couldn't be decoded.") from exc
    # Documented examples are UTF-16LE (every second byte zero); be tolerant of UTF-8 as well.
    wide = len(raw) >= 2 and len(raw) % 2 == 0 and all(b == 0 for b in raw[1::2])
    return raw.decode("utf-16-le" if wide else "utf-8", errors="replace")


def reveal_laps(graph: Any, device: DeviceSummary, *, actor: str = "", log_path: Any = None) -> list[LapsCredential]:
    """The local administrator passwords backed up to Entra for a device, newest first."""
    action = "device.reveal_laps_password"
    try:
        body = _unwrap(graph.get(f"{LAPS_PATH}/{segment(_hardware_id(device))}", select=["credentials"]))
    except GraphNotFoundError as exc:
        _record(action, device, actor, "failed", log_path)
        raise DeviceSecretError(f"No local administrator password is backed up to Entra for {device.label}.",
                                "Windows LAPS must be configured to back up to Microsoft Entra ID.") from exc
    except GraphPermissionError as exc:
        _record(action, device, actor, "denied", log_path)
        raise DeviceSecretError("You aren't allowed to read this device's local administrator password.",
                                LAPS_HINT) from exc
    except GraphError as exc:
        _record(action, device, actor, "failed", log_path)
        raise DeviceSecretError(f"The local administrator password couldn't be read: {exc}") from exc
    found = [LapsCredential(account=str(c.get("accountName") or "?"), password=_decode(str(c.get("passwordBase64") or "")),
                            backed_up=c.get("backupDateTime")) for c in body.get("credentials") or []]
    _record(action, device, actor, "ok" if found else "failed", log_path)
    if not found:
        raise DeviceSecretError("Graph answered without any credentials.", LAPS_HINT)
    return sorted(found, key=lambda c: (c.backed_up is None, -(c.backed_up.timestamp() if c.backed_up else 0)))

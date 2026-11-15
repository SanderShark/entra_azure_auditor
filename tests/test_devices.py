"""Device recovery secrets: BitLocker keys and LAPS passwords are read on demand and never logged."""

from __future__ import annotations

import base64

import pytest

from entra_auditor.toolkit.devices import DeviceSecretError, list_bitlocker_keys, reveal_bitlocker_key, reveal_laps
from entra_auditor.toolkit.directory import load_devices
from tests.fakes import FakeTenant

KEY = "123456-231453-873456-213546-654678-765689-123456-324565"


def b64(text, encoding="utf-16-le"):
    return base64.b64encode(text.encode(encoding)).decode()


def tenant():
    t = FakeTenant()
    t.bitlocker = {
        "k-old": {"deviceId": "hw-1111", "volumeType": "2", "createdDateTime": "2024-01-05T00:00:00Z", "key": "000000-old"},
        "k-new": {"deviceId": "hw-1111", "volumeType": "1", "createdDateTime": "2026-03-01T00:00:00Z", "key": KEY},
        "k-other": {"deviceId": "hw-2222", "volumeType": "1", "createdDateTime": "2026-01-01T00:00:00Z", "key": "999"},
    }
    t.laps = {"hw-1111": [
        {"accountName": "Administrator", "backupDateTime": "2025-01-01T00:00:00Z", "passwordBase64": b64("Old-Pw-1")},
        {"accountName": "LocalAdmin", "backupDateTime": "2026-06-01T00:00:00Z", "passwordBase64": b64("N3w*Pw(2)")}]}
    return t


def device(t, name="SEA-LT-001"):
    return next(d for d in load_devices(t) if d.label == name)


def test_keys_are_listed_for_the_device_by_its_hardware_id_without_the_key():
    t = tenant()
    keys = list_bitlocker_keys(t, device(t))
    assert [k.id for k in keys] == ["k-new", "k-old"]                    # newest first, not the other device's
    assert keys[0].label == "operating system drive, backed up 2026-03-01 (key id k-new)"
    assert keys[1].volume == "fixed data drive" and "hw-1111" in t.filters[-1] and "dev-1" not in t.filters[-1]
    assert KEY not in repr(keys)
    assert list_bitlocker_keys(t, device(t, "OLD-PC")) == []


def test_revealing_a_key_asks_for_it_explicitly_and_logs_the_read_but_not_the_key(tmp_path):
    t = tenant()
    dev = device(t)
    key = list_bitlocker_keys(t, dev)[0]
    log = tmp_path / "log"
    assert reveal_bitlocker_key(t, dev, key, actor="user:me@contoso.com", log_path=log) == KEY
    text = log.read_text()
    assert "device.reveal_bitlocker_key" in text and "k-new" in text and "SEA-LT-001" in text and "me@contoso.com" in text
    assert KEY not in text and "123456" not in text


def test_laps_passwords_are_decoded_newest_first_and_never_logged(tmp_path):
    t = tenant()
    log = tmp_path / "log"
    found = reveal_laps(t, device(t), actor="user:me@contoso.com", log_path=log)
    assert [(c.account, c.password) for c in found] == [("LocalAdmin", "N3w*Pw(2)"), ("Administrator", "Old-Pw-1")]
    text = log.read_text()
    assert "device.reveal_laps_password" in text and "N3w" not in text and "Old-Pw" not in text and "passwordBase64" not in text
    t.laps["hw-1111"] = [{"accountName": "A", "passwordBase64": b64("Utf8-Pässword", "utf-8")}]     # tolerated too
    assert reveal_laps(t, device(t), log_path=log)[0].password == "Utf8-Pässword"


def test_refusals_and_missing_secrets_say_what_to_check(tmp_path):
    t = tenant()
    log = tmp_path / "log"
    with pytest.raises(DeviceSecretError, match="No local administrator password is backed up") as info:
        reveal_laps(t, device(t, "Pixel 8"), log_path=log)
    assert "back up to Microsoft Entra ID" in info.value.hint
    dev = device(t)
    key = list_bitlocker_keys(t, dev)[0]
    t.secrets_denied = True
    with pytest.raises(DeviceSecretError) as info:
        list_bitlocker_keys(t, dev)
    assert "BitlockerKey.Read.All" in info.value.hint
    with pytest.raises(DeviceSecretError) as info:
        reveal_bitlocker_key(t, dev, key, log_path=log)
    assert "Cloud Device Administrator" in info.value.hint
    with pytest.raises(DeviceSecretError) as info:
        reveal_laps(t, dev, log_path=log)
    assert "DeviceLocalCredential.Read.All" in info.value.hint
    assert log.read_text().count('"status": "denied"') == 2           # refused reads are on record too
    t.secrets_denied = False
    t.laps["hw-1111"] = [{"accountName": "A", "passwordBase64": "not base64!"}]
    with pytest.raises(DeviceSecretError, match="couldn't be decoded"):
        reveal_laps(t, dev, log_path=log)


def test_a_device_without_a_hardware_id_cannot_be_looked_up():
    t = tenant()
    dev = device(t).model_copy(update={"device_id": None})
    with pytest.raises(DeviceSecretError, match="no device id"):
        list_bitlocker_keys(t, dev)

"""The interactive menus, driven with scripted keystrokes (`pick`) and scripted y/n + text (`say`)."""

import pytest

import entra_auditor.cli as maincli
import entra_auditor.toolkit.cli as tcli
from entra_auditor import reports
from tests.builders import finding, make_run
from tests.fakes import FakeTenant


def with_role(tenant, name):
    tenant.active_roles["r"] = name
    return tenant


def drive(tk, tenant, picks, says=(), **kw):
    session = tk.use(tenant, interactive=True, **kw)
    tk.prompts.pick(*picks)
    tk.prompts.say(*says)
    code, out = tk.run(tcli.toolkit_menu_loop, session)
    return code, out


def test_find_an_identity_add_it_to_a_group_and_elevate_when_asked(tk):
    tenant = FakeTenant()
    code, out = drive(tk, tenant, ["Find an identity", "alice@contoso.com", "Add to a group", "Finance", "<- Back", "Back"],
                      says=[True, 1, True, "INC-9"])          # apply? / which role / activate? / justification
    assert code == 0 and "u-alice" in tenant.members["g-fin"]
    assert tk.prompts.exhausted                              # no unexpected prompts, none left unanswered


def test_edit_attributes(tk):
    tenant = with_role(FakeTenant(), "User Administrator")
    code, _ = drive(tk, tenant, ["Find an identity", "alice@contoso.com", "Edit attributes", "jobTitle", "Principal Engineer",
                                 "Apply 1 change(s)", "<- Back", "Back"], says=[True])
    assert code == 0 and tenant.users["u-alice"]["jobTitle"] == "Principal Engineer" and tk.prompts.exhausted


def test_certificate_ids_show_the_prefix_so_only_the_data_is_typed(tk):
    tenant = with_role(FakeTenant(eligible=("Privileged Authentication Administrator",)), "Privileged Authentication Administrator")
    code, _ = drive(tk, tenant, ["Find an identity", "alice@contoso.com", "Certificate user IDs", "Add", "Subject Key Identifier",
                                 "ab:cd:ef", "<- Back", "<- Back", "Back"], says=[True])
    assert code == 0 and tenant.certs["u-alice"][-1] == "X509:<SKI>abcdef"
    assert any("X509:<SKI>" in message for kind, message in tk.prompts.asked_menu if kind == "text")


def test_password_reset_shows_the_generated_password(tk):
    tenant = with_role(FakeTenant(), "Helpdesk Administrator")
    code, out = drive(tk, tenant, ["Find an identity", "alice@contoso.com", "Reset password", "Let Entra generate", "<- Back", "Back"], says=[True])
    assert code == 0 and "Gen3rated!Pw42" in out


def test_disable_remove_from_group_and_revoke(tk):
    tenant = with_role(FakeTenant(), "User Administrator")
    tenant.active_roles["r2"] = "Groups Administrator"
    code, out = drive(tk, tenant, ["Find an identity", "alice@contoso.com", "Disable account", "Remove from a group", "Project X",
                                   "Revoke sign-in sessions", "<- Back", "Back"], says=[True, True, True])
    assert code == 0 and tenant.users["u-alice"]["accountEnabled"] is False and "u-alice" not in tenant.members["g-m365"]
    assert tk.prompts.exhausted


def test_an_ambiguous_search_lets_you_choose(tk):
    code, out = drive(tk, FakeTenant(), ["Find an identity", "Bob", "bob.smith@contoso.com", "View full profile", "<- Back", "Back"])
    assert code == 0 and "bob.smith@contoso.com" in out and tk.prompts.exhausted


def test_nothing_found_is_handled(tk):
    code, out = drive(tk, FakeTenant(), ["Find an identity", "nobody-here-xyz", "Back"])
    assert code == 0 and "Nothing matched" in out


def test_ctrl_c_leaves_the_menu_cleanly(tk):
    assert drive(tk, FakeTenant(), [None])[0] == 0


def test_a_change_graph_cannot_make_is_explained_and_the_menu_carries_on(tk):
    code, out = drive(tk, FakeTenant(), ["Find a group", "Mail-Sec", "Add a member", "alice@contoso.com", "<- Back", "Back"])
    assert code == 0 and "Exchange" in out and tk.prompts.exhausted


def test_group_owners_and_members_can_be_removed(tk):
    tenant = with_role(FakeTenant(), "Groups Administrator")
    code, _ = drive(tk, tenant, ["Find a group", "Finance Share", "Remove owners", ["bob@contoso.com"], "<- Back", "Back"], says=[True])
    assert code == 0 and "u-bob" not in tenant.owners["g-fin"] and tk.prompts.exhausted


def test_pim_activate_then_deactivate(tk):
    tenant = FakeTenant()
    code, _ = drive(tk, tenant, ["My roles", "Activate a role", "User Administrator", "1 hour", "INC-5", "Deactivate a role",
                                 "User Administrator", "<- Back", "Back"])
    assert code == 0 and not tenant.active_roles and tk.prompts.exhausted


def test_pim_menu_refuses_app_mode(tk):
    code, out = drive(tk, FakeTenant(), ["My roles", "Back"], user_mode=False)
    assert "needs a user sign-in" in out


def test_recent_changes_with_nothing_recorded_yet(tk):
    assert "No changes recorded yet" in drive(tk, FakeTenant(), ["Recent changes", "Back"])[1]


def test_recent_changes_are_listed_once_something_was_done(tk, isolated_env):
    from entra_auditor.toolkit import audit_log
    audit_log.record({"actor": "user:me@contoso.com", "title": "Reset password", "status": "ok",
                      "target": {"type": "user", "id": "u1", "name": "Alice Ng (alice@contoso.com)"}}, path=isolated_env.log)
    out = drive(tk, FakeTenant(), ["Recent changes", "Back"])[1]
    assert "Recent changes made with this tool" in out and "Reset password" in out and "Alice Ng" in out


# ---- fixing unowned groups from the latest audit -----------------------------------------

@pytest.fixture
def saved_run():
    def gf(cid, name, gid, severity, **ev):
        base = {"kind_label": "Security", "owners": 0, "user_members": 0, "other_members": 0, "created": "2024-01-01",
                "age_days": 800, "synced_from_ad": False, "dynamic_rule": None, "usage": []}
        return finding(cid, severity, gid, resource_type="group", resource_name=name, evidence={**base, **ev})
    run = make_run([gf("GROUP_UNOWNED", "Team Site", "g-m365", "medium", kind_label="Microsoft 365", user_members=5)], checks=["groups"])
    reports.save_run(run)
    return run


def test_open_a_flagged_group_and_give_it_an_owner(tk, saved_run):
    tenant = with_role(FakeTenant(), "Groups Administrator")
    code, out = drive(tk, tenant, ["Unowned / empty / stale", "Team Site", "Add an owner", "bob@contoso.com", "<- Back", "<- Back", "Back"], says=[True])
    assert code == 0 and "u-bob" in tenant.owners["g-m365"] and tk.prompts.exhausted


def test_the_stale_group_menu_without_a_saved_run_says_what_to_do(tk):
    code, out = drive(tk, FakeTenant(), ["Unowned / empty / stale", "Back"])
    assert code == 0 and "auditor run --checks groups" in out


# ---- the main audit menu -----------------------------------------------------------------

def test_the_main_menu_has_working_toolkit_and_group_entries(tk, fake_tty):
    tk.use(FakeTenant(), interactive=True)
    tk.prompts.pick("Unowned / empty / stale", "Identity toolkit", "Back", "Quit")
    code, out = tk.run(maincli.menu)
    assert code == 0 and "No run loaded yet" in out and tk.prompts.exhausted


def test_a_failed_audit_does_not_replace_the_run_you_were_viewing(tk, fake_tty, monkeypatch, saved_run):
    from entra_auditor.engine import RunStatus
    failed = make_run(status=RunStatus.FAILED, run_id="failed-run", error="Graph said no")   # has no group findings
    monkeypatch.setattr(maincli, "_execute_run", lambda *a, **k: failed)
    tk.use(FakeTenant(), interactive=True)
    tk.prompts.pick("Run a new audit", ["inactive"], "Unowned / empty / stale", "Quit")
    code, out = tk.run(maincli.menu)
    # the earlier good run (with one flagged group) is still the one being viewed
    assert code == 0 and "stale groups (1)" in out and "No flagged groups" not in out

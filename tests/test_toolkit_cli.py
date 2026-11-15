"""Toolkit commands, run for real against a fake tenant. Nothing here needs a terminal or a network."""

import csv

import pytest

import entra_auditor.toolkit.cli as tcli
from entra_auditor import reports
from entra_auditor.toolkit import audit_log
from tests.builders import make_run, finding
from tests.fakes import FakeTenant


def with_role(tenant, name):
    tenant.active_roles["r"] = name
    return tenant


# ---- read-only commands ------------------------------------------------------------------

def test_search_by_upn(tk):
    tk.use()
    code, out = tk.run(tcli.id_search, "alice@contoso.com")
    assert code == 0 and "alice@contoso.com" in out and "Alice Ng" in out


def test_search_shows_how_a_match_was_found(tk):
    tk.use()
    code, out = tk.run(tcli.id_search, "a.ng@contoso.com")
    assert "proxy address" in out and "alice@contoso.com" in out


def test_search_across_users_groups_and_apps(tk):
    tk.use()
    code, out = tk.run(tcli.id_search, "Finance", kind="all")
    assert "Finance Share" in out and "Security" in out


def test_search_with_no_results(tk):
    tk.use()
    assert "No matches" in tk.run(tcli.id_search, "zzz-nobody")[1]


@pytest.mark.parametrize("kwargs,message", [(dict(kind="bogus"), "--type must be"), (dict(by="bogus"), "Unknown search type")])
def test_bad_search_options_are_rejected_cleanly(tk, kwargs, message):
    tk.use()
    code, out = tk.run(tcli.id_search, "x", **kwargs)
    assert code == 1 and message in out


def test_show_prints_the_whole_profile(tk):
    tk.use()
    code, out = tk.run(tcli.id_show, "alice@contoso.com")
    assert code == 0
    for expected in ("Engineer", "Mia Manager", "Project X (Microsoft 365)", "Phone (SMS/voice)", "X509:<PN>alice@contoso.com"):
        assert expected in out


def test_an_ambiguous_name_stops_non_interactive_runs(tk):
    tk.use()
    code, out = tk.run(tcli.id_show, "Bob")
    assert code == 1 and "several users" in out and "bob.smith@contoso.com" in out


def test_an_ambiguous_name_asks_you_to_pick_when_interactive(tk):
    tk.use(interactive=True)
    tk.prompts.say(2)
    code, out = tk.run(tcli.id_show, "Bob")
    assert code == 0 and "bob.smith@contoso.com" in out and tk.prompts.asked_typer[0][0] == "prompt"


def test_group_show_lists_owners_and_members(tk):
    tk.use()
    code, out = tk.run(tcli.group_show, "Finance Share")
    assert "bob@contoso.com" in out and "Owners" in out and "Members" in out
    assert "NONE (unowned)" in tk.run(tcli.group_show, "Project X")[1]


def test_the_action_log_starts_empty(tk):
    tk.use()
    assert "No changes recorded" in tk.run(tcli.id_log)[1]


# ---- previewing, dry-run, cancelling -----------------------------------------------------

def test_dry_run_previews_and_sends_nothing(tk, isolated_env):
    tenant = FakeTenant()
    tk.use(tenant)
    code, out = tk.run(tcli.id_edit, "alice@contoso.com", set_=["title=Principal", "dept="], dry_run=True)
    assert code == 0 and "jobTitle: 'Engineer' -> 'Principal'" in out and "department: 'IT' -> (empty)" in out
    assert "DRY_RUN" in out and not tenant.writes and not isolated_env.log.exists()


def test_declining_the_confirmation_changes_nothing(tk):
    tenant = FakeTenant()
    tk.use(tenant, interactive=True)
    tk.prompts.say(False)
    code, out = tk.run(tcli.id_edit, "alice@contoso.com", set_=["title=Principal"])
    assert code == 0 and "Cancelled" in out and not tenant.writes and tenant.users["u-alice"]["jobTitle"] == "Engineer"


@pytest.mark.parametrize("set_,message", [(["title=Engineer"], "Nothing to change"), (["salary=5"], "can't be edited"), (None, "Nothing to change")])
def test_pointless_or_invalid_edits_are_refused(tk, set_, message):
    tk.use(interactive=True)
    code, out = tk.run(tcli.id_edit, "alice@contoso.com", set_=set_)
    assert code == 1 and message in out


def test_previews_name_the_person_not_just_the_upn(tk):
    tk.use()
    out = tk.run(tcli.id_password, "alice@contoso.com", dry_run=True)[1]
    assert "Alice Ng (alice@contoso.com)" in out and "Nothing was sent." in out and "would send: Reset password (POST)" in out


# ---- permissions and PIM elevation -------------------------------------------------------

def test_without_a_role_a_scripted_run_explains_and_fails(tk):
    tenant = FakeTenant()
    tk.use(tenant)
    code, out = tk.run(tcli.id_edit, "alice@contoso.com", set_=["title=Principal"], yes=True)
    assert code == 1 and "your current permissions aren't enough" in out and "auditor pim activate" in out
    assert tenant.users["u-alice"]["jobTitle"] == "Engineer"


def test_no_elevate_never_activates_a_role(tk):
    tenant = FakeTenant()
    tk.use(tenant)
    assert tk.run(tcli.id_edit, "alice@contoso.com", set_=["title=P"], yes=True, elevate=False)[0] == 1
    assert not tenant.active_roles


def test_when_you_are_not_eligible_it_says_what_you_are_eligible_for(tk):
    tk.use(FakeTenant())
    code, out = tk.run(tcli.id_cert_add, "alice@contoso.com", binding="ski", data=["AB"], yes=True, elevate=True, reason="x")
    assert code == 1 and "aren't eligible" in out and "Privileged Authentication Administrator" in out and "User Administrator" in out


def test_app_mode_cannot_use_pim(tk):
    tk.use(FakeTenant(), user_mode=False)
    code, out = tk.run(tcli.id_edit, "alice@contoso.com", set_=["title=P"], yes=True)
    assert code == 1 and "only works with a user sign-in" in out


def test_elevating_waits_for_the_role_to_take_effect_and_retries(tk):
    tenant = FakeTenant(propagation_delay=1)
    session = tk.use(tenant)
    code, out = tk.run(tcli.id_edit, "alice@contoso.com", set_=["title=Principal"], yes=True, elevate=True, reason="INC-1 fix title")
    body = [w for w in tenant.writes if w[1] == "pim"][0][2]
    assert code == 0 and "OK:" in out and tenant.users["u-alice"]["jobTitle"] == "Principal"
    assert body["justification"] == "INC-1 fix title" and body["roleDefinitionId"] == "r-user-administrator"
    assert session.provider.refreshes >= 1                      # token refreshed so the new role is in it


def test_a_role_that_is_already_active_is_not_activated_twice(tk):
    tenant = FakeTenant()
    tk.use(tenant)
    tk.run(tcli.id_edit, "alice@contoso.com", set_=["title=Principal"], yes=True, elevate=True, reason="x")
    assert tk.run(tcli.id_edit, "alice@contoso.com", set_=["dept=Security"], yes=True)[0] == 0
    assert sum(1 for w in tenant.writes if w[1] == "pim") == 1


def test_the_interactive_flow_asks_in_the_right_order(tk):
    tenant = FakeTenant()
    tk.use(tenant, interactive=True)
    tk.prompts.say(True, 1, True, "INC-77")        # apply? / which role / activate? / justification
    code, out = tk.run(tcli.group_add_member, "Finance Share", ["alice@contoso.com"])
    assert code == 0 and "u-alice" in tenant.members["g-fin"]
    assert [kind for kind, _ in tk.prompts.asked_typer] == ["confirm", "prompt", "confirm", "prompt"]
    assert [w for w in tenant.writes if w[1] == "pim"][0][2]["roleDefinitionId"] == "r-groups-administrator"


def test_a_role_that_needs_mfa_gives_guidance_not_a_traceback(tk):
    tk.use(FakeTenant(require_mfa={"User Administrator"}))
    code, out = tk.run(tcli.id_edit, "alice@contoso.com", set_=["title=P"], yes=True, elevate=True, reason="x")
    assert code == 1 and "multifactor" in out.lower() and "login --mode browser" in out


def test_unreadable_pim_roles_print_the_manual_hint_before_the_result(tk, monkeypatch):
    from entra_auditor.graph.client import GraphError
    from entra_auditor.toolkit.pim import PimService

    def boom(self):
        raise GraphError("boom", status_code=500)

    monkeypatch.setattr(PimService, "eligible", boom)
    tk.use(FakeTenant())
    code, out = tk.run(tcli.id_edit, "alice@contoso.com", set_=["title=P"], yes=True)
    assert code == 1 and "Couldn't read your PIM roles" in out
    assert out.index("Couldn't read") < out.index("auditor pim activate") < out.index("DENIED")


def test_elevation_requires_a_justification(tk):
    tk.use(FakeTenant())
    code, out = tk.run(tcli.id_edit, "alice@contoso.com", set_=["title=P"], yes=True, elevate=True)
    assert code == 1 and "justification is required" in out.lower()


# ---- passwords ---------------------------------------------------------------------------

def test_an_entra_generated_password_is_shown_once(tk):
    tk.use(with_role(FakeTenant(), "Helpdesk Administrator"))
    code, out = tk.run(tcli.id_password, "alice@contoso.com", yes=True)
    assert code == 0 and "Gen3rated!Pw42" in out and "never logged" in out


def test_a_locally_generated_password_is_sent_and_revealed_once(tk):
    tenant = with_role(FakeTenant(), "Helpdesk Administrator")
    tk.use(tenant)
    code, out = tk.run(tcli.id_password, "alice@contoso.com", local=True, yes=True)
    sent = [w for w in tenant.writes if w[1].endswith("/resetPassword")][0][2]["newPassword"]
    assert code == 0 and sent in out and len(sent) == 20


def test_a_typed_password_is_used_but_never_printed(tk):
    tenant = with_role(FakeTenant(), "Helpdesk Administrator")
    tk.use(tenant, interactive=True)
    tk.prompts.say("Str0ng!Passw0rd#9")
    code, out = tk.run(tcli.id_password, "alice@contoso.com", prompt_=True, yes=True)
    assert code == 0 and "Str0ng" not in out and tenant.writes[-1][2] == {"newPassword": "Str0ng!Passw0rd#9"}


def test_a_weak_typed_password_is_rejected_before_anything_is_sent(tk):
    tenant = with_role(FakeTenant(), "Helpdesk Administrator")
    tk.use(tenant)
    tk.prompts.say("weak")
    code, out = tk.run(tcli.id_password, "alice@contoso.com", prompt_=True, yes=True)
    assert code == 1 and "rejected" in out and not tenant.writes


def test_prompt_and_local_conflict(tk):
    tk.use()
    assert tk.run(tcli.id_password, "alice@contoso.com", prompt_=True, local=True)[0] == 1


def test_synced_accounts_get_a_locally_generated_password(tk):
    tenant = with_role(FakeTenant(), "Helpdesk Administrator")
    tk.use(tenant)
    code, out = tk.run(tcli.id_password, "sam@contoso.com", yes=True)
    assert code == 0 and "Synced account" in out and tenant.writes[-1][2]["newPassword"] in out


def test_resetting_an_admin_asks_for_a_privileged_role(tk):
    tk.use()
    out = tk.run(tcli.id_password, "ada@contoso.com", dry_run=True)[1]
    assert "Privileged Authentication Administrator" in out and "holds admin roles" in out


def test_no_password_ever_reaches_the_action_log(tk, isolated_env):
    tenant = with_role(FakeTenant(), "Helpdesk Administrator")
    tk.use(tenant, interactive=True)
    tk.prompts.say("Str0ng!Passw0rd#9")
    tk.run(tcli.id_password, "alice@contoso.com", prompt_=True, yes=True)
    tk.run(tcli.id_password, "alice@contoso.com", yes=True)
    tk.run(tcli.id_password, "alice@contoso.com", local=True, yes=True)
    log = isolated_env.log.read_text()
    assert log and "Str0ng" not in log and "Gen3rated" not in log
    assert tenant.writes[-1][2]["newPassword"] not in log


# ---- certificate user IDs ----------------------------------------------------------------

@pytest.fixture
def cert_tenant():
    tenant = FakeTenant(eligible=("Privileged Authentication Administrator",))
    return with_role(tenant, "Privileged Authentication Administrator")


def test_cert_list(tk, cert_tenant):
    tk.use(cert_tenant)
    out = tk.run(tcli.id_cert_list, "alice@contoso.com")[1]
    assert "PrincipalName" in out and "X509:<PN>alice@contoso.com" in out


def test_cert_add_prefixes_the_data_and_keeps_existing_entries(tk, cert_tenant):
    tk.use(cert_tenant)
    code, _ = tk.run(tcli.id_cert_add, "alice@contoso.com", binding="ski", value=["AB:CD:EF"], yes=True)
    assert code == 0 and cert_tenant.certs["u-alice"] == ["X509:<PN>alice@contoso.com", "X509:<SKI>ABCDEF"]


def test_cert_data_can_be_pasted_as_a_positional_argument(tk, cert_tenant):
    """From the first live run: `cert-add bob --type ski 444` used to be rejected."""
    tk.use(cert_tenant)
    code, out = tk.run(tcli.id_cert_add, "alice@contoso.com", data=["444"], binding="ski", dry_run=True)
    assert code == 0 and "X509:<SKI>444" in out and "DRY_RUN" in out and not cert_tenant.writes
    assert tk.run(tcli.id_cert_add, "alice@contoso.com", data=["AB:CD:EF"], binding="ski", yes=True)[0] == 0
    assert cert_tenant.certs["u-alice"][-1] == "X509:<SKI>ABCDEF"


def test_positional_data_and_the_value_option_combine(tk, cert_tenant):
    tk.use(cert_tenant)
    tk.run(tcli.id_cert_add, "alice@contoso.com", data=["aa"], value=["bb"], binding="ski", yes=True)
    assert cert_tenant.certs["u-alice"][-2:] == ["X509:<SKI>aa", "X509:<SKI>bb"]


def test_cert_add_without_a_type_explains_what_is_needed(tk, cert_tenant):
    tk.use(cert_tenant)
    code, out = tk.run(tcli.id_cert_add, "alice@contoso.com", data=["444"], yes=True)
    assert code == 1 and "needs --type" in out
    code, out = tk.run(tcli.id_cert_add, "alice@contoso.com", yes=True)
    assert code == 1 and "--type" in out


def test_duplicate_entries_are_a_no_op(tk, cert_tenant):
    tk.use(cert_tenant)
    tk.run(tcli.id_cert_add, "alice@contoso.com", binding="ski", value=["AB"], yes=True)
    code, out = tk.run(tcli.id_cert_add, "alice@contoso.com", binding="ski", value=["AB"], yes=True)
    assert code == 0 and "Already present" in out and "Nothing to add" in out


def test_complete_entries_are_accepted_and_bad_ones_rejected(tk, cert_tenant):
    tk.use(cert_tenant)
    tk.run(tcli.id_cert_add, "alice@contoso.com", full=["X509:<RFC822>alice@contoso.com"], yes=True)
    assert cert_tenant.certs["u-alice"][-1] == "X509:<RFC822>alice@contoso.com"
    code, out = tk.run(tcli.id_cert_add, "alice@contoso.com", full=["x509:<pn>nope"], yes=True)
    assert code == 1 and "recognised" in out


@pytest.mark.parametrize("kwargs,message", [
    (dict(binding="issuer-serial", value=["only-one"]), "needs 2"), (dict(binding="pn", value=["a<SR>b"]), "must not contain")])
def test_invalid_certificate_input_is_rejected(tk, cert_tenant, kwargs, message):
    tk.use(cert_tenant)
    code, out = tk.run(tcli.id_cert_add, "alice@contoso.com", yes=True, **kwargs)
    assert code == 1 and message in out


def test_two_part_bindings(tk, cert_tenant):
    tk.use(cert_tenant)
    tk.run(tcli.id_cert_add, "alice@contoso.com", binding="issuer-serial", data=["CN=CA", "1122"], yes=True)
    assert cert_tenant.certs["u-alice"][-1] == "X509:<I>CN=CA<SR>1122"


def test_interactive_prompts_show_the_prefix_so_only_the_data_is_pasted(tk, cert_tenant):
    tk.use(cert_tenant, interactive=True)
    tk.prompts.say("sha1", "ab cd ef 01")
    code, _ = tk.run(tcli.id_cert_add, "alice@contoso.com", yes=True)
    assert code == 0 and cert_tenant.certs["u-alice"][-1] == "X509:<SHA1-PUKEY>abcdef01"
    assert "X509:<SHA1-PUKEY>" in tk.prompts.asked_typer[1][1]


def test_cert_remove(tk, cert_tenant):
    tk.use(cert_tenant)
    tk.run(tcli.id_cert_add, "alice@contoso.com", binding="ski", value=["AB"], yes=True)
    assert tk.run(tcli.id_cert_remove, "alice@contoso.com", value=["X509:<SKI>AB"], yes=True)[0] == 0
    assert "X509:<SKI>AB" not in cert_tenant.certs["u-alice"]
    assert "Nothing to remove" in tk.run(tcli.id_cert_remove, "alice@contoso.com", value=["X509:<SKI>nope"], yes=True)[1]


# ---- groups ------------------------------------------------------------------------------

@pytest.fixture
def group_tenant():
    return with_role(FakeTenant(), "Groups Administrator")


def test_add_members_is_idempotent(tk, group_tenant):
    tk.use(group_tenant)
    code, out = tk.run(tcli.group_add_member, "Finance Share", ["alice@contoso.com", "bob@contoso.com"], yes=True)
    assert code == 0 and "already in that state" in out and {"u-alice", "u-bob"} <= group_tenant.members["g-fin"]


@pytest.mark.parametrize("group,message", [("Mail-Sec", "Exchange"), ("AD Group", "on-premises"), ("Dynamic IT", "dynamic")])
def test_groups_graph_cannot_change_are_refused_before_anything_is_sent(tk, group_tenant, group, message):
    tk.use(group_tenant)
    code, out = tk.run(tcli.group_add_member, group, ["alice@contoso.com"], yes=True)
    assert code == 1 and message.lower() in out.lower() and not group_tenant.writes


def test_owners_can_be_added_and_removed(tk, group_tenant):
    tk.use(group_tenant)
    assert tk.run(tcli.group_add_owner, "Project X", ["bob@contoso.com"], yes=True)[0] == 0 and "u-bob" in group_tenant.owners["g-m365"]
    out = tk.run(tcli.group_remove_owner, "Project X", ["bob@contoso.com"], yes=True)[1]
    assert "u-bob" not in group_tenant.owners["g-m365"] and "becomes unowned" in out
    assert tk.run(tcli.group_add_owner, "Dynamic IT", ["alice@contoso.com"], yes=True)[0] == 0   # dynamic groups can have owners


def test_removing_a_non_member_is_idempotent(tk, group_tenant):
    tk.use(group_tenant)
    assert tk.run(tcli.group_remove_member, "Finance Share", ["bob@contoso.com"], yes=True)[0] == 0
    code, out = tk.run(tcli.group_remove_member, "Finance Share", ["bob@contoso.com"], yes=True)
    assert code == 0 and "already in that state" in out


def test_role_assignable_groups_warn_about_the_needed_role(tk, group_tenant):
    tk.use(group_tenant)
    assert "Privileged Role Administrator" in tk.run(tcli.group_add_member, "Role Group", ["alice@contoso.com"], dry_run=True)[1]


def test_group_plans_list_people_by_label(tk, group_tenant):
    tk.use(group_tenant)
    assert "+ alice@contoso.com" in tk.run(tcli.group_add_member, "Finance Share", ["alice@contoso.com"], dry_run=True)[1]


# ---- PIM commands ------------------------------------------------------------------------

def test_pim_list_activate_and_deactivate(tk):
    tenant = FakeTenant()
    tk.use(tenant)
    code, out = tk.run(tcli.pim_list)
    assert code == 0 and "User Administrator" in out and "eligible" in out
    code, out = tk.run(tcli.pim_activate, "user adm", reason="INC-5", minutes=30)
    assert code == 0 and "is active for 30 minutes" in out and tenant.active_roles
    assert [w for w in tenant.writes if w[1] == "pim"][-1][2]["scheduleInfo"]["expiration"]["duration"] == "PT30M"
    assert "already active" in tk.run(tcli.pim_activate, "user adm", reason="again")[1]
    assert "active (activated)" in tk.run(tcli.pim_list)[1]
    code, out = tk.run(tcli.pim_deactivate, "user adm")
    assert code == 0 and "Revoked" in out and not tenant.active_roles


@pytest.mark.parametrize("args,kwargs,message", [
    (("wizard",), dict(reason="x"), "No role matches"), (("administrator",), dict(reason="x"), "several roles"),
    (("global reader",), {}, "justification is required")])
def test_pim_activation_errors_are_explained(tk, args, kwargs, message):
    tk.use(FakeTenant())
    code, out = tk.run(tcli.pim_activate, *args, **kwargs)
    assert code == 1 and message.lower() in out.lower()


def test_pim_needs_a_user_sign_in(tk):
    tk.use(FakeTenant(), user_mode=False)
    code, out = tk.run(tcli.pim_list)
    assert code == 1 and "signed-in person" in out


# ---- unowned / empty / stale groups from a saved audit -----------------------------------

def group_finding(check_id, name, gid, severity, **evidence):
    base = {"kind_label": "Security", "owners": 0, "user_members": 0, "other_members": 0, "created": "2024-01-01",
            "age_days": 800, "synced_from_ad": False, "dynamic_rule": None, "usage": []}
    return finding(check_id, severity, gid, resource_type="group", resource_name=name, evidence={**base, **evidence})


@pytest.fixture
def saved_run(isolated_env):
    run = make_run([
        group_finding("GROUP_UNOWNED", "Old Project", "g-old", "low"), group_finding("GROUP_EMPTY", "Old Project", "g-old", "low"),
        group_finding("GROUP_STALE", "Old Project", "g-old", "low"),
        group_finding("GROUP_UNOWNED", "Team Site", "g-m365", "medium", kind_label="Microsoft 365", user_members=5, usage=["grants access to 1 app(s)"]),
        group_finding("GROUP_EMPTY", "Dynamic IT", "g-dyn", "low", owners=1)], checks=["groups"])
    reports.save_run(run)
    return run


def test_stale_groups_merges_findings_per_group(tk, saved_run):
    code, out = tk.run(tcli.group_stale)
    assert code == 0 and "(3)" in out and out.count("Old Project") == 1 and "unowned, empty, stale" in out


@pytest.mark.parametrize("kwargs,count,absent", [
    (dict(only="unowned"), "(2)", "Dynamic IT"), (dict(only="stale"), "(1)", "Team Site"), (dict(kind="microsoft"), "(1)", "Old Project")])
def test_stale_group_filters(tk, saved_run, kwargs, count, absent):
    out = tk.run(tcli.group_stale, **kwargs)[1]
    assert count in out and absent not in out


def test_a_bad_filter_is_rejected(tk, saved_run):
    assert tk.run(tcli.group_stale, only="bogus")[0] == 1


def test_stale_groups_can_be_exported(tk, saved_run, tmp_path):
    path = tmp_path / "groups.csv"
    tk.run(tcli.group_stale, export=path)
    rows = list(csv.DictReader(open(path)))
    assert len(rows) == 3 and rows[0]["group"] and "issues" in rows[0]


def test_stale_groups_without_any_saved_run(tk):
    code, out = tk.run(tcli.group_stale)
    assert code == 1 and "No saved runs" in out


# ---- the action log ----------------------------------------------------------------------

def test_every_applied_change_is_logged_with_who_and_what(tk, isolated_env):
    tk.use(with_role(FakeTenant(), "User Administrator"))
    tk.run(tcli.id_edit, "alice@contoso.com", set_=["title=Principal"], yes=True)
    entry = audit_log.read_recent(5, isolated_env.log)[-1]
    assert entry["actor"] == "user:me@contoso.com" and entry["status"] == "ok" and entry["action"] == "user.update"
    assert "Alice Ng" in entry["target"]["name"]
    assert "Update user attributes" in tk.run(tcli.id_log)[1]

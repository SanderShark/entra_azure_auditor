import pytest

from entra_auditor.graph.client import GraphAuthError, GraphPermissionError
from entra_auditor.toolkit.profile import (
    get_certificate_user_ids,
    group_detail,
    holds_admin_roles,
    list_group_people,
    load_user_profile,
    profile_current_values,
)
from entra_auditor.toolkit.search import resolve_group
from tests.fakes import FakeTenant


def test_core_attributes_and_extras(tenant):
    p = load_user_profile(tenant, "u-alice")
    assert p.upn == "alice@contoso.com" and p.job_title == "Engineer" and p.employee_id == "E100"
    assert p.manager == "Mia Manager"
    assert p.cert_user_ids == ["X509:<PN>alice@contoso.com"]
    assert p.auth_methods == ["Password", "Phone (SMS/voice)"]
    assert [g.label for g in p.groups] == ["Project X (Microsoft 365)"]
    assert "smtp:a.ng@contoso.com" in p.proxy_addresses and p.other_mails == ["alice@home.example"]
    assert p.warnings == []


def test_last_sign_in_is_the_newest_of_all_kinds(tenant):
    p = load_user_profile(tenant, "u-alice")
    assert (p.last_sign_in.month, p.last_sign_in.day) == (10, 1)   # the non-interactive one is newer


def test_admin_roles_are_listed(tenant):
    p = load_user_profile(tenant, "u-admin")
    assert p.roles_active == ["Global Administrator"] and holds_admin_roles(p)
    assert not holds_admin_roles(load_user_profile(tenant, "u-alice"))


def test_a_permission_problem_in_one_extra_becomes_a_warning():
    class NoSignIn(FakeTenant):
        def get(self, path, **kw):
            if kw.get("select") == ["signInActivity"]:
                raise GraphPermissionError("needs AuditLog.Read.All", status_code=403)
            return super().get(path, **kw)

    p = load_user_profile(NoSignIn(), "u-alice")
    assert p.sign_in_available is False and p.last_sign_in is None
    assert any("sign-in activity" in w for w in p.warnings)
    assert p.upn == "alice@contoso.com"      # everything else still loaded


def test_auth_failures_are_not_swallowed():
    class Expired(FakeTenant):
        def get(self, path, **kw):
            if kw.get("select") == ["authorizationInfo"]:
                raise GraphAuthError("token expired", status_code=401)
            return super().get(path, **kw)

    with pytest.raises(GraphAuthError):
        load_user_profile(Expired(), "u-alice")


def test_current_values_match_the_editable_fields(tenant):
    values = profile_current_values(load_user_profile(tenant, "u-alice"))
    assert values["jobTitle"] == "Engineer" and values["department"] == "IT" and "displayName" in values


def test_certificate_ids_helper(tenant):
    assert get_certificate_user_ids(tenant, "u-alice") == ["X509:<PN>alice@contoso.com"]
    assert get_certificate_user_ids(tenant, "u-bob") == []


def test_group_people_listing(tenant):
    people, more = list_group_people(tenant, "g-fin", "owners", 10)
    assert [p.name for p in people] == ["bob@contoso.com"] and not more
    with pytest.raises(ValueError):
        list_group_people(tenant, "g-fin", "bogus")


def test_group_people_are_truncated_at_the_limit(tenant):
    tenant.members["g-fin"] = {"u-alice", "u-bob", "u-bob2"}
    people, more = list_group_people(tenant, "g-fin", "members", 2)
    assert len(people) == 2 and more


def test_group_detail_has_owners_and_members(tenant):
    detail = group_detail(tenant, resolve_group(tenant, "Finance Share"))
    assert [o.name for o in detail["owners"]] == ["bob@contoso.com"]
    assert [m.name for m in detail["members"]] == ["bob@contoso.com"]


# ---- the on-premises half of a hybrid user ---------------------------------------------------------

def hybrid_tenant():
    from tests.fakes import FakeTenant
    t = FakeTenant()
    t.users["u-sync"].update(
        onPremisesDomainName="corp.contoso.com", onPremisesSamAccountName="ssam",
        onPremisesUserPrincipalName="sam@corp.contoso.com",
        onPremisesDistinguishedName="CN=Sam\\, Sync,OU=Staff,OU=CORP,DC=corp,DC=contoso,DC=com",
        onPremisesSecurityIdentifier="S-1-5-21-1-2-3-1104", onPremisesImmutableId="qWeRtY==",
        onPremisesLastSyncDateTime="2026-11-14T08:30:00Z",
        onPremisesExtensionAttributes={"extensionAttribute14": "no0365sync", "extensionAttribute2": "B", "extensionAttribute1": None},
        onPremisesProvisioningErrors=[{"category": "PropertyConflict", "propertyCausingError": "ProxyAddresses",
                                       "value": "SMTP:sam@contoso.com"}])
    return t


def test_a_synced_user_carries_its_on_premises_record():
    from entra_auditor.toolkit.profile import load_user_profile
    record = load_user_profile(hybrid_tenant(), "u-sync").on_prem
    assert record.synced and record.has_record
    assert record.location == "corp.contoso.com/CORP/Staff"            # ADUC-style; the escaped comma stays in the CN
    assert record.logon_name == "CORP\\ssam" and record.sid.endswith("-1104") and record.immutable_id == "qWeRtY=="
    assert f"{record.last_sync:%Y-%m-%d %H:%M}" == "2026-11-14 08:30"
    assert list(record.extension_attributes.items()) == [("extensionAttribute2", "B"), ("extensionAttribute14", "no0365sync")]
    assert record.provisioning_errors == ["PropertyConflict / ProxyAddresses / SMTP:sam@contoso.com"]


def test_a_cloud_only_user_has_no_record_and_an_unreadable_one_is_unknown():
    from entra_auditor.graph.client import GraphError
    from entra_auditor.toolkit.models import OnPremRecord
    from entra_auditor.toolkit.profile import ON_PREM_SELECT, load_user_profile
    t = hybrid_tenant()
    record = load_user_profile(t, "u-alice").on_prem
    assert record is not None and not record.synced and not record.has_record and record.location is None
    assert OnPremRecord(sam_account="x").logon_name == "x" and OnPremRecord(distinguished_name="CN=a,DC=x").has_record
    real_get = t.get

    def get(path, **kw):
        if kw.get("select") == ON_PREM_SELECT:
            raise GraphError("Invalid property", status_code=400)
        return real_get(path, **kw)

    t.get = get
    profile = load_user_profile(t, "u-sync")
    assert profile.on_prem is None and any("on-premises record: unavailable" in w for w in profile.warnings)
    assert profile.display_name == "Sync Sam"                          # the rest of the profile is unaffected

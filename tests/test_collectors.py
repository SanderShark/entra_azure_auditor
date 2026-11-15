"""Collectors: raw Graph JSON -> models, and how collection degrades when one source fails."""

import pytest

from entra_auditor.graph import collectors as c
from entra_auditor.graph.client import (
    GraphAuthError,
    GraphError,
    GraphNotFoundError,
    GraphPermissionError,
    GraphRetryExhaustedError,
)
from entra_auditor.models import MICROSOFT_TENANT_ID
from tests.fakes import FakeGraph

BETA = "https://graph.microsoft.com/beta"
GRAPH_APP = "00000003-0000-0000-c000-000000000000"


# =========================================================================== parsers

def test_parse_user_reads_sign_in_activity_and_sync_flags():
    user = c.parse_user({
        "id": "u1", "userPrincipalName": "a@x.com", "userType": "Guest", "accountEnabled": True,
        "onPremisesSyncEnabled": True, "externalUserState": "PendingAcceptance",
        "signInActivity": {"lastSignInDateTime": "2026-09-01T00:00:00Z",
                           "lastNonInteractiveSignInDateTime": "2026-09-20T00:00:00Z"}})
    assert user.is_guest and user.on_prem_synced and user.has_pending_invitation
    assert user.last_activity.day == 20            # newest of the three kinds


def test_parse_user_without_sign_in_data_has_no_activity():
    assert c.parse_user({"id": "u1"}).last_activity is None


def test_parse_role_assignment_flags_pim_activations_and_expiry():
    defs = {"r1": c.parse_role_definition({"id": "r1", "displayName": "Global Administrator", "isPrivileged": True})}
    activated = c.parse_role_assignment(
        {"principalId": "u1", "roleDefinitionId": "r1", "assignmentType": "Activated", "endDateTime": "2026-10-06T10:00:00Z",
         "principal": {"@odata.type": "#microsoft.graph.user", "userPrincipalName": "a@x.com"}}, defs, state="active")
    assert activated.activated_via_pim and not activated.is_permanent and activated.principal_type == "user"
    assert activated.is_privileged_role is True and activated.role_name == "Global Administrator"
    standing = c.parse_role_assignment({"principalId": "u1", "roleDefinitionId": "r1", "assignmentType": "Assigned"}, defs, state="active")
    assert standing.is_permanent


def test_parse_eligible_assignment_reads_expiry_from_the_schedule():
    ra = c.parse_role_assignment(
        {"principalId": "u1", "roleDefinitionId": "unknown-role",
         "scheduleInfo": {"expiration": {"endDateTime": "2027-01-01T00:00:00Z"}}}, {}, state="eligible")
    assert ra.end_date_time.year == 2027 and ra.role_name == "unknown-role" and not ra.is_permanent


@pytest.mark.parametrize("odata,expected", [
    ("#microsoft.graph.servicePrincipal", "servicePrincipal"), ("#microsoft.graph.group", "group"), ("#other", "unknown")])
def test_principal_types(odata, expected):
    ra = c.parse_role_assignment({"principalId": "p", "roleDefinitionId": "r", "principal": {"@odata.type": odata}}, {}, state="active")
    assert ra.principal_type == expected


def test_parse_ca_policy_extracts_who_what_when_and_action():
    policy = c.parse_ca_policy({
        "id": "p1", "displayName": "Policy", "state": "enabledForReportingButNotEnforced",
        "createdDateTime": "2026-01-01T00:00:00Z", "modifiedDateTime": "2026-02-01T00:00:00Z",
        "conditions": {
            "users": {"includeUsers": ["All"], "excludeUsers": ["u1"], "excludeGroups": ["g1"], "excludeRoles": ["r1"],
                      "includeGuestsOrExternalUsers": {"guestOrExternalUserTypes": "b2bCollaborationGuest,internalGuest"},
                      "excludeGuestsOrExternalUsers": {"guestOrExternalUserTypes": "serviceProvider"}},
            "applications": {"includeApplications": ["All"], "excludeApplications": ["app1"],
                             "includeUserActions": ["urn:user:registersecurityinfo"]},
            "clientAppTypes": ["exchangeActiveSync", "other"],
            "platforms": {"includePlatforms": ["all"], "excludePlatforms": ["linux"]},
            "locations": {"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]},
            "devices": {"deviceFilter": {"mode": "exclude", "rule": "device.isCompliant -eq True"}},
            "signInRiskLevels": "medium,high", "userRiskLevels": ["high"],
            "authenticationFlows": {"transferMethods": "deviceCodeFlow,authenticationTransfer"}},
        "grantControls": {"operator": "AND", "builtInControls": ["mfa", "compliantDevice"],
                          "authenticationStrength": {"id": "s1", "displayName": "Phishing-resistant"}, "termsOfUse": ["t1"]},
        "sessionControls": {"signInFrequency": {"isEnabled": True, "type": "hours", "value": 4}}})
    assert policy.is_report_only and policy.includes_guests_or_external and policy.excludes_guests_or_external
    assert policy.include_guest_types == ["b2bCollaborationGuest", "internalGuest"] and policy.exclude_guest_types == ["serviceProvider"]
    assert policy.exclude_users == ["u1"] and policy.exclude_groups == ["g1"] and policy.exclude_roles == ["r1"]
    assert policy.include_user_actions == ["urn:user:registersecurityinfo"] and policy.exclude_applications == ["app1"]
    assert policy.exclude_platforms == ["linux"] and policy.exclude_locations == ["AllTrusted"]
    assert (policy.device_filter_mode, policy.device_filter_rule) == ("exclude", "device.isCompliant -eq True")
    assert policy.sign_in_risk_levels == ["medium", "high"] and policy.user_risk_levels == ["high"]
    assert policy.authentication_flows == ["deviceCodeFlow", "authenticationTransfer"]
    assert policy.grant_controls == ["mfa", "compliantDevice"] and policy.grant_operator == "AND"
    assert policy.authentication_strength_name == "Phishing-resistant" and policy.terms_of_use == ["t1"]
    assert policy.session_controls["signInFrequency"]["value"] == 4 and policy.requires_mfa and not policy.blocks_access


def test_parse_ca_policy_tolerates_missing_sections():
    policy = c.parse_ca_policy({"id": "p1"})
    assert policy.state == "disabled" and policy.include_users == [] and policy.grant_controls == []


def test_credentials_are_split_into_secrets_and_certificates():
    creds = c.parse_credentials({"passwordCredentials": [{"keyId": "k1", "endDateTime": "2027-01-01T00:00:00Z"}],
                                 "keyCredentials": [{"keyId": "k2", "displayName": "saml"}]})
    assert [(x.kind, x.key_id) for x in creds] == [("secret", "k1"), ("certificate", "k2")]


def test_owner_count_is_none_when_owners_were_not_expanded():
    assert c.parse_application({"id": "a", "appId": "x"}).owner_count is None
    assert c.parse_application({"id": "a", "appId": "x", "owners": []}).owner_count == 0
    assert c.parse_service_principal({"id": "s", "owners": [{"id": "o"}]}).owner_count == 1


def test_first_party_apps_are_recognised():
    assert c.parse_service_principal({"id": "s", "appOwnerOrganizationId": MICROSOFT_TENANT_ID}).is_microsoft_first_party


def test_named_locations():
    ip = c.parse_named_location({"@odata.type": "#microsoft.graph.ipNamedLocation", "id": "l1", "displayName": "HQ", "isTrusted": True, "ipRanges": [{}, {}]})
    country = c.parse_named_location({"@odata.type": "#microsoft.graph.countryNamedLocation", "id": "l2", "countriesAndRegions": ["US", "CA"]})
    assert (ip.kind, ip.is_trusted, ip.ip_range_count) == ("ip", True, 2)
    assert (country.kind, country.countries, country.is_trusted) == ("country", ["US", "CA"], None)


def test_parse_group_detects_teams_licences_and_dynamic_membership():
    group = c.parse_group({"id": "g", "displayName": "G", "groupTypes": ["Unified", "DynamicMembership"], "mailEnabled": True,
                           "securityEnabled": False, "resourceProvisioningOptions": ["Team"], "assignedLicenses": [{"skuId": "x"}],
                           "isAssignableToRole": True, "onPremisesSyncEnabled": True})
    assert group.is_team and group.has_licenses and group.is_dynamic and group.is_role_assignable
    assert group.kind == "microsoft365" and group.on_prem_synced


def test_latest_service_principal_sign_in_looks_across_every_activity_type():
    raw = {"lastSignInActivity": {"lastSignInDateTime": "2026-01-01T00:00:00Z"},
           "applicationAuthenticationClientSignInActivity": {"lastSignInDateTime": "2026-03-01T00:00:00Z"}}
    assert c.latest_sp_sign_in(raw).month == 3
    assert c.latest_sp_sign_in({}) is None


# ====================================================================== collector behaviour

DEFS = "/roleManagement/directory/roleDefinitions"


def collector(data):
    return c.TenantCollector(FakeGraph(data))


def test_privileged_flag_comes_from_beta_when_available():
    col = collector({BETA + DEFS: [{"id": "r1", "displayName": "Global Administrator", "isPrivileged": True}]})
    assert col.role_definitions()[0].is_privileged is True and col.warnings == []


def test_falls_back_to_v1_without_the_unsupported_property():
    """Regression: v1.0 rejects `isPrivileged` with a 400, which used to abort the whole audit."""
    def v1(kw):
        if "isPrivileged" in kw["select"]:
            raise GraphError("400 Could not find a property named 'isPrivileged'", status_code=400)
        return [{"id": "r1", "displayName": "Global Administrator"}]

    graph = FakeGraph({BETA + DEFS: GraphError("400 beta says no", status_code=400), DEFS: v1})
    definitions = c.TenantCollector(graph).role_definitions()
    assert definitions[0].is_privileged is None and definitions[0].display_name == "Global Administrator"
    assert all("isPrivileged" not in str(call[1].get("select")) for call in graph.calls if call[0] == DEFS)


@pytest.mark.parametrize("error", [GraphError("400 bad", status_code=400), GraphPermissionError("403", status_code=403),
                                   GraphNotFoundError("404", status_code=404)])
def test_one_failing_source_becomes_a_warning_not_a_crash(error):
    col = collector({"/identity/conditionalAccess/policies": error})
    assert col.ca_policies() is None
    assert len(col.warnings) == 1 and "conditional access policies" in col.warnings[0]


@pytest.mark.parametrize("error", [GraphAuthError("401", status_code=401), GraphRetryExhaustedError("429 forever", status_code=429)])
def test_auth_failures_and_exhausted_retries_abort_collection(error):
    with pytest.raises(type(error)):
        collector({"/identity/conditionalAccess/policies": error}).ca_policies()


def test_users_fall_back_when_sign_in_activity_is_not_licensed():
    def users(kw):
        if "signInActivity" in kw["select"]:
            raise GraphPermissionError("needs P1", status_code=403)
        return [{"id": "u1", "userPrincipalName": "a@x.com"}]

    col = collector({"/users": users})
    assert [u.id for u in col.users()] == ["u1"]
    assert col.sign_in_data_available is False and any("sign-in activity" in w for w in col.warnings)


def test_users_with_sign_in_data_set_the_flag():
    col = collector({"/users": [{"id": "u1", "signInActivity": {"lastSignInDateTime": "2026-01-01T00:00:00Z"}}]})
    assert col.users()[0].last_activity and col.sign_in_data_available is True


ROLE_BASE = "/roleManagement/directory"


def test_pim_data_missing_falls_back_to_plain_assignments_and_marks_eligibility_unavailable():
    col = collector({
        ROLE_BASE + "/roleAssignmentScheduleInstances": GraphPermissionError("needs P2", status_code=403),
        ROLE_BASE + "/roleAssignments": [{"principalId": "u1", "roleDefinitionId": "r1", "principal": {"@odata.type": "#microsoft.graph.user"}}],
        ROLE_BASE + "/roleEligibilitySchedules": GraphPermissionError("needs P2", status_code=403)})
    assignments = col.role_assignments([c.parse_role_definition({"id": "r1", "displayName": "Role"})])
    assert [a.principal_id for a in assignments] == ["u1"] and col.eligible_roles_available is False
    assert any("PIM schedule data unavailable" in w for w in col.warnings)


def test_people_who_hold_a_role_only_through_a_group_are_found():
    group_assignment = {"principalId": "g1", "roleDefinitionId": "r1",
                        "principal": {"@odata.type": "#microsoft.graph.group", "displayName": "Admins"}}
    col = collector({
        ROLE_BASE + "/roleAssignmentScheduleInstances": [group_assignment],
        ROLE_BASE + "/roleEligibilitySchedules": [],
        "/groups/g1/transitiveMembers": [
            {"@odata.type": "#microsoft.graph.user", "id": "u1", "userPrincipalName": "a@x.com"},
            {"@odata.type": "#microsoft.graph.group", "id": "nested"},                # nested group object: skipped
            {"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp1"}]})
    result = col.role_assignments([c.parse_role_definition({"id": "r1", "displayName": "Role"})])
    inherited = [a for a in result if a.via_group_id]
    assert {(a.principal_id, a.principal_type) for a in inherited} == {("u1", "user"), ("sp1", "servicePrincipal")}
    assert all(a.via_group_id == "g1" for a in inherited)


def test_service_principals_get_their_graph_permissions_and_last_sign_in():
    def sps(kw):
        if kw.get("filter") and GRAPH_APP in kw["filter"]:
            return [{"id": "graph-sp", "appRoles": [{"id": "role1", "value": "Directory.ReadWrite.All"}]}]
        return [{"id": "s1", "appId": "app1", "displayName": "App", "owners": []}]

    col = collector({
        "/servicePrincipals": sps,
        "/servicePrincipals/graph-sp/appRoleAssignedTo": [
            {"principalId": "s1", "principalType": "ServicePrincipal", "appRoleId": "role1"},
            {"principalId": "someuser", "principalType": "User", "appRoleId": "role1"}],
        BETA + "/reports/servicePrincipalSignInActivities": [
            {"appId": "app1", "lastSignInActivity": {"lastSignInDateTime": "2026-02-02T00:00:00Z"}}]})
    sp = col.service_principals()[0]
    assert sp.graph_app_roles == ["Directory.ReadWrite.All"] and sp.owner_count == 0
    assert sp.last_sign_in.month == 2 and col.sp_sign_in_data_available is True


def test_missing_sign_in_report_degrades_instead_of_failing():
    col = collector({
        "/servicePrincipals": lambda kw: [] if kw.get("filter") else [{"id": "s1", "appId": "a"}],
        BETA + "/reports/servicePrincipalSignInActivities": GraphError("400 beta changed", status_code=400)})
    sp = col.service_principals()[0]
    assert sp.last_sign_in is None and col.sp_sign_in_data_available is False


def test_only_the_requested_sections_are_collected():
    """An audit of one check must not pull data the other checks need (FakeGraph fails on unexpected paths)."""
    graph = FakeGraph({"/users": [{"id": "u1"}], "/applications": [], "/servicePrincipals": lambda kw: [],
                       BETA + "/reports/servicePrincipalSignInActivities": []})
    snapshot = c.TenantCollector(graph).collect("t", {"apps"})
    assert [u.id for u in snapshot.users] == ["u1"] and snapshot.applications == [] and snapshot.service_principals == []
    assert snapshot.ca_policies is None and snapshot.role_assignments is None and snapshot.mfa_registrations is None
    assert snapshot.groups is None


def test_groups_used_by_conditional_access_are_named_and_the_excluded_ones_sized():
    graph = FakeGraph({
        "/groups/g-ex": {"id": "g-ex", "displayName": "CA Exclusions"},
        "/groups/g-ex/transitiveMembers": [{"id": "m1"}, {"id": "m2"}, {"id": "m3"}],
        "/groups/g-in": {"id": "g-in", "displayName": "Included"},
        "/groups/g-gone": GraphNotFoundError("404", status_code=404)})
    policy = c.parse_ca_policy({"id": "p", "conditions": {"users": {"includeGroups": ["g-in"], "excludeGroups": ["g-ex", "g-gone"]}}})
    infos = {i.id: i for i in c.TenantCollector(graph).ca_groups([policy])}
    assert infos["g-ex"].member_count == 3 and infos["g-ex"].display_name == "CA Exclusions"
    assert infos["g-in"].member_count is None            # sizes are only counted for exclusion groups
    assert infos["g-gone"].exists is False


def test_group_names_denied_once_stops_asking():
    graph = FakeGraph({"/groups/a": GraphPermissionError("403", status_code=403), "/groups/b": {"id": "b"}})
    policy = c.parse_ca_policy({"id": "p", "conditions": {"users": {"excludeGroups": ["a", "b"]}}})
    col = c.TenantCollector(graph)
    assert col.ca_groups([policy]) == []
    assert [call[0] for call in graph.calls] == ["/groups/a"] and len(col.warnings) == 1

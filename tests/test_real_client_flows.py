"""Toolkit flows driven through the REAL GraphClient (on an httpx mock transport), not a fake.

Fakes can drift from the real client (that is how `graph.base_url` shipped missing). These tests make sure the
requests that actually go over the wire are right for the actions that change a tenant."""

import json

import httpx

from entra_auditor.graph.client import GraphClient
from entra_auditor.toolkit import actions
from entra_auditor.toolkit.actions import execute_plan
from entra_auditor.toolkit.models import GroupSummary, UserSummary
from entra_auditor.toolkit.pim import PimService


class Token:
    def get_token(self):
        return "tok"


def client_for(handler):
    return GraphClient(Token(), transport=httpx.MockTransport(handler), sleep=lambda s: None)


def recorder(responses=None):
    seen = []

    def handler(request):
        body = json.loads(request.content) if request.content else None
        seen.append((request.method, request.url.path, body))
        return (responses or {}).get(request.url.path, httpx.Response(204))

    return seen, handler


GROUP = GroupSummary(id="g1", display_name="Finance", security_enabled=True)
USER = UserSummary(id="u1", upn="a@x.com", display_name="Alice")


def test_adding_a_member_sends_a_link_built_from_the_clients_own_base_url(tmp_path):
    seen, handler = recorder()
    client = client_for(handler)
    plan = actions.plan_add_group_members(GROUP, [USER], client.base_url)
    assert execute_plan(client, plan, log_path=tmp_path / "log.jsonl").status == "ok"
    assert seen == [("POST", "/v1.0/groups/g1/members/$ref",
                     {"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/u1"})]


def test_sovereign_clouds_get_their_own_links(tmp_path):
    seen, handler = recorder()
    client = GraphClient(Token(), base_url="https://graph.microsoft.us/v1.0", transport=httpx.MockTransport(handler))
    execute_plan(client, actions.plan_add_group_owners(GROUP, [USER], client.base_url), log_path=tmp_path / "log.jsonl")
    assert seen[0][2] == {"@odata.id": "https://graph.microsoft.us/v1.0/directoryObjects/u1"}


def test_removing_members_and_owners_uses_the_right_methods_and_paths(tmp_path):
    seen, handler = recorder()
    client = client_for(handler)
    log = tmp_path / "log.jsonl"
    execute_plan(client, actions.plan_remove_group_members(GROUP, [USER]), log_path=log)
    execute_plan(client, actions.plan_remove_group_owners(GROUP, [USER]), log_path=log)
    assert [(m, p) for m, p, _ in seen] == [("DELETE", "/v1.0/groups/g1/members/u1/$ref"),
                                            ("DELETE", "/v1.0/groups/g1/owners/u1/$ref")]


def test_a_password_reset_posts_to_the_documented_endpoint_and_polls_the_operation(tmp_path):
    base = "https://graph.microsoft.com/v1.0/users/u1/authentication"
    responses = {
        "/v1.0/users/u1/authentication/methods/28c10230-6103-485e-b985-444c60001490/resetPassword":
            httpx.Response(202, json={"newPassword": "Abcd1234"}, headers={"Location": base + "/operations/op1"}),
        "/v1.0/users/u1/authentication/operations/op1": httpx.Response(200, json={"status": "succeeded"}),
    }
    seen, handler = recorder(responses)
    result = execute_plan(client_for(handler), actions.plan_reset_password(USER, None), log_path=tmp_path / "l",
                          sleep=lambda s: None)
    assert result.status == "ok" and result.secrets == {"password": "Abcd1234"}
    assert [m for m, _, _ in seen] == ["POST", "GET"] and seen[0][2] == {}


def test_pim_activation_goes_over_the_wire_as_documented():
    responses = {"/v1.0/me": httpx.Response(200, json={"id": "me-id", "userPrincipalName": "me@x.com"}),
                 "/v1.0/roleManagement/directory/roleAssignmentScheduleRequests": httpx.Response(201, json={"id": "r1", "status": "Granted"})}
    seen, handler = recorder(responses)
    pim = PimService(client_for(handler))
    from entra_auditor.toolkit.pim import PimRole
    result = pim.activate(PimRole("role-1", "User Administrator"), reason="INC-1", minutes=45)
    method, path, body = seen[-1]
    assert (method, path) == ("POST", "/v1.0/roleManagement/directory/roleAssignmentScheduleRequests")
    assert body["action"] == "selfActivate" and body["principalId"] == "me-id" and body["roleDefinitionId"] == "role-1"
    assert body["scheduleInfo"]["expiration"] == {"type": "afterDuration", "duration": "PT45M"}
    assert result.active_now


def test_group_pim_activation_posts_to_the_documented_endpoint():
    from datetime import datetime, timezone

    from entra_auditor.toolkit.group_pim import GroupAccess, GroupPimService

    responses = {"/v1.0/me": httpx.Response(200, json={"id": "me-1"}),
                 "/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests":
                     httpx.Response(201, json={"id": "r1", "status": "Provisioned"})}
    seen, handler = recorder(responses)
    svc = GroupPimService(client_for(handler), clock=lambda: datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc))
    result = svc.activate(GroupAccess("g1", "Helpdesk Admins", "member"), reason="INC-1", minutes=60)
    method, path, body = seen[-1]
    assert (method, path) == ("POST", "/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests")
    assert body == {"accessId": "member", "principalId": "me-1", "groupId": "g1", "action": "selfActivate",
                    "justification": "INC-1", "scheduleInfo": {"startDateTime": "2026-01-02T03:04:00Z",
                                                              "expiration": {"type": "afterDuration", "duration": "PT1H"}}}
    assert result.active_now


def test_administrative_unit_changes_use_the_documented_requests(tmp_path):
    from entra_auditor.toolkit.admin_units import AdminUnit, AuMember

    seen, handler = recorder()
    client = client_for(handler)
    log = tmp_path / "log.jsonl"
    unit = AdminUnit(id="au1", display_name="Seattle")
    member = AuMember(id="u1", kind="user", name="Alice")
    execute_plan(client, actions.plan_add_au_members(unit, [member], client.base_url), log_path=log)
    execute_plan(client, actions.plan_remove_au_members(unit, [member]), log_path=log)
    execute_plan(client, actions.plan_update_admin_unit(unit, {"description": "Office"}), log_path=log)
    assert seen == [
        ("POST", "/v1.0/directory/administrativeUnits/au1/members/$ref",
         {"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/u1"}),
        ("DELETE", "/v1.0/directory/administrativeUnits/au1/members/u1/$ref", None),
        ("PATCH", "/v1.0/directory/administrativeUnits/au1", {"description": "Office"}),
    ]

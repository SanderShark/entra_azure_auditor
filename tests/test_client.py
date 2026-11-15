"""GraphClient: paging, retry rules, error mapping. Uses httpx's own MockTransport (no network)."""

import json

import httpx
import pytest

from entra_auditor.graph.client import (
    GraphAuthError,
    GraphClient,
    GraphError,
    GraphNotFoundError,
    GraphPermissionError,
    GraphRetryExhaustedError,
)


class Token:
    def get_token(self):
        return "tok"


def make(handler, **kw):
    sleeps: list = []
    client = GraphClient(Token(), transport=httpx.MockTransport(handler), sleep=sleeps.append,
                         max_retries=3, **kw)
    return client, sleeps


def error(status, code="Err", message="boom", **kw):
    return httpx.Response(status, json={"error": {"code": code, "message": message}}, **kw)


def test_paging_follows_next_links():
    def handler(request):
        if "skiptoken" not in str(request.url):
            return httpx.Response(200, json={"value": [{"id": 1}], "@odata.nextLink": "https://graph.microsoft.com/v1.0/x?$skiptoken=a"})
        return httpx.Response(200, json={"value": [{"id": 2}]})

    client, _ = make(handler)
    assert [i["id"] for i in client.get_paged("/x")] == [1, 2]


def test_max_pages_stops_early():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(200, json={"value": [{"id": len(calls)}], "@odata.nextLink": "https://graph.microsoft.com/v1.0/x?n=1"})

    client, _ = make(handler)
    assert len(list(client.get_paged("/x", max_pages=2))) == 2 and len(calls) == 2


def test_a_next_link_to_another_host_is_refused():
    # the bearer token is attached to every request, so following it would leak the token
    def handler(request):
        return httpx.Response(200, json={"value": [], "@odata.nextLink": "https://evil.example/steal"})

    client, _ = make(handler)
    with pytest.raises(GraphError, match="unexpected host"):
        list(client.get_paged("/x"))


def test_query_options_and_headers_are_sent():
    seen = {}

    def handler(request):
        seen["params"], seen["headers"] = dict(request.url.params), request.headers
        return httpx.Response(200, json={"value": []})

    client, _ = make(handler)
    list(client.get_paged("/users", select=["id", "displayName"], filter="a eq 'b'", top=5, count=True))
    assert seen["params"]["$select"] == "id,displayName"
    assert seen["params"]["$filter"] == "a eq 'b'"
    assert seen["params"]["$top"] == "5" and seen["params"]["$count"] == "true"
    assert seen["headers"]["ConsistencyLevel"] == "eventual"   # required for advanced queries
    assert seen["headers"]["Authorization"] == "Bearer tok"


def test_a_throttled_post_is_retried_honouring_retry_after():
    calls = []

    def handler(request):
        calls.append(1)
        return error(429, headers={"Retry-After": "2"}) if len(calls) == 1 else httpx.Response(201, json={"id": "new"})

    client, sleeps = make(handler)
    assert client.post("/things", {"a": 1}).status_code == 201
    assert len(calls) == 2 and sleeps == [2.0]


def test_a_post_is_not_resent_after_a_server_error():
    # the write may already have been applied: resending could duplicate it
    calls = []

    def handler(request):
        calls.append(1)
        return error(503)

    client, _ = make(handler)
    with pytest.raises(GraphError) as info:
        client.post("/things", {"a": 1})
    assert len(calls) == 1 and info.value.status_code == 503


def test_a_post_is_not_resent_after_a_network_error():
    calls = []

    def handler(request):
        calls.append(1)
        raise httpx.ConnectError("timeout")

    client, _ = make(handler)
    with pytest.raises(GraphError, match="may or may not"):
        client.post("/things", {"a": 1})
    assert len(calls) == 1


def test_patch_and_delete_are_retried_on_server_errors():
    calls = []

    def handler(request):
        calls.append(1)
        return error(503) if len(calls) < 3 else httpx.Response(204)

    client, _ = make(handler)
    response = client.patch("/users/1", {"jobTitle": "x"})
    assert response.status_code == 204 and response.body == {} and len(calls) == 3


def test_delete_is_retried_after_a_network_error():
    calls = []

    def handler(request):
        calls.append(1)
        if len(calls) == 1:
            raise httpx.ConnectError("reset")
        return httpx.Response(204)

    client, _ = make(handler)
    assert client.delete("/groups/1/members/2/$ref").status_code == 204 and len(calls) == 2


def test_gives_up_after_max_retries():
    client, _ = make(lambda request: error(503))
    with pytest.raises(GraphRetryExhaustedError):
        client.patch("/u", {"a": 1})


@pytest.mark.parametrize("status,exc", [(401, GraphAuthError), (403, GraphPermissionError), (404, GraphNotFoundError), (400, GraphError)])
def test_status_codes_map_to_specific_errors(status, exc):
    client, _ = make(lambda request: error(status, code="SomeCode", message="details"))
    with pytest.raises(exc) as info:
        client.get("/x")
    assert info.value.code == "SomeCode" and "details" in str(info.value)


def test_json_body_is_sent_on_writes():
    seen = {}

    def handler(request):
        seen["body"], seen["method"] = json.loads(request.content), request.method
        return httpx.Response(204)

    client, _ = make(handler)
    client.patch("/users/1", {"jobTitle": "Engineer"})
    assert seen == {"body": {"jobTitle": "Engineer"}, "method": "PATCH"}


def test_long_running_operations_expose_the_location_header():
    def handler(request):
        return httpx.Response(202, json={"newPassword": "Abc"}, headers={"Location": "https://graph.microsoft.com/v1.0/users/1/authentication/operations/9"})

    client, _ = make(handler)
    response = client.post("/u/resetPassword", {})
    assert response.location.endswith("/operations/9") and response.body["newPassword"] == "Abc"


def test_get_accepts_an_absolute_url_for_polling():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, json={"status": "succeeded"})

    client, _ = make(handler)
    assert client.get("https://graph.microsoft.com/v1.0/users/1/authentication/operations/9")["status"] == "succeeded"
    assert seen[0].startswith("https://graph.microsoft.com/v1.0/users/1/authentication/operations")


def test_the_base_url_is_exposed_for_building_directory_object_links():
    client, _ = make(lambda request: httpx.Response(200, json={}))
    assert client.base_url == "https://graph.microsoft.com/v1.0"
    sovereign, _ = make(lambda request: httpx.Response(200, json={}), base_url="https://graph.microsoft.us/v1.0/")
    assert sovereign.base_url == "https://graph.microsoft.us/v1.0"


def test_the_same_request_id_is_used_across_retries():
    ids = []

    def handler(request):
        ids.append(request.headers["client-request-id"])
        return error(503) if len(ids) < 2 else httpx.Response(200, json={})

    client, _ = make(handler)
    client.get("/x")
    assert len(ids) == 2 and ids[0] == ids[1]

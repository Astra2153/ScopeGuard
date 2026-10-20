import pytest

from app.matrix import (
    Endpoint,
    MatrixError,
    extract_endpoints,
    fill,
    findings_for,
    same,
    validate_auth,
    validate_object_ids,
)
from app.ssrf import FetchResult, TargetRejected, safe_get


def res(status, body):
    return FetchResult(status, body, False)


def test_extract_endpoints_keeps_only_safe_get_endpoints_with_params():
    spec = {"paths": {
        "/a/{id}": {"get": {}},
        "/b/{id}": {"post": {}},
        "/c": {"get": {}},
        "/d/../{id}": {"get": {}},
        "no-slash/{id}": {"get": {}},
        "/e/{id}/x y": {"get": {}},
        "/f/{}": {"get": {}},
        "/g/{id": {"get": {}},
        "/h/{a}/{b}": {"get": {}},
        "/i//{id}": {"get": {}},
        5: {"get": {}},
    }}
    assert extract_endpoints(spec) == [Endpoint("/a/{id}", ("id",)), Endpoint("/h/{a}/{b}", ("a", "b"))]


@pytest.mark.parametrize("spec", [None, [], {}, {"paths": []}, {"paths": {"/a/{id}": "nope"}}])
def test_extract_endpoints_tolerates_garbage(spec):
    assert extract_endpoints(spec) == []


def test_validate_auth_accepts_only_authorization_and_cookie():
    assert validate_auth({"authorization": "Bearer abc"}) == {"Authorization": "Bearer abc"}
    assert validate_auth({"Cookie": "sid=1"}) == {"Cookie": "sid=1"}


@pytest.mark.parametrize(
    "bad",
    [
        {}, None, "x", {"x-api-key": "k"}, {"authorization": ""}, {"authorization": 5},
        {"authorization": "Bearer x\r\nX-Evil: 1"}, {"authorization": "Bearer \u00e9"},
        {"authorization": "a" * 5000}, {"authorization": "a", "cookie": "b", "x": "c"},
    ],
)
def test_validate_auth_rejects_bad_input(bad):
    with pytest.raises(MatrixError):
        validate_auth(bad)


def test_validate_object_ids():
    assert validate_object_ids({"orderId": "1001"}) == {"orderId": "1001"}
    for bad in ({}, None, {"orderId": "../x"}, {"orderId": "a b"}, {"orderId": "x" * 65},
                {"1bad": "1"}, {"orderId": 5}):
        with pytest.raises(MatrixError):
            validate_object_ids(bad)


def test_fill_substitutes_path_parameters():
    assert fill("/u/{uid}/o/{oid}", {"uid": "1", "oid": "2"}) == "/u/1/o/2"


def test_same_ignores_key_order_and_whitespace():
    assert same(res(200, b'{"a": 1, "b": 2}'), res(200, b'{"b":2,"a":1}'))


def test_same_requires_success_and_content():
    assert not same(res(200, b'{"a":1}'), res(404, b'{"a":1}'))
    assert not same(res(200, b""), res(200, b""))
    assert not same(res(200, b'{"a":1}'), res(200, b'{"a":2}'))
    assert not same(res(401, b"x"), res(401, b"x"))


def test_same_compares_non_json_bytes():
    assert same(res(200, b"plain text"), res(200, b"plain text"))
    assert not same(res(200, b"plain text"), res(200, b"other text"))


def test_findings_are_fixed_text_with_stable_keys():
    f1 = findings_for("/api/orders/{orderId}", "confirmed_bola", True)
    f2 = findings_for("/api/orders/{orderId}", "confirmed_bola", True)
    assert set(f1) == set(f2) and len(f1) == 2
    assert findings_for("/x/{id}", "denied", False) == {}
    assert findings_for("/x/{id}", "inconclusive_catch_all", False) == {}


def test_safe_get_sends_only_allowed_auth_headers(lab_mode, lab_server):
    res_ok = safe_get(lab_server.origin, "/api/orders/1001", auth_headers={"Authorization": "Bearer alice-token"})
    assert res_ok.status == 200
    assert lab_server.httpd.auth_seen[-1][1] == "Bearer alice-token"
    with pytest.raises(TargetRejected):
        safe_get(lab_server.origin, "/ok", auth_headers={"X-Evil": "1"})
    with pytest.raises(TargetRejected):
        safe_get(lab_server.origin, "/ok", auth_headers={"Authorization": "Bearer x\r\nX-Evil: 1"})

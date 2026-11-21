"""IAM users and CloudTrail trails against replayed AWS responses.

Cassettes follow AWS's documented response shapes (IAM query API XML, the
credential report CSV, CloudTrail JSON 1.1); they are not recorded from a live
account. Request signatures change every second, so replay matches on method,
URL, and body.
"""

import json
from pathlib import Path

import pytest
from ogrl_integration.http import Request, Response
from ogrl_integration.testing import Cassette, Harness, HarnessError

from aws_integration import app

CASSETTES = Path(__file__).parent / "cassettes"
CONFIG = {"region": "us-east-1"}
ROLE = {"AWS_ACCESS_KEY_ID": "ASIAEXAMPLE", "AWS_SECRET_ACCESS_KEY": "secret", "AWS_SESSION_TOKEN": "session"}


@pytest.fixture(autouse=True)
def no_wait(monkeypatch):
    monkeypatch.setattr("aws_integration.time.sleep", lambda _s: None)


def collect(resource: str, cassette: str):
    app.transport = Cassette(CASSETTES / f"{cassette}.json")
    return Harness(app).collect(resource, 1, CONFIG, ROLE)


def by_name(items):
    return {i["name"]: i for i in items}


def test_iam_users_from_the_credential_report():
    users = by_name(collect("iam-users", "iam-users").items)
    root = users["<root_account>"]
    assert (root["root"], root["console_access"], root["mfa_active"], root["active_access_keys"]) == (
        True,
        True,
        True,
        1,
    )
    assert users["alice"]["oldest_active_key_rotated"] is None
    bob = users["bob"]
    assert (bob["console_access"], bob["mfa_active"], bob["password_last_used"]) == (True, False, None)
    ci = users["ci-deploy"]
    assert (ci["console_access"], ci["active_access_keys"]) == (False, 2)
    assert ci["oldest_active_key_rotated"] == "2025-12-01T00:00:00Z"
    assert ci["access_key_last_used"] == "2026-11-21T03:00:00Z"
    assert ci["id"] == "arn:aws:iam::447100000000:user/ci-deploy"


def test_root_without_credentials_is_not_a_console_user():
    """Organizations' centralized root access removes member accounts' root credentials.
    The report then says password_enabled=false, as recorded from a live account."""
    (root,) = collect("iam-users", "iam-users-root-removed").items
    assert (root["root"], root["console_access"], root["mfa_active"]) == (True, False, False)


def test_a_report_that_never_finishes_is_incomplete():
    result = collect("iam-users", "iam-users-stuck")
    assert (result.items, result.complete) == ([], False)
    assert "did not finish" in result.reason


def test_trails_read_status_from_each_home_region():
    trails = by_name(collect("trails", "trails").items)
    org = trails["org-trail"]
    assert (org["home_region"], org["multi_region"], org["logging"], org["log_file_validation"]) == (
        "us-west-2",
        True,
        True,
        True,
    )
    assert (org["kms_encrypted"], org["latest_delivery"]) == (True, "2025-11-21T06:00:00Z")
    dev = trails["dev-trail"]
    assert (dev["logging"], dev["latest_delivery_error"]) == (False, "AccessDenied")


class Spy:
    def __init__(self) -> None:
        self.request: Request | None = None

    def send(self, request: Request, timeout: float) -> Response:
        self.request = request
        recorded = json.loads((CASSETTES / "sts.json").read_text())["interactions"][0]
        return Response(200, {}, recorded["body"].encode())


def test_validate_signs_with_the_role_session():
    app.transport = Cassette(CASSETTES / "sts.json")
    out = Harness(app).validate(CONFIG, ROLE)
    assert (
        out["identity"]
        == "447100000000 as arn:aws:sts::447100000000:assumed-role/ogrl-readonly/ogrl-connection"
    )

    app.transport = spy = Spy()
    Harness(app).validate(CONFIG, ROLE)
    headers = spy.request.headers
    assert headers["X-Amz-Security-Token"] == "session"
    assert headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=ASIAEXAMPLE/")
    assert "/us-east-1/sts/aws4_request" in headers["Authorization"]


def test_without_role_credentials_the_operation_is_invalid_config():
    app.transport = Cassette(CASSETTES / "sts.json")
    with pytest.raises(HarnessError) as caught:
        Harness(app).validate(CONFIG, {})
    assert caught.value.kind == "invalid_config"

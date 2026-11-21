from pathlib import Path

from ogrl_integration.testing import Cassette, Harness

from aws_integration import app
from tests.rules import evaluate, template

CASSETTES = Path(__file__).parent / "cassettes"
ROLE = {"AWS_ACCESS_KEY_ID": "a", "AWS_SECRET_ACCESS_KEY": "b", "AWS_SESSION_TOKEN": "c"}


def collect(resource, cassette, monkeypatch):
    monkeypatch.setattr("aws_integration.time.sleep", lambda _s: None)
    app.transport = Cassette(CASSETTES / f"{cassette}.json")
    return Harness(app).collect(resource, 1, {"region": "us-east-1"}, ROLE).items


def test_identity_templates(monkeypatch):
    users = collect("iam-users", "iam-users", monkeypatch)
    arn = "arn:aws:iam::447100000000:"
    selected, failing, _ = evaluate(template("console-mfa"), users)
    assert (selected, failing) == ([f"{arn}root", f"{arn}user/alice", f"{arn}user/bob"], [f"{arn}user/bob"])

    # Library parameter rotation_period is "90 days"; the fixtures are evaluated at 2026-11-21.
    selected, failing, _ = evaluate(template("access-key-age"), users, {"rotation_period": "90 days"})
    assert selected == [f"{arn}root", f"{arn}user/bob", f"{arn}user/ci-deploy"]
    assert failing == selected  # 2021, March 2026, and December 2025 are all older than 90 days

    _, failing, _ = evaluate(template("root-access-keys"), users)
    assert failing == [f"{arn}root"]


def test_audit_logging_template(monkeypatch):
    trails = collect("trails", "trails", monkeypatch)
    assert evaluate(template("audit-logging"), trails)[2] is True
    dev_only = [t for t in trails if t["name"] == "dev-trail"]
    assert evaluate(template("audit-logging"), dev_only)[2] is False

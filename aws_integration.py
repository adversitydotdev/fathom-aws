"""AWS for OGRL (RFC 0005): IAM users from the credential report, and CloudTrail trails.

Credentials come from the `aws_role` connection: the OGRL host assumes the
organization's read-only role and passes short-lived keys. Requests are signed
with SigV4 here (see sigv4.py), so the package needs nothing beyond the SDK.
The role needs `SecurityAudit` plus `iam:GenerateCredentialReport`.
"""

import base64
import csv
import io
import json
import time
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from urllib.parse import urlencode

from ogrl_integration import Incomplete, Integration, InvalidConfig, VendorError

from sigv4 import sign

app = Integration("dev.adversity.aws", "0.1.0")

IAM = "https://iam.amazonaws.com/"
IAM_VERSION = "2010-05-08"
REPORT_POLLS = 15
REPORT_WAIT = 2.0
ROOT = "<root_account>"


def _signed(ctx, method: str, url: str, service: str, region: str, headers=None, body: bytes = b""):
    creds = ctx.aws_credentials
    signed = sign(
        method,
        url,
        dict(headers or {}),
        body,
        access_key=creds["AWS_ACCESS_KEY_ID"],
        secret_key=creds["AWS_SECRET_ACCESS_KEY"],
        session_token=creds.get("AWS_SESSION_TOKEN"),
        region=region,
        service=service,
    )
    return ctx.http.request(method, url, headers=signed, content=body or None)


def _region(ctx) -> str:
    region = ctx.config.get("region")
    if not region:
        raise InvalidConfig("set the region")
    return region


def _iam(ctx, action: str) -> ET.Element:
    url = f"{IAM}?{urlencode({'Action': action, 'Version': IAM_VERSION})}"
    response = _signed(ctx, "GET", url, "iam", "us-east-1")
    return ET.fromstring(response.body)


def _text(root: ET.Element, tag: str) -> str | None:
    found = root.find(f".//{{*}}{tag}")
    return found.text if found is not None else None


@app.validate
def validate(ctx):
    region = _region(ctx)
    body = urlencode({"Action": "GetCallerIdentity", "Version": "2011-06-15"}).encode()
    response = _signed(
        ctx,
        "POST",
        f"https://sts.{region}.amazonaws.com/",
        "sts",
        region,
        {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
        body,
    )
    root = ET.fromstring(response.body)
    return ctx.identity(f"{_text(root, 'Account')} as {_text(root, 'Arn')}")


def _when(value: str | None) -> str | None:
    """Credential report cells: an ISO time, or N/A, no_information, not_supported."""
    if not value or value in ("N/A", "no_information", "not_supported"):
        return None
    return value.replace("+00:00", "Z")


def _report(ctx) -> str:
    for _ in range(REPORT_POLLS):
        if _text(_iam(ctx, "GenerateCredentialReport"), "State") == "COMPLETE":
            break
        time.sleep(REPORT_WAIT)
    else:
        raise Incomplete("the IAM credential report did not finish generating")
    content = _text(_iam(ctx, "GetCredentialReport"), "Content")
    if content is None:
        raise VendorError("GetCredentialReport returned no content")
    return base64.b64decode(content).decode()


@app.resource("iam-users", version=1)
def iam_users(ctx):
    for row in csv.DictReader(io.StringIO(_report(ctx))):
        root = row["user"] == ROOT
        keys = [
            _when(row.get(f"access_key_{n}_last_rotated"))
            for n in (1, 2)
            if row.get(f"access_key_{n}_active") == "true"
        ]
        rotated = sorted(k for k in keys if k)
        used = sorted(u for n in (1, 2) if (u := _when(row.get(f"access_key_{n}_last_used_date"))))
        yield {
            "id": row["arn"],
            "name": row["user"],
            "root": root,
            "created": _when(row.get("user_creation_time")),
            "console_access": root or row.get("password_enabled") == "true",
            "password_last_used": _when(row.get("password_last_used")),
            "mfa_active": row.get("mfa_active") == "true",
            "active_access_keys": len(keys),
            "oldest_active_key_rotated": rotated[0] if rotated else None,
            "access_key_last_used": used[-1] if used else None,
        }


def _cloudtrail(ctx, region: str, operation: str, payload: dict):
    response = _signed(
        ctx,
        "POST",
        f"https://cloudtrail.{region}.amazonaws.com/",
        "cloudtrail",
        region,
        {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": f"com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.{operation}",
        },
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(),
    )
    return response.json()


def _epoch(value) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(float(value), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@app.resource("trails", version=1)
def trails(ctx):
    region = _region(ctx)
    listed = _cloudtrail(ctx, region, "DescribeTrails", {"includeShadowTrails": True})
    for trail in listed.get("trailList", []):
        home = trail.get("HomeRegion") or region
        status = _cloudtrail(ctx, home, "GetTrailStatus", {"Name": trail["TrailARN"]})
        yield {
            "id": trail["TrailARN"],
            "name": trail["Name"],
            "home_region": home,
            "multi_region": trail.get("IsMultiRegionTrail", False),
            "organization_trail": trail.get("IsOrganizationTrail", False),
            "global_service_events": trail.get("IncludeGlobalServiceEvents", False),
            "logging": status.get("IsLogging", False),
            "log_file_validation": trail.get("LogFileValidationEnabled", False),
            "s3_bucket": trail.get("S3BucketName"),
            "kms_encrypted": bool(trail.get("KmsKeyId")),
            "latest_delivery": _epoch(status.get("LatestDeliveryTime")),
            "latest_delivery_error": status.get("LatestDeliveryError"),
        }

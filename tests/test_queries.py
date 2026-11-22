"""Query sources (OGRL RFC 0007) over the bundled AWS models: common queries validate.

Static only: no network. Catches a model that stops loading, or a model update that
renames a member these queries rely on, before the package ships.
"""

from pathlib import Path

import pytest
import yaml
from ogrl_integration import smithy

ROOT = Path(__file__).parents[1]
SETTINGS = smithy.Settings.from_json(yaml.safe_load((ROOT / "manifest.yaml").read_text())["smithy"])
API = smithy.load(SETTINGS, lambda path: (ROOT / path).read_bytes())
Q = smithy.Query

QUERIES = {
    "open security groups": Q(
        "ec2.DescribeSecurityGroups",
        params={"Filters": '[{"Name": "ip-permission.cidr", "Values": ["0.0.0.0/0"]}]'},
        fields={"id": "GroupId", "name": "GroupName", "vpc": "VpcId", "rules": "IpPermissions"},
        regions="*",
    ),
    "EBS encryption by default": Q(
        "ec2.GetEbsEncryptionByDefault",
        fields={"id": "$region", "name": "$region", "enabled": "EbsEncryptionByDefault"},
        regions="*",
    ),
    "EBS volumes": Q(
        "ec2.DescribeVolumes",
        fields={"id": "VolumeId", "name": "VolumeId", "encrypted": "Encrypted", "kms_key": "KmsKeyId"},
        regions="*",
    ),
    "RDS instances": Q(
        "rds.DescribeDBInstances",
        fields={
            "id": "DbiResourceId",
            "name": "DBInstanceIdentifier",
            "encrypted": "StorageEncrypted",
            "public": "PubliclyAccessible",
            "backup_days": "BackupRetentionPeriod",
        },
        regions="*",
    ),
    "KMS keys": Q("kms.ListKeys", fields={"id": "KeyId", "name": "KeyArn"}, regions="*"),
    "GuardDuty detectors": Q("guardduty.ListDetectors", fields={"id": ".", "name": "."}, regions="*"),
    "CloudTrail trails": Q(
        "cloudtrail.ListTrails", fields={"id": "TrailARN", "name": "Name", "home": "HomeRegion"}, regions="*"
    ),
    "S3 buckets": Q(
        "s3.ListBuckets",
        params={"BucketRegion": "$region"},
        fields={"id": "BucketArn", "name": "Name", "created": "CreationDate"},
        regions="*",
    ),
    "S3 bucket encryption": Q(
        "s3.GetBucketEncryption",
        fields={
            "id": "$parent.BucketArn",
            "name": "$parent.Name",
            "rules": "ServerSideEncryptionConfiguration.Rules",
        },
        regions="*",
        for_each=smithy.ForEach(
            "s3.ListBuckets", bind={"Bucket": "Name"}, params={"BucketRegion": "$region"}
        ),
    ),
    "S3 public access block": Q(
        "s3.GetPublicAccessBlock",
        fields={
            "id": "$parent.BucketArn",
            "name": "$parent.Name",
            "block_public_acls": "PublicAccessBlockConfiguration.BlockPublicAcls",
            "block_public_policy": "PublicAccessBlockConfiguration.BlockPublicPolicy",
            "ignore_public_acls": "PublicAccessBlockConfiguration.IgnorePublicAcls",
            "restrict_public_buckets": "PublicAccessBlockConfiguration.RestrictPublicBuckets",
        },
        regions="*",
        for_each=smithy.ForEach(
            "s3.ListBuckets", bind={"Bucket": "Name"}, params={"BucketRegion": "$region"}
        ),
    ),
    "IAM roles": Q(
        "iam.ListRoles",
        fields={"id": "RoleId", "name": "RoleName", "last_used": "RoleLastUsed.LastUsedDate"},
    ),
    "IAM password policy": Q(
        "iam.GetAccountPasswordPolicy",
        fields={
            "id": "PasswordPolicy.MinimumPasswordLength",
            "name": "PasswordPolicy.MinimumPasswordLength",
            "min_length": "PasswordPolicy.MinimumPasswordLength",
            "symbols": "PasswordPolicy.RequireSymbols",
        },
    ),
}


@pytest.mark.parametrize("label", sorted(QUERIES))
def test_common_queries_validate(label):
    problems, schema = smithy.validate(API, QUERIES[label])
    assert [(p.pointer, p.detail) for p in problems] == []
    assert schema and set(QUERIES[label].fields) <= set(schema["properties"])


def test_every_denied_operation_exists():
    """A typo in deny_operations would deny nothing."""
    assert [name for name in SETTINGS.deny_operations if name not in API.operations] == []


@pytest.mark.parametrize(
    "name",
    [
        "ec2.GetPasswordData",
        "ec2.DescribeInstanceAttribute",
        "iam.CreateUser",
        "s3.GetObject",
        "s3.PutBucketPolicy",
    ],
)
def test_content_reads_and_writes_cannot_be_queried(name):
    assert not API.operations[name].readable


def test_every_service_speaks_a_supported_protocol():
    assert {m.protocol for m in API.models.values()} <= set(smithy.SUPPORTED)

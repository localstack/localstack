import json
from uuid import uuid4

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


class TestKmsPartitions:
    # We only have access to the AWS partition, not CHINA/US-GOV/etc
    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-1", "aws"), ("cn-north-1", "aws-cn")])
    def test_key_in_different_partitions(self, account_id, aws_client_factory, region, partition):
        kms_client = aws_client_factory(region_name=region).kms

        key = kms_client.create_key(Description="test", KeyUsage="ENCRYPT_DECRYPT")["KeyMetadata"]
        assert key["Arn"] == f"arn:{partition}:kms:{region}:{account_id}:key/{key['KeyId']}"

        key_policy = json.loads(
            kms_client.get_key_policy(KeyId=key["KeyId"], PolicyName="default")["Policy"]
        )
        principal = key_policy["Statement"][0]["Principal"]["AWS"]
        assert principal == f"arn:{partition}:iam::{account_id}:root"

        # Just validate it can be found
        kms_client.describe_key(KeyId=key["KeyId"])
        kms_client.describe_key(KeyId=key["Arn"])

        # Create/list grants
        kms_client.create_grant(
            KeyId=key["Arn"], GranteePrincipal="someone", Operations=["Decrypt"]
        )
        grants = kms_client.list_grants(KeyId=key["Arn"])["Grants"]
        assert len(grants) == 1

        # DescribeKey should throw a partition-aware error for unknown keys
        unknown_key_id = str(uuid4())
        with pytest.raises(ClientError) as exc:
            kms_client.describe_key(KeyId=unknown_key_id)
        err = exc.value.response["Error"]
        assert (
            err["Message"]
            == f"Key 'arn:{partition}:kms:{region}:{account_id}:key/{unknown_key_id}' does not exist"
        )

    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-1", "aws"), ("cn-north-1", "aws-cn")])
    def test_alias_in_different_partitions(self, account_id, aws_client_factory, region, partition):
        kms_client = aws_client_factory(region_name=region).kms

        key = kms_client.create_key(Description="test", KeyUsage="ENCRYPT_DECRYPT")["KeyMetadata"]

        alias_name = f"alias/{short_uid()}"
        kms_client.create_alias(AliasName=alias_name, TargetKeyId=key["KeyId"])

        alias = kms_client.list_aliases(KeyId=key["KeyId"])["Aliases"][0]
        assert alias["AliasArn"] == f"arn:{partition}:kms:{region}:{account_id}:{alias_name}"

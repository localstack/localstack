import botocore.exceptions
import pytest

from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID


class TestKMS:
    def test_create_key(self, kms_client):

        response = kms_client.list_keys()
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        keys_before = response["Keys"]

        response = kms_client.create_key(
            Policy="policy1", Description="test key 123", KeyUsage="ENCRYPT_DECRYPT"
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        key_id = response["KeyMetadata"]["KeyId"]

        response = kms_client.list_keys()
        assert len(response["Keys"]) == len(keys_before) + 1

        response = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
        assert response["KeyId"] == key_id
        assert ":%s:" % config.DEFAULT_REGION in response["Arn"]
        assert ":%s:" % TEST_AWS_ACCOUNT_ID in response["Arn"]

    def test_create_grant_with_invalid_key(self, kms_client):
        with pytest.raises(botocore.exceptions.ClientError):
            kms_client.create_grant(
                KeyId="invalid",
                GranteePrincipal="arn:aws:iam::000000000000:role/test",
                Operations=["Decrypt", "Encrypt"],
            )

    def test_list_grants_with_invalid_key(self, kms_client):
        with pytest.raises(botocore.exceptions.ClientError):
            kms_client.list_grants(
                KeyId="invalid",
            )

    def test_create_grant_with_valid_key(self, kms_client, kms_key):
        key_id = kms_key["KeyMetadata"]["KeyId"]

        grants_before = kms_client.list_grants(KeyId=key_id)["Grants"]

        grant = kms_client.create_grant(
            KeyId=key_id,
            GranteePrincipal="arn:aws:iam::000000000000:role/test",
            Operations=["Decrypt", "Encrypt"],
        )
        assert "GrantId" in grant
        assert "GrantToken" in grant

        grants_after = kms_client.list_grants(KeyId=key_id)["Grants"]
        assert len(grants_after) == len(grants_before) + 1

    def test_revoke_grant(self, kms_client, kms_grant_and_key):
        grant = kms_grant_and_key[0]
        key_id = kms_grant_and_key[1]["KeyMetadata"]["KeyId"]
        grants_before = kms_client.list_grants(KeyId=key_id)["Grants"]

        kms_client.revoke_grant(KeyId=key_id, GrantId=grant["GrantId"])

        grants_after = kms_client.list_grants(KeyId=key_id)["Grants"]
        assert len(grants_after) == len(grants_before) - 1

    def test_retire_grant(self, kms_client, kms_grant_and_key):
        grant = kms_grant_and_key[0]
        key_id = kms_grant_and_key[1]["KeyMetadata"]["KeyId"]
        grants_before = kms_client.list_grants(KeyId=key_id)["Grants"]

        kms_client.retire_grant(GrantToken=grant["GrantToken"])

        grants_after = kms_client.list_grants(KeyId=key_id)["Grants"]
        assert len(grants_after) == len(grants_before) - 1

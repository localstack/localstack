import pytest
from botocore.exceptions import ClientError

from localstack.constants import TEST_AWS_ACCOUNT_ID


def test_lifecycle_public_access_block(s3control_client):
    with pytest.raises(ClientError) as ce:
        s3control_client.get_public_access_block(AccountId=TEST_AWS_ACCOUNT_ID)
    assert ce.value.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration"

    access_block_config = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }

    put_response = s3control_client.put_public_access_block(
        AccountId=TEST_AWS_ACCOUNT_ID, PublicAccessBlockConfiguration=access_block_config
    )

    assert put_response["ResponseMetadata"]["HTTPStatusCode"] == 201

    get_response = s3control_client.get_public_access_block(AccountId=TEST_AWS_ACCOUNT_ID)
    assert access_block_config == get_response["PublicAccessBlockConfiguration"]

    s3control_client.delete_public_access_block(AccountId=TEST_AWS_ACCOUNT_ID)


def test_public_access_block_validations(s3control_client):
    with pytest.raises(ClientError) as error:
        s3control_client.get_public_access_block(AccountId="111111111111")
    assert error.value.response["Error"]["Code"] == "AccessDenied"

    with pytest.raises(ClientError) as error:
        s3control_client.put_public_access_block(
            AccountId="111111111111",
            PublicAccessBlockConfiguration={"BlockPublicAcls": True},
        )
    assert error.value.response["Error"]["Code"] == "AccessDenied"

    with pytest.raises(ClientError) as error:
        s3control_client.put_public_access_block(
            AccountId=TEST_AWS_ACCOUNT_ID, PublicAccessBlockConfiguration={}
        )
    assert error.value.response["Error"]["Code"] == "InvalidRequest"

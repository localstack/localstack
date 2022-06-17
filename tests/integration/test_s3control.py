import pytest
from botocore.exceptions import ClientError

from localstack.aws.accounts import get_aws_account_id
from localstack.config import EDGE_PORT
from localstack.constants import LOCALHOST_HOSTNAME
from localstack.utils.aws.aws_stack import create_external_boto_client

remote_endpoint = "https://%s:%s" % (LOCALHOST_HOSTNAME, EDGE_PORT)
s3control_client = create_external_boto_client("s3control", endpoint_url=remote_endpoint)


def test_lifecycle_public_access_block():
    with pytest.raises(ClientError) as ce:
        s3control_client.get_public_access_block(AccountId=get_aws_account_id())
    assert ce.value.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration"

    access_block_config = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }

    put_response = s3control_client.put_public_access_block(
        AccountId=get_aws_account_id(), PublicAccessBlockConfiguration=access_block_config
    )

    assert put_response["ResponseMetadata"]["HTTPStatusCode"] == 201

    get_response = s3control_client.get_public_access_block(AccountId=get_aws_account_id())
    assert access_block_config == get_response["PublicAccessBlockConfiguration"]

    s3control_client.delete_public_access_block(AccountId=get_aws_account_id())


def test_public_access_block_validations():
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
            AccountId=get_aws_account_id(), PublicAccessBlockConfiguration={}
        )
    assert error.value.response["Error"]["Code"] == "InvalidRequest"

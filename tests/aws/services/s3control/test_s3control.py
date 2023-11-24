import pytest
from botocore.client import Config
from botocore.exceptions import ClientError

from localstack import config
from localstack.constants import (
    TEST_AWS_ACCESS_KEY_ID,
    TEST_AWS_ACCOUNT_ID,
    TEST_AWS_SECRET_ACCESS_KEY,
)
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers

remote_endpoint = config.external_service_url(protocol="https")
s3_control_endpoint = f"http://s3-control.{remote_endpoint.split('://')[1]}"


@pytest.fixture(autouse=True)
def s3control_snapshot(snapshot):
    snapshot.add_transformers_list(
        [snapshot.transform.key_value("HostId", reference_replacement=False)]
    )


@pytest.fixture
def s3control_client(aws_client_factory, aws_client):
    """
    The endpoint for S3 Control looks like `http(s)://<account-id>.s3-control.<host>/v20180820/configuration/<path>
    We need to manually set it to something else than `localhost` so that it is resolvable, as boto will prefix the host
    with the account-id
    """
    if not is_aws_cloud():
        return aws_client_factory(
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
            endpoint_url=s3_control_endpoint,
        ).s3control
    else:
        return aws_client.s3control


@markers.aws.unknown
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

    assert put_response["ResponseMetadata"]["HTTPStatusCode"] == 200

    get_response = s3control_client.get_public_access_block(AccountId=TEST_AWS_ACCOUNT_ID)
    assert access_block_config == get_response["PublicAccessBlockConfiguration"]

    s3control_client.delete_public_access_block(AccountId=TEST_AWS_ACCOUNT_ID)


@markers.aws.unknown
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


class TestS3ControlPublicAccessBlock:
    @markers.aws.validated
    # @pytest.mark.xfail(
    #     condition=config.LEGACY_V2_S3_PROVIDER,
    #     reason="Moto implementation does not have default public access block",
    # )
    def test_crud_public_access_block(self, s3control_client, account_id, snapshot):
        with pytest.raises(ClientError) as e:
            s3control_client.get_public_access_block(AccountId=account_id)
        snapshot.match("get-default-public-access-block", e.value.response)

        put_public_access_block = s3control_client.put_public_access_block(
            AccountId=account_id,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
            },
        )
        snapshot.match("put-public-access-block", put_public_access_block)

        get_public_access_block = s3control_client.get_public_access_block(AccountId=account_id)
        snapshot.match("get-public-access-block", get_public_access_block)

        delete_public_access_block = s3control_client.delete_public_access_block(
            AccountId=account_id
        )
        snapshot.match("delete-public-access-block", delete_public_access_block)

        with pytest.raises(ClientError) as e:
            s3control_client.get_public_access_block(AccountId=account_id)
        snapshot.match("get-public-access-block-after-delete", e.value.response)

        delete_public_access_block = s3control_client.delete_public_access_block(
            AccountId=account_id
        )
        snapshot.match("idempotent-delete-public-access-block", delete_public_access_block)

    @markers.aws.validated
    def test_empty_public_access_block(self, aws_client_factory, account_id, snapshot):
        # we need to disable validation for this test
        if not is_aws_cloud():
            s3control_client = aws_client_factory(
                config=Config(parameter_validation=False),
                aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
                aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
                endpoint_url=s3_control_endpoint,
            ).s3control
        else:
            s3control_client = aws_client_factory(
                config=Config(parameter_validation=False)
            ).s3control

        with pytest.raises(ClientError) as e:
            s3control_client.put_public_access_block(
                AccountId=account_id,
                PublicAccessBlockConfiguration={},
            )
        snapshot.match("put-public-access-block-empty", e.value.response)
        # Wanted to try it with a wrong key in the PublicAccessBlockConfiguration but boto is unable to serialize


class TestS3ControlAccessPoint:
    pass

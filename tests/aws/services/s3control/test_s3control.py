import contextlib

import pytest
from botocore.client import Config
from botocore.exceptions import ClientError

from localstack.constants import (
    TEST_AWS_ACCESS_KEY_ID,
    TEST_AWS_ACCOUNT_ID,
    TEST_AWS_SECRET_ACCESS_KEY,
)
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.urls import localstack_host

s3_control_endpoint = f"http://s3-control.{localstack_host()}"


@pytest.fixture(autouse=True)
def s3control_snapshot(snapshot):
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("HostId", reference_replacement=False),
            snapshot.transform.key_value("Name"),
            snapshot.transform.key_value("Bucket"),
            snapshot.transform.regex("amazonaws.com", "<endpoint-host>"),
            snapshot.transform.regex(localstack_host().host_and_port(), "<endpoint-host>"),
            snapshot.transform.regex(
                '([a-z0-9]{34})(?=.*-s3alias")', replacement="<alias-random-part>"
            ),
        ]
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


@pytest.fixture
def s3control_client_no_validation(aws_client_factory):
    if not is_aws_cloud():
        s3control_client = aws_client_factory(
            config=Config(parameter_validation=False),
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
            endpoint_url=s3_control_endpoint,
        ).s3control
    else:
        s3control_client = aws_client_factory(config=Config(parameter_validation=False)).s3control

    return s3control_client


@pytest.fixture
def s3control_create_access_point(s3control_client):
    access_points = []

    def _create_access_point(**kwargs):
        resp = s3control_client.create_access_point(**kwargs)
        access_points.append((kwargs["Name"], kwargs["AccountId"]))
        return resp

    yield _create_access_point

    for access_point_name, account_id in access_points:
        with contextlib.suppress(ClientError):
            s3control_client.delete_access_point(AccountId=account_id, Name=access_point_name)


class TestLegacyS3Control:
    @markers.aws.unknown
    def test_lifecycle_public_access_block(self, s3control_client):
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
    @pytest.mark.skip(reason="Moto forces IAM use with the account id even when not enabled")
    def test_public_access_block_validations(self, s3control_client):
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
    def test_empty_public_access_block(self, s3control_client_no_validation, account_id, snapshot):
        # we need to disable validation for this test

        with pytest.raises(ClientError) as e:
            s3control_client_no_validation.put_public_access_block(
                AccountId=account_id,
                PublicAccessBlockConfiguration={},
            )
        snapshot.match("put-public-access-block-empty", e.value.response)
        # Wanted to try it with a wrong key in the PublicAccessBlockConfiguration but boto is unable to serialize


class TestS3ControlAccessPoint:
    @markers.aws.validated
    def test_access_point_lifecycle(
        self, s3control_client, s3control_create_access_point, account_id, s3_bucket, snapshot
    ):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("Name"),
                snapshot.transform.key_value("Bucket"),
                snapshot.transform.regex("amazonaws.com", "<endpoint-host>"),
                snapshot.transform.regex(localstack_host().host_and_port(), "<endpoint-host>"),
            ]
        )

        list_access_points = s3control_client.list_access_points(AccountId=account_id)
        snapshot.match("list-access-points-start", list_access_points)

        ap_name = short_uid()
        create_access_point = s3control_create_access_point(
            AccountId=account_id, Name=ap_name, Bucket=s3_bucket
        )

        alias_random_part = create_access_point["Alias"].split("-")[1]
        assert len(alias_random_part) == 34

        snapshot.match("create-access-point", create_access_point)

        get_access_point = s3control_client.get_access_point(AccountId=account_id, Name=ap_name)
        snapshot.match("get-access-point", get_access_point)

        list_access_points = s3control_client.list_access_points(AccountId=account_id)
        snapshot.match("list-access-points-after-create", list_access_points)

        delete_access_point = s3control_client.delete_access_point(
            AccountId=account_id, Name=ap_name
        )
        snapshot.match("delete-access-point", delete_access_point)

        list_access_points = s3control_client.list_access_points(AccountId=account_id)
        snapshot.match("list-access-points-after-delete", list_access_points)

        with pytest.raises(ClientError) as e:
            s3control_client.get_access_point(AccountId=account_id, Name=ap_name)
        snapshot.match("get-delete-access-point", e.value.response)

        with pytest.raises(ClientError) as e:
            s3control_client.delete_access_point(AccountId=account_id, Name=ap_name)
        snapshot.match("delete-already-deleted-access-point", e.value.response)

    @markers.aws.validated
    def test_access_point_bucket_not_exists(
        self, s3control_create_access_point, account_id, snapshot
    ):
        ap_name = short_uid()
        with pytest.raises(ClientError) as e:
            s3control_create_access_point(
                AccountId=account_id,
                Name=ap_name,
                Bucket=f"fake-bucket-{short_uid()}-{short_uid()}",
            )
        snapshot.match("access-point-bucket-not-exists", e.value.response)

    @markers.aws.validated
    def test_access_point_name_validation(
        self, s3control_client_no_validation, account_id, snapshot, s3_bucket
    ):
        # not using parametrization because that would be a lot of snapshot.
        # only validate the first one
        wrong_name = "xn--test-alias"
        wrong_names = [
            "-hyphen-start",
            "cannot-end-s3alias",
            "cannot-have.dot",
        ]

        with pytest.raises(ClientError) as e:
            s3control_client_no_validation.create_access_point(
                AccountId=account_id,
                Name=wrong_name,
                Bucket=s3_bucket,
            )
        snapshot.match("access-point-wrong-naming", e.value.response)

        for name in wrong_names:
            with pytest.raises(ClientError) as e:
                s3control_client_no_validation.create_access_point(
                    AccountId=account_id,
                    Name=name,
                    Bucket=s3_bucket,
                )
            assert e.match("Your Amazon S3 AccessPoint name is invalid"), (name, e.value.response)

        # error is different for too short of a name
        with pytest.raises(ClientError) as e:
            s3control_client_no_validation.create_access_point(
                AccountId=account_id,
                Name="sa",
                Bucket=s3_bucket,
            )
        snapshot.match("access-point-name-too-short", e.value.response)

        uri_error_names = [
            "a" * 51,
            "WRONG-casing",
            "cannot-have_underscore",
        ]
        for name in uri_error_names:
            with pytest.raises(ClientError) as e:
                s3control_client_no_validation.create_access_point(
                    AccountId=account_id,
                    Name="a" * 51,
                    Bucket=s3_bucket,
                )
            assert e.match("InvalidURI"), (name, e.value.response)

    @markers.aws.validated
    def test_access_point_already_exists(
        self, s3control_create_access_point, s3_bucket, account_id, snapshot
    ):
        ap_name = short_uid()
        s3control_create_access_point(AccountId=account_id, Name=ap_name, Bucket=s3_bucket)
        with pytest.raises(ClientError) as e:
            s3control_create_access_point(AccountId=account_id, Name=ap_name, Bucket=s3_bucket)
        snapshot.match("access-point-already-exists", e.value.response)

    @markers.aws.validated
    def test_access_point_vpc_config(
        self, s3control_create_access_point, s3control_client, account_id, snapshot, s3_bucket
    ):
        pass

    @markers.aws.validated
    def test_access_point_public_access_block_configuration(
        self, s3control_client, s3control_create_access_point, account_id, snapshot, s3_bucket
    ):
        # set a letter in the name for ordering
        ap_name_1 = f"a{short_uid()}"
        response = s3control_create_access_point(
            AccountId=account_id,
            Name=ap_name_1,
            Bucket=s3_bucket,
            PublicAccessBlockConfiguration={},
        )
        snapshot.match("put-ap-empty-pabc", response)
        get_ap = s3control_client.get_access_point(AccountId=account_id, Name=ap_name_1)
        snapshot.match("get-ap-empty-pabc", get_ap)

        ap_name_2 = f"b{short_uid()}"
        response = s3control_create_access_point(
            AccountId=account_id,
            Name=ap_name_2,
            Bucket=s3_bucket,
            PublicAccessBlockConfiguration={"BlockPublicAcls": False},
        )
        snapshot.match("put-ap-partial-pabc", response)
        get_ap = s3control_client.get_access_point(AccountId=account_id, Name=ap_name_2)
        snapshot.match("get-ap-partial-pabc", get_ap)

        ap_name_3 = f"c{short_uid()}"
        response = s3control_create_access_point(
            AccountId=account_id,
            Name=ap_name_3,
            Bucket=s3_bucket,
            PublicAccessBlockConfiguration={"BlockPublicAcls": True},
        )
        snapshot.match("put-ap-partial-true-pabc", response)
        get_ap = s3control_client.get_access_point(AccountId=account_id, Name=ap_name_3)
        snapshot.match("get-ap-partial-true-pabc", get_ap)

        ap_name_4 = f"d{short_uid()}"
        response = s3control_create_access_point(
            AccountId=account_id,
            Name=ap_name_4,
            Bucket=s3_bucket,
        )
        snapshot.match("put-ap-pabc-not-set", response)
        get_ap = s3control_client.get_access_point(AccountId=account_id, Name=ap_name_4)
        snapshot.match("get-ap-pabc-not-set", get_ap)

        list_access_points = s3control_client.list_access_points(AccountId=account_id)
        snapshot.match("list-access-points", list_access_points)

    @markers.aws.validated
    def test_access_point_regions(self):
        pass

    @markers.aws.validated
    def test_access_point_pagination(self):
        pass

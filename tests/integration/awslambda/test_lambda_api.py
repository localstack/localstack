"""
API-focused tests only. Don't add tests for asynchronous, blocking or implicit behavior here.

# TODO: create a re-usable pattern for fairly reproducible scenarios with slower updates/creates to test intermediary states
# TODO: code signing https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html
# TODO: file systems https://docs.aws.amazon.com/lambda/latest/dg/configuration-filesystem.html
# TODO: VPC config https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html

"""
import base64
import io
import json
from hashlib import sha256
from io import BytesIO
from typing import Callable

import pytest
import requests
from botocore.config import Config
from botocore.exceptions import ClientError

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.lambda_utils import is_old_provider
from localstack.testing.snapshots.transformer import SortingTransformer
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.files import load_file
from localstack.utils.strings import long_uid, short_uid, to_str
from localstack.utils.sync import wait_until
from localstack.utils.testutil import create_lambda_archive
from tests.integration.awslambda.test_lambda import (
    FUNCTION_MAX_UNZIPPED_SIZE,
    TEST_LAMBDA_NODEJS,
    TEST_LAMBDA_PYTHON_ECHO,
    TEST_LAMBDA_PYTHON_VERSION,
)

KB = 1024


@pytest.fixture(autouse=True)
def fixture_snapshot(snapshot):
    snapshot.add_transformer(snapshot.transform.lambda_api())
    snapshot.add_transformer(snapshot.transform.key_value("CodeSha256"))


def string_length_bytes(s: str) -> int:
    return len(s.encode("utf-8"))


def environment_length_bytes(e: dict) -> int:
    serialized_environment = json.dumps(e, separators=(":", ","))
    return string_length_bytes(serialized_environment)


@pytest.mark.skipif(is_old_provider(), reason="focusing on new provider")
class TestLambdaFunction:
    @pytest.mark.aws_validated
    def test_function_lifecycle(
        self, lambda_client, snapshot, create_lambda_function, lambda_su_role
    ):
        """Tests CRUD for the lifecycle of a Lambda function and its config"""
        function_name = f"fn-{short_uid()}"
        create_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
            MemorySize=256,
            Timeout=5,
        )
        snapshot.match("create_response", create_response)
        lambda_client.get_waiter("function_active_v2").wait(FunctionName=function_name)

        get_function_response = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get_function_response", get_function_response)

        update_func_conf_response = lambda_client.update_function_configuration(
            FunctionName=function_name,
            Runtime=Runtime.python3_8,
            Description="Changed-Description",
            MemorySize=512,
            Timeout=10,
            Environment={"Variables": {"ENV_A": "a"}},
        )
        snapshot.match("update_func_conf_response", update_func_conf_response)

        lambda_client.get_waiter("function_updated_v2").wait(FunctionName=function_name)

        get_function_response_postupdate = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get_function_response_postupdate", get_function_response_postupdate)

        zip_f = create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_VERSION), get_content=True)
        update_code_response = lambda_client.update_function_code(
            FunctionName=function_name,
            ZipFile=zip_f,
        )
        snapshot.match("update_code_response", update_code_response)

        lambda_client.get_waiter("function_updated_v2").wait(FunctionName=function_name)

        get_function_response_postcodeupdate = lambda_client.get_function(
            FunctionName=function_name
        )
        snapshot.match("get_function_response_postcodeupdate", get_function_response_postcodeupdate)

        delete_response = lambda_client.delete_function(FunctionName=function_name)
        snapshot.match("delete_response", delete_response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.delete_function(FunctionName=function_name)
        snapshot.match("delete_postdelete", e.value.response)

    @pytest.mark.aws_validated
    def test_redundant_updates(self, lambda_client, create_lambda_function, snapshot):
        """validates that redundant updates work (basically testing idempotency)"""
        function_name = f"fn-{short_uid()}"

        create_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            Description="Initial description",
        )
        snapshot.match("create_response", create_response)

        first_update_result = lambda_client.update_function_configuration(
            FunctionName=function_name, Description="1st update description"
        )
        snapshot.match("first_update_result", first_update_result)

        lambda_client.get_waiter("function_updated_v2").wait(FunctionName=function_name)

        get_fn_config_result = lambda_client.get_function_configuration(FunctionName=function_name)
        snapshot.match("get_fn_config_result", get_fn_config_result)

        get_fn_result = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get_fn_result", get_fn_result)

        redundant_update_result = lambda_client.update_function_configuration(
            FunctionName=function_name, Description="1st update description"
        )
        snapshot.match("redundant_update_result", redundant_update_result)
        lambda_client.get_waiter("function_updated_v2").wait(FunctionName=function_name)
        get_fn_result_after_redundant_update = lambda_client.get_function(
            FunctionName=function_name
        )
        snapshot.match("get_fn_result_after_redundant_update", get_fn_result_after_redundant_update)

    @pytest.mark.parametrize(
        "clientfn",
        [
            "delete_function",
            "get_function",
            "get_function_configuration",
        ],
    )
    @pytest.mark.aws_validated
    def test_ops_with_arn_qualifier_mismatch(
        self, lambda_client, create_lambda_function, snapshot, account_id, clientfn
    ):
        function_name = "some-function"
        method = getattr(lambda_client, clientfn)
        with pytest.raises(ClientError) as e:
            method(
                FunctionName=f"arn:aws:lambda:{lambda_client.meta.region_name}:{account_id}:function:{function_name}:1",
                Qualifier="$LATEST",
            )
        snapshot.match("not_match_exception", e.value.response)
        # check if it works if it matches - still no function there
        with pytest.raises(ClientError) as e:
            method(
                FunctionName=f"arn:aws:lambda:{lambda_client.meta.region_name}:{account_id}:function:{function_name}:$LATEST",
                Qualifier="$LATEST",
            )
        snapshot.match("match_exception", e.value.response)

    @pytest.mark.parametrize(
        "clientfn",
        [
            "get_function",
            "get_function_configuration",
            "get_function_event_invoke_config",
        ],
    )
    @pytest.mark.aws_validated
    def test_ops_on_nonexisting_version(
        self, lambda_client, create_lambda_function, snapshot, clientfn
    ):
        """Test API responses on existing function names, but not existing versions"""
        function_name = f"i-exist-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(function_name, "<fn-name>"))
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            Description="Initial description",
        )
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            method = getattr(lambda_client, clientfn)
            method(FunctionName=function_name, Qualifier="1221")
        snapshot.match("version_not_found_exception", e.value.response)

    @pytest.mark.aws_validated
    def test_delete_on_nonexisting_version(self, lambda_client, create_lambda_function, snapshot):
        """Test API responses on existing function names, but not existing versions"""
        function_name = f"i-exist-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(function_name, "<fn-name>"))
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            Description="Initial description",
        )
        # it seems delete function on a random qualifier is idempotent
        lambda_client.delete_function(FunctionName=function_name, Qualifier="1233")
        lambda_client.delete_function(FunctionName=function_name, Qualifier="1233")
        lambda_client.delete_function(FunctionName=function_name)
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.delete_function(FunctionName=function_name)
        snapshot.match("delete_function_response_non_existent", e.value.response)
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.delete_function(FunctionName=function_name, Qualifier="1233")
        snapshot.match("delete_function_response_non_existent_with_qualifier", e.value.response)

    @pytest.mark.parametrize(
        "clientfn",
        [
            "delete_function",
            "get_function",
            "get_function_configuration",
            "get_function_url_config",
            "get_function_code_signing_config",
            "get_function_event_invoke_config",
            "get_function_concurrency",
        ],
    )
    @pytest.mark.aws_validated
    def test_ops_on_nonexisting_fn(self, lambda_client, snapshot, clientfn):
        """Test API responses on non-existing function names"""
        # technically the short_uid isn't really required but better safe than sorry
        function_name = f"i-dont-exist-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(function_name, "<nonexisting-fn-name>"))
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            method = getattr(lambda_client, clientfn)
            method(FunctionName=function_name)
        snapshot.match("not_found_exception", e.value.response)

    @pytest.mark.parametrize(
        "clientfn",
        [
            "get_function",
            "get_function_configuration",
            "get_function_url_config",
            "get_function_code_signing_config",
            "get_function_event_invoke_config",
            "get_function_concurrency",
            "delete_function",
            "invoke",
        ],
    )
    @pytest.mark.aws_validated
    def test_get_function_wrong_region(
        self, lambda_client, create_lambda_function, account_id, snapshot, clientfn
    ):
        function_name = f"i-exist-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(function_name, "<fn-name>"))
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            Description="Initial description",
        )
        wrong_region = (
            "us-east-1" if lambda_client.meta.region_name != "us-east-1" else "eu-central-1"
        )
        snapshot.add_transformer(snapshot.transform.regex(wrong_region, "<wrong-region>"))
        wrong_region_arn = f"arn:aws:lambda:{wrong_region}:{account_id}:function:{function_name}"
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            method = getattr(lambda_client, clientfn)
            method(FunctionName=wrong_region_arn)
        snapshot.match("wrong_region_exception", e.value.response)

    def test_lambda_code_location_zipfile(
        self, lambda_client, snapshot, create_lambda_function_aws, lambda_su_role
    ):
        function_name = f"code-function-{short_uid()}"
        zip_file_bytes = create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True)
        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Handler="index.handler",
            Code={"ZipFile": zip_file_bytes},
            PackageType="Zip",
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
        )
        snapshot.match("create-response-zip-file", create_response)
        get_function_response = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get-function-response", get_function_response)
        code_location = get_function_response["Code"]["Location"]
        response = requests.get(code_location)
        assert zip_file_bytes == response.content
        h = sha256(zip_file_bytes)
        b64digest = to_str(base64.b64encode(h.digest()))
        assert b64digest == get_function_response["Configuration"]["CodeSha256"]
        assert len(zip_file_bytes) == get_function_response["Configuration"]["CodeSize"]
        zip_file_bytes_updated = create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON_VERSION), get_content=True
        )
        update_function_response = lambda_client.update_function_code(
            FunctionName=function_name, ZipFile=zip_file_bytes_updated
        )
        snapshot.match("update-function-response", update_function_response)
        get_function_response_updated = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get-function-response-updated", get_function_response_updated)
        code_location_updated = get_function_response_updated["Code"]["Location"]
        response = requests.get(code_location_updated)
        assert zip_file_bytes_updated == response.content
        h = sha256(zip_file_bytes_updated)
        b64digest_updated = to_str(base64.b64encode(h.digest()))
        assert b64digest != b64digest_updated
        assert b64digest_updated == get_function_response_updated["Configuration"]["CodeSha256"]
        assert (
            len(zip_file_bytes_updated)
            == get_function_response_updated["Configuration"]["CodeSize"]
        )

    def test_lambda_code_location_s3(
        self,
        lambda_client,
        s3_bucket,
        s3_client,
        snapshot,
        create_lambda_function_aws,
        lambda_su_role,
    ):
        function_name = f"code-function-{short_uid()}"
        bucket_key = "code/code-function.zip"
        zip_file_bytes = create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True)
        s3_client.upload_fileobj(
            Fileobj=io.BytesIO(zip_file_bytes), Bucket=s3_bucket, Key=bucket_key
        )
        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Handler="index.handler",
            Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
            PackageType="Zip",
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
        )
        snapshot.match("create_response_s3", create_response)
        get_function_response = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get-function-response", get_function_response)
        code_location = get_function_response["Code"]["Location"]
        response = requests.get(code_location)
        assert zip_file_bytes == response.content
        h = sha256(zip_file_bytes)
        b64digest = to_str(base64.b64encode(h.digest()))
        assert b64digest == get_function_response["Configuration"]["CodeSha256"]
        assert len(zip_file_bytes) == get_function_response["Configuration"]["CodeSize"]
        zip_file_bytes_updated = create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON_VERSION), get_content=True
        )
        # TODO check bucket addressing with version id as well?
        s3_client.upload_fileobj(
            Fileobj=io.BytesIO(zip_file_bytes_updated), Bucket=s3_bucket, Key=bucket_key
        )
        update_function_response = lambda_client.update_function_code(
            FunctionName=function_name, S3Bucket=s3_bucket, S3Key=bucket_key
        )
        snapshot.match("update-function-response", update_function_response)
        get_function_response_updated = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get-function-response-updated", get_function_response_updated)
        code_location_updated = get_function_response_updated["Code"]["Location"]
        response = requests.get(code_location_updated)
        assert zip_file_bytes_updated == response.content
        h = sha256(zip_file_bytes_updated)
        b64digest_updated = to_str(base64.b64encode(h.digest()))
        assert b64digest != b64digest_updated
        assert b64digest_updated == get_function_response_updated["Configuration"]["CodeSha256"]
        assert (
            len(zip_file_bytes_updated)
            == get_function_response_updated["Configuration"]["CodeSize"]
        )

    @pytest.mark.aws_validated
    def test_create_lambda_exceptions(self, lambda_client, lambda_su_role, snapshot):
        function_name = f"invalid-function-{short_uid()}"
        zip_file_bytes = create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True)
        # test invalid role arn
        with pytest.raises(ClientError) as e:
            lambda_client.create_function(
                FunctionName=function_name,
                Handler="index.handler",
                Code={"ZipFile": zip_file_bytes},
                PackageType="Zip",
                Role="r1",
                Runtime=Runtime.python3_9,
            )
        snapshot.match("invalid_role_arn_exc", e.value.response)
        # test invalid runtimes
        with pytest.raises(ClientError) as e:
            lambda_client.create_function(
                FunctionName=function_name,
                Handler="index.handler",
                Code={"ZipFile": zip_file_bytes},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime="non-existent-runtime",
            )
        snapshot.match("invalid_runtime_exc", e.value.response)
        with pytest.raises(ClientError) as e:
            lambda_client.create_function(
                FunctionName=function_name,
                Handler="index.handler",
                Code={"ZipFile": zip_file_bytes},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime="PYTHON3.9",
            )
        snapshot.match("uppercase_runtime_exc", e.value.response)

        # test what happens with an invalid zip file
        with pytest.raises(ClientError) as e:
            lambda_client.create_function(
                FunctionName=function_name,
                Handler="index.handler",
                Code={"ZipFile": b"this is not a zipfile, just a random string"},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime="python3.9",
            )
        snapshot.match("invalid_zip_exc", e.value.response)

    @pytest.mark.aws_validated
    def test_update_lambda_exceptions(
        self, lambda_client, create_lambda_function_aws, lambda_su_role, snapshot
    ):
        function_name = f"invalid-function-{short_uid()}"
        zip_file_bytes = create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True)
        create_lambda_function_aws(
            FunctionName=function_name,
            Handler="index.handler",
            Code={"ZipFile": zip_file_bytes},
            PackageType="Zip",
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
        )
        with pytest.raises(ClientError) as e:
            lambda_client.update_function_configuration(
                FunctionName=function_name,
                Role="r1",
            )
        snapshot.match("invalid_role_arn_exc", e.value.response)
        with pytest.raises(ClientError) as e:
            lambda_client.update_function_configuration(
                FunctionName=function_name,
                Runtime="non-existent-runtime",
            )
        snapshot.match("invalid_runtime_exc", e.value.response)
        with pytest.raises(ClientError) as e:
            lambda_client.update_function_configuration(
                FunctionName=function_name,
                Runtime="PYTHON3.9",
            )
        snapshot.match("uppercase_runtime_exc", e.value.response)

    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..CodeSha256",  # TODO
        ]
    )
    @pytest.mark.aws_validated
    def test_list_functions(self, lambda_client, create_lambda_function, lambda_su_role, snapshot):
        snapshot.add_transformer(SortingTransformer("Functions", lambda x: x["FunctionArn"]))

        function_name_1 = f"list-fn-1-{short_uid()}"
        function_name_2 = f"list-fn-2-{short_uid()}"
        # create lambda + version
        create_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name_1,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
            Publish=True,
        )
        snapshot.match("create_response_1", create_response)

        create_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name_2,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
        )
        snapshot.match("create_response_2", create_response)

        with pytest.raises(lambda_client.exceptions.ClientError) as e:
            lambda_client.list_functions(FunctionVersion="invalid")
        snapshot.match("list_functions_invalid_functionversion", e.value.response)

        list_paginator = lambda_client.get_paginator("list_functions")
        # ALL means it should also return all published versions for the functions
        test_fn = [function_name_1, function_name_2]
        list_all = list_paginator.paginate(
            FunctionVersion="ALL",
            PaginationConfig={
                "PageSize": 1,
            },
        ).build_full_result()
        list_default = list_paginator.paginate(PaginationConfig={"PageSize": 1}).build_full_result()

        # we can't filter on the API level, so we'll just need to remove all entries that don't belong here manually before snapshotting
        list_all["Functions"] = [f for f in list_all["Functions"] if f["FunctionName"] in test_fn]
        list_default["Functions"] = [
            f for f in list_default["Functions"] if f["FunctionName"] in test_fn
        ]

        assert len(list_all["Functions"]) == 3  # $LATEST + Version "1" for fn1 & $LATEST for fn2
        assert len(list_default["Functions"]) == 2  # $LATEST for fn1 and fn2

        snapshot.match("list_all", list_all)
        snapshot.match("list_default", list_default)


@pytest.mark.skipif(is_old_provider(), reason="focusing on new provider")
# TODO fix version state after publish
@pytest.mark.skip_snapshot_verify(
    paths=[
        "$..LastUpdateStatus",
        "$..LastUpdateStatusReason",
        "$..LastUpdateStatusReasonCode",
        "$..State",
        "$..StateReason",
        "$..StateReasonCode",
    ]
)
class TestLambdaVersions:
    @pytest.mark.aws_validated
    def test_publish_version_on_create(
        self, lambda_client, create_lambda_function_aws, lambda_su_role, snapshot
    ):
        function_name = f"fn-{short_uid()}"

        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Handler="index.handler",
            Code={
                "ZipFile": create_lambda_archive(
                    load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True
                )
            },
            PackageType="Zip",
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
            Publish=True,
        )
        snapshot.match("create_response", create_response)

        get_function_result = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get_function_result", get_function_result)

        get_function_version_result = lambda_client.get_function(
            FunctionName=function_name, Qualifier="1"
        )
        snapshot.match("get_function_version_result", get_function_version_result)

        get_function_latest_result = lambda_client.get_function(
            FunctionName=function_name, Qualifier="$LATEST"
        )
        snapshot.match("get_function_latest_result", get_function_latest_result)

        list_versions_result = lambda_client.list_versions_by_function(FunctionName=function_name)
        snapshot.match("list_versions_result", list_versions_result)

        # rerelease just published function, should not release new version
        repeated_publish_response = lambda_client.publish_version(
            FunctionName=function_name, Description="Repeated version description :)"
        )
        snapshot.match("repeated_publish_response", repeated_publish_response)
        list_versions_result_after_publish = lambda_client.list_versions_by_function(
            FunctionName=function_name
        )
        snapshot.match("list_versions_result_after_publish", list_versions_result_after_publish)

    @pytest.mark.aws_validated
    # TODO fix revision ids changed due to state changes after publish
    @pytest.mark.skip_snapshot_verify(paths=["$..RevisionId"])
    def test_version_lifecycle(
        self, lambda_client, create_lambda_function_aws, lambda_su_role, snapshot
    ):
        """
        Test the function version "lifecycle" (there are no deletes)
        """
        waiter = lambda_client.get_waiter("function_updated_v2")
        function_name = f"fn-{short_uid()}"
        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Handler="index.handler",
            Code={
                "ZipFile": create_lambda_archive(
                    load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True
                )
            },
            PackageType="Zip",
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
            Description="No version :(",
        )
        snapshot.match("create_response", create_response)

        get_function_result = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get_function_result", get_function_result)

        list_versions_result = lambda_client.list_versions_by_function(FunctionName=function_name)
        snapshot.match("list_versions_result", list_versions_result)

        first_update_response = lambda_client.update_function_configuration(
            FunctionName=function_name, Description="First version :)"
        )
        snapshot.match("first_update_response", first_update_response)
        waiter.wait(FunctionName=function_name)
        first_update_get_function = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("first_update_get_function", first_update_get_function)

        first_publish_response = lambda_client.publish_version(
            FunctionName=function_name, Description="First version description :)"
        )
        snapshot.match("first_publish_response", first_publish_response)

        first_publish_get_function = lambda_client.get_function(
            FunctionName=function_name, Qualifier=first_publish_response["Version"]
        )
        snapshot.match("first_publish_get_function", first_publish_get_function)
        first_publish_get_function_config = lambda_client.get_function_configuration(
            FunctionName=function_name, Qualifier=first_publish_response["Version"]
        )
        snapshot.match("first_publish_get_function_config", first_publish_get_function_config)

        second_update_response = lambda_client.update_function_configuration(
            FunctionName=function_name, Description="Second version :))"
        )
        snapshot.match("second_update_response", second_update_response)
        waiter.wait(FunctionName=function_name)
        # check if first publish get function changed:
        first_publish_get_function_after_update = lambda_client.get_function(
            FunctionName=function_name, Qualifier=first_publish_response["Version"]
        )
        snapshot.match(
            "first_publish_get_function_after_update", first_publish_get_function_after_update
        )

        # Same state published as two different versions.
        # The publish_version api is idempotent, so the second publish_version will *NOT* create a new version because $LATEST hasn't been updated!
        second_publish_response = lambda_client.publish_version(FunctionName=function_name)
        snapshot.match("second_publish_response", second_publish_response)
        third_publish_response = lambda_client.publish_version(
            FunctionName=function_name, Description="Third version description :)))"
        )
        snapshot.match("third_publish_response", third_publish_response)

        list_versions_result_end = lambda_client.list_versions_by_function(
            FunctionName=function_name
        )
        snapshot.match("list_versions_result_end", list_versions_result_end)

    @pytest.mark.aws_validated
    def test_publish_with_wrong_revisionid(
        self, lambda_client, create_lambda_function_aws, lambda_su_role, snapshot
    ):
        function_name = f"fn-{short_uid()}"
        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Handler="index.handler",
            Code={
                "ZipFile": create_lambda_archive(
                    load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True
                )
            },
            PackageType="Zip",
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
        )
        snapshot.match("create_response", create_response)

        get_fn_response = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get_fn_response", get_fn_response)

        # state change causes rev id change!
        assert create_response["RevisionId"] != get_fn_response["Configuration"]["RevisionId"]

        # publish_versions fails for the wrong revision id
        with pytest.raises(lambda_client.exceptions.PreconditionFailedException) as e:
            lambda_client.publish_version(FunctionName=function_name, RevisionId="doesntexist")
        snapshot.match("publish_wrong_revisionid_exc", e.value.response)

        # but with the proper rev id, it should work
        publish_result = lambda_client.publish_version(
            FunctionName=function_name, RevisionId=get_fn_response["Configuration"]["RevisionId"]
        )
        snapshot.match("publish_result", publish_result)

    @pytest.mark.aws_validated
    def test_publish_with_wrong_sha256(
        self, lambda_client, create_lambda_function_aws, lambda_su_role, snapshot
    ):
        function_name = f"fn-{short_uid()}"
        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Handler="index.handler",
            Code={
                "ZipFile": create_lambda_archive(
                    load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True
                )
            },
            PackageType="Zip",
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
        )
        snapshot.match("create_response", create_response)

        get_fn_response = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get_fn_response", get_fn_response)

        # publish_versions fails for the wrong revision id
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.publish_version(
                FunctionName=function_name, CodeSha256="somenonexistentsha256"
            )
        snapshot.match("publish_wrong_sha256_exc", e.value.response)

        # but with the proper rev id, it should work
        publish_result = lambda_client.publish_version(
            FunctionName=function_name, CodeSha256=get_fn_response["Configuration"]["CodeSha256"]
        )
        snapshot.match("publish_result", publish_result)

    def test_publish_with_update(
        self, lambda_client, create_lambda_function_aws, lambda_su_role, snapshot
    ):
        function_name = f"fn-{short_uid()}"

        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Handler="index.handler",
            Code={
                "ZipFile": create_lambda_archive(
                    load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True
                )
            },
            PackageType="Zip",
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
        )
        snapshot.match("create_response", create_response)

        get_function_result = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get_function_result", get_function_result)
        update_zip_file = create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON_VERSION), get_content=True
        )
        update_function_code_result = lambda_client.update_function_code(
            FunctionName=function_name, ZipFile=update_zip_file, Publish=True
        )
        snapshot.match("update_function_code_result", update_function_code_result)

        get_function_version_result = lambda_client.get_function(
            FunctionName=function_name, Qualifier="1"
        )
        snapshot.match("get_function_version_result", get_function_version_result)

        get_function_latest_result = lambda_client.get_function(
            FunctionName=function_name, Qualifier="$LATEST"
        )
        snapshot.match("get_function_latest_result", get_function_latest_result)


# TODO fix version state after publish
@pytest.mark.skip_snapshot_verify(
    paths=[
        "$..LastUpdateStatus",
        "$..LastUpdateStatusReason",
        "$..LastUpdateStatusReasonCode",
        "$..State",
        "$..StateReason",
        "$..StateReasonCode",
    ]
)
@pytest.mark.skipif(is_old_provider(), reason="focusing on new provider")
class TestLambdaAlias:
    @pytest.mark.aws_validated
    def test_alias_lifecycle(
        self, lambda_client, create_lambda_function_aws, lambda_su_role, snapshot
    ):
        """
        The function has 2 (excl. $LATEST) versions:
        Version 1: env with testenv==staging
        Version 2: env with testenv==prod

        Alias A (Version == 1) has a routing config targeting both versions
        Alias B (Version == 1) has no routing config and simply is an alias for Version 1
        Alias C (Version == 2) has no routing config

        """
        function_name = f"alias-fn-{short_uid()}"
        snapshot.add_transformer(SortingTransformer("Aliases", lambda x: x["Name"]))

        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Handler="index.handler",
            Code={
                "ZipFile": create_lambda_archive(
                    load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True
                )
            },
            PackageType="Zip",
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
            Environment={"Variables": {"testenv": "staging"}},
        )
        snapshot.match("create_response", create_response)

        publish_v1 = lambda_client.publish_version(FunctionName=function_name)
        snapshot.match("publish_v1", publish_v1)

        lambda_client.update_function_configuration(
            FunctionName=function_name, Environment={"Variables": {"testenv": "prod"}}
        )
        waiter = lambda_client.get_waiter("function_updated_v2")
        waiter.wait(FunctionName=function_name)

        publish_v2 = lambda_client.publish_version(FunctionName=function_name)
        snapshot.match("publish_v2", publish_v2)

        create_alias_1_1 = lambda_client.create_alias(
            FunctionName=function_name,
            Name="aliasname1_1",
            FunctionVersion="1",
            Description="custom-alias",
            RoutingConfig={"AdditionalVersionWeights": {"2": 0.2}},
        )
        snapshot.match("create_alias_1_1", create_alias_1_1)
        get_alias_1_1 = lambda_client.get_alias(FunctionName=function_name, Name="aliasname1_1")
        snapshot.match("get_alias_1_1", get_alias_1_1)

        create_alias_1_2 = lambda_client.create_alias(
            FunctionName=function_name,
            Name="aliasname1_2",
            FunctionVersion="1",
            Description="custom-alias",
        )
        snapshot.match("create_alias_1_2", create_alias_1_2)
        get_alias_1_2 = lambda_client.get_alias(FunctionName=function_name, Name="aliasname1_2")
        snapshot.match("get_alias_1_2", get_alias_1_2)

        create_alias_1_3 = lambda_client.create_alias(
            FunctionName=function_name,
            Name="aliasname1_3",
            FunctionVersion="1",
        )
        snapshot.match("create_alias_1_3", create_alias_1_3)
        get_alias_1_3 = lambda_client.get_alias(FunctionName=function_name, Name="aliasname1_3")
        snapshot.match("get_alias_1_3", get_alias_1_3)

        create_alias_2 = lambda_client.create_alias(
            FunctionName=function_name,
            Name="aliasname2",
            FunctionVersion="2",
            Description="custom-alias",
        )
        snapshot.match("create_alias_2", create_alias_2)
        get_alias_2 = lambda_client.get_alias(FunctionName=function_name, Name="aliasname2")
        snapshot.match("get_alias_2", get_alias_2)

        # list_aliases can be optionally called with a FunctionVersion to filter only aliases for this version
        list_alias_paginator = lambda_client.get_paginator("list_aliases")
        list_aliases_for_fnname = list_alias_paginator.paginate(
            FunctionName=function_name, PaginationConfig={"PageSize": 1}
        ).build_full_result()  # 4 aliases
        snapshot.match("list_aliases_for_fnname", list_aliases_for_fnname)
        assert len(list_aliases_for_fnname["Aliases"]) == 4
        # update alias 1_1 to remove routing config
        update_alias_1_1 = lambda_client.update_alias(
            FunctionName=function_name,
            Name="aliasname1_1",
            RoutingConfig={"AdditionalVersionWeights": {}},
        )
        snapshot.match("update_alias_1_1", update_alias_1_1)
        get_alias_1_1_after_update = lambda_client.get_alias(
            FunctionName=function_name, Name="aliasname1_1"
        )
        snapshot.match("get_alias_1_1_after_update", get_alias_1_1_after_update)
        list_aliases_for_fnname_after_update = lambda_client.list_aliases(
            FunctionName=function_name
        )  # 4 aliases
        snapshot.match("list_aliases_for_fnname_after_update", list_aliases_for_fnname_after_update)
        assert len(list_aliases_for_fnname_after_update["Aliases"]) == 4
        # check update without changes
        update_alias_1_2 = lambda_client.update_alias(
            FunctionName=function_name,
            Name="aliasname1_2",
        )
        snapshot.match("update_alias_1_2", update_alias_1_2)
        get_alias_1_2_after_update = lambda_client.get_alias(
            FunctionName=function_name, Name="aliasname1_2"
        )
        snapshot.match("get_alias_1_2_after_update", get_alias_1_2_after_update)
        list_aliases_for_fnname_after_update_2 = lambda_client.list_aliases(
            FunctionName=function_name
        )  # 4 aliases
        snapshot.match(
            "list_aliases_for_fnname_after_update_2", list_aliases_for_fnname_after_update_2
        )
        assert len(list_aliases_for_fnname_after_update["Aliases"]) == 4

        list_aliases_for_version = lambda_client.list_aliases(
            FunctionName=function_name, FunctionVersion="1"
        )  # 3 aliases
        snapshot.match("list_aliases_for_version", list_aliases_for_version)
        assert len(list_aliases_for_version["Aliases"]) == 3

        delete_alias_response = lambda_client.delete_alias(
            FunctionName=function_name, Name="aliasname1_1"
        )
        snapshot.match("delete_alias_response", delete_alias_response)

        list_aliases_for_fnname_afterdelete = lambda_client.list_aliases(
            FunctionName=function_name
        )  # 3 aliases
        snapshot.match("list_aliases_for_fnname_afterdelete", list_aliases_for_fnname_afterdelete)

    def test_notfound_and_invalid_routingconfigs(
        self, create_boto_client, create_lambda_function_aws, snapshot, lambda_su_role
    ):
        lambda_client = create_boto_client(
            "lambda", additional_config=Config(parameter_validation=False)
        )
        function_name = f"alias-fn-{short_uid()}"

        create_response = create_lambda_function_aws(
            FunctionName=function_name,
            Handler="index.handler",
            Code={
                "ZipFile": create_lambda_archive(
                    load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True
                )
            },
            PackageType="Zip",
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
            Publish=True,
            Environment={"Variables": {"testenv": "staging"}},
        )
        snapshot.match("create_response", create_response)

        # create 2 versions
        publish_v1 = lambda_client.publish_version(FunctionName=function_name)
        snapshot.match("publish_v1", publish_v1)

        lambda_client.update_function_configuration(
            FunctionName=function_name, Environment={"Variables": {"testenv": "prod"}}
        )
        waiter = lambda_client.get_waiter("function_updated_v2")
        waiter.wait(FunctionName=function_name)

        publish_v2 = lambda_client.publish_version(FunctionName=function_name)
        snapshot.match("publish_v2", publish_v2)

        # routing config with more than one entry (which isn't supported atm by AWS)
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.create_alias(
                FunctionName=function_name,
                Name="custom",
                FunctionVersion="1",
                RoutingConfig={"AdditionalVersionWeights": {"1": 0.8, "2": 0.2}},
            )
        snapshot.match("routing_config_exc_toomany", e.value.response)

        # value > 1
        with pytest.raises(ClientError) as e:
            lambda_client.create_alias(
                FunctionName=function_name,
                Name="custom",
                FunctionVersion="1",
                RoutingConfig={"AdditionalVersionWeights": {"2": 2}},
            )
        snapshot.match("routing_config_exc_toohigh", e.value.response)

        # value < 0
        with pytest.raises(ClientError) as e:
            lambda_client.create_alias(
                FunctionName=function_name,
                Name="custom",
                FunctionVersion="1",
                RoutingConfig={"AdditionalVersionWeights": {"2": -1}},
            )
        snapshot.match("routing_config_exc_subzero", e.value.response)

        # same version as alias pointer
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.create_alias(
                FunctionName=function_name,
                Name="custom",
                FunctionVersion="1",
                RoutingConfig={"AdditionalVersionWeights": {"1": 0.5}},
            )
        snapshot.match("routing_config_exc_sameversion", e.value.response)

        # function version 10 doesn't exist
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.create_alias(
                FunctionName=function_name,
                Name="custom",
                FunctionVersion="10",
                RoutingConfig={"AdditionalVersionWeights": {"2": 0.5}},
            )
        snapshot.match("target_version_doesnotexist", e.value.response)
        # function version 10 doesn't exist (routingconfig)
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.create_alias(
                FunctionName=function_name,
                Name="custom",
                FunctionVersion="1",
                RoutingConfig={"AdditionalVersionWeights": {"10": 0.5}},
            )
        snapshot.match("routing_config_exc_version_doesnotexist", e.value.response)
        # function version $LATEST not supported in function version if it points to more than one version
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.create_alias(
                FunctionName=function_name,
                Name="custom",
                FunctionVersion="$LATEST",
                RoutingConfig={"AdditionalVersionWeights": {"1": 0.5}},
            )
        snapshot.match("target_version_exc_version_latest", e.value.response)
        # function version $LATEST not supported in routing config
        with pytest.raises(ClientError) as e:
            lambda_client.create_alias(
                FunctionName=function_name,
                Name="custom",
                FunctionVersion="1",
                RoutingConfig={"AdditionalVersionWeights": {"$LATEST": 0.5}},
            )
        snapshot.match("routing_config_exc_version_latest", e.value.response)
        create_alias_latest = lambda_client.create_alias(
            FunctionName=function_name,
            Name="custom-latest",
            FunctionVersion="$LATEST",
        )
        snapshot.match("create-alias-latest", create_alias_latest)

        # function doesn't exist
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.create_alias(
                FunctionName=f"{function_name}-unknown",
                Name="custom",
                FunctionVersion="1",
                RoutingConfig={"AdditionalVersionWeights": {"2": 0.5}},
            )
        snapshot.match("routing_config_exc_fn_doesnotexist", e.value.response)

        # empty routing config works fine
        create_alias_empty_routingconfig = lambda_client.create_alias(
            FunctionName=function_name,
            Name="custom-empty-routingconfig",
            FunctionVersion="1",
            RoutingConfig={"AdditionalVersionWeights": {}},
        )
        snapshot.match("create_alias_empty_routingconfig", create_alias_empty_routingconfig)

        # "normal scenario" works:
        create_alias_response = lambda_client.create_alias(
            FunctionName=function_name,
            Name="custom",
            FunctionVersion="1",
            RoutingConfig={"AdditionalVersionWeights": {"2": 0.5}},
        )
        snapshot.match("create_alias_response", create_alias_response)
        # can't create a second alias with the same name
        with pytest.raises(lambda_client.exceptions.ResourceConflictException) as e:
            lambda_client.create_alias(
                FunctionName=function_name,
                Name="custom",
                FunctionVersion="1",
                RoutingConfig={"AdditionalVersionWeights": {"2": 0.5}},
            )
        snapshot.match("routing_config_exc_already_exist", e.value.response)
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.get_alias(
                FunctionName=function_name,
                Name="non-existent",
            )
        snapshot.match("alias_does_not_exist_esc", e.value.response)


@pytest.mark.skipif(is_old_provider(), reason="focusing on new provider")
class TestLambdaTag:
    @pytest.fixture(scope="function")
    def fn_arn(self, create_lambda_function, lambda_client):
        """simple reusable setup to test tagging operations against"""
        function_name = f"fn-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        yield lambda_client.get_function(FunctionName=function_name)["Configuration"]["FunctionArn"]

    @pytest.mark.aws_validated
    def test_create_tag_on_fn_create(self, lambda_client, create_lambda_function, snapshot):
        function_name = f"fn-{short_uid()}"
        custom_tag = f"tag-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(custom_tag, "<custom-tag>"))
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            Tags={"testtag": custom_tag},
        )
        get_function_result = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get_function_result", get_function_result)
        fn_arn = get_function_result["Configuration"]["FunctionArn"]

        list_tags_result = lambda_client.list_tags(Resource=fn_arn)
        snapshot.match("list_tags_result", list_tags_result)

    @pytest.mark.aws_validated
    def test_tag_lifecycle(self, lambda_client, create_lambda_function, snapshot, fn_arn):

        # 1. add tag
        tag_single_response = lambda_client.tag_resource(Resource=fn_arn, Tags={"A": "tag-a"})
        snapshot.match("tag_single_response", tag_single_response)
        snapshot.match("tag_single_response_listtags", lambda_client.list_tags(Resource=fn_arn))

        # 2. add multiple tags
        tag_multiple_response = lambda_client.tag_resource(
            Resource=fn_arn, Tags={"B": "tag-b", "C": "tag-c"}
        )
        snapshot.match("tag_multiple_response", tag_multiple_response)
        snapshot.match("tag_multiple_response_listtags", lambda_client.list_tags(Resource=fn_arn))

        # 3. add overlapping tags
        tag_overlap_response = lambda_client.tag_resource(
            Resource=fn_arn, Tags={"C": "tag-c-newsuffix", "D": "tag-d"}
        )
        snapshot.match("tag_overlap_response", tag_overlap_response)
        snapshot.match("tag_overlap_response_listtags", lambda_client.list_tags(Resource=fn_arn))

        # 3. remove tag
        untag_single_response = lambda_client.untag_resource(Resource=fn_arn, TagKeys=["A"])
        snapshot.match("untag_single_response", untag_single_response)
        snapshot.match("untag_single_response_listtags", lambda_client.list_tags(Resource=fn_arn))

        # 4. remove multiple tags
        untag_multiple_response = lambda_client.untag_resource(Resource=fn_arn, TagKeys=["B", "C"])
        snapshot.match("untag_multiple_response", untag_multiple_response)
        snapshot.match("untag_multiple_response_listtags", lambda_client.list_tags(Resource=fn_arn))

        # 5. try to remove only tags that don't exist
        untag_nonexisting_response = lambda_client.untag_resource(Resource=fn_arn, TagKeys=["F"])
        snapshot.match("untag_nonexisting_response", untag_nonexisting_response)
        snapshot.match(
            "untag_nonexisting_response_listtags", lambda_client.list_tags(Resource=fn_arn)
        )

        # 6. remove a mix of tags that exist & don't exist
        untag_existing_and_nonexisting_response = lambda_client.untag_resource(
            Resource=fn_arn, TagKeys=["D", "F"]
        )
        snapshot.match(
            "untag_existing_and_nonexisting_response", untag_existing_and_nonexisting_response
        )
        snapshot.match(
            "untag_existing_and_nonexisting_response_listtags",
            lambda_client.list_tags(Resource=fn_arn),
        )

    @pytest.mark.aws_validated
    def test_tag_nonexisting_resource(self, lambda_client, snapshot, fn_arn):
        get_result = lambda_client.get_function(FunctionName=fn_arn)
        snapshot.match("pre_delete_get_function", get_result)
        lambda_client.delete_function(FunctionName=fn_arn)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.tag_resource(Resource=fn_arn, Tags={"A": "B"})
        snapshot.match("not_found_exception_tag", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.untag_resource(Resource=fn_arn, TagKeys=["A"])
        snapshot.match("not_found_exception_untag", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.list_tags(Resource=fn_arn)
        snapshot.match("not_found_exception_list", e.value.response)


# some more common ones that usually don't work in the old provider
pytestmark = pytest.mark.skip_snapshot_verify(
    condition=is_old_provider,
    paths=[
        "$..Architectures",
        "$..EphemeralStorage",
        "$..LastUpdateStatus",
        "$..MemorySize",
        "$..State",
        "$..StateReason",
        "$..StateReasonCode",
        "$..VpcConfig",
        "$..CodeSigningConfig",
        "$..Environment",  # missing
        "$..HTTPStatusCode",  # 201 vs 200
        "$..Layers",
    ],
)


@pytest.mark.skipif(condition=is_old_provider(), reason="not supported")
class TestLambdaEventInvokeConfig:
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..LastUpdateStatus",
            "$..LastUpdateStatusReason",
            "$..LastUpdateStatusReasonCode",
            "$..State",
            "$..StateReason",
            "$..StateReasonCode",
        ]
    )
    def test_lambda_eventinvokeconfig_exceptions(
        self, lambda_client, create_lambda_function, snapshot, lambda_su_role, account_id
    ):
        snapshot.add_transformer(
            SortingTransformer(
                key="FunctionEventInvokeConfigs", sorting_fn=lambda conf: conf["FunctionArn"]
            )
        )
        function_name = f"fn-eventinvoke-{short_uid()}"
        function_name_2 = f"fn-eventinvoke-2-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
        )
        get_fn_result = lambda_client.get_function(FunctionName=function_name)
        fn_arn = get_fn_result["Configuration"]["FunctionArn"]

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name_2,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
        )
        get_fn_result_2 = lambda_client.get_function(FunctionName=function_name_2)
        fn_arn_2 = get_fn_result_2["Configuration"]["FunctionArn"]

        # one version and one alias

        fn_version_result = lambda_client.publish_version(FunctionName=function_name)
        snapshot.match("fn_version_result", fn_version_result)
        fn_version = fn_version_result["Version"]

        fn_alias_result = lambda_client.create_alias(
            FunctionName=function_name, Name="eventinvokealias", FunctionVersion=fn_version
        )
        snapshot.match("fn_alias_result", fn_alias_result)
        fn_alias = fn_alias_result["Name"]

        # FunctionName tests

        fake_arn = (
            f"arn:aws:lambda:{lambda_client.meta.region_name}:{account_id}:function:doesnotexist"
        )

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.put_function_event_invoke_config(
                FunctionName="doesnotexist", MaximumRetryAttempts=1
            )
        snapshot.match("put_functionname_name_notfound", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.put_function_event_invoke_config(
                FunctionName=fake_arn, MaximumRetryAttempts=1
            )
        snapshot.match("put_functionname_arn_notfound", e.value.response)

        # Arguments missing

        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.put_function_event_invoke_config(FunctionName="doesnotexist")
        snapshot.match("put_functionname_nootherargs", e.value.response)

        # Destination value tests

        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.put_function_event_invoke_config(
                FunctionName=function_name,
                DestinationConfig={"OnSuccess": {"Destination": fake_arn}},
            )
        snapshot.match("put_destination_lambda_doesntexist", e.value.response)

        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.put_function_event_invoke_config(
                FunctionName=function_name, DestinationConfig={"OnSuccess": {"Destination": fn_arn}}
            )
        snapshot.match("put_destination_recursive", e.value.response)

        response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name, DestinationConfig={"OnSuccess": {"Destination": fn_arn_2}}
        )
        snapshot.match("put_destination_other_lambda", response)

        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.put_function_event_invoke_config(
                FunctionName=function_name,
                DestinationConfig={
                    "OnSuccess": {"Destination": fn_arn.replace(":lambda:", ":iam:")}
                },
            )
        snapshot.match("put_destination_invalid_service_arn", e.value.response)

        response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name, DestinationConfig={"OnSuccess": {}}
        )
        snapshot.match("put_destination_success_no_destination_arn", response)

        response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name, DestinationConfig={"OnFailure": {}}
        )
        snapshot.match("put_destination_failure_no_destination_arn", response)

        with pytest.raises(lambda_client.exceptions.ClientError) as e:
            lambda_client.put_function_event_invoke_config(
                FunctionName=function_name,
                DestinationConfig={
                    "OnFailure": {"Destination": fn_arn.replace(":lambda:", ":_-/!lambda:")}
                },
            )
        snapshot.match("put_destination_invalid_arn_pattern", e.value.response)

        # Function Name & Qualifier tests
        response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name, MaximumRetryAttempts=1
        )
        snapshot.match("put_destination_latest", response)
        response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name, Qualifier="$LATEST", MaximumRetryAttempts=1
        )
        snapshot.match("put_destination_latest_explicit_qualifier", response)

        response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name, Qualifier=fn_version, MaximumRetryAttempts=1
        )
        snapshot.match("put_destination_version", response)
        response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name, Qualifier=fn_alias, MaximumRetryAttempts=1
        )
        snapshot.match("put_alias_functionname_qualifier", response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.put_function_event_invoke_config(
                FunctionName=function_name,
                Qualifier=f"{fn_alias}doesnotexist",
                MaximumRetryAttempts=1,
            )
        snapshot.match("put_alias_doesnotexist", e.value.response)
        response = lambda_client.put_function_event_invoke_config(
            FunctionName=fn_alias_result["AliasArn"], MaximumRetryAttempts=1
        )
        snapshot.match("put_alias_qualifiedarn", response)
        response = lambda_client.put_function_event_invoke_config(
            FunctionName=fn_alias_result["AliasArn"], Qualifier=fn_alias, MaximumRetryAttempts=1
        )
        snapshot.match("put_alias_qualifiedarn_qualifier", response)
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.put_function_event_invoke_config(
                FunctionName=fn_alias_result["AliasArn"],
                Qualifier=f"{fn_alias}doesnotexist",
                MaximumRetryAttempts=1,
            )
        snapshot.match("put_alias_qualifiedarn_qualifierconflict", e.value.response)

        response = lambda_client.put_function_event_invoke_config(
            FunctionName=f"{function_name}:{fn_alias}", MaximumRetryAttempts=1
        )
        snapshot.match("put_alias_shorthand", response)
        response = lambda_client.put_function_event_invoke_config(
            FunctionName=f"{function_name}:{fn_alias}", Qualifier=fn_alias, MaximumRetryAttempts=1
        )
        snapshot.match("put_alias_shorthand_qualifier", response)

        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.put_function_event_invoke_config(
                FunctionName=f"{function_name}:{fn_alias}",
                Qualifier=f"{fn_alias}doesnotexist",
                MaximumRetryAttempts=1,
            )
        snapshot.match("put_alias_shorthand_qualifierconflict", e.value.response)

        # apparently this also works with function numbers (not in the docs!)
        response = lambda_client.put_function_event_invoke_config(
            FunctionName=f"{function_name}:{fn_version}", MaximumRetryAttempts=1
        )
        snapshot.match("put_version_shorthand", response)

        response = lambda_client.put_function_event_invoke_config(
            FunctionName=f"{function_name}:$LATEST", Qualifier="$LATEST", MaximumRetryAttempts=1
        )
        snapshot.match("put_shorthand_qualifier_match", response)

        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.put_function_event_invoke_config(
                FunctionName=f"{function_name}:{fn_version}",
                Qualifier="$LATEST",
                MaximumRetryAttempts=1,
            )
        snapshot.match("put_shorthand_qualifier_mismatch_1", e.value.response)

        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.put_function_event_invoke_config(
                FunctionName=f"{function_name}:$LATEST",
                Qualifier=fn_version,
                MaximumRetryAttempts=1,
            )
        snapshot.match("put_shorthand_qualifier_mismatch_2", e.value.response)

        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.put_function_event_invoke_config(
                FunctionName=f"{function_name}:{fn_version}",
                Qualifier=fn_alias,
                MaximumRetryAttempts=1,
            )
        snapshot.match("put_shorthand_qualifier_mismatch_3", e.value.response)

        # Test overwrite existing values +  differences between put & update
        # first create a config with both values set, then overwrite it with only one value set

        first_overwrite_response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name, MaximumRetryAttempts=2, MaximumEventAgeInSeconds=60
        )
        snapshot.match("put_pre_overwrite", first_overwrite_response)
        second_overwrite_response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name, MaximumRetryAttempts=0
        )
        snapshot.match("put_post_overwrite", second_overwrite_response)
        second_overwrite_existing_response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name, MaximumRetryAttempts=0
        )
        snapshot.match("second_overwrite_existing_response", second_overwrite_existing_response)
        get_postoverwrite_response = lambda_client.get_function_event_invoke_config(
            FunctionName=function_name
        )
        snapshot.match("get_post_overwrite", get_postoverwrite_response)
        assert get_postoverwrite_response["MaximumRetryAttempts"] == 0
        assert "MaximumEventAgeInSeconds" not in get_postoverwrite_response

        pre_update_response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name, MaximumRetryAttempts=2, MaximumEventAgeInSeconds=60
        )
        snapshot.match("pre_update_response", pre_update_response)
        update_response = lambda_client.update_function_event_invoke_config(
            FunctionName=function_name, MaximumRetryAttempts=0
        )
        snapshot.match("update_response", update_response)

        update_response_existing = lambda_client.update_function_event_invoke_config(
            FunctionName=function_name, MaximumRetryAttempts=0
        )
        snapshot.match("update_response_existing", update_response_existing)

        get_postupdate_response = lambda_client.get_function_event_invoke_config(
            FunctionName=function_name
        )
        assert get_postupdate_response["MaximumRetryAttempts"] == 0
        assert get_postupdate_response["MaximumEventAgeInSeconds"] == 60

        # Test delete & listing
        list_response = lambda_client.list_function_event_invoke_configs(FunctionName=function_name)
        snapshot.match("list_configs", list_response)

        paged_response = lambda_client.list_function_event_invoke_configs(
            FunctionName=function_name, MaxItems=2
        )  # 2 out of 3
        assert len(paged_response["FunctionEventInvokeConfigs"]) == 2
        assert paged_response["NextMarker"]

        delete_latest = lambda_client.delete_function_event_invoke_config(
            FunctionName=function_name, Qualifier="$LATEST"
        )
        snapshot.match("delete_latest", delete_latest)
        delete_version = lambda_client.delete_function_event_invoke_config(
            FunctionName=function_name, Qualifier=fn_version
        )
        snapshot.match("delete_version", delete_version)
        delete_alias = lambda_client.delete_function_event_invoke_config(
            FunctionName=function_name, Qualifier=fn_alias
        )
        snapshot.match("delete_alias", delete_alias)

        list_response_postdelete = lambda_client.list_function_event_invoke_configs(
            FunctionName=function_name
        )
        snapshot.match("list_configs_postdelete", list_response_postdelete)
        assert len(list_response_postdelete["FunctionEventInvokeConfigs"]) == 0

        # already deleted, try to delete again
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.delete_function_event_invoke_config(FunctionName=function_name)
        snapshot.match("delete_function_not_found", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.delete_function_event_invoke_config(FunctionName="doesnotexist")
        snapshot.match("delete_function_doesnotexist", e.value.response)

        # more excs

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.list_function_event_invoke_configs(FunctionName="doesnotexist")
        snapshot.match("list_function_doesnotexist", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.get_function_event_invoke_config(FunctionName="doesnotexist")
        snapshot.match("get_function_doesnotexist", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.get_function_event_invoke_config(
                FunctionName=function_name, Qualifier="doesnotexist"
            )
        snapshot.match("get_qualifier_doesnotexist", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.update_function_event_invoke_config(
                FunctionName="doesnotexist", MaximumRetryAttempts=0
            )
        snapshot.match("update_eventinvokeconfig_function_doesnotexist", e.value.response)

        # ARN is valid but the alias doesn't have an event invoke config anymore (see previous delete)
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.get_function_event_invoke_config(FunctionName=fn_alias_result["AliasArn"])
        snapshot.match("get_eventinvokeconfig_doesnotexist", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.update_function_event_invoke_config(
                FunctionName=fn_alias_result["AliasArn"], MaximumRetryAttempts=0
            )
        snapshot.match(
            "update_eventinvokeconfig_config_doesnotexist_with_qualifier", e.value.response
        )

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.update_function_event_invoke_config(
                FunctionName=fn_arn, MaximumRetryAttempts=0
            )
        snapshot.match(
            "update_eventinvokeconfig_config_doesnotexist_without_qualifier", e.value.response
        )


# note: these tests are inherently a bit flaky on AWS since it depends on account/region global usage limits/quotas
@pytest.mark.skipif(condition=is_old_provider(), reason="not supported")
class TestLambdaReservedConcurrency:
    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider)
    def test_function_concurrency_exceptions(self, lambda_client, create_lambda_function, snapshot):
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        acc_settings = lambda_client.get_account_settings()

        if acc_settings["AccountLimit"]["UnreservedConcurrentExecutions"] <= 100:
            pytest.skip(
                "Account limits are too low. You'll need to request a quota increase on AWS for UnreservedConcurrentExecution."
            )

        reserved_limit = acc_settings["AccountLimit"]["UnreservedConcurrentExecutions"]
        min_capacity = 100

        # actual needed capacity on AWS is 101+ (!)
        # new accounts in an organization have by default a quota of 50 though
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.put_function_concurrency(
                FunctionName="unknown", ReservedConcurrentExecutions=1
            )
        snapshot.match("put_concurrency_unknown_fn", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.put_function_concurrency(
                FunctionName="unknown", ReservedConcurrentExecutions=0
            )
        snapshot.match("put_concurrency_unknown_fn_invalid_concurrency", e.value.response)

        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.put_function_concurrency(
                FunctionName=function_name,
                ReservedConcurrentExecutions=reserved_limit - min_capacity + 1,
            )
        snapshot.match("put_concurrency_known_fn_concurrency_limit_exceeded", e.value.response)

        # positive references
        put_0_response = lambda_client.put_function_concurrency(
            FunctionName=function_name, ReservedConcurrentExecutions=0
        )  # This kind of "disables" a function since it can never exceed 0.
        snapshot.match("put_0_response", put_0_response)
        put_1_response = lambda_client.put_function_concurrency(
            FunctionName=function_name, ReservedConcurrentExecutions=1
        )
        snapshot.match("put_1_response", put_1_response)
        delete_response = lambda_client.delete_function_concurrency(FunctionName=function_name)
        snapshot.match("delete_response", delete_response)

        # maximum limit
        lambda_client.put_function_concurrency(
            FunctionName=function_name, ReservedConcurrentExecutions=reserved_limit - (min_capacity)
        )

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(condition=is_old_provider)
    def test_function_concurrency(self, lambda_client, create_lambda_function, snapshot):
        """Testing the api of the put function concurrency action"""

        acc_settings = lambda_client.get_account_settings()
        if acc_settings["AccountLimit"]["UnreservedConcurrentExecutions"] <= 100:
            pytest.skip(
                "Account limits are too low. You'll need to request a quota increase on AWS for UnreservedConcurrentExecution."
            )

        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        #  An error occurred (InvalidParameterValueException) when calling the PutFunctionConcurrency operation: Specified ReservedConcurrentExecutions for function decreases account's UnreservedConcurrentExecution below its minimum value of [50].
        response = lambda_client.put_function_concurrency(
            FunctionName=function_name, ReservedConcurrentExecutions=1
        )
        snapshot.match("put_function_concurrency", response)
        response = lambda_client.get_function_concurrency(FunctionName=function_name)
        snapshot.match("get_function_concurrency", response)
        response = lambda_client.delete_function_concurrency(FunctionName=function_name)
        snapshot.match("delete_function_concurrency", response)

        response = lambda_client.get_function_concurrency(FunctionName=function_name)
        snapshot.match("get_function_concurrency_postdelete", response)


@pytest.mark.skipif(condition=is_old_provider(), reason="not supported")
class TestLambdaProvisionedConcurrency:

    # TODO: test ARN
    # TODO: test shorthand ARN
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..LastUpdateStatus",
            "$..LastUpdateStatusReason",
            "$..LastUpdateStatusReasonCode",
            "$..State",
            "$..StateReason",
            "$..StateReasonCode",
        ]
    )
    @pytest.mark.aws_validated
    def test_provisioned_concurrency_exceptions(
        self, lambda_client, create_lambda_function, snapshot
    ):
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        publish_version_result = lambda_client.publish_version(FunctionName=function_name)
        function_version = publish_version_result["Version"]
        snapshot.match("publish_version_result", publish_version_result)

        ### GET

        # normal (valid) structure, but function version doesn't have a provisioned config yet
        with pytest.raises(
            lambda_client.exceptions.ProvisionedConcurrencyConfigNotFoundException
        ) as e:
            lambda_client.get_provisioned_concurrency_config(
                FunctionName=function_name, Qualifier=function_version
            )
        snapshot.match("get_provisioned_config_doesnotexist", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.get_provisioned_concurrency_config(
                FunctionName="doesnotexist", Qualifier="noalias"
            )
        snapshot.match("get_provisioned_functionname_doesnotexist", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.get_provisioned_concurrency_config(
                FunctionName=function_name, Qualifier="noalias"
            )
        snapshot.match("get_provisioned_qualifier_doesnotexist", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.get_provisioned_concurrency_config(
                FunctionName=function_name, Qualifier="10"
            )
        snapshot.match("get_provisioned_version_doesnotexist", e.value.response)

        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.get_provisioned_concurrency_config(
                FunctionName=function_name, Qualifier="$LATEST"
            )
        snapshot.match("get_provisioned_latest", e.value.response)

        ### LIST

        list_empty = lambda_client.list_provisioned_concurrency_configs(FunctionName=function_name)
        snapshot.match("list_provisioned_noconfigs", list_empty)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.list_provisioned_concurrency_configs(FunctionName="doesnotexist")
        snapshot.match("list_provisioned_functionname_doesnotexist", e.value.response)

        ### DELETE

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.delete_provisioned_concurrency_config(
                FunctionName="doesnotexist", Qualifier=function_version
            )
        snapshot.match("delete_provisioned_functionname_doesnotexist", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.delete_provisioned_concurrency_config(
                FunctionName=function_name, Qualifier="noalias"
            )
        snapshot.match("delete_provisioned_qualifier_doesnotexist", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.delete_provisioned_concurrency_config(
                FunctionName=function_name, Qualifier="10"
            )
        snapshot.match("delete_provisioned_version_doesnotexist", e.value.response)

        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.delete_provisioned_concurrency_config(
                FunctionName=function_name, Qualifier="$LATEST"
            )
        snapshot.match("delete_provisioned_latest", e.value.response)

        delete_nonexistent = lambda_client.delete_provisioned_concurrency_config(
            FunctionName=function_name, Qualifier=function_version
        )
        snapshot.match("delete_provisioned_config_doesnotexist", delete_nonexistent)

        ### PUT

        # function does not exist
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.put_provisioned_concurrency_config(
                FunctionName="doesnotexist", Qualifier="noalias", ProvisionedConcurrentExecutions=1
            )
        snapshot.match("put_provisioned_functionname_doesnotexist_alias", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.put_provisioned_concurrency_config(
                FunctionName="doesnotexist", Qualifier="1", ProvisionedConcurrentExecutions=1
            )
        snapshot.match("put_provisioned_functionname_doesnotexist_version", e.value.response)

        # invalid alias
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.put_provisioned_concurrency_config(
                FunctionName=function_name,
                Qualifier="doesnotexist",
                ProvisionedConcurrentExecutions=1,
            )
        snapshot.match("put_provisioned_qualifier_doesnotexist", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.put_provisioned_concurrency_config(
                FunctionName=function_name, Qualifier="10", ProvisionedConcurrentExecutions=1
            )
        snapshot.match("put_provisioned_version_doesnotexist", e.value.response)

        # set for $LATEST
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.put_provisioned_concurrency_config(
                FunctionName=function_name, Qualifier="$LATEST", ProvisionedConcurrentExecutions=1
            )
        snapshot.match("put_provisioned_latest", e.value.response)

    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..LastUpdateStatus",
            "$..LastUpdateStatusReason",
            "$..LastUpdateStatusReasonCode",
            "$..State",
            "$..StateReason",
            "$..StateReasonCode",
        ]
    )
    @pytest.mark.aws_validated
    def test_lambda_provisioned_lifecycle(self, lambda_client, create_lambda_function, snapshot):
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        publish_version_result = lambda_client.publish_version(FunctionName=function_name)
        function_version = publish_version_result["Version"]
        snapshot.match("publish_version_result", publish_version_result)

        lambda_client.get_waiter("function_active_v2").wait(
            FunctionName=function_name, Qualifier=function_version
        )
        lambda_client.get_waiter("function_updated_v2").wait(
            FunctionName=function_name, Qualifier=function_version
        )

        alias_name = f"alias-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(alias_name, "<alias-name>"))
        create_alias_result = lambda_client.create_alias(
            FunctionName=function_name, Name=alias_name, FunctionVersion=function_version
        )
        snapshot.match("create_alias_result", create_alias_result)

        # some edge cases

        # attempt to set up provisioned concurrency for an alias that is pointing to a version that already has a provisioned concurrency setup

        put_provisioned_on_version = lambda_client.put_provisioned_concurrency_config(
            FunctionName=function_name,
            Qualifier=function_version,
            ProvisionedConcurrentExecutions=1,
        )
        snapshot.match("put_provisioned_on_version", put_provisioned_on_version)
        with pytest.raises(lambda_client.exceptions.ResourceConflictException) as e:
            lambda_client.put_provisioned_concurrency_config(
                FunctionName=function_name, Qualifier=alias_name, ProvisionedConcurrentExecutions=1
            )
        snapshot.match("put_provisioned_on_alias_versionconflict", e.value.response)

        delete_provisioned_version = lambda_client.delete_provisioned_concurrency_config(
            FunctionName=function_name, Qualifier=function_version
        )
        snapshot.match("delete_provisioned_version", delete_provisioned_version)

        with pytest.raises(
            lambda_client.exceptions.ProvisionedConcurrencyConfigNotFoundException
        ) as e:
            lambda_client.get_provisioned_concurrency_config(
                FunctionName=function_name, Qualifier=function_version
            )
        snapshot.match("get_provisioned_version_postdelete", e.value.response)

        # now the other way around

        put_provisioned_on_alias = lambda_client.put_provisioned_concurrency_config(
            FunctionName=function_name, Qualifier=alias_name, ProvisionedConcurrentExecutions=1
        )
        snapshot.match("put_provisioned_on_alias", put_provisioned_on_alias)
        with pytest.raises(lambda_client.exceptions.ResourceConflictException) as e:
            lambda_client.put_provisioned_concurrency_config(
                FunctionName=function_name,
                Qualifier=function_version,
                ProvisionedConcurrentExecutions=1,
            )
        snapshot.match("put_provisioned_on_version_conflict", e.value.response)

        # deleting the alias will also delete the provisioned concurrency config that points to it
        delete_alias_result = lambda_client.delete_alias(
            FunctionName=function_name, Name=alias_name
        )
        snapshot.match("delete_alias_result", delete_alias_result)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.get_provisioned_concurrency_config(
                FunctionName=function_name, Qualifier=alias_name
            )
        snapshot.match("get_provisioned_alias_postaliasdelete", e.value.response)

        list_response_postdeletes = lambda_client.list_provisioned_concurrency_configs(
            FunctionName=function_name
        )
        assert len(list_response_postdeletes["ProvisionedConcurrencyConfigs"]) == 0
        snapshot.match("list_response_postdeletes", list_response_postdeletes)


@pytest.mark.skip_snapshot_verify(
    condition=is_old_provider,
    paths=["$..RevisionId", "$..Policy.Statement", "$..PolicyName", "$..PolicyArn", "$..Layers"],
)
class TestLambdaPermissions:
    @pytest.mark.skipif(condition=is_old_provider(), reason="not supported")
    @pytest.mark.aws_validated
    def test_permission_exceptions(
        self, lambda_client, iam_client, create_lambda_function, account_id, snapshot
    ):
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.get_policy(FunctionName="doesnotexist")
        snapshot.match("get_policy_fn_doesnotexist", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.add_permission(
                FunctionName="doesnotexist",
                Action="lambda:InvokeFunction",
                StatementId="s3",
                Principal="s3.amazonaws.com",
                SourceArn=aws_stack.s3_bucket_arn("test-bucket"),
            )
        snapshot.match("add_permission_fn_doesnotexist", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.remove_permission(
                FunctionName="doesnotexist",
                StatementId="s3",
            )
        snapshot.match("remove_permission_fn_doesnotexist", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.remove_permission(
                FunctionName=function_name,
                StatementId="s3",
            )
        snapshot.match("remove_permission_policy_doesnotexist", e.value.response)

    @pytest.mark.aws_validated
    def test_add_lambda_permission_aws(
        self, lambda_client, iam_client, create_lambda_function, account_id, snapshot
    ):
        """Testing the add_permission call on lambda, by adding a new resource-based policy to a lambda function"""

        function_name = f"lambda_func-{short_uid()}"
        lambda_create_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        snapshot.match("create_lambda", lambda_create_response)
        # create lambda permission
        action = "lambda:InvokeFunction"
        sid = "s3"
        principal = "s3.amazonaws.com"
        resp = lambda_client.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal=principal,
            SourceArn=aws_stack.s3_bucket_arn("test-bucket"),
        )
        snapshot.match("add_permission", resp)

        # fetch lambda policy
        get_policy_result = lambda_client.get_policy(FunctionName=function_name)
        snapshot.match("get_policy", get_policy_result)

    @pytest.mark.skip_snapshot_verify(paths=["$..Message"], condition=is_old_provider)
    @pytest.mark.aws_validated
    def test_remove_multi_permissions(self, lambda_client, create_lambda_function, snapshot):
        """Tests creation and subsequent removal of multiple permissions, including the changes in the policy"""

        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        action = "lambda:InvokeFunction"
        sid = "s3"
        principal = "s3.amazonaws.com"
        permission_1_add = lambda_client.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal=principal,
        )
        snapshot.match("add_permission_1", permission_1_add)

        sid_2 = "sqs"
        principal_2 = "sqs.amazonaws.com"
        permission_2_add = lambda_client.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid_2,
            Principal=principal_2,
            SourceArn=aws_stack.s3_bucket_arn("test-bucket"),
        )
        snapshot.match("add_permission_2", permission_2_add)
        policy_response = lambda_client.get_policy(
            FunctionName=function_name,
        )
        snapshot.match("policy_after_2_add", policy_response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.remove_permission(
                FunctionName=function_name,
                StatementId="non-existent",
            )
        snapshot.match("expect_error_remove_permission", e.value.response)

        lambda_client.remove_permission(
            FunctionName=function_name,
            StatementId=sid_2,
        )
        policy = json.loads(
            lambda_client.get_policy(
                FunctionName=function_name,
            )["Policy"]
        )
        snapshot.match("policy_after_removal", policy)

        lambda_client.remove_permission(
            FunctionName=function_name,
            StatementId=sid,
        )
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as ctx:
            lambda_client.get_policy(FunctionName=function_name)
        snapshot.match("expect_exception_get_policy", ctx.value.response)

    @pytest.mark.aws_validated
    def test_create_multiple_lambda_permissions(
        self, lambda_client, create_lambda_function, snapshot
    ):
        """Test creating multiple lambda permissions and checking the policy"""

        function_name = f"test-function-{short_uid()}"

        create_lambda_function(
            func_name=function_name,
            runtime=Runtime.python3_7,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
        )

        action = "lambda:InvokeFunction"
        sid = "logs"
        resp = lambda_client.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal="logs.amazonaws.com",
        )
        snapshot.match("add_permission_response_1", resp)

        sid = "kinesis"
        resp = lambda_client.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal="kinesis.amazonaws.com",
        )
        snapshot.match("add_permission_response_2", resp)

        policy_response = lambda_client.get_policy(
            FunctionName=function_name,
        )
        snapshot.match("policy_after_2_add", policy_response)


# TODO fix version state after publish
@pytest.mark.skip_snapshot_verify(
    paths=[
        "$..LastUpdateStatus",
        "$..LastUpdateStatusReason",
        "$..LastUpdateStatusReasonCode",
        "$..State",
        "$..StateReason",
        "$..StateReasonCode",
    ]
)
class TestLambdaUrl:
    @pytest.mark.skipif(condition=is_old_provider(), reason="not supported")
    @pytest.mark.aws_validated
    def test_url_config_exceptions(self, lambda_client, create_lambda_function, snapshot):
        """
        note: list order is not defined
        """
        snapshot.add_transformer(
            snapshot.transform.key_value("FunctionUrl", "lambda-url", reference_replacement=False)
        )
        snapshot.add_transformer(
            SortingTransformer("FunctionUrlConfigs", sorting_fn=lambda x: x["FunctionArn"])
        )

        function_name = f"test-function-{short_uid()}"
        alias_name = "urlalias"

        create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_NODEJS, get_content=True),
            runtime=Runtime.nodejs14_x,
            handler="lambda_handler.handler",
        )
        fn_arn = lambda_client.get_function(FunctionName=function_name)["Configuration"][
            "FunctionArn"
        ]
        fn_version_result = lambda_client.publish_version(FunctionName=function_name)
        snapshot.match("fn_version_result", fn_version_result)
        create_alias_result = lambda_client.create_alias(
            FunctionName=function_name,
            Name=alias_name,
            FunctionVersion=fn_version_result["Version"],
        )
        snapshot.match("create_alias_result", create_alias_result)

        # function name + qualifier tests
        fn_arn_doesnotexist = fn_arn.replace(function_name, "doesnotexist")

        def test_name_and_qualifier(method: Callable, snapshot_prefix: str, tests, **kwargs):
            for t in tests:
                with pytest.raises(t["exc"]) as e:
                    method(**t["args"], **kwargs)
                snapshot.match(f"{snapshot_prefix}_{t['SnapshotName']}", e.value.response)

        tests = [
            {
                "args": {"FunctionName": "doesnotexist"},
                "SnapshotName": "name_doesnotexist",
                "exc": lambda_client.exceptions.ResourceNotFoundException,
            },
            {
                "args": {"FunctionName": fn_arn_doesnotexist},
                "SnapshotName": "arn_doesnotexist",
                "exc": lambda_client.exceptions.ResourceNotFoundException,
            },
            {
                "args": {"FunctionName": "doesnotexist", "Qualifier": "1"},
                "SnapshotName": "name_doesnotexist_qualifier",
                "exc": lambda_client.exceptions.ClientError,
            },
            {
                "args": {"FunctionName": function_name, "Qualifier": "1"},
                "SnapshotName": "qualifier_version",
                "exc": lambda_client.exceptions.ClientError,
            },
            {
                "args": {"FunctionName": function_name, "Qualifier": "2"},
                "SnapshotName": "qualifier_version_doesnotexist",
                "exc": lambda_client.exceptions.ClientError,
            },
            {
                "args": {"FunctionName": function_name, "Qualifier": "v1"},
                "SnapshotName": "qualifier_alias_doesnotexist",
                "exc": lambda_client.exceptions.ResourceNotFoundException,
            },
        ]
        config_doesnotexist_tests = [
            {
                "args": {"FunctionName": function_name},
                "SnapshotName": "config_doesnotexist",
                "exc": lambda_client.exceptions.ResourceNotFoundException,
            },
        ]

        test_name_and_qualifier(
            lambda_client.create_function_url_config,
            "create_function_url_config",
            tests,
            AuthType="NONE",
        )
        test_name_and_qualifier(
            lambda_client.get_function_url_config,
            "get_function_url_config",
            tests + config_doesnotexist_tests,
        )
        test_name_and_qualifier(
            lambda_client.delete_function_url_config,
            "delete_function_url_config",
            tests + config_doesnotexist_tests,
        )
        test_name_and_qualifier(
            lambda_client.update_function_url_config,
            "update_function_url_config",
            tests + config_doesnotexist_tests,
            AuthType="AWS_IAM",
        )

    @pytest.mark.skipif(condition=is_old_provider(), reason="not supported")
    @pytest.mark.aws_validated
    def test_url_config_list_paging(self, lambda_client, create_lambda_function, snapshot):
        snapshot.add_transformer(
            snapshot.transform.key_value("FunctionUrl", "lambda-url", reference_replacement=False)
        )
        snapshot.add_transformer(
            SortingTransformer("FunctionUrlConfigs", sorting_fn=lambda x: x["FunctionArn"])
        )
        function_name = f"test-function-{short_uid()}"
        alias_name = "urlalias"

        create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_NODEJS, get_content=True),
            runtime=Runtime.nodejs14_x,
            handler="lambda_handler.handler",
        )

        fn_version_result = lambda_client.publish_version(FunctionName=function_name)
        snapshot.match("fn_version_result", fn_version_result)
        create_alias_result = lambda_client.create_alias(
            FunctionName=function_name,
            Name=alias_name,
            FunctionVersion=fn_version_result["Version"],
        )
        snapshot.match("create_alias_result", create_alias_result)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.list_function_url_configs(FunctionName="doesnotexist")
        snapshot.match("list_function_notfound", e.value.response)

        list_all_empty = lambda_client.list_function_url_configs(FunctionName=function_name)
        snapshot.match("list_all_empty", list_all_empty)

        url_config_fn = lambda_client.create_function_url_config(
            FunctionName=function_name, AuthType="NONE"
        )
        snapshot.match("url_config_fn", url_config_fn)
        url_config_alias = lambda_client.create_function_url_config(
            FunctionName=function_name, Qualifier=alias_name, AuthType="NONE"
        )
        snapshot.match("url_config_alias", url_config_alias)

        list_all = lambda_client.list_function_url_configs(FunctionName=function_name)
        snapshot.match("list_all", list_all)

        total_configs = [url_config_fn["FunctionUrl"], url_config_alias["FunctionUrl"]]

        list_max_1_item = lambda_client.list_function_url_configs(
            FunctionName=function_name, MaxItems=1
        )
        assert len(list_max_1_item["FunctionUrlConfigs"]) == 1
        assert list_max_1_item["FunctionUrlConfigs"][0]["FunctionUrl"] in total_configs

        list_max_2_item = lambda_client.list_function_url_configs(
            FunctionName=function_name, MaxItems=2
        )
        assert len(list_max_2_item["FunctionUrlConfigs"]) == 2
        assert list_max_2_item["FunctionUrlConfigs"][0]["FunctionUrl"] in total_configs
        assert list_max_2_item["FunctionUrlConfigs"][1]["FunctionUrl"] in total_configs

        list_max_1_item_marker = lambda_client.list_function_url_configs(
            FunctionName=function_name, MaxItems=1, Marker=list_max_1_item["NextMarker"]
        )
        assert len(list_max_1_item_marker["FunctionUrlConfigs"]) == 1
        assert list_max_1_item_marker["FunctionUrlConfigs"][0]["FunctionUrl"] in total_configs
        assert (
            list_max_1_item_marker["FunctionUrlConfigs"][0]["FunctionUrl"]
            != list_max_1_item["FunctionUrlConfigs"][0]["FunctionUrl"]
        )

    @pytest.mark.aws_validated
    def test_url_config_lifecycle(self, lambda_client, create_lambda_function, snapshot):
        snapshot.add_transformer(
            snapshot.transform.key_value("FunctionUrl", "lambda-url", reference_replacement=False)
        )

        function_name = f"test-function-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_NODEJS, get_content=True),
            runtime=Runtime.nodejs14_x,
            handler="lambda_handler.handler",
        )

        url_config_created = lambda_client.create_function_url_config(
            FunctionName=function_name,
            AuthType="NONE",
        )
        snapshot.match("url_creation", url_config_created)

        with pytest.raises(lambda_client.exceptions.ResourceConflictException) as ex:
            lambda_client.create_function_url_config(
                FunctionName=function_name,
                AuthType="NONE",
            )
        snapshot.match("failed_duplication", ex.value.response)

        url_config_obtained = lambda_client.get_function_url_config(FunctionName=function_name)
        snapshot.match("get_url_config", url_config_obtained)

        url_config_updated = lambda_client.update_function_url_config(
            FunctionName=function_name,
            AuthType="AWS_IAM",
        )
        snapshot.match("updated_url_config", url_config_updated)

        lambda_client.delete_function_url_config(FunctionName=function_name)
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as ex:
            lambda_client.get_function_url_config(FunctionName=function_name)
        snapshot.match("failed_getter", ex.value.response)


class TestLambdaSizeLimits:
    def _generate_sized_python_str(self, filepath: str, size: int) -> str:
        """Generate a text of the specified size by appending #s at the end of the file"""
        with open(filepath, "r") as f:
            py_str = f.read()
        py_str += "#" * (size - len(py_str))
        return py_str

    @pytest.mark.skip_snapshot_verify(condition=is_old_provider)
    @pytest.mark.aws_validated
    def test_oversized_request_create_lambda(self, lambda_client, lambda_su_role, snapshot):
        function_name = f"test_lambda_{short_uid()}"
        code_str = self._generate_sized_python_str(TEST_LAMBDA_PYTHON_ECHO, 50 * 1024 * 1024)

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            code_str, get_content=True, runtime=Runtime.python3_9
        )

        # create lambda function
        with pytest.raises(ClientError) as e:
            lambda_client.create_function(
                FunctionName=function_name,
                Runtime=Runtime.python3_9,
                Handler="handler.handler",
                Role=lambda_su_role,
                Code={"ZipFile": zip_file},
                Timeout=10,
            )
        snapshot.match("invalid_param_exc", e.value.response)

    @pytest.mark.aws_validated
    def test_oversized_unzipped_lambda(
        self, lambda_client, s3_client, s3_bucket, lambda_su_role, snapshot
    ):
        function_name = f"test_lambda_{short_uid()}"
        bucket_key = "test_lambda.zip"
        code_str = self._generate_sized_python_str(
            TEST_LAMBDA_PYTHON_ECHO, FUNCTION_MAX_UNZIPPED_SIZE
        )

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            code_str, get_content=True, runtime=Runtime.python3_9
        )
        s3_client.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.create_function(
                FunctionName=function_name,
                Runtime=Runtime.python3_9,
                Handler="handler.handler",
                Role=lambda_su_role,
                Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
                Timeout=10,
            )
        snapshot.match("invalid_param_exc", e.value.response)

    @pytest.mark.aws_validated
    def test_large_lambda(
        self, lambda_client, s3_client, s3_bucket, lambda_su_role, snapshot, cleanups
    ):
        function_name = f"test_lambda_{short_uid()}"
        cleanups.append(lambda: lambda_client.delete_function(FunctionName=function_name))
        bucket_key = "test_lambda.zip"
        code_str = self._generate_sized_python_str(
            TEST_LAMBDA_PYTHON_ECHO, FUNCTION_MAX_UNZIPPED_SIZE - 1000
        )

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            code_str, get_content=True, runtime=Runtime.python3_9
        )
        s3_client.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        result = lambda_client.create_function(
            FunctionName=function_name,
            Runtime=Runtime.python3_9,
            Handler="handler.handler",
            Role=lambda_su_role,
            Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
            Timeout=10,
        )
        snapshot.match("create_function_large_zip", result)

    @pytest.mark.aws_validated
    def test_large_environment_variables_fails(
        self, lambda_client, create_lambda_function, snapshot
    ):
        """Lambda functions with environment variables larger than 4 KB should fail to create."""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        # set up environment mapping with a total size of 4 KB
        key = "LARGE_VAR"
        key_bytes = string_length_bytes(key)
        #  need to reserve bytes for json encoding ({, }, 2x" and :). This is 7
        #  bytes, so reserving 6 makes the environment variables one byte to
        #  big.
        target_size = 4 * KB - 6
        large_envvar_bytes = target_size - key_bytes
        large_envvar = "x" * large_envvar_bytes

        function_name = f"large-envvar-lambda-{short_uid()}"

        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as ex:
            create_lambda_function(
                handler_file=TEST_LAMBDA_PYTHON_ECHO,
                func_name=function_name,
                runtime=Runtime.python3_9,
                envvars={
                    "LARGE_VAR": large_envvar,
                },
            )

        snapshot.match("failed_create_fn_result", ex.value.response)
        with pytest.raises(ClientError) as ex:
            lambda_client.get_function(FunctionName=function_name)

        assert ex.match("ResourceNotFoundException")

    @pytest.mark.aws_validated
    def test_large_environment_fails_multiple_keys(
        self, lambda_client, create_lambda_function, snapshot
    ):
        """Lambda functions with environment mappings larger than 4 KB should fail to create"""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        # set up environment mapping with a total size of 4 KB
        env = {"SMALL_VAR": "ok"}

        key = "LARGE_VAR"
        # this size makes the environment > 4K
        target_size = 4064
        large_envvar = "x" * target_size
        env[key] = large_envvar
        assert environment_length_bytes(env) == 4097

        function_name = f"large-envvar-lambda-{short_uid()}"

        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as ex:
            create_lambda_function(
                handler_file=TEST_LAMBDA_PYTHON_ECHO,
                func_name=function_name,
                runtime=Runtime.python3_9,
                envvars=env,
            )

        snapshot.match("failured_create_fn_result_multi_key", ex.value.response)

        with pytest.raises(ClientError) as exc:
            lambda_client.get_function(FunctionName=function_name)

        assert exc.match("ResourceNotFoundException")

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..CodeSha256",
            "$..EphemeralStorage",
            "$..LastUpdateStatus",
            "$..MemorySize",
            "$..ResponseMetadata",
            "$..State",
            "$..StateReason",
            "$..StateReasonCode",
            "$..VpcConfig",
        ],
    )
    def test_lambda_envvars_near_limit_succeeds(
        self, lambda_client, create_lambda_function, snapshot
    ):
        """Lambda functions with environments less than or equal to 4 KB can be created."""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        # set up environment mapping with a total size of 4 KB
        key = "LARGE_VAR"
        key_bytes = string_length_bytes(key)
        # the environment variable size is exactly 4KB, so should succeed
        target_size = 4 * KB - 7
        large_envvar_bytes = target_size - key_bytes
        large_envvar = "x" * large_envvar_bytes

        function_name = f"large-envvar-lambda-{short_uid()}"
        res = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            envvars={
                "LARGE_VAR": large_envvar,
            },
        )

        snapshot.match("successful_create_fn_result", res)
        lambda_client.get_function(FunctionName=function_name)


# TODO: test paging
# TODO: test function name / ARN resolving
@pytest.mark.skipif(is_old_provider(), reason="not implemented")
class TestCodeSigningConfig:
    @pytest.mark.aws_validated
    def test_function_code_signing_config(
        self, lambda_client, create_lambda_function, snapshot, account_id
    ):
        """Testing the API of code signing config"""

        function_name = f"lambda_func-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        response = lambda_client.create_code_signing_config(
            Description="Testing CodeSigning Config",
            AllowedPublishers={
                "SigningProfileVersionArns": [
                    f"arn:aws:signer:{lambda_client.meta.region_name}:{account_id}:/signing-profiles/test",
                ]
            },
            CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Enforce"},
        )
        snapshot.match("create_code_signing_config", response)

        code_signing_arn = response["CodeSigningConfig"]["CodeSigningConfigArn"]
        response = lambda_client.update_code_signing_config(
            CodeSigningConfigArn=code_signing_arn,
            CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Warn"},
        )
        snapshot.match("update_code_signing_config", response)

        response = lambda_client.get_code_signing_config(CodeSigningConfigArn=code_signing_arn)
        snapshot.match("get_code_signing_config", response)

        response = lambda_client.put_function_code_signing_config(
            CodeSigningConfigArn=code_signing_arn, FunctionName=function_name
        )
        snapshot.match("put_function_code_signing_config", response)

        response = lambda_client.get_function_code_signing_config(FunctionName=function_name)
        snapshot.match("get_function_code_signing_config", response)

        response = lambda_client.list_code_signing_configs()
        snapshot.match("list_code_signing_configs", response)

        response = lambda_client.list_functions_by_code_signing_config(
            CodeSigningConfigArn=code_signing_arn
        )
        snapshot.match("list_functions_by_code_signing_config", response)

        response = lambda_client.delete_function_code_signing_config(FunctionName=function_name)
        snapshot.match("delete_function_code_signing_config", response)

        response = lambda_client.delete_code_signing_config(CodeSigningConfigArn=code_signing_arn)
        snapshot.match("delete_code_signing_config", response)

    def test_code_signing_not_found_excs(
        self, snapshot, lambda_client, create_lambda_function, account_id
    ):
        """tests for exceptions on missing resources and related corner cases"""

        function_name = f"lambda_func-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        response = lambda_client.create_code_signing_config(
            Description="Testing CodeSigning Config",
            AllowedPublishers={
                "SigningProfileVersionArns": [
                    f"arn:aws:signer:{lambda_client.meta.region_name}:{account_id}:/signing-profiles/test",
                ]
            },
            CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Enforce"},
        )
        snapshot.match("create_code_signing_config", response)

        csc_arn = response["CodeSigningConfig"]["CodeSigningConfigArn"]
        csc_arn_invalid = f"{csc_arn[:-1]}x"
        snapshot.add_transformer(snapshot.transform.regex(csc_arn_invalid, "<csc_arn_invalid>"))

        nonexisting_fn_name = "csc-test-doesnotexist"

        # deletes
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.delete_code_signing_config(CodeSigningConfigArn=csc_arn_invalid)
        snapshot.match("delete_csc_notfound", e.value.response)

        nothing_to_delete_response = lambda_client.delete_function_code_signing_config(
            FunctionName=function_name
        )
        snapshot.match("nothing_to_delete_response", nothing_to_delete_response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.delete_function_code_signing_config(FunctionName="csc-test-doesnotexist")
        snapshot.match("delete_function_csc_fnnotfound", e.value.response)

        # put
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.put_function_code_signing_config(
                FunctionName=nonexisting_fn_name, CodeSigningConfigArn=csc_arn
            )
        snapshot.match("put_function_csc_invalid_fnname", e.value.response)

        with pytest.raises(lambda_client.exceptions.CodeSigningConfigNotFoundException) as e:
            lambda_client.put_function_code_signing_config(
                FunctionName=function_name, CodeSigningConfigArn=csc_arn_invalid
            )
        snapshot.match("put_function_csc_invalid_csc_arn", e.value.response)

        with pytest.raises(lambda_client.exceptions.CodeSigningConfigNotFoundException) as e:
            lambda_client.put_function_code_signing_config(
                FunctionName=nonexisting_fn_name, CodeSigningConfigArn=csc_arn_invalid
            )
        snapshot.match("put_function_csc_invalid_both", e.value.response)

        # update csc
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.update_code_signing_config(
                CodeSigningConfigArn=csc_arn_invalid, Description="new-description"
            )
        snapshot.match("update_csc_invalid_csc_arn", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.update_code_signing_config(CodeSigningConfigArn=csc_arn_invalid)
        snapshot.match("update_csc_noupdates", e.value.response)

        update_csc_noupdate_response = lambda_client.update_code_signing_config(
            CodeSigningConfigArn=csc_arn
        )
        snapshot.match("update_csc_noupdate_response", update_csc_noupdate_response)

        # get
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.get_code_signing_config(CodeSigningConfigArn=csc_arn_invalid)
        snapshot.match("get_csc_invalid", e.value.response)

        get_function_csc_fnwithoutcsc = lambda_client.get_function_code_signing_config(
            FunctionName=function_name
        )
        snapshot.match("get_function_csc_fnwithoutcsc", get_function_csc_fnwithoutcsc)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.get_function_code_signing_config(FunctionName=nonexisting_fn_name)
        snapshot.match("get_function_csc_nonexistingfn", e.value.response)

        # list
        list_functions_by_csc_fnwithoutcsc = lambda_client.list_functions_by_code_signing_config(
            CodeSigningConfigArn=csc_arn
        )
        snapshot.match("list_functions_by_csc_fnwithoutcsc", list_functions_by_csc_fnwithoutcsc)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.list_functions_by_code_signing_config(
                CodeSigningConfigArn=csc_arn_invalid
            )
        snapshot.match("list_functions_by_csc_invalid_cscarn", e.value.response)


@pytest.mark.skipif(is_old_provider(), reason="not implemented")
class TestLambdaAccountSettings:

    # TODO: for now probably fine if it just returns some static values, but might be interesting to properly implement this in the new provider
    @pytest.mark.aws_validated
    def test_account_settings(self, lambda_client, snapshot):
        acc_settings = lambda_client.get_account_settings()
        acc_settings["AccountLimit"] = sorted(list(acc_settings["AccountLimit"].keys()))
        acc_settings["AccountUsage"] = sorted(list(acc_settings["AccountUsage"].keys()))
        snapshot.match("acc_settings_modded", acc_settings)


@pytest.mark.skipif(is_old_provider(), reason="new provider only")
class TestLambdaEventSourceMappings:
    def test_event_source_mapping_exceptions(self, lambda_client, snapshot):

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.get_event_source_mapping(UUID=long_uid())
        snapshot.match("get_unknown_uuid", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.delete_event_source_mapping(UUID=long_uid())
        snapshot.match("delete_unknown_uuid", e.value.response)

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.update_event_source_mapping(UUID=long_uid(), Enabled=False)
        snapshot.match("update_unknown_uuid", e.value.response)

        # note: list doesn't care about the resource filters existing
        lambda_client.list_event_source_mappings()
        lambda_client.list_event_source_mappings(FunctionName="doesnotexist")
        lambda_client.list_event_source_mappings(
            EventSourceArn="arn:aws:sqs:us-east-1:111111111111:somequeue"
        )

        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.create_event_source_mapping(FunctionName="doesnotexist")
        snapshot.match("create_no_event_source_arn", e.value.response)

        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.create_event_source_mapping(
                FunctionName="doesnotexist",
                EventSourceArn="arn:aws:sqs:us-east-1:111111111111:somequeue",
            )
        snapshot.match("create_unknown_params", e.value.response)

    @pytest.mark.skip_snapshot_verify(paths=["$..State"])  # TODO: fix and remove
    def test_event_source_mapping_lifecycle(
        self,
        create_lambda_function,
        lambda_client,
        snapshot,
        sqs_create_queue,
        sqs_client,
        cleanups,
        lambda_su_role,
    ):
        function_name = f"lambda_func-{short_uid()}"

        queue_url = sqs_create_queue()
        queue_arn = sqs_client.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
        )
        # "minimal"
        create_response = lambda_client.create_event_source_mapping(
            FunctionName=function_name, EventSourceArn=queue_arn
        )
        snapshot.match("create_response", create_response)
        uuid = create_response["UUID"]
        cleanups.append(lambda: lambda_client.delete_event_source_mapping(UUID=uuid))

        # the stream might not be active immediately(!)
        def check_esm_active():
            return lambda_client.get_event_source_mapping(UUID=uuid)["State"] != "Creating"

        assert wait_until(check_esm_active)

        get_response = lambda_client.get_event_source_mapping(UUID=uuid)
        snapshot.match("get_response", get_response)
        #
        delete_response = lambda_client.delete_event_source_mapping(UUID=uuid)
        snapshot.match("delete_response", delete_response)

        # TODO: continue here after initial CRUD PR
        # check what happens when we delete the function
        # check behavior in relation to version/alias
        # wait until the stream is actually active
        #
        # lambda_client.update_event_source_mapping()
        #
        # lambda_client.list_event_source_mappings(FunctionName=function_name)
        # lambda_client.list_event_source_mappings(FunctionName=function_name, EventSourceArn=queue_arn)
        # lambda_client.list_event_source_mappings(EventSourceArn=queue_arn)
        #
        # lambda_client.delete_event_source_mapping(UUID=uuid)


@pytest.mark.skipif(condition=is_old_provider(), reason="not correctly supported")
class TestLambdaTags:
    def test_tag_exceptions(self, lambda_client, create_lambda_function, snapshot, account_id):
        function_name = f"fn-tag-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        function_arn = lambda_client.get_function(FunctionName=function_name)["Configuration"][
            "FunctionArn"
        ]
        arn_prefix = f"arn:aws:lambda:{lambda_client.meta.region_name}:{account_id}:function:"

        # invalid ARN
        with pytest.raises(lambda_client.exceptions.ClientError) as e:
            lambda_client.tag_resource(Resource="arn:aws:something", Tags={"key_a": "value_a"})
        snapshot.match("tag_lambda_invalidarn", e.value.response)

        # ARN valid but lambda function doesn't exist
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.tag_resource(
                Resource=f"{arn_prefix}doesnotexist", Tags={"key_a": "value_a"}
            )
        snapshot.match("tag_lambda_doesnotexist", e.value.response)

        # function exists but the qualifier in the ARN doesn't
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.tag_resource(Resource=f"{function_arn}:v1", Tags={"key_a": "value_a"})
        snapshot.match("tag_lambda_qualifier_doesnotexist", e.value.response)

        # get tags for resource that never had tags
        list_tags_response = lambda_client.list_tags(Resource=function_arn)
        snapshot.match("list_tag_lambda_empty", list_tags_response)

        # delete non-existing tag key
        untag_nomatch = lambda_client.untag_resource(Resource=function_arn, TagKeys=["somekey"])
        snapshot.match("untag_nomatch", untag_nomatch)

        # delete empty tags
        with pytest.raises(lambda_client.exceptions.ClientError) as e:
            lambda_client.untag_resource(Resource=function_arn, TagKeys=[])
        snapshot.match("untag_empty_keys", e.value.response)

        # add empty tags
        with pytest.raises(lambda_client.exceptions.ClientError) as e:
            lambda_client.tag_resource(Resource=function_arn, Tags={})
        snapshot.match("tag_empty_tags", e.value.response)

        # partial delete (one exists, one doesn't)
        lambda_client.tag_resource(
            Resource=function_arn, Tags={"a_key": "a_value", "b_key": "b_value"}
        )
        lambda_client.untag_resource(Resource=function_arn, TagKeys=["a_key", "c_key"])
        assert "a_key" not in lambda_client.list_tags(Resource=function_arn)["Tags"]
        assert "b_key" in lambda_client.list_tags(Resource=function_arn)["Tags"]

    def test_tag_limits(self, lambda_client, create_lambda_function, snapshot):
        """test the limit of 50 tags per resource"""
        function_name = f"fn-tag-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        function_arn = lambda_client.get_function(FunctionName=function_name)["Configuration"][
            "FunctionArn"
        ]

        # invalid
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.tag_resource(
                Resource=function_arn, Tags={f"{k}_key": f"{k}_value" for k in range(51)}
            )
        snapshot.match("tag_lambda_too_many_tags", e.value.response)

        # valid
        tag_response = lambda_client.tag_resource(
            Resource=function_arn, Tags={f"{k}_key": f"{k}_value" for k in range(50)}
        )
        snapshot.match("tag_response", tag_response)

        list_tags_response = lambda_client.list_tags(Resource=function_arn)
        snapshot.match("list_tags_response", list_tags_response)

        get_fn_response = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get_fn_response", get_fn_response)

        # try to add one more :)
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.tag_resource(Resource=function_arn, Tags={"a_key": "a_value"})
        snapshot.match("tag_lambda_too_many_tags_additional", e.value.response)

    def test_tag_versions(self, lambda_client, create_lambda_function, snapshot):
        function_name = f"fn-tag-{short_uid()}"
        create_function_result = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            Tags={"key_a": "value_a"},
        )
        function_arn = create_function_result["CreateFunctionResponse"]["FunctionArn"]
        publish_version_response = lambda_client.publish_version(FunctionName=function_name)
        version_arn = publish_version_response["FunctionArn"]
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.tag_resource(
                Resource=version_arn,
                Tags={
                    "key_b": "value_b",
                    "key_c": "value_c",
                    "key_d": "value_d",
                    "key_e": "value_e",
                },
            )
        snapshot.match("tag_resource_exception", e.value.response)

        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.tag_resource(
                Resource=f"{function_arn}:$LATEST",
                Tags={
                    "key_b": "value_b",
                    "key_c": "value_c",
                    "key_d": "value_d",
                    "key_e": "value_e",
                },
            )
        snapshot.match("tag_resource_latest_exception", e.value.response)

    def test_tag_lifecycle(self, lambda_client, create_lambda_function, snapshot):
        function_name = f"fn-tag-{short_uid()}"

        def snapshot_tags_for_resource(resource_arn: str, snapshot_suffix: str):
            list_tags_response = lambda_client.list_tags(Resource=resource_arn)
            snapshot.match(f"list_tags_response_{snapshot_suffix}", list_tags_response)
            get_fn_response = lambda_client.get_function(FunctionName=resource_arn)
            snapshot.match(f"get_fn_response_{snapshot_suffix}", get_fn_response)

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            Tags={"key_a": "value_a"},
        )
        fn_arn = lambda_client.get_function(FunctionName=function_name)["Configuration"][
            "FunctionArn"
        ]
        snapshot_tags_for_resource(fn_arn, "postfncreate")

        tag_resource_response = lambda_client.tag_resource(
            Resource=fn_arn,
            Tags={
                "key_b": "value_b",
                "key_c": "value_c",
                "key_d": "value_d",
                "key_e": "value_e",
            },
        )
        snapshot.match("tag_resource_response", tag_resource_response)
        snapshot_tags_for_resource(fn_arn, "postaddtags")

        tag_resource_response = lambda_client.tag_resource(
            Resource=fn_arn,
            Tags={
                "key_b": "value_b",
                "key_c": "value_x",
            },
        )
        snapshot.match("tag_resource_overwrite", tag_resource_response)
        snapshot_tags_for_resource(fn_arn, "overwrite")

        # remove two tags
        lambda_client.untag_resource(Resource=fn_arn, TagKeys=["key_c", "key_d"])
        snapshot_tags_for_resource(fn_arn, "postuntag")

        # remove all tags
        lambda_client.untag_resource(Resource=fn_arn, TagKeys=["key_a", "key_b", "key_e"])
        snapshot_tags_for_resource(fn_arn, "postuntagall")

        lambda_client.delete_function(FunctionName=function_name)
        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as e:
            lambda_client.list_tags(Resource=fn_arn)
        snapshot.match("list_tags_postdelete", e.value.response)

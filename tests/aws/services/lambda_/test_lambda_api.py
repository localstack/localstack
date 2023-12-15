"""API-focused tests only.
Everything related to behavior and implicit functionality goes into test_lambda.py instead
Don't add tests for asynchronous, blocking or implicit behavior here.

# TODO: create a re-usable pattern for fairly reproducible scenarios with slower updates/creates to test intermediary states
# TODO: code signing https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html
# TODO: file systems https://docs.aws.amazon.com/lambda/latest/dg/configuration-filesystem.html
# TODO: VPC config https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html

"""
import base64
import io
import json
import logging
import re
from hashlib import sha256
from io import BytesIO
from typing import Callable

import pytest
import requests
from botocore.config import Config
from botocore.exceptions import ClientError, ParamValidationError

from localstack import config
from localstack.aws.api.lambda_ import Architecture, Runtime
from localstack.constants import SECONDARY_TEST_AWS_REGION_NAME
from localstack.services.lambda_.api_utils import ARCHITECTURES
from localstack.services.lambda_.runtimes import (
    ALL_RUNTIMES,
    SNAP_START_SUPPORTED_RUNTIMES,
)
from localstack.testing.aws.lambda_utils import (
    _await_dynamodb_table_active,
    _await_event_source_mapping_enabled,
)
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer import SortingTransformer
from localstack.utils import testutil
from localstack.utils.aws import arns
from localstack.utils.docker_utils import DOCKER_CLIENT
from localstack.utils.files import load_file
from localstack.utils.functions import call_safe
from localstack.utils.strings import long_uid, short_uid, to_str
from localstack.utils.sync import ShortCircuitWaitException, wait_until
from localstack.utils.testutil import create_lambda_archive
from tests.aws.services.lambda_.test_lambda import (
    TEST_LAMBDA_JAVA_WITH_LIB,
    TEST_LAMBDA_NODEJS,
    TEST_LAMBDA_PYTHON_ECHO,
    TEST_LAMBDA_PYTHON_ECHO_ZIP,
    TEST_LAMBDA_PYTHON_VERSION,
    check_concurrency_quota,
)

LOG = logging.getLogger(__name__)

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


class TestLambdaFunction:
    @markers.snapshot.skip_snapshot_verify(
        # The RuntimeVersionArn is currently a hardcoded id and therefore does not reflect the ARN resource update
        # from python3.9 to python3.8 in update_func_conf_response.
        paths=["$..RuntimeVersionConfig.RuntimeVersionArn"]
    )
    @markers.aws.validated
    def test_function_lifecycle(self, snapshot, create_lambda_function, lambda_su_role, aws_client):
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
        aws_client.lambda_.get_waiter("function_active_v2").wait(FunctionName=function_name)

        get_function_response = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_function_response", get_function_response)

        update_func_conf_response = aws_client.lambda_.update_function_configuration(
            FunctionName=function_name,
            Runtime=Runtime.python3_8,
            Description="Changed-Description",
            MemorySize=512,
            Timeout=10,
            Environment={"Variables": {"ENV_A": "a"}},
        )
        snapshot.match("update_func_conf_response", update_func_conf_response)

        aws_client.lambda_.get_waiter("function_updated_v2").wait(FunctionName=function_name)

        get_function_response_postupdate = aws_client.lambda_.get_function(
            FunctionName=function_name
        )
        snapshot.match("get_function_response_postupdate", get_function_response_postupdate)

        zip_f = create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_VERSION), get_content=True)
        update_code_response = aws_client.lambda_.update_function_code(
            FunctionName=function_name,
            ZipFile=zip_f,
        )
        snapshot.match("update_code_response", update_code_response)

        aws_client.lambda_.get_waiter("function_updated_v2").wait(FunctionName=function_name)

        get_function_response_postcodeupdate = aws_client.lambda_.get_function(
            FunctionName=function_name
        )
        snapshot.match("get_function_response_postcodeupdate", get_function_response_postcodeupdate)

        delete_response = aws_client.lambda_.delete_function(FunctionName=function_name)
        snapshot.match("delete_response", delete_response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.delete_function(FunctionName=function_name)
        snapshot.match("delete_postdelete", e.value.response)

    @markers.aws.validated
    def test_redundant_updates(self, create_lambda_function, snapshot, aws_client):
        """validates that redundant updates work (basically testing idempotency)"""
        function_name = f"fn-{short_uid()}"

        create_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            Description="Initial description",
        )
        snapshot.match("create_response", create_response)

        first_update_result = aws_client.lambda_.update_function_configuration(
            FunctionName=function_name, Description="1st update description"
        )
        snapshot.match("first_update_result", first_update_result)

        aws_client.lambda_.get_waiter("function_updated_v2").wait(FunctionName=function_name)

        get_fn_config_result = aws_client.lambda_.get_function_configuration(
            FunctionName=function_name
        )
        snapshot.match("get_fn_config_result", get_fn_config_result)

        get_fn_result = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_fn_result", get_fn_result)

        redundant_update_result = aws_client.lambda_.update_function_configuration(
            FunctionName=function_name, Description="1st update description"
        )
        snapshot.match("redundant_update_result", redundant_update_result)
        aws_client.lambda_.get_waiter("function_updated_v2").wait(FunctionName=function_name)
        get_fn_result_after_redundant_update = aws_client.lambda_.get_function(
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
    @markers.aws.validated
    def test_ops_with_arn_qualifier_mismatch(
        self, create_lambda_function, snapshot, account_id, clientfn, aws_client
    ):
        function_name = "some-function"
        method = getattr(aws_client.lambda_, clientfn)
        with pytest.raises(ClientError) as e:
            method(
                FunctionName=f"arn:aws:lambda:{aws_client.lambda_.meta.region_name}:{account_id}:function:{function_name}:1",
                Qualifier="$LATEST",
            )
        snapshot.match("not_match_exception", e.value.response)
        # check if it works if it matches - still no function there
        with pytest.raises(ClientError) as e:
            method(
                FunctionName=f"arn:aws:lambda:{aws_client.lambda_.meta.region_name}:{account_id}:function:{function_name}:$LATEST",
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
    @markers.aws.validated
    def test_ops_on_nonexisting_version(
        self, create_lambda_function, snapshot, clientfn, aws_client
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
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            method = getattr(aws_client.lambda_, clientfn)
            method(FunctionName=function_name, Qualifier="1221")
        snapshot.match("version_not_found_exception", e.value.response)

    @markers.aws.validated
    def test_delete_on_nonexisting_version(self, create_lambda_function, snapshot, aws_client):
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
        aws_client.lambda_.delete_function(FunctionName=function_name, Qualifier="1233")
        aws_client.lambda_.delete_function(FunctionName=function_name, Qualifier="1233")
        aws_client.lambda_.delete_function(FunctionName=function_name)
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.delete_function(FunctionName=function_name)
        snapshot.match("delete_function_response_non_existent", e.value.response)
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.delete_function(FunctionName=function_name, Qualifier="1233")
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
    @markers.aws.validated
    def test_ops_on_nonexisting_fn(self, snapshot, clientfn, aws_client):
        """Test API responses on non-existing function names"""
        # technically the short_uid isn't really required but better safe than sorry
        function_name = f"i-dont-exist-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(function_name, "<nonexisting-fn-name>"))
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            method = getattr(aws_client.lambda_, clientfn)
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
    @markers.aws.validated
    def test_get_function_wrong_region(
        self, create_lambda_function, account_id, snapshot, clientfn, aws_client
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
            "us-east-1" if aws_client.lambda_.meta.region_name != "us-east-1" else "eu-central-1"
        )
        snapshot.add_transformer(snapshot.transform.regex(wrong_region, "<wrong-region>"))
        wrong_region_arn = f"arn:aws:lambda:{wrong_region}:{account_id}:function:{function_name}"
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            method = getattr(aws_client.lambda_, clientfn)
            method(FunctionName=wrong_region_arn)
        snapshot.match("wrong_region_exception", e.value.response)

    @markers.aws.validated
    def test_lambda_code_location_zipfile(
        self, snapshot, create_lambda_function_aws, lambda_su_role, aws_client
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
        get_function_response = aws_client.lambda_.get_function(FunctionName=function_name)
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
        update_function_response = aws_client.lambda_.update_function_code(
            FunctionName=function_name, ZipFile=zip_file_bytes_updated
        )
        snapshot.match("update-function-response", update_function_response)
        get_function_response_updated = aws_client.lambda_.get_function(FunctionName=function_name)
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

    @markers.aws.validated
    def test_lambda_code_location_s3(
        self, s3_bucket, snapshot, create_lambda_function_aws, lambda_su_role, aws_client
    ):
        function_name = f"code-function-{short_uid()}"
        bucket_key = "code/code-function.zip"
        zip_file_bytes = create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True)
        aws_client.s3.upload_fileobj(
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
        get_function_response = aws_client.lambda_.get_function(FunctionName=function_name)
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
        aws_client.s3.upload_fileobj(
            Fileobj=io.BytesIO(zip_file_bytes_updated), Bucket=s3_bucket, Key=bucket_key
        )
        update_function_response = aws_client.lambda_.update_function_code(
            FunctionName=function_name, S3Bucket=s3_bucket, S3Key=bucket_key
        )
        snapshot.match("update-function-response", update_function_response)
        get_function_response_updated = aws_client.lambda_.get_function(FunctionName=function_name)
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

    # TODO: fix type of AccessDeniedException yielding null
    @markers.snapshot.skip_snapshot_verify(paths=["function_arn_other_account_exc..Error.Message"])
    @markers.aws.validated
    def test_function_arns(
        self, create_lambda_function, region, account_id, aws_client, lambda_su_role, snapshot
    ):
        # create_function
        function_name_1 = f"test-function-arn-{short_uid()}"
        function_arn = f"arn:aws:lambda:{region}:{account_id}:function:{function_name_1}"
        function_arn_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_arn,
            runtime=Runtime.python3_12,
        )
        snapshot.match("create-function-arn-response", function_arn_response)

        function_name_2 = f"test-partial-arn-{short_uid()}"
        partial_arn = f"{account_id}:function:{function_name_2}"
        function_partial_arn_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=partial_arn,
            runtime=Runtime.python3_12,
        )
        snapshot.match("create-function-partial-arn-response", function_partial_arn_response)

        # create_function exceptions
        zip_file_bytes = create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True)
        # test invalid function name
        with pytest.raises(ClientError) as e:
            aws_client.lambda_.create_function(
                FunctionName="invalid:function:name",
                Handler="index.handler",
                Code={"ZipFile": zip_file_bytes},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime=Runtime.python3_12,
            )
        snapshot.match("invalid_function_name_exc", e.value.response)

        # test too long function name
        with pytest.raises(ClientError) as e:
            aws_client.lambda_.create_function(
                FunctionName="a" * 65,
                Handler="index.handler",
                Code={"ZipFile": zip_file_bytes},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime=Runtime.python3_12,
            )
        snapshot.match("long_function_name_exc", e.value.response)

        # test too long function arn
        max_function_arn_length = 140
        function_arn_prefix = f"arn:aws:lambda:{region}:{account_id}:function:"
        suffix_length = max_function_arn_length - len(function_arn_prefix) + 1
        long_function_arn = function_arn_prefix + "a" * suffix_length
        with pytest.raises(ClientError) as e:
            aws_client.lambda_.create_function(
                FunctionName=long_function_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_file_bytes},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime=Runtime.python3_12,
            )
        snapshot.match("long_function_arn_exc", e.value.response)

        # test other region in function arn than client
        function_name_1 = f"test-function-arn-{short_uid()}"
        other_region = "ap-southeast-1"
        assert (
            region != other_region
        ), "This test assumes that the region in the function arn differs from the client region"
        function_arn_other_region = (
            f"arn:aws:lambda:{other_region}:{account_id}:function:{function_name_1}"
        )
        with pytest.raises(ClientError) as e:
            aws_client.lambda_.create_function(
                FunctionName=function_arn_other_region,
                Handler="index.handler",
                Code={"ZipFile": zip_file_bytes},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime=Runtime.python3_12,
            )
        snapshot.match("function_arn_other_region_exc", e.value.response)

        # test other account in function arn than client
        function_name_1 = f"test-function-arn-{short_uid()}"
        other_account = "123456789012"
        assert (
            account_id != other_account
        ), "This test assumes that the account in the function arn differs from the client region"
        function_arn_other_account = (
            f"arn:aws:lambda:{region}:{other_account}:function:{function_name_1}"
        )
        with pytest.raises(ClientError) as e:
            aws_client.lambda_.create_function(
                FunctionName=function_arn_other_account,
                Handler="index.handler",
                Code={"ZipFile": zip_file_bytes},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime=Runtime.python3_12,
            )
        snapshot.match("function_arn_other_account_exc", e.value.response)

    @markers.lambda_runtime_update
    @markers.aws.validated
    def test_create_lambda_exceptions(self, lambda_su_role, snapshot, aws_client):
        function_name = f"invalid-function-{short_uid()}"
        zip_file_bytes = create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True)
        # test invalid role arn
        with pytest.raises(ClientError) as e:
            aws_client.lambda_.create_function(
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
            aws_client.lambda_.create_function(
                FunctionName=function_name,
                Handler="index.handler",
                Code={"ZipFile": zip_file_bytes},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime="non-existent-runtime",
            )
        snapshot.match("invalid_runtime_exc", e.value.response)
        with pytest.raises(ClientError) as e:
            aws_client.lambda_.create_function(
                FunctionName=function_name,
                Handler="index.handler",
                Code={"ZipFile": zip_file_bytes},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime="PYTHON3.9",
            )
        snapshot.match("uppercase_runtime_exc", e.value.response)

        # test empty architectures
        with pytest.raises(ParamValidationError) as e:
            aws_client.lambda_.create_function(
                FunctionName=function_name,
                Handler="index.handler",
                Code={"ZipFile": zip_file_bytes},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime=Runtime.python3_9,
                Architectures=[],
            )
        snapshot.match("empty_architectures", e.value)

        # test multiple architectures
        with pytest.raises(ClientError) as e:
            aws_client.lambda_.create_function(
                FunctionName=function_name,
                Handler="index.handler",
                Code={"ZipFile": zip_file_bytes},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime=Runtime.python3_9,
                Architectures=[Architecture.x86_64, Architecture.arm64],
            )
        snapshot.match("multiple_architectures", e.value.response)

        # test invalid architecture: capital "X" instead of "x"
        with pytest.raises(ClientError) as e:
            aws_client.lambda_.create_function(
                FunctionName=function_name,
                Handler="index.handler",
                Code={"ZipFile": zip_file_bytes},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime=Runtime.python3_9,
                Architectures=["X86_64"],
            )
        snapshot.match("uppercase_architecture", e.value.response)

        # test what happens with an invalid zip file
        with pytest.raises(ClientError) as e:
            aws_client.lambda_.create_function(
                FunctionName=function_name,
                Handler="index.handler",
                Code={"ZipFile": b"this is not a zipfile, just a random string"},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime="python3.9",
            )
        snapshot.match("invalid_zip_exc", e.value.response)

    @markers.lambda_runtime_update
    @markers.aws.validated
    def test_update_lambda_exceptions(
        self, create_lambda_function_aws, lambda_su_role, snapshot, aws_client
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
            aws_client.lambda_.update_function_configuration(
                FunctionName=function_name,
                Role="r1",
            )
        snapshot.match("invalid_role_arn_exc", e.value.response)
        with pytest.raises(ClientError) as e:
            aws_client.lambda_.update_function_configuration(
                FunctionName=function_name,
                Runtime="non-existent-runtime",
            )
        snapshot.match("invalid_runtime_exc", e.value.response)
        with pytest.raises(ClientError) as e:
            aws_client.lambda_.update_function_configuration(
                FunctionName=function_name,
                Runtime="PYTHON3.9",
            )
        snapshot.match("uppercase_runtime_exc", e.value.response)

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..CodeSha256",  # TODO
        ]
    )
    @markers.aws.validated
    def test_list_functions(self, create_lambda_function, lambda_su_role, snapshot, aws_client):
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

        with pytest.raises(aws_client.lambda_.exceptions.ClientError) as e:
            aws_client.lambda_.list_functions(FunctionVersion="invalid")
        snapshot.match("list_functions_invalid_functionversion", e.value.response)

        list_paginator = aws_client.lambda_.get_paginator("list_functions")
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

    @markers.snapshot.skip_snapshot_verify(paths=["$..Ipv6AllowedForDualStack"])
    @markers.aws.validated
    def test_vpc_config(
        self, create_lambda_function, lambda_su_role, snapshot, aws_client, cleanups
    ):
        """
        Test "VpcConfig" Property on the Lambda Function

        Note: on AWS this takes quite a while since creating a function with VPC usually takes at least 4 minutes
        FIXME: Unfortunately the cleanup in this test doesn't work properly on AWS and the last subnet/security group + vpc are leaking.
        TODO: test a few more edge cases (e.g. multiple subnets / security groups, invalid vpc ids, etc.)
        """

        # VPC setup
        security_group_name_1 = f"test-security-group-{short_uid()}"
        security_group_name_2 = f"test-security-group-{short_uid()}"
        vpc_id = aws_client.ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        cleanups.append(lambda: aws_client.ec2.delete_vpc(VpcId=vpc_id))
        aws_client.ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id])
        security_group_id_1 = aws_client.ec2.create_security_group(
            VpcId=vpc_id, GroupName=security_group_name_1, Description="Test security group 1"
        )["GroupId"]
        cleanups.append(lambda: aws_client.ec2.delete_security_group(GroupId=security_group_id_1))
        security_group_id_2 = aws_client.ec2.create_security_group(
            VpcId=vpc_id, GroupName=security_group_name_2, Description="Test security group 2"
        )["GroupId"]
        cleanups.append(lambda: aws_client.ec2.delete_security_group(GroupId=security_group_id_2))
        subnet_id_1 = aws_client.ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.0.0/24")["Subnet"][
            "SubnetId"
        ]
        cleanups.append(lambda: aws_client.ec2.delete_subnet(SubnetId=subnet_id_1))
        subnet_id_2 = aws_client.ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")["Subnet"][
            "SubnetId"
        ]
        cleanups.append(lambda: aws_client.ec2.delete_subnet(SubnetId=subnet_id_2))
        snapshot.add_transformer(snapshot.transform.regex(vpc_id, "<vpc_id>"))
        snapshot.add_transformer(snapshot.transform.regex(subnet_id_1, "<subnet_id_1>"))
        snapshot.add_transformer(snapshot.transform.regex(subnet_id_2, "<subnet_id_2>"))
        snapshot.add_transformer(
            snapshot.transform.regex(security_group_id_1, "<security_group_id_1>")
        )
        snapshot.add_transformer(
            snapshot.transform.regex(security_group_id_2, "<security_group_id_2>")
        )

        cleanups.append(
            lambda: aws_client.lambda_.delete_function(FunctionName=function_name)
        )  # needed because otherwise VPC is still linked to function and deletion is blocked

        # Lambda creation
        function_name = f"fn-{short_uid()}"
        create_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
            MemorySize=256,
            Timeout=5,
            VpcConfig={
                "SubnetIds": [subnet_id_1],
                "SecurityGroupIds": [security_group_id_1],
            },
        )

        snapshot.match("create_response", create_response)
        aws_client.lambda_.get_waiter("function_active_v2").wait(FunctionName=function_name)

        get_function_response = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_function_response", get_function_response)

        # update VPC config
        update_vpcconfig_update_response = aws_client.lambda_.update_function_configuration(
            FunctionName=function_name,
            VpcConfig={
                "SubnetIds": [subnet_id_2],
                "SecurityGroupIds": [security_group_id_2],
            },
        )
        snapshot.match("update_vpcconfig_update_response", update_vpcconfig_update_response)
        # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/lambda/waiter/FunctionUpdatedV2.html#Lambda.Waiter.FunctionUpdatedV2.wait
        waiter_config = {"Delay": 1, "MaxAttempts": 60}
        # Increase timeouts because it can take longer than 5 minutes against AWS due to VPC.
        if is_aws_cloud():
            waiter_config = {"Delay": 5, "MaxAttempts": 90}
        aws_client.lambda_.get_waiter("function_updated_v2").wait(
            FunctionName=function_name, WaiterConfig=waiter_config
        )

        update_vpcconfig_get_function_response = aws_client.lambda_.get_function(
            FunctionName=function_name
        )
        snapshot.match(
            "update_vpcconfig_get_function_response", update_vpcconfig_get_function_response
        )

        # update VPC config (delete VPC => should detach VPC)
        delete_vpcconfig_update_response = aws_client.lambda_.update_function_configuration(
            FunctionName=function_name,
            VpcConfig={
                "SubnetIds": [],
                "SecurityGroupIds": [],
            },
        )
        snapshot.match("delete_vpcconfig_update_response", delete_vpcconfig_update_response)
        aws_client.lambda_.get_waiter("function_updated_v2").wait(FunctionName=function_name)

        delete_vpcconfig_get_function_response = aws_client.lambda_.get_function(
            FunctionName=function_name
        )
        snapshot.match(
            "delete_vpcconfig_get_function_response", delete_vpcconfig_get_function_response
        )


class TestLambdaImages:
    @pytest.fixture(scope="class")
    def login_docker_client(self, aws_client):
        if not is_aws_cloud():
            return
        auth_data = aws_client.ecr.get_authorization_token()
        # if check is necessary since registry login data is not available at LS before min. 1 repository is created
        if auth_data["authorizationData"]:
            auth_data = auth_data["authorizationData"][0]
            decoded_auth_token = str(
                base64.decodebytes(bytes(auth_data["authorizationToken"], "utf-8")), "utf-8"
            )
            username, password = decoded_auth_token.split(":")
            DOCKER_CLIENT.login(
                username=username, password=password, registry=auth_data["proxyEndpoint"]
            )

    @pytest.fixture(scope="class")
    def ecr_image(self, aws_client, login_docker_client):
        repository_names = []
        image_names = []

        def _create_test_image(base_image: str):
            if is_aws_cloud():
                repository_name = f"test-repo-{short_uid()}"
                repository_uri = aws_client.ecr.create_repository(repositoryName=repository_name)[
                    "repository"
                ]["repositoryUri"]
                image_name = f"{repository_uri}:latest"
                repository_names.append(repository_name)
            else:
                image_name = f"test-image-{short_uid()}:latest"
            image_names.append(image_name)

            DOCKER_CLIENT.pull_image(base_image)
            DOCKER_CLIENT.tag_image(base_image, image_name)
            if is_aws_cloud():
                DOCKER_CLIENT.push_image(image_name)
            return image_name

        yield _create_test_image

        for image_name in image_names:
            try:
                DOCKER_CLIENT.remove_image(image=image_name, force=True)
            except Exception as e:
                LOG.debug("Error cleaning up image %s: %s", image_name, e)

        for repository_name in repository_names:
            try:
                image_ids = aws_client.ecr.list_images(repositoryName=repository_name).get(
                    "imageIds", []
                )
                if image_ids:
                    call_safe(
                        aws_client.ecr.batch_delete_image,
                        kwargs={"repositoryName": repository_name, "imageIds": image_ids},
                    )
                aws_client.ecr.delete_repository(repositoryName=repository_name)
            except Exception as e:
                LOG.debug("Error cleaning up repository %s: %s", repository_name, e)

    @markers.aws.validated
    def test_lambda_image_crud(
        self, create_lambda_function_aws, lambda_su_role, ecr_image, snapshot, aws_client
    ):
        """Test lambda crud with package type image"""
        image = ecr_image("alpine")
        repo_uri = image.rpartition(":")[0]
        snapshot.add_transformer(snapshot.transform.regex(repo_uri, "<repo_uri>"))
        function_name = f"test-function-{short_uid()}"
        create_image_response = create_lambda_function_aws(
            FunctionName=function_name,
            Role=lambda_su_role,
            Code={"ImageUri": image},
            PackageType="Image",
            Environment={"Variables": {"CUSTOM_ENV": "test"}},
        )
        snapshot.match("create-image-response", create_image_response)
        aws_client.lambda_.get_waiter("function_active_v2").wait(FunctionName=function_name)
        get_function_response = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get-function-code-response", get_function_response)
        get_function_config_response = aws_client.lambda_.get_function_configuration(
            FunctionName=function_name
        )
        snapshot.match("get-function-config-response", get_function_config_response)

        # try update to a zip file - should fail
        with pytest.raises(ClientError) as e:
            aws_client.lambda_.update_function_code(
                FunctionName=function_name,
                ZipFile=create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True),
            )
        snapshot.match("image-to-zipfile-error", e.value.response)

        image_2 = ecr_image("debian")
        repo_uri_2 = image_2.rpartition(":")[0]
        snapshot.add_transformer(snapshot.transform.regex(repo_uri_2, "<repo_uri_2>"))
        update_function_code_response = aws_client.lambda_.update_function_code(
            FunctionName=function_name, ImageUri=image_2
        )
        snapshot.match("update-function-code-response", update_function_code_response)
        aws_client.lambda_.get_waiter("function_updated_v2").wait(FunctionName=function_name)

        get_function_response = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get-function-code-response-after-update", get_function_response)
        get_function_config_response = aws_client.lambda_.get_function_configuration(
            FunctionName=function_name
        )
        snapshot.match("get-function-config-response-after-update", get_function_config_response)

    @markers.aws.validated
    def test_lambda_zip_file_to_image(
        self, create_lambda_function_aws, lambda_su_role, ecr_image, snapshot, aws_client
    ):
        """Test that verifies conversion from zip file lambda to image lambda is not possible"""
        image = ecr_image("alpine")
        repo_uri = image.rpartition(":")[0]
        snapshot.add_transformer(snapshot.transform.regex(repo_uri, "<repo_uri>"))
        function_name = f"test-function-{short_uid()}"
        create_image_response = create_lambda_function_aws(
            FunctionName=function_name,
            Role=lambda_su_role,
            Runtime=Runtime.python3_9,
            Handler="handler.handler",
            Code={
                "ZipFile": create_lambda_archive(
                    load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True
                )
            },
        )
        snapshot.match("create-image-response", create_image_response)
        aws_client.lambda_.get_waiter("function_active_v2").wait(FunctionName=function_name)
        get_function_response = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get-function-code-response", get_function_response)
        get_function_config_response = aws_client.lambda_.get_function_configuration(
            FunctionName=function_name
        )
        snapshot.match("get-function-config-response", get_function_config_response)

        with pytest.raises(ClientError) as e:
            aws_client.lambda_.update_function_code(FunctionName=function_name, ImageUri=image)
        snapshot.match("zipfile-to-image-error", e.value.response)

        get_function_response = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get-function-code-response-after-update", get_function_response)
        get_function_config_response = aws_client.lambda_.get_function_configuration(
            FunctionName=function_name
        )
        snapshot.match("get-function-config-response-after-update", get_function_config_response)

    @markers.aws.validated
    def test_lambda_image_and_image_config_crud(
        self, create_lambda_function_aws, lambda_su_role, ecr_image, snapshot, aws_client
    ):
        """Test lambda crud with packagetype image and image configs"""
        image = ecr_image("alpine")
        repo_uri = image.rpartition(":")[0]
        snapshot.add_transformer(snapshot.transform.regex(repo_uri, "<repo_uri>"))
        # Create another lambda with image config
        function_name = f"test-function-{short_uid()}"
        image_config = {
            "EntryPoint": ["sh"],
            "Command": ["-c", "echo test"],
            "WorkingDirectory": "/app1",
        }
        create_image_response = create_lambda_function_aws(
            FunctionName=function_name,
            Role=lambda_su_role,
            Code={"ImageUri": image},
            PackageType="Image",
            ImageConfig=image_config,
            Environment={"Variables": {"CUSTOM_ENV": "test"}},
        )
        snapshot.match("create-image-with-config-response", create_image_response)
        aws_client.lambda_.get_waiter("function_active_v2").wait(FunctionName=function_name)
        get_function_response = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get-function-code-with-config-response", get_function_response)
        get_function_config_response = aws_client.lambda_.get_function_configuration(
            FunctionName=function_name
        )
        snapshot.match("get-function-config-with-config-response", get_function_config_response)

        # update image config
        new_image_config = {
            "Command": ["-c", "echo test1"],
            "WorkingDirectory": "/app1",
        }
        update_function_config_response = aws_client.lambda_.update_function_configuration(
            FunctionName=function_name, ImageConfig=new_image_config
        )
        snapshot.match("update-function-code-response", update_function_config_response)
        aws_client.lambda_.get_waiter("function_updated_v2").wait(FunctionName=function_name)

        get_function_response = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get-function-code-response-after-update", get_function_response)
        get_function_config_response = aws_client.lambda_.get_function_configuration(
            FunctionName=function_name
        )
        snapshot.match("get-function-config-response-after-update", get_function_config_response)

        # update to empty image config
        update_function_config_response = aws_client.lambda_.update_function_configuration(
            FunctionName=function_name, ImageConfig={}
        )
        snapshot.match(
            "update-function-code-delete-imageconfig-response", update_function_config_response
        )
        aws_client.lambda_.get_waiter("function_updated_v2").wait(FunctionName=function_name)

        get_function_response = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get-function-code-response-after-delete-imageconfig", get_function_response)
        get_function_config_response = aws_client.lambda_.get_function_configuration(
            FunctionName=function_name
        )
        snapshot.match(
            "get-function-config-response-after-delete-imageconfig", get_function_config_response
        )

    @markers.aws.validated
    def test_lambda_image_versions(
        self, create_lambda_function_aws, lambda_su_role, ecr_image, snapshot, aws_client
    ):
        """Test lambda versions with package type image"""
        image = ecr_image("alpine")
        repo_uri = image.rpartition(":")[0]
        snapshot.add_transformer(snapshot.transform.regex(repo_uri, "<repo_uri>"))
        function_name = f"test-function-{short_uid()}"
        create_image_response = create_lambda_function_aws(
            FunctionName=function_name,
            Role=lambda_su_role,
            Code={"ImageUri": image},
            PackageType="Image",
            Environment={"Variables": {"CUSTOM_ENV": "test"}},
            Publish=True,
        )
        snapshot.match("create_image_response", create_image_response)

        get_function_result = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_function_result", get_function_result)

        list_versions_result = aws_client.lambda_.list_versions_by_function(
            FunctionName=function_name
        )
        snapshot.match("list_versions_result", list_versions_result)

        first_update_response = aws_client.lambda_.update_function_configuration(
            FunctionName=function_name, Description="Second version :)"
        )
        snapshot.match("first_update_response", first_update_response)
        waiter = aws_client.lambda_.get_waiter("function_updated_v2")
        waiter.wait(FunctionName=function_name)
        first_update_get_function = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("first_update_get_function", first_update_get_function)

        # Try publishing with wrong codesha256
        with pytest.raises(ClientError) as e:
            aws_client.lambda_.publish_version(
                FunctionName=function_name,
                Description="Second version description :)",
                CodeSha256="a" * 64,
            )
        snapshot.match("invalid_sha_publish", e.value.response)

        # publish with correct codesha256
        first_publish_response = aws_client.lambda_.publish_version(
            FunctionName=function_name,
            Description="Second version description :)",
            CodeSha256=get_function_result["Configuration"]["CodeSha256"],
        )
        snapshot.match("first_publish_response", first_publish_response)

        second_update_response = aws_client.lambda_.update_function_configuration(
            FunctionName=function_name, Description="Third version :)"
        )
        snapshot.match("second_update_response", second_update_response)
        waiter = aws_client.lambda_.get_waiter("function_updated_v2")
        waiter.wait(FunctionName=function_name)
        second_update_get_function = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("second_update_get_function", second_update_get_function)

        # publish without codesha256
        second_publish_response = aws_client.lambda_.publish_version(
            FunctionName=function_name, Description="Third version description :)"
        )
        snapshot.match("second_publish_response", second_publish_response)


class TestLambdaVersions:
    @markers.aws.validated
    def test_publish_version_on_create(
        self, create_lambda_function_aws, lambda_su_role, snapshot, aws_client
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

        get_function_result = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_function_result", get_function_result)

        get_function_version_result = aws_client.lambda_.get_function(
            FunctionName=function_name, Qualifier="1"
        )
        snapshot.match("get_function_version_result", get_function_version_result)

        get_function_latest_result = aws_client.lambda_.get_function(
            FunctionName=function_name, Qualifier="$LATEST"
        )
        snapshot.match("get_function_latest_result", get_function_latest_result)

        list_versions_result = aws_client.lambda_.list_versions_by_function(
            FunctionName=function_name
        )
        snapshot.match("list_versions_result", list_versions_result)

        # rerelease just published function, should not release new version
        repeated_publish_response = aws_client.lambda_.publish_version(
            FunctionName=function_name, Description="Repeated version description :)"
        )
        snapshot.match("repeated_publish_response", repeated_publish_response)
        list_versions_result_after_publish = aws_client.lambda_.list_versions_by_function(
            FunctionName=function_name
        )
        snapshot.match("list_versions_result_after_publish", list_versions_result_after_publish)

    @markers.aws.validated
    def test_version_lifecycle(
        self, create_lambda_function_aws, lambda_su_role, snapshot, aws_client
    ):
        """
        Test the function version "lifecycle" (there are no deletes)
        """
        waiter = aws_client.lambda_.get_waiter("function_updated_v2")
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

        get_function_result = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_function_result", get_function_result)

        list_versions_result = aws_client.lambda_.list_versions_by_function(
            FunctionName=function_name
        )
        snapshot.match("list_versions_result", list_versions_result)

        first_update_response = aws_client.lambda_.update_function_configuration(
            FunctionName=function_name, Description="First version :)"
        )
        snapshot.match("first_update_response", first_update_response)
        waiter.wait(FunctionName=function_name)
        first_update_get_function = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("first_update_get_function", first_update_get_function)

        first_publish_response = aws_client.lambda_.publish_version(
            FunctionName=function_name, Description="First version description :)"
        )
        snapshot.match("first_publish_response", first_publish_response)

        first_publish_get_function = aws_client.lambda_.get_function(
            FunctionName=function_name, Qualifier=first_publish_response["Version"]
        )
        snapshot.match("first_publish_get_function", first_publish_get_function)
        first_publish_get_function_config = aws_client.lambda_.get_function_configuration(
            FunctionName=function_name, Qualifier=first_publish_response["Version"]
        )
        snapshot.match("first_publish_get_function_config", first_publish_get_function_config)

        second_update_response = aws_client.lambda_.update_function_configuration(
            FunctionName=function_name, Description="Second version :))"
        )
        snapshot.match("second_update_response", second_update_response)
        waiter.wait(FunctionName=function_name)
        # check if first publish get function changed:
        first_publish_get_function_after_update = aws_client.lambda_.get_function(
            FunctionName=function_name, Qualifier=first_publish_response["Version"]
        )
        snapshot.match(
            "first_publish_get_function_after_update", first_publish_get_function_after_update
        )

        # Same state published as two different versions.
        # The publish_version api is idempotent, so the second publish_version will *NOT* create a new version because $LATEST hasn't been updated!
        second_publish_response = aws_client.lambda_.publish_version(FunctionName=function_name)
        snapshot.match("second_publish_response", second_publish_response)
        third_publish_response = aws_client.lambda_.publish_version(
            FunctionName=function_name, Description="Third version description :)))"
        )
        snapshot.match("third_publish_response", third_publish_response)

        list_versions_result_end = aws_client.lambda_.list_versions_by_function(
            FunctionName=function_name
        )
        snapshot.match("list_versions_result_end", list_versions_result_end)

    @markers.aws.validated
    def test_publish_with_wrong_sha256(
        self, create_lambda_function_aws, lambda_su_role, snapshot, aws_client
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

        get_fn_response = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_fn_response", get_fn_response)

        # publish_versions fails for the wrong revision id
        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.publish_version(
                FunctionName=function_name, CodeSha256="somenonexistentsha256"
            )
        snapshot.match("publish_wrong_sha256_exc", e.value.response)

        # but with the proper rev id, it should work
        publish_result = aws_client.lambda_.publish_version(
            FunctionName=function_name, CodeSha256=get_fn_response["Configuration"]["CodeSha256"]
        )
        snapshot.match("publish_result", publish_result)

    @markers.aws.validated
    def test_publish_with_update(
        self, create_lambda_function_aws, lambda_su_role, snapshot, aws_client
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

        get_function_result = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_function_result", get_function_result)
        update_zip_file = create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON_VERSION), get_content=True
        )
        update_function_code_result = aws_client.lambda_.update_function_code(
            FunctionName=function_name, ZipFile=update_zip_file, Publish=True
        )
        snapshot.match("update_function_code_result", update_function_code_result)

        get_function_version_result = aws_client.lambda_.get_function(
            FunctionName=function_name, Qualifier="1"
        )
        snapshot.match("get_function_version_result", get_function_version_result)

        get_function_latest_result = aws_client.lambda_.get_function(
            FunctionName=function_name, Qualifier="$LATEST"
        )
        snapshot.match("get_function_latest_result", get_function_latest_result)


class TestLambdaAlias:
    @markers.aws.validated
    def test_alias_lifecycle(
        self, create_lambda_function_aws, lambda_su_role, snapshot, aws_client
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

        publish_v1 = aws_client.lambda_.publish_version(FunctionName=function_name)
        snapshot.match("publish_v1", publish_v1)

        aws_client.lambda_.update_function_configuration(
            FunctionName=function_name, Environment={"Variables": {"testenv": "prod"}}
        )
        waiter = aws_client.lambda_.get_waiter("function_updated_v2")
        waiter.wait(FunctionName=function_name)

        publish_v2 = aws_client.lambda_.publish_version(FunctionName=function_name)
        snapshot.match("publish_v2", publish_v2)

        create_alias_1_1 = aws_client.lambda_.create_alias(
            FunctionName=function_name,
            Name="aliasname1_1",
            FunctionVersion="1",
            Description="custom-alias",
            RoutingConfig={"AdditionalVersionWeights": {"2": 0.2}},
        )
        snapshot.match("create_alias_1_1", create_alias_1_1)
        get_alias_1_1 = aws_client.lambda_.get_alias(
            FunctionName=function_name, Name="aliasname1_1"
        )
        snapshot.match("get_alias_1_1", get_alias_1_1)
        get_function_alias_1_1 = aws_client.lambda_.get_function(
            FunctionName=function_name, Qualifier="aliasname1_1"
        )
        snapshot.match("get_function_alias_1_1", get_function_alias_1_1)
        get_function_byarn_alias_1_1 = aws_client.lambda_.get_function(
            FunctionName=create_alias_1_1["AliasArn"]
        )
        snapshot.match("get_function_byarn_alias_1_1", get_function_byarn_alias_1_1)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.get_function(
                FunctionName=function_name, Qualifier="aliasdoesnotexist"
            )
        snapshot.match("get_function_alias_notfound_exc", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.get_function(
                FunctionName=create_alias_1_1["AliasArn"].replace(
                    "aliasname1_1", "aliasdoesnotexist"
                )
            )
        snapshot.match("get_function_alias_byarn_notfound_exc", e.value.response)

        create_alias_1_2 = aws_client.lambda_.create_alias(
            FunctionName=function_name,
            Name="aliasname1_2",
            FunctionVersion="1",
            Description="custom-alias",
        )
        snapshot.match("create_alias_1_2", create_alias_1_2)
        get_alias_1_2 = aws_client.lambda_.get_alias(
            FunctionName=function_name, Name="aliasname1_2"
        )
        snapshot.match("get_alias_1_2", get_alias_1_2)

        create_alias_1_3 = aws_client.lambda_.create_alias(
            FunctionName=function_name,
            Name="aliasname1_3",
            FunctionVersion="1",
        )
        snapshot.match("create_alias_1_3", create_alias_1_3)
        get_alias_1_3 = aws_client.lambda_.get_alias(
            FunctionName=function_name, Name="aliasname1_3"
        )
        snapshot.match("get_alias_1_3", get_alias_1_3)

        create_alias_2 = aws_client.lambda_.create_alias(
            FunctionName=function_name,
            Name="aliasname2",
            FunctionVersion="2",
            Description="custom-alias",
        )
        snapshot.match("create_alias_2", create_alias_2)
        get_alias_2 = aws_client.lambda_.get_alias(FunctionName=function_name, Name="aliasname2")
        snapshot.match("get_alias_2", get_alias_2)

        # list_aliases can be optionally called with a FunctionVersion to filter only aliases for this version
        list_alias_paginator = aws_client.lambda_.get_paginator("list_aliases")
        list_aliases_for_fnname = list_alias_paginator.paginate(
            FunctionName=function_name, PaginationConfig={"PageSize": 1}
        ).build_full_result()  # 4 aliases
        snapshot.match("list_aliases_for_fnname", list_aliases_for_fnname)
        assert len(list_aliases_for_fnname["Aliases"]) == 4
        # update alias 1_1 to remove routing config
        update_alias_1_1 = aws_client.lambda_.update_alias(
            FunctionName=function_name,
            Name="aliasname1_1",
            RoutingConfig={"AdditionalVersionWeights": {}},
        )
        snapshot.match("update_alias_1_1", update_alias_1_1)
        get_alias_1_1_after_update = aws_client.lambda_.get_alias(
            FunctionName=function_name, Name="aliasname1_1"
        )
        snapshot.match("get_alias_1_1_after_update", get_alias_1_1_after_update)
        list_aliases_for_fnname_after_update = aws_client.lambda_.list_aliases(
            FunctionName=function_name
        )  # 4 aliases
        snapshot.match("list_aliases_for_fnname_after_update", list_aliases_for_fnname_after_update)
        assert len(list_aliases_for_fnname_after_update["Aliases"]) == 4
        # check update without changes
        update_alias_1_2 = aws_client.lambda_.update_alias(
            FunctionName=function_name,
            Name="aliasname1_2",
        )
        snapshot.match("update_alias_1_2", update_alias_1_2)
        get_alias_1_2_after_update = aws_client.lambda_.get_alias(
            FunctionName=function_name, Name="aliasname1_2"
        )
        snapshot.match("get_alias_1_2_after_update", get_alias_1_2_after_update)
        list_aliases_for_fnname_after_update_2 = aws_client.lambda_.list_aliases(
            FunctionName=function_name
        )  # 4 aliases
        snapshot.match(
            "list_aliases_for_fnname_after_update_2", list_aliases_for_fnname_after_update_2
        )
        assert len(list_aliases_for_fnname_after_update["Aliases"]) == 4

        list_aliases_for_version = aws_client.lambda_.list_aliases(
            FunctionName=function_name, FunctionVersion="1"
        )  # 3 aliases
        snapshot.match("list_aliases_for_version", list_aliases_for_version)
        assert len(list_aliases_for_version["Aliases"]) == 3

        delete_alias_response = aws_client.lambda_.delete_alias(
            FunctionName=function_name, Name="aliasname1_1"
        )
        snapshot.match("delete_alias_response", delete_alias_response)

        list_aliases_for_fnname_afterdelete = aws_client.lambda_.list_aliases(
            FunctionName=function_name
        )  # 3 aliases
        snapshot.match("list_aliases_for_fnname_afterdelete", list_aliases_for_fnname_afterdelete)

    @markers.aws.validated
    def test_notfound_and_invalid_routingconfigs(
        self, aws_client_factory, create_lambda_function_aws, snapshot, lambda_su_role, aws_client
    ):
        lambda_client = aws_client_factory(config=Config(parameter_validation=False)).lambda_
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


class TestLambdaRevisions:
    @markers.snapshot.skip_snapshot_verify(
        # The RuntimeVersionArn is currently a hardcoded id and therefore does not reflect the ARN resource update
        # from python3.9 to python3.8 in update_function_configuration_response_rev5.
        paths=[
            "update_function_configuration_response_rev5..RuntimeVersionConfig.RuntimeVersionArn",
            "get_function_response_rev6..RuntimeVersionConfig.RuntimeVersionArn",
        ]
    )
    @markers.aws.validated
    def test_function_revisions_basic(self, create_lambda_function, snapshot, aws_client):
        """Tests basic revision id lifecycle for creating and updating functions"""
        function_name = f"fn-{short_uid()}"
        zip_file_content = load_file(TEST_LAMBDA_PYTHON_ECHO_ZIP, mode="rb")

        # rev1: create function
        # The fixture waits until the function is not in Pending state anymore
        create_function_response = create_lambda_function(
            func_name=function_name,
            zip_file=zip_file_content,
            handler="index.handler",
            runtime=Runtime.python3_9,
        )
        snapshot.match("create_function_response_rev1", create_function_response)
        rev1_create_function = create_function_response["CreateFunctionResponse"]["RevisionId"]

        # rev2: created function becomes active (the fixture does the waiting)
        get_function_response_rev2 = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_function_response_rev2", get_function_response_rev2)
        rev2_active_state = get_function_response_rev2["Configuration"]["RevisionId"]
        # State change from Pending to Active causes revision id change!
        # Lambda function states: https://docs.aws.amazon.com/lambda/latest/dg/functions-states.html
        assert rev1_create_function != rev2_active_state

        with pytest.raises(aws_client.lambda_.exceptions.PreconditionFailedException) as e:
            aws_client.lambda_.update_function_code(
                FunctionName=function_name,
                ZipFile=zip_file_content,
                RevisionId="wrong",
            )
        snapshot.match("update_function_revision_exception", e.value.response)

        # rev3: update function code
        update_fn_code_response = aws_client.lambda_.update_function_code(
            FunctionName=function_name,
            ZipFile=zip_file_content,
            RevisionId=rev2_active_state,
        )
        snapshot.match("update_function_code_response_rev3", update_fn_code_response)
        rev3_update_fn_code = update_fn_code_response["RevisionId"]
        assert rev2_active_state != rev3_update_fn_code

        # rev4: function code update completed
        aws_client.lambda_.get_waiter("function_updated_v2").wait(FunctionName=function_name)
        get_function_response_rev4 = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_function_response_rev4", get_function_response_rev4)
        rev4_fn_code_updated = get_function_response_rev4["Configuration"]["RevisionId"]
        assert rev3_update_fn_code != rev4_fn_code_updated

        with pytest.raises(aws_client.lambda_.exceptions.PreconditionFailedException) as e:
            aws_client.lambda_.update_function_configuration(
                FunctionName=function_name, Runtime=Runtime.python3_8, RevisionId="wrong"
            )
        snapshot.match("update_function_configuration_revision_exception", e.value.response)

        # rev5: update function configuration
        update_fn_config_response = aws_client.lambda_.update_function_configuration(
            FunctionName=function_name, Runtime=Runtime.python3_8, RevisionId=rev4_fn_code_updated
        )
        snapshot.match("update_function_configuration_response_rev5", update_fn_config_response)
        rev5_fn_config_update = update_fn_config_response["RevisionId"]
        assert rev4_fn_code_updated != rev5_fn_config_update

        # rev6: function configuration updated completed
        aws_client.lambda_.get_waiter("function_updated_v2").wait(FunctionName=function_name)
        get_function_response_rev6 = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_function_response_rev6", get_function_response_rev6)
        rev6_fn_config_update_done = get_function_response_rev6["Configuration"]["RevisionId"]
        assert rev5_fn_config_update != rev6_fn_config_update_done

    @markers.aws.validated
    def test_function_revisions_version_and_alias(
        self, create_lambda_function, snapshot, aws_client
    ):
        """Tests revision id lifecycle for 1) publishing function versions and 2) creating and updating aliases
        Shortcut notation to clarify branching:
        revN: revision counter for $LATEST
        rev_vN: revision counter for versions
        rev_aN: revision counter for aliases
        """
        # rev1: create function
        function_name = f"fn-{short_uid()}"
        create_function_response = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=Runtime.python3_9,
        )
        snapshot.match("create_function_response_rev1", create_function_response)
        rev1_create_function = create_function_response["CreateFunctionResponse"]["RevisionId"]

        # rev2: created function becomes active
        get_function_response_rev2 = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_function_active_rev2", get_function_response_rev2)
        rev2_active_state = get_function_response_rev2["Configuration"]["RevisionId"]
        assert rev1_create_function != rev2_active_state

        with pytest.raises(aws_client.lambda_.exceptions.PreconditionFailedException) as e:
            aws_client.lambda_.publish_version(FunctionName=function_name, RevisionId="wrong")
        snapshot.match("publish_version_revision_exception", e.value.response)

        # rev_v1: publish version
        fn_version_response = aws_client.lambda_.publish_version(
            FunctionName=function_name, RevisionId=rev2_active_state
        )
        snapshot.match("publish_version_response_rev_v1", fn_version_response)
        function_version = fn_version_response["Version"]
        rev_v1_publish_version = fn_version_response["RevisionId"]
        assert rev2_active_state != rev_v1_publish_version

        # rev_v2: published version becomes active does NOT change revision
        aws_client.lambda_.get_waiter("published_version_active").wait(FunctionName=function_name)
        get_function_response_rev_v2 = aws_client.lambda_.get_function(
            FunctionName=function_name, Qualifier=function_version
        )
        snapshot.match("get_function_published_version_rev_v2", get_function_response_rev_v2)
        rev_v2_publish_version_done = get_function_response_rev_v2["Configuration"]["RevisionId"]
        assert rev_v1_publish_version == rev_v2_publish_version_done

        # publish_version changes the revision id of $LATEST
        get_function_response_rev3 = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_function_latest_rev3", get_function_response_rev3)
        rev3_publish_version = get_function_response_rev3["Configuration"]["RevisionId"]
        assert rev2_active_state != rev3_publish_version

        # rev_a1: create alias
        alias_name = "revision_alias"
        create_alias_response = aws_client.lambda_.create_alias(
            FunctionName=function_name,
            Name=alias_name,
            FunctionVersion=function_version,
        )
        snapshot.match("create_alias_response_rev_a1", create_alias_response)
        rev_a1_create_alias = create_alias_response["RevisionId"]
        assert rev_v2_publish_version_done != rev_a1_create_alias

        # create_alias does NOT change the revision id of $LATEST
        get_function_response_rev4 = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_function_latest_rev4", get_function_response_rev4)
        rev4_create_alias = get_function_response_rev4["Configuration"]["RevisionId"]
        assert rev3_publish_version == rev4_create_alias

        # create_alias does NOT change the revision id of versions
        get_function_response_rev_v3 = aws_client.lambda_.get_function(
            FunctionName=function_name, Qualifier=function_version
        )
        snapshot.match("get_function_published_version_rev_v3", get_function_response_rev_v3)
        rev_v3_create_alias = get_function_response_rev_v3["Configuration"]["RevisionId"]
        assert rev_v2_publish_version_done == rev_v3_create_alias

        with pytest.raises(aws_client.lambda_.exceptions.PreconditionFailedException) as e:
            aws_client.lambda_.update_alias(
                FunctionName=function_name,
                Name=alias_name,
                RevisionId="wrong",
            )
        snapshot.match("update_alias_revision_exception", e.value.response)

        # rev_a2: update alias
        update_alias_response = aws_client.lambda_.update_alias(
            FunctionName=function_name,
            Name=alias_name,
            Description="something changed",
            RevisionId=rev_a1_create_alias,
        )
        snapshot.match("update_alias_response_rev_a2", update_alias_response)
        rev_a2_update_alias = update_alias_response["RevisionId"]
        assert rev_a1_create_alias != rev_a2_update_alias

    @markers.aws.validated
    def test_function_revisions_permissions(self, create_lambda_function, snapshot, aws_client):
        """Tests revision id lifecycle for adding and removing permissions"""
        # rev1: create function
        function_name = f"fn-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=Runtime.python3_9,
        )

        # rev2: created function becomes active
        get_function_response_rev2 = aws_client.lambda_.get_function(FunctionName=function_name)
        rev2_active_state = get_function_response_rev2["Configuration"]["RevisionId"]

        sid = "s3"
        with pytest.raises(aws_client.lambda_.exceptions.PreconditionFailedException) as e:
            aws_client.lambda_.add_permission(
                FunctionName=function_name,
                StatementId=sid,
                Action="lambda:InvokeFunction",
                Principal="s3.amazonaws.com",
                RevisionId="wrong",
            )
        snapshot.match("add_permission_revision_exception", e.value.response)

        # rev3: add permission
        add_permission_response = aws_client.lambda_.add_permission(
            FunctionName=function_name,
            StatementId=sid,
            Action="lambda:InvokeFunction",
            Principal="s3.amazonaws.com",
            RevisionId=rev2_active_state,
        )
        snapshot.match("add_permission_response", add_permission_response)

        get_policy_response_rev3 = aws_client.lambda_.get_policy(FunctionName=function_name)
        snapshot.match("get_policy_response_rev3", get_policy_response_rev3)
        rev3policy_added_permission = get_policy_response_rev3["RevisionId"]
        assert rev2_active_state != rev3policy_added_permission
        # function revision is the same as policy revision
        get_function_response_rev3 = aws_client.lambda_.get_function(FunctionName=function_name)
        rev3_added_permission = get_function_response_rev3["Configuration"]["RevisionId"]
        assert rev3_added_permission == rev3policy_added_permission

        with pytest.raises(aws_client.lambda_.exceptions.PreconditionFailedException) as e:
            aws_client.lambda_.remove_permission(
                FunctionName=function_name, StatementId=sid, RevisionId="wrong"
            )
        snapshot.match("remove_permission_revision_exception", e.value.response)

        # rev4: remove permission
        remove_permission_response = aws_client.lambda_.remove_permission(
            FunctionName=function_name, StatementId=sid, RevisionId=rev3_added_permission
        )
        snapshot.match("remove_permission_response", remove_permission_response)

        get_function_response_rev4 = aws_client.lambda_.get_function(FunctionName=function_name)
        rev4_removed_permission = get_function_response_rev4["Configuration"]["RevisionId"]
        assert rev3_added_permission != rev4_removed_permission


class TestLambdaTag:
    @pytest.fixture(scope="function")
    def fn_arn(self, create_lambda_function, aws_client):
        """simple reusable setup to test tagging operations against"""
        function_name = f"fn-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        yield aws_client.lambda_.get_function(FunctionName=function_name)["Configuration"][
            "FunctionArn"
        ]

    @markers.aws.validated
    def test_create_tag_on_fn_create(self, create_lambda_function, snapshot, aws_client):
        function_name = f"fn-{short_uid()}"
        custom_tag = f"tag-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(custom_tag, "<custom-tag>"))
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            Tags={"testtag": custom_tag},
        )
        get_function_result = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_function_result", get_function_result)
        fn_arn = get_function_result["Configuration"]["FunctionArn"]

        list_tags_result = aws_client.lambda_.list_tags(Resource=fn_arn)
        snapshot.match("list_tags_result", list_tags_result)

    @markers.aws.validated
    def test_tag_lifecycle(self, create_lambda_function, snapshot, fn_arn, aws_client):
        # 1. add tag
        tag_single_response = aws_client.lambda_.tag_resource(Resource=fn_arn, Tags={"A": "tag-a"})
        snapshot.match("tag_single_response", tag_single_response)
        snapshot.match(
            "tag_single_response_listtags", aws_client.lambda_.list_tags(Resource=fn_arn)
        )

        # 2. add multiple tags
        tag_multiple_response = aws_client.lambda_.tag_resource(
            Resource=fn_arn, Tags={"B": "tag-b", "C": "tag-c"}
        )
        snapshot.match("tag_multiple_response", tag_multiple_response)
        snapshot.match(
            "tag_multiple_response_listtags", aws_client.lambda_.list_tags(Resource=fn_arn)
        )

        # 3. add overlapping tags
        tag_overlap_response = aws_client.lambda_.tag_resource(
            Resource=fn_arn, Tags={"C": "tag-c-newsuffix", "D": "tag-d"}
        )
        snapshot.match("tag_overlap_response", tag_overlap_response)
        snapshot.match(
            "tag_overlap_response_listtags", aws_client.lambda_.list_tags(Resource=fn_arn)
        )

        # 3. remove tag
        untag_single_response = aws_client.lambda_.untag_resource(Resource=fn_arn, TagKeys=["A"])
        snapshot.match("untag_single_response", untag_single_response)
        snapshot.match(
            "untag_single_response_listtags", aws_client.lambda_.list_tags(Resource=fn_arn)
        )

        # 4. remove multiple tags
        untag_multiple_response = aws_client.lambda_.untag_resource(
            Resource=fn_arn, TagKeys=["B", "C"]
        )
        snapshot.match("untag_multiple_response", untag_multiple_response)
        snapshot.match(
            "untag_multiple_response_listtags", aws_client.lambda_.list_tags(Resource=fn_arn)
        )

        # 5. try to remove only tags that don't exist
        untag_nonexisting_response = aws_client.lambda_.untag_resource(
            Resource=fn_arn, TagKeys=["F"]
        )
        snapshot.match("untag_nonexisting_response", untag_nonexisting_response)
        snapshot.match(
            "untag_nonexisting_response_listtags", aws_client.lambda_.list_tags(Resource=fn_arn)
        )

        # 6. remove a mix of tags that exist & don't exist
        untag_existing_and_nonexisting_response = aws_client.lambda_.untag_resource(
            Resource=fn_arn, TagKeys=["D", "F"]
        )
        snapshot.match(
            "untag_existing_and_nonexisting_response", untag_existing_and_nonexisting_response
        )
        snapshot.match(
            "untag_existing_and_nonexisting_response_listtags",
            aws_client.lambda_.list_tags(Resource=fn_arn),
        )

    @markers.aws.validated
    def test_tag_nonexisting_resource(self, snapshot, fn_arn, aws_client):
        get_result = aws_client.lambda_.get_function(FunctionName=fn_arn)
        snapshot.match("pre_delete_get_function", get_result)
        aws_client.lambda_.delete_function(FunctionName=fn_arn)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.tag_resource(Resource=fn_arn, Tags={"A": "B"})
        snapshot.match("not_found_exception_tag", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.untag_resource(Resource=fn_arn, TagKeys=["A"])
        snapshot.match("not_found_exception_untag", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.list_tags(Resource=fn_arn)
        snapshot.match("not_found_exception_list", e.value.response)


class TestLambdaEventInvokeConfig:
    """TODO: add sqs & stream specific lifecycle snapshot tests"""

    @markers.aws.validated
    def test_lambda_eventinvokeconfig_lifecycle(
        self, create_lambda_function, lambda_su_role, snapshot, aws_client
    ):
        function_name = f"fn-eventinvoke-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
        )

        put_invokeconfig_retries_0 = aws_client.lambda_.put_function_event_invoke_config(
            FunctionName=function_name,
            MaximumRetryAttempts=0,
        )
        snapshot.match("put_invokeconfig_retries_0", put_invokeconfig_retries_0)

        put_invokeconfig_eventage_60 = aws_client.lambda_.put_function_event_invoke_config(
            FunctionName=function_name, MaximumEventAgeInSeconds=60
        )
        snapshot.match("put_invokeconfig_eventage_60", put_invokeconfig_eventage_60)

        update_invokeconfig_eventage_nochange = (
            aws_client.lambda_.update_function_event_invoke_config(
                FunctionName=function_name, MaximumEventAgeInSeconds=60
            )
        )
        snapshot.match(
            "update_invokeconfig_eventage_nochange", update_invokeconfig_eventage_nochange
        )

        update_invokeconfig_retries = aws_client.lambda_.update_function_event_invoke_config(
            FunctionName=function_name, MaximumRetryAttempts=1
        )
        snapshot.match("update_invokeconfig_retries", update_invokeconfig_retries)

        get_invokeconfig = aws_client.lambda_.get_function_event_invoke_config(
            FunctionName=function_name
        )
        snapshot.match("get_invokeconfig", get_invokeconfig)

        get_invokeconfig_latest = aws_client.lambda_.get_function_event_invoke_config(
            FunctionName=function_name, Qualifier="$LATEST"
        )
        snapshot.match("get_invokeconfig_latest", get_invokeconfig_latest)

        list_single_invokeconfig = aws_client.lambda_.list_function_event_invoke_configs(
            FunctionName=function_name
        )
        snapshot.match("list_single_invokeconfig", list_single_invokeconfig)

        # publish a version so we can have more than one entries for list ops
        publish_version_result = aws_client.lambda_.publish_version(FunctionName=function_name)
        snapshot.match("publish_version_result", publish_version_result)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.get_function_event_invoke_config(
                FunctionName=function_name, Qualifier=publish_version_result["Version"]
            )
        snapshot.match("get_invokeconfig_postpublish", e.value.response)

        put_published_invokeconfig = aws_client.lambda_.put_function_event_invoke_config(
            FunctionName=function_name,
            Qualifier=publish_version_result["Version"],
            MaximumEventAgeInSeconds=120,
        )
        snapshot.match("put_published_invokeconfig", put_published_invokeconfig)

        get_published_invokeconfig = aws_client.lambda_.get_function_event_invoke_config(
            FunctionName=function_name, Qualifier=publish_version_result["Version"]
        )
        snapshot.match("get_published_invokeconfig", get_published_invokeconfig)

        # list paging
        list_paging_single = aws_client.lambda_.list_function_event_invoke_configs(
            FunctionName=function_name, MaxItems=1
        )
        list_paging_nolimit = aws_client.lambda_.list_function_event_invoke_configs(
            FunctionName=function_name
        )
        assert len(list_paging_single["FunctionEventInvokeConfigs"]) == 1
        assert len(list_paging_nolimit["FunctionEventInvokeConfigs"]) == 2

        all_arns = {a["FunctionArn"] for a in list_paging_nolimit["FunctionEventInvokeConfigs"]}

        list_paging_remaining = aws_client.lambda_.list_function_event_invoke_configs(
            FunctionName=function_name, Marker=list_paging_single["NextMarker"], MaxItems=1
        )
        assert len(list_paging_remaining["FunctionEventInvokeConfigs"]) == 1
        assert all_arns == {
            list_paging_single["FunctionEventInvokeConfigs"][0]["FunctionArn"],
            list_paging_remaining["FunctionEventInvokeConfigs"][0]["FunctionArn"],
        }

        aws_client.lambda_.delete_function_event_invoke_config(FunctionName=function_name)
        list_paging_nolimit_postdelete = aws_client.lambda_.list_function_event_invoke_configs(
            FunctionName=function_name
        )
        snapshot.match("list_paging_nolimit_postdelete", list_paging_nolimit_postdelete)

    @markers.aws.validated
    def test_lambda_eventinvokeconfig_exceptions(
        self,
        create_lambda_function,
        snapshot,
        lambda_su_role,
        account_id,
        aws_client_factory,
        aws_client,
    ):
        """some parts could probably be split apart (e.g. overwriting with update)"""
        lambda_client = aws_client_factory(config=Config(parameter_validation=False)).lambda_
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

        put_maxevent_maxvalue_result = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name, MaximumRetryAttempts=2, MaximumEventAgeInSeconds=21600
        )
        snapshot.match("put_maxevent_maxvalue_result", put_maxevent_maxvalue_result)

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


# NOTE: These tests are inherently a bit flaky on AWS since they depend on account/region global usage limits/quotas
# Against AWS, these tests might require increasing the service quota for concurrent executions (e.g., 10 => 101):
# https://us-east-1.console.aws.amazon.com/servicequotas/home/services/lambda/quotas/L-B99A9384
# New accounts in an organization have by default a quota of 10 or 50.
class TestLambdaReservedConcurrency:
    @markers.aws.validated
    def test_function_concurrency_exceptions(
        self, create_lambda_function, snapshot, aws_client, monkeypatch
    ):
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.put_function_concurrency(
                FunctionName="doesnotexist", ReservedConcurrentExecutions=1
            )
        snapshot.match("put_function_concurrency_with_function_name_doesnotexist", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.put_function_concurrency(
                FunctionName="doesnotexist", ReservedConcurrentExecutions=0
            )
        snapshot.match(
            "put_function_concurrency_with_function_name_doesnotexist_and_invalid_concurrency",
            e.value.response,
        )

        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        fn = aws_client.lambda_.get_function_configuration(
            FunctionName=function_name, Qualifier="$LATEST"
        )

        qualified_arn_latest = fn["FunctionArn"]
        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.put_function_concurrency(
                FunctionName=qualified_arn_latest, ReservedConcurrentExecutions=0
            )
        snapshot.match("put_function_concurrency_with_qualified_arn", e.value.response)

    @markers.aws.validated
    def test_function_concurrency_limits(
        self, aws_client, aws_client_factory, create_lambda_function, snapshot, monkeypatch
    ):
        """Test limits exceptions separately because they require custom transformers."""
        monkeypatch.setattr(config, "LAMBDA_LIMITS_CONCURRENT_EXECUTIONS", 5)
        monkeypatch.setattr(config, "LAMBDA_LIMITS_MINIMUM_UNRESERVED_CONCURRENCY", 3)

        # We need to replace limits that are specific to AWS accounts (see test_provisioned_concurrency_limits)
        # Unlike for provisioned concurrency, reserved concurrency does not have a different error message for
        # values higher than the account limit of concurrent executions.
        prefix = re.escape("minimum value of [")
        number_pattern = "\d+"  # noqa W605
        suffix = re.escape("]")
        min_unreserved_regex = re.compile(f"(?<={prefix}){number_pattern}(?={suffix})")
        snapshot.add_transformer(
            snapshot.transform.regex(min_unreserved_regex, "<min_unreserved_concurrency>")
        )

        lambda_client = aws_client.lambda_
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        account_settings = aws_client.lambda_.get_account_settings()
        concurrent_executions = account_settings["AccountLimit"]["ConcurrentExecutions"]

        # Higher reserved concurrency than ConcurrentExecutions account limit
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.put_function_concurrency(
                FunctionName=function_name,
                ReservedConcurrentExecutions=concurrent_executions + 1,
            )
        snapshot.match("put_function_concurrency_account_limit_exceeded", e.value.response)

        # Not enough UnreservedConcurrentExecutions available in account
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.put_function_concurrency(
                FunctionName=function_name,
                ReservedConcurrentExecutions=concurrent_executions,
            )
        snapshot.match("put_function_concurrency_below_unreserved_min_value", e.value.response)

    @markers.aws.validated
    def test_function_concurrency(self, create_lambda_function, snapshot, aws_client, monkeypatch):
        """Testing the api of the put function concurrency action"""
        # A lower limits (e.g., 11) could work if the minium unreservered concurrency is lower as well
        min_concurrent_executions = 101
        monkeypatch.setattr(
            config, "LAMBDA_LIMITS_CONCURRENT_EXECUTIONS", min_concurrent_executions
        )
        check_concurrency_quota(aws_client, min_concurrent_executions)

        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        # Disable the function by throttling all incoming events.
        put_0_response = aws_client.lambda_.put_function_concurrency(
            FunctionName=function_name, ReservedConcurrentExecutions=0
        )
        snapshot.match("put_function_concurrency_with_reserved_0", put_0_response)

        put_1_response = aws_client.lambda_.put_function_concurrency(
            FunctionName=function_name, ReservedConcurrentExecutions=1
        )
        snapshot.match("put_function_concurrency_with_reserved_1", put_1_response)

        get_response = aws_client.lambda_.get_function_concurrency(FunctionName=function_name)
        snapshot.match("get_function_concurrency", get_response)

        delete_response = aws_client.lambda_.delete_function_concurrency(FunctionName=function_name)
        snapshot.match("delete_response", delete_response)

        get_response_after_delete = aws_client.lambda_.get_function_concurrency(
            FunctionName=function_name
        )
        snapshot.match("get_function_concurrency_after_delete", get_response_after_delete)

        # Maximum limit
        account_settings = aws_client.lambda_.get_account_settings()
        unreserved_concurrent_executions = account_settings["AccountLimit"][
            "UnreservedConcurrentExecutions"
        ]
        max_reserved_concurrent_executions = (
            unreserved_concurrent_executions - min_concurrent_executions
        )
        put_max_response = aws_client.lambda_.put_function_concurrency(
            FunctionName=function_name,
            ReservedConcurrentExecutions=max_reserved_concurrent_executions,
        )
        # Cannot snapshot this edge case because the maximum value depends on the AWS account
        assert (
            put_max_response["ReservedConcurrentExecutions"] == max_reserved_concurrent_executions
        )


class TestLambdaProvisionedConcurrency:
    # TODO: test ARN
    # TODO: test shorthand ARN
    @markers.aws.validated
    def test_provisioned_concurrency_exceptions(
        self, aws_client, aws_client_factory, create_lambda_function, snapshot
    ):
        lambda_client = aws_client_factory(config=Config(parameter_validation=False)).lambda_
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

        # is provisioned = 0 equal to deleted? => no, invalid
        with pytest.raises(Exception) as e:
            lambda_client.put_provisioned_concurrency_config(
                FunctionName=function_name,
                Qualifier=function_version,
                ProvisionedConcurrentExecutions=0,
            )
        snapshot.match("put_provisioned_invalid_param_0", e.value.response)

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

    @markers.aws.validated
    def test_provisioned_concurrency_limits(
        self, aws_client, aws_client_factory, create_lambda_function, snapshot, monkeypatch
    ):
        """Test limits exceptions separately because this could be a dangerous test to run when misconfigured on AWS!"""
        # Adjust limits in LocalStack to avoid creating a Lambda fork-bomb
        monkeypatch.setattr(config, "LAMBDA_LIMITS_CONCURRENT_EXECUTIONS", 5)
        monkeypatch.setattr(config, "LAMBDA_LIMITS_MINIMUM_UNRESERVED_CONCURRENCY", 3)

        # We need to replace limits that are specific to AWS accounts
        # Using positive lookarounds to ensure we replace the correct number (e.g., if both limits have the same value)
        # Example: unreserved concurrency [10] => unreserved concurrency [<unreserved_concurrency>]
        prefix = re.escape("unreserved concurrency [")
        number_pattern = "\d+"  # noqa W605
        suffix = re.escape("]")
        unreserved_regex = re.compile(f"(?<={prefix}){number_pattern}(?={suffix})")
        snapshot.add_transformer(
            snapshot.transform.regex(unreserved_regex, "<unreserved_concurrency>")
        )
        prefix = re.escape("minimum value of [")
        min_unreserved_regex = re.compile(f"(?<={prefix}){number_pattern}(?={suffix})")
        snapshot.add_transformer(
            snapshot.transform.regex(min_unreserved_regex, "<min_unreserved_concurrency>")
        )

        lambda_client = aws_client.lambda_
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        publish_version_result = lambda_client.publish_version(FunctionName=function_name)
        function_version = publish_version_result["Version"]

        account_settings = aws_client.lambda_.get_account_settings()
        concurrent_executions = account_settings["AccountLimit"]["ConcurrentExecutions"]

        # Higher provisioned concurrency than ConcurrentExecutions account limit
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.put_provisioned_concurrency_config(
                FunctionName=function_name,
                Qualifier=function_version,
                ProvisionedConcurrentExecutions=concurrent_executions + 1,
            )
        snapshot.match("put_provisioned_concurrency_account_limit_exceeded", e.value.response)
        assert (
            int(re.search(unreserved_regex, e.value.response["message"]).group(0))
            == concurrent_executions
        )

        # Not enough UnreservedConcurrentExecutions available in account
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.put_provisioned_concurrency_config(
                FunctionName=function_name,
                Qualifier=function_version,
                ProvisionedConcurrentExecutions=concurrent_executions,
            )
        snapshot.match("put_provisioned_concurrency_below_unreserved_min_value", e.value.response)

    @markers.aws.validated
    def test_lambda_provisioned_lifecycle(
        self, create_lambda_function, snapshot, aws_client, monkeypatch
    ):
        min_unreservered_executions = 10
        # Required +2 for the extra alias
        min_concurrent_executions = min_unreservered_executions + 2
        monkeypatch.setattr(
            config, "LAMBDA_LIMITS_CONCURRENT_EXECUTIONS", min_concurrent_executions
        )
        monkeypatch.setattr(
            config, "LAMBDA_LIMITS_MINIMUM_UNRESERVED_CONCURRENCY", min_unreservered_executions
        )
        check_concurrency_quota(aws_client, min_concurrent_executions)

        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        publish_version_result = aws_client.lambda_.publish_version(FunctionName=function_name)
        function_version = publish_version_result["Version"]
        snapshot.match("publish_version_result", publish_version_result)

        aws_client.lambda_.get_waiter("function_active_v2").wait(
            FunctionName=function_name, Qualifier=function_version
        )
        aws_client.lambda_.get_waiter("function_updated_v2").wait(
            FunctionName=function_name, Qualifier=function_version
        )

        alias_name = f"alias-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(alias_name, "<alias-name>"))
        create_alias_result = aws_client.lambda_.create_alias(
            FunctionName=function_name, Name=alias_name, FunctionVersion=function_version
        )
        snapshot.match("create_alias_result", create_alias_result)

        # some edge cases

        # attempt to set up provisioned concurrency for an alias that is pointing to a version that already has a provisioned concurrency setup

        put_provisioned_on_version = aws_client.lambda_.put_provisioned_concurrency_config(
            FunctionName=function_name,
            Qualifier=function_version,
            ProvisionedConcurrentExecutions=1,
        )
        snapshot.match("put_provisioned_on_version", put_provisioned_on_version)
        with pytest.raises(aws_client.lambda_.exceptions.ResourceConflictException) as e:
            aws_client.lambda_.put_provisioned_concurrency_config(
                FunctionName=function_name, Qualifier=alias_name, ProvisionedConcurrentExecutions=1
            )
        snapshot.match("put_provisioned_on_alias_versionconflict", e.value.response)

        # TODO: implement updates while IN_PROGRESS in LocalStack (currently not supported)
        def _wait_provisioned():
            status = aws_client.lambda_.get_provisioned_concurrency_config(
                FunctionName=function_name, Qualifier=function_version
            )["Status"]
            if status == "FAILED":
                raise ShortCircuitWaitException("terminal fail state")
            return status == "READY"

        assert wait_until(_wait_provisioned)

        delete_provisioned_version = aws_client.lambda_.delete_provisioned_concurrency_config(
            FunctionName=function_name, Qualifier=function_version
        )
        snapshot.match("delete_provisioned_version", delete_provisioned_version)

        with pytest.raises(
            aws_client.lambda_.exceptions.ProvisionedConcurrencyConfigNotFoundException
        ) as e:
            aws_client.lambda_.get_provisioned_concurrency_config(
                FunctionName=function_name, Qualifier=function_version
            )
        snapshot.match("get_provisioned_version_postdelete", e.value.response)

        # now the other way around

        put_provisioned_on_alias = aws_client.lambda_.put_provisioned_concurrency_config(
            FunctionName=function_name,
            Qualifier=alias_name,
            ProvisionedConcurrentExecutions=1,
        )
        snapshot.match("put_provisioned_on_alias", put_provisioned_on_alias)
        with pytest.raises(aws_client.lambda_.exceptions.ResourceConflictException) as e:
            aws_client.lambda_.put_provisioned_concurrency_config(
                FunctionName=function_name,
                Qualifier=function_version,
                ProvisionedConcurrentExecutions=1,
            )
        snapshot.match("put_provisioned_on_version_conflict", e.value.response)

        # deleting the alias will also delete the provisioned concurrency config that points to it
        delete_alias_result = aws_client.lambda_.delete_alias(
            FunctionName=function_name, Name=alias_name
        )
        snapshot.match("delete_alias_result", delete_alias_result)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.get_provisioned_concurrency_config(
                FunctionName=function_name, Qualifier=alias_name
            )
        snapshot.match("get_provisioned_alias_postaliasdelete", e.value.response)

        list_response_postdeletes = aws_client.lambda_.list_provisioned_concurrency_configs(
            FunctionName=function_name
        )
        assert len(list_response_postdeletes["ProvisionedConcurrencyConfigs"]) == 0
        snapshot.match("list_response_postdeletes", list_response_postdeletes)


class TestLambdaPermissions:
    @markers.aws.validated
    def test_permission_exceptions(self, create_lambda_function, account_id, snapshot, aws_client):
        function_name = f"lambda_func-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(function_name, "<function-name>"))
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        # invalid statement id
        with pytest.raises(aws_client.lambda_.exceptions.ClientError) as e:
            aws_client.lambda_.add_permission(
                FunctionName=function_name,
                Action="lambda:InvokeFunction",
                StatementId="example.com",
                Principal="s3.amazonaws.com",
            )
        snapshot.match("add_permission_invalid_statement_id", e.value.response)

        # qualifier mismatch between specified Qualifier and derived ARN from FunctionName
        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.add_permission(
                FunctionName=f"{function_name}:alias-not-42",
                Action="lambda:InvokeFunction",
                StatementId="s3",
                Principal="s3.amazonaws.com",
                SourceArn=arns.s3_bucket_arn("test-bucket"),
                Qualifier="42",
            )
        snapshot.match("add_permission_fn_qualifier_mismatch", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.add_permission(
                FunctionName=f"{function_name}:$LATEST",
                Action="lambda:InvokeFunction",
                StatementId="s3",
                Principal="s3.amazonaws.com",
                SourceArn=arns.s3_bucket_arn("test-bucket"),
                Qualifier="$LATEST",
            )
        snapshot.match("add_permission_fn_qualifier_latest", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.add_permission(
                FunctionName=function_name,
                Action="lambda:InvokeFunction",
                StatementId="lambda",
                Principal="invalid.nonaws.com",
                # TODO: implement AWS principle matching based on explicit list
                # Principal="invalid.amazonaws.com",
                SourceAccount=account_id,
            )
        snapshot.match("add_permission_principal_invalid", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.get_policy(FunctionName="doesnotexist")
        snapshot.match("get_policy_fn_doesnotexist", e.value.response)

        non_existing_version = "77"
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.get_policy(
                FunctionName=function_name, Qualifier=non_existing_version
            )
        snapshot.match("get_policy_fn_version_doesnotexist", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.add_permission(
                FunctionName="doesnotexist",
                Action="lambda:InvokeFunction",
                StatementId="s3",
                Principal="s3.amazonaws.com",
                SourceArn=arns.s3_bucket_arn("test-bucket"),
            )
        snapshot.match("add_permission_fn_doesnotexist", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.remove_permission(
                FunctionName=function_name,
                StatementId="s3",
            )
        snapshot.match("remove_permission_policy_doesnotexist", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.add_permission(
                FunctionName=f"{function_name}:alias-doesnotexist",
                Action="lambda:InvokeFunction",
                StatementId="s3",
                Principal="s3.amazonaws.com",
                SourceArn=arns.s3_bucket_arn("test-bucket"),
            )
        snapshot.match("add_permission_fn_alias_doesnotexist", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.add_permission(
                FunctionName=function_name,  # same behavior with version postfix :42
                Action="lambda:InvokeFunction",
                StatementId="s3",
                Principal="s3.amazonaws.com",
                SourceArn=arns.s3_bucket_arn("test-bucket"),
                Qualifier="42",
            )
        snapshot.match("add_permission_fn_version_doesnotexist", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ClientError) as e:
            aws_client.lambda_.add_permission(
                FunctionName=function_name,
                Action="lambda:InvokeFunction",
                StatementId="s3",
                Principal="s3.amazonaws.com",
                SourceArn=arns.s3_bucket_arn("test-bucket"),
                Qualifier="invalid-qualifier-with-?-char",
            )
        snapshot.match("add_permission_fn_qualifier_invalid", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.add_permission(
                FunctionName=function_name,
                Action="lambda:InvokeFunction",
                StatementId="s3",
                Principal="s3.amazonaws.com",
                SourceArn=arns.s3_bucket_arn("test-bucket"),
                # NOTE: $ is allowed here because "$LATEST" is a valid version
                Qualifier="valid-with-$-but-doesnotexist",
            )
        snapshot.match("add_permission_fn_qualifier_valid_doesnotexist", e.value.response)

        aws_client.lambda_.add_permission(
            FunctionName=function_name,
            Action="lambda:InvokeFunction",
            StatementId="s3",
            Principal="s3.amazonaws.com",
            SourceArn=arns.s3_bucket_arn("test-bucket"),
        )

        sid = "s3"
        with pytest.raises(aws_client.lambda_.exceptions.ResourceConflictException) as e:
            aws_client.lambda_.add_permission(
                FunctionName=function_name,
                Action="lambda:InvokeFunction",
                StatementId=sid,
                Principal="s3.amazonaws.com",
                SourceArn=arns.s3_bucket_arn("test-bucket"),
            )
        snapshot.match("add_permission_conflicting_statement_id", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.remove_permission(
                FunctionName="doesnotexist",
                StatementId=sid,
            )
        snapshot.match("remove_permission_fn_doesnotexist", e.value.response)

        non_existing_alias = "alias-doesnotexist"
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.remove_permission(
                FunctionName=function_name, StatementId=sid, Qualifier=non_existing_alias
            )
        snapshot.match("remove_permission_fn_alias_doesnotexist", e.value.response)

    @markers.aws.validated
    def test_add_lambda_permission_aws(
        self, create_lambda_function, account_id, snapshot, aws_client
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
        resp = aws_client.lambda_.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal=principal,
            SourceArn=arns.s3_bucket_arn("test-bucket"),
        )
        snapshot.match("add_permission", resp)

        # fetch lambda policy
        get_policy_result = aws_client.lambda_.get_policy(FunctionName=function_name)
        snapshot.match("get_policy", get_policy_result)

    @markers.aws.validated
    def test_lambda_permission_fn_versioning(
        self, create_lambda_function, account_id, snapshot, aws_client
    ):
        """Testing how lambda permissions behave when publishing different function versions and using qualifiers"""
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        # create lambda permission
        action = "lambda:InvokeFunction"
        sid = "s3"
        principal = "s3.amazonaws.com"
        resp = aws_client.lambda_.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal=principal,
            SourceArn=arns.s3_bucket_arn("test-bucket"),
        )
        snapshot.match("add_permission", resp)

        # fetch lambda policy
        get_policy_result_base = aws_client.lambda_.get_policy(FunctionName=function_name)
        snapshot.match("get_policy", get_policy_result_base)

        # publish version
        fn_version_result = aws_client.lambda_.publish_version(FunctionName=function_name)
        snapshot.match("publish_version_result", fn_version_result)
        fn_version = fn_version_result["Version"]
        aws_client.lambda_.get_waiter("published_version_active").wait(FunctionName=function_name)
        get_function_result_after_publish = aws_client.lambda_.get_function(
            FunctionName=function_name
        )
        snapshot.match("get_function_result_after_publishing", get_function_result_after_publish)
        get_policy_result_after_publishing = aws_client.lambda_.get_policy(
            FunctionName=function_name
        )
        snapshot.match("get_policy_after_publishing_latest", get_policy_result_after_publishing)

        # permissions apply per function unless providing a specific version or alias
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.get_policy(FunctionName=function_name, Qualifier=fn_version)
        snapshot.match("get_policy_after_publishing_new_version", e.value.response)

        # create lambda permission with the same sid for specific function version
        aws_client.lambda_.add_permission(
            FunctionName=f"{function_name}:{fn_version}",  # version suffix matching Qualifier
            Action=action,
            StatementId=sid,
            Principal=principal,
            SourceArn=arns.s3_bucket_arn("test-bucket"),
            Qualifier=fn_version,
        )
        get_policy_result_version = aws_client.lambda_.get_policy(
            FunctionName=function_name, Qualifier=fn_version
        )
        snapshot.match("get_policy_version", get_policy_result_version)

        alias_name = "permission-alias"
        create_alias_response = aws_client.lambda_.create_alias(
            FunctionName=function_name,
            Name=alias_name,
            FunctionVersion=fn_version,
        )
        snapshot.match("create_alias_response", create_alias_response)

        get_alias_response = aws_client.lambda_.get_alias(
            FunctionName=function_name, Name=alias_name
        )
        snapshot.match("get_alias", get_alias_response)
        assert get_alias_response["RevisionId"] == create_alias_response["RevisionId"]

        sid = "s3"
        with pytest.raises(aws_client.lambda_.exceptions.PreconditionFailedException) as e:
            aws_client.lambda_.add_permission(
                FunctionName=function_name,
                Action=action,
                StatementId=sid,
                Principal=principal,
                SourceArn=arns.s3_bucket_arn("test-bucket"),
                Qualifier=alias_name,
                RevisionId="wrong",
            )
        snapshot.match("add_permission_alias_revision_exception", e.value.response)

        # create lambda permission with the same sid for specific alias
        aws_client.lambda_.add_permission(
            FunctionName=f"{function_name}:{alias_name}",  # alias suffix matching Qualifier
            Action=action,
            StatementId=sid,
            Principal=principal,
            SourceArn=arns.s3_bucket_arn("test-bucket"),
            Qualifier=alias_name,
            RevisionId=create_alias_response["RevisionId"],
        )
        get_policy_result_alias = aws_client.lambda_.get_policy(
            FunctionName=function_name, Qualifier=alias_name
        )
        snapshot.match("get_policy_alias", get_policy_result_alias)

        get_policy_result = aws_client.lambda_.get_policy(FunctionName=function_name)
        snapshot.match("get_policy_after_adding_to_new_version", get_policy_result)

        # create lambda permission with other sid and correct revision id
        aws_client.lambda_.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=f"{sid}_2",
            Principal=principal,
            SourceArn=arns.s3_bucket_arn("test-bucket"),
            RevisionId=get_policy_result["RevisionId"],
        )

        get_policy_result_adding_2 = aws_client.lambda_.get_policy(FunctionName=function_name)
        snapshot.match("get_policy_after_adding_2", get_policy_result_adding_2)

    @markers.aws.validated
    def test_add_lambda_permission_fields(
        self, create_lambda_function, account_id, snapshot, aws_client
    ):
        # prevent resource transformer from matching the LS default username "root", which collides with other resources
        snapshot.add_transformer(
            snapshot.transform.jsonpath(
                "add_permission_principal_arn..Statement.Principal.AWS",
                "<user_arn>",
                reference_replacement=False,
            ),
            priority=-1,
        )

        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        resp = aws_client.lambda_.add_permission(
            FunctionName=function_name,
            Action="lambda:InvokeFunction",
            StatementId="wilcard",
            Principal="*",
            SourceAccount=account_id,
        )
        snapshot.match("add_permission_principal_wildcard", resp)

        resp = aws_client.lambda_.add_permission(
            FunctionName=function_name,
            Action="lambda:InvokeFunction",
            StatementId="lambda",
            Principal="lambda.amazonaws.com",
            SourceAccount=account_id,
        )
        snapshot.match("add_permission_principal_service", resp)

        resp = aws_client.lambda_.add_permission(
            FunctionName=function_name,
            Action="lambda:InvokeFunction",
            StatementId="account-id",
            Principal=account_id,
        )
        snapshot.match("add_permission_principal_account", resp)

        user_arn = aws_client.sts.get_caller_identity()["Arn"]
        resp = aws_client.lambda_.add_permission(
            FunctionName=function_name,
            Action="lambda:InvokeFunction",
            StatementId="user-arn",
            Principal=user_arn,
            SourceAccount=account_id,
        )
        snapshot.match("add_permission_principal_arn", resp)
        assert json.loads(resp["Statement"])["Principal"]["AWS"] == user_arn

        resp = aws_client.lambda_.add_permission(
            FunctionName=function_name,
            StatementId="urlPermission",
            Action="lambda:InvokeFunctionUrl",
            Principal="*",
            # optional fields:
            SourceArn=arns.s3_bucket_arn("test-bucket"),
            SourceAccount=account_id,
            PrincipalOrgID="o-1234567890",
            # "FunctionUrlAuthType is only supported for lambda:InvokeFunctionUrl action"
            FunctionUrlAuthType="NONE",
        )
        snapshot.match("add_permission_optional_fields", resp)

        # create alexa skill lambda permission:
        # https://developer.amazon.com/en-US/docs/alexa/custom-skills/host-a-custom-skill-as-an-aws-lambda-function.html#use-aws-cli
        response = aws_client.lambda_.add_permission(
            FunctionName=function_name,
            StatementId="alexaSkill",
            Action="lambda:InvokeFunction",
            Principal="*",
            # alexa skill token cannot be used together with source account and source arn
            EventSourceToken="amzn1.ask.skill.xxxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        )
        snapshot.match("add_permission_alexa_skill", response)

    @markers.aws.validated
    def test_remove_multi_permissions(self, create_lambda_function, snapshot, aws_client):
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
        permission_1_add = aws_client.lambda_.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal=principal,
        )
        snapshot.match("add_permission_1", permission_1_add)

        sid_2 = "sqs"
        principal_2 = "sqs.amazonaws.com"
        permission_2_add = aws_client.lambda_.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid_2,
            Principal=principal_2,
            SourceArn=arns.s3_bucket_arn("test-bucket"),
        )
        snapshot.match("add_permission_2", permission_2_add)
        policy_response = aws_client.lambda_.get_policy(
            FunctionName=function_name,
        )
        snapshot.match("policy_after_2_add", policy_response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.remove_permission(
                FunctionName=function_name,
                StatementId="non-existent",
            )
        snapshot.match("remove_permission_exception_nonexisting_sid", e.value.response)

        aws_client.lambda_.remove_permission(
            FunctionName=function_name,
            StatementId=sid_2,
        )

        policy_response_removal = aws_client.lambda_.get_policy(
            FunctionName=function_name,
        )
        snapshot.match("policy_after_removal", policy_response_removal)

        policy_response_removal_attempt = aws_client.lambda_.get_policy(
            FunctionName=function_name,
        )
        snapshot.match("policy_after_removal_attempt", policy_response_removal_attempt)

        aws_client.lambda_.remove_permission(
            FunctionName=function_name,
            StatementId=sid,
            RevisionId=policy_response_removal_attempt["RevisionId"],
        )
        # get_policy raises an exception after removing all permissions
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as ctx:
            aws_client.lambda_.get_policy(FunctionName=function_name)
        snapshot.match("get_policy_exception_removed_all", ctx.value.response)

    @markers.aws.validated
    def test_create_multiple_lambda_permissions(self, create_lambda_function, snapshot, aws_client):
        """Test creating multiple lambda permissions and checking the policy"""

        function_name = f"test-function-{short_uid()}"

        create_lambda_function(
            func_name=function_name,
            runtime=Runtime.python3_9,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
        )

        action = "lambda:InvokeFunction"
        sid = "logs"
        resp = aws_client.lambda_.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal="logs.amazonaws.com",
        )
        snapshot.match("add_permission_response_1", resp)

        sid = "kinesis"
        resp = aws_client.lambda_.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal="kinesis.amazonaws.com",
        )
        snapshot.match("add_permission_response_2", resp)

        policy_response = aws_client.lambda_.get_policy(
            FunctionName=function_name,
        )
        snapshot.match("policy_after_2_add", policy_response)


class TestLambdaUrl:
    @markers.aws.validated
    def test_url_config_exceptions(self, create_lambda_function, snapshot, aws_client):
        """
        note: list order is not defined
        """
        snapshot.add_transformer(
            snapshot.transform.key_value("FunctionUrl", "lambda-url", reference_replacement=False)
        )
        snapshot.add_transformer(
            SortingTransformer("FunctionUrlConfigs", sorting_fn=lambda x: x["FunctionArn"])
        )
        # broken at AWS yielding InternalFailure but should return InvalidParameterValueException as in
        # get_function_url_config_qualifier_alias_doesnotmatch_arn
        snapshot.add_transformer(
            snapshot.transform.jsonpath(
                "delete_function_url_config_qualifier_alias_doesnotmatch_arn",
                "<aws_internal_failure>",
                reference_replacement=False,
            ),
            priority=-1,
        )
        function_name = f"test-function-{short_uid()}"
        alias_name = "urlalias"

        create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_NODEJS, get_content=True),
            runtime=Runtime.nodejs14_x,
            handler="lambda_handler.handler",
        )
        fn_arn = aws_client.lambda_.get_function(FunctionName=function_name)["Configuration"][
            "FunctionArn"
        ]
        fn_version_result = aws_client.lambda_.publish_version(FunctionName=function_name)
        snapshot.match("fn_version_result", fn_version_result)
        create_alias_result = aws_client.lambda_.create_alias(
            FunctionName=function_name,
            Name=alias_name,
            FunctionVersion=fn_version_result["Version"],
        )
        snapshot.match("create_alias_result", create_alias_result)

        # function name + qualifier tests
        fn_arn_doesnotexist = fn_arn.replace(function_name, "doesnotexist")

        def assert_name_and_qualifier(method: Callable, snapshot_prefix: str, tests, **kwargs):
            for t in tests:
                with pytest.raises(t["exc"]) as e:
                    method(**t["args"], **kwargs)
                snapshot.match(f"{snapshot_prefix}_{t['SnapshotName']}", e.value.response)

        tests = [
            {
                "args": {"FunctionName": "doesnotexist"},
                "SnapshotName": "name_doesnotexist",
                "exc": aws_client.lambda_.exceptions.ResourceNotFoundException,
            },
            {
                "args": {"FunctionName": fn_arn_doesnotexist},
                "SnapshotName": "arn_doesnotexist",
                "exc": aws_client.lambda_.exceptions.ResourceNotFoundException,
            },
            {
                "args": {"FunctionName": "doesnotexist", "Qualifier": "1"},
                "SnapshotName": "name_doesnotexist_qualifier",
                "exc": aws_client.lambda_.exceptions.ClientError,
            },
            {
                "args": {"FunctionName": function_name, "Qualifier": "1"},
                "SnapshotName": "qualifier_version",
                "exc": aws_client.lambda_.exceptions.ClientError,
            },
            {
                "args": {"FunctionName": function_name, "Qualifier": "2"},
                "SnapshotName": "qualifier_version_doesnotexist",
                "exc": aws_client.lambda_.exceptions.ClientError,
            },
            {
                "args": {"FunctionName": function_name, "Qualifier": "v1"},
                "SnapshotName": "qualifier_alias_doesnotexist",
                "exc": aws_client.lambda_.exceptions.ResourceNotFoundException,
            },
            {
                "args": {
                    "FunctionName": f"{function_name}:{alias_name}-doesnotmatch",
                    "Qualifier": alias_name,
                },
                "SnapshotName": "qualifier_alias_doesnotmatch_arn",
                "exc": aws_client.lambda_.exceptions.ClientError,
            },
            {
                "args": {
                    "FunctionName": function_name,
                    "Qualifier": "$LATEST",
                },
                "SnapshotName": "qualifier_latest",
                "exc": aws_client.lambda_.exceptions.ClientError,
            },
        ]
        config_doesnotexist_tests = [
            {
                "args": {"FunctionName": function_name},
                "SnapshotName": "config_doesnotexist",
                "exc": aws_client.lambda_.exceptions.ResourceNotFoundException,
            },
        ]

        assert_name_and_qualifier(
            aws_client.lambda_.create_function_url_config,
            "create_function_url_config",
            tests,
            AuthType="NONE",
        )
        assert_name_and_qualifier(
            aws_client.lambda_.get_function_url_config,
            "get_function_url_config",
            tests + config_doesnotexist_tests,
        )
        assert_name_and_qualifier(
            aws_client.lambda_.delete_function_url_config,
            "delete_function_url_config",
            tests + config_doesnotexist_tests,
        )
        assert_name_and_qualifier(
            aws_client.lambda_.update_function_url_config,
            "update_function_url_config",
            tests + config_doesnotexist_tests,
            AuthType="AWS_IAM",
        )

    @markers.snapshot.skip_snapshot_verify(paths=["$..FunctionUrlConfigs..InvokeMode"])
    @markers.aws.validated
    def test_url_config_list_paging(self, create_lambda_function, snapshot, aws_client):
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

        fn_version_result = aws_client.lambda_.publish_version(FunctionName=function_name)
        snapshot.match("fn_version_result", fn_version_result)
        create_alias_result = aws_client.lambda_.create_alias(
            FunctionName=function_name,
            Name=alias_name,
            FunctionVersion=fn_version_result["Version"],
        )
        snapshot.match("create_alias_result", create_alias_result)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.list_function_url_configs(FunctionName="doesnotexist")
        snapshot.match("list_function_notfound", e.value.response)

        list_all_empty = aws_client.lambda_.list_function_url_configs(FunctionName=function_name)
        snapshot.match("list_all_empty", list_all_empty)

        url_config_fn = aws_client.lambda_.create_function_url_config(
            FunctionName=function_name, AuthType="NONE"
        )
        snapshot.match("url_config_fn", url_config_fn)
        url_config_alias = aws_client.lambda_.create_function_url_config(
            FunctionName=f"{function_name}:{alias_name}", Qualifier=alias_name, AuthType="NONE"
        )
        snapshot.match("url_config_alias", url_config_alias)

        list_all = aws_client.lambda_.list_function_url_configs(FunctionName=function_name)
        snapshot.match("list_all", list_all)

        total_configs = [url_config_fn["FunctionUrl"], url_config_alias["FunctionUrl"]]

        list_max_1_item = aws_client.lambda_.list_function_url_configs(
            FunctionName=function_name, MaxItems=1
        )
        assert len(list_max_1_item["FunctionUrlConfigs"]) == 1
        assert list_max_1_item["FunctionUrlConfigs"][0]["FunctionUrl"] in total_configs

        list_max_2_item = aws_client.lambda_.list_function_url_configs(
            FunctionName=function_name, MaxItems=2
        )
        assert len(list_max_2_item["FunctionUrlConfigs"]) == 2
        assert list_max_2_item["FunctionUrlConfigs"][0]["FunctionUrl"] in total_configs
        assert list_max_2_item["FunctionUrlConfigs"][1]["FunctionUrl"] in total_configs

        list_max_1_item_marker = aws_client.lambda_.list_function_url_configs(
            FunctionName=function_name, MaxItems=1, Marker=list_max_1_item["NextMarker"]
        )
        assert len(list_max_1_item_marker["FunctionUrlConfigs"]) == 1
        assert list_max_1_item_marker["FunctionUrlConfigs"][0]["FunctionUrl"] in total_configs
        assert (
            list_max_1_item_marker["FunctionUrlConfigs"][0]["FunctionUrl"]
            != list_max_1_item["FunctionUrlConfigs"][0]["FunctionUrl"]
        )

    @markers.snapshot.skip_snapshot_verify(paths=["$..InvokeMode"])
    @markers.aws.validated
    def test_url_config_lifecycle(self, create_lambda_function, snapshot, aws_client):
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

        url_config_created = aws_client.lambda_.create_function_url_config(
            FunctionName=function_name,
            AuthType="NONE",
        )
        snapshot.match("url_creation", url_config_created)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceConflictException) as ex:
            aws_client.lambda_.create_function_url_config(
                FunctionName=function_name,
                AuthType="NONE",
            )
        snapshot.match("failed_duplication", ex.value.response)

        url_config_obtained = aws_client.lambda_.get_function_url_config(FunctionName=function_name)
        snapshot.match("get_url_config", url_config_obtained)

        url_config_updated = aws_client.lambda_.update_function_url_config(
            FunctionName=function_name,
            AuthType="AWS_IAM",
        )
        snapshot.match("updated_url_config", url_config_updated)

        aws_client.lambda_.delete_function_url_config(FunctionName=function_name)
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as ex:
            aws_client.lambda_.get_function_url_config(FunctionName=function_name)
        snapshot.match("failed_getter", ex.value.response)


class TestLambdaSizeLimits:
    def _generate_sized_python_str(self, filepath: str, size: int) -> str:
        """Generate a text of the specified size by appending #s at the end of the file"""
        with open(filepath, "r") as f:
            py_str = f.read()
        py_str += "#" * (size - len(py_str))
        return py_str

    @markers.aws.validated
    def test_oversized_request_create_lambda(self, lambda_su_role, snapshot, aws_client):
        function_name = f"test_lambda_{short_uid()}"
        # ensure that we are slightly below the zipped size limit because it is checked before the request limit
        code_str = self._generate_sized_python_str(
            TEST_LAMBDA_PYTHON_ECHO, config.LAMBDA_LIMITS_CODE_SIZE_ZIPPED - 1024
        )

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            code_str, get_content=True, runtime=Runtime.python3_9
        )

        # enlarge the request beyond its limit while accounting for the zip file size
        delta = (
            config.LAMBDA_LIMITS_CREATE_FUNCTION_REQUEST_SIZE
            - config.LAMBDA_LIMITS_CODE_SIZE_ZIPPED
        )
        large_env = self._generate_sized_python_str(TEST_LAMBDA_PYTHON_ECHO, delta + 1024 * 1024)

        # create lambda function
        with pytest.raises(ClientError) as e:
            aws_client.lambda_.create_function(
                FunctionName=function_name,
                Runtime=Runtime.python3_9,
                Handler="handler.handler",
                Role=lambda_su_role,
                Code={"ZipFile": zip_file},
                Timeout=10,
                Environment={"Variables": {"largeKey": large_env}},
            )
        snapshot.match("invalid_param_exc", e.value.response)

    @markers.aws.validated
    def test_oversized_zipped_create_lambda(self, lambda_su_role, snapshot, aws_client):
        function_name = f"test_lambda_{short_uid()}"
        # use the highest boundary to test that the zipped size is checked before the request size
        code_str = self._generate_sized_python_str(
            TEST_LAMBDA_PYTHON_ECHO, config.LAMBDA_LIMITS_CODE_SIZE_ZIPPED
        )

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            code_str, get_content=True, runtime=Runtime.python3_9
        )

        # create lambda function
        with pytest.raises(ClientError) as e:
            aws_client.lambda_.create_function(
                FunctionName=function_name,
                Runtime=Runtime.python3_9,
                Handler="handler.handler",
                Role=lambda_su_role,
                Code={"ZipFile": zip_file},
                Timeout=10,
            )
        snapshot.match("invalid_param_exc", e.value.response)

    @markers.aws.validated
    def test_oversized_unzipped_lambda(self, s3_bucket, lambda_su_role, snapshot, aws_client):
        function_name = f"test_lambda_{short_uid()}"
        bucket_key = "test_lambda.zip"
        code_str = self._generate_sized_python_str(
            TEST_LAMBDA_PYTHON_ECHO, config.LAMBDA_LIMITS_CODE_SIZE_UNZIPPED
        )

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            code_str, get_content=True, runtime=Runtime.python3_9
        )
        aws_client.s3.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.create_function(
                FunctionName=function_name,
                Runtime=Runtime.python3_9,
                Handler="handler.handler",
                Role=lambda_su_role,
                Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
                Timeout=10,
            )
        snapshot.match("invalid_param_exc", e.value.response)

    @markers.aws.validated
    def test_large_lambda(self, s3_bucket, lambda_su_role, snapshot, cleanups, aws_client):
        function_name = f"test_lambda_{short_uid()}"
        cleanups.append(lambda: aws_client.lambda_.delete_function(FunctionName=function_name))
        bucket_key = "test_lambda.zip"
        code_str = self._generate_sized_python_str(
            TEST_LAMBDA_PYTHON_ECHO, config.LAMBDA_LIMITS_CODE_SIZE_UNZIPPED - 1000
        )

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            code_str, get_content=True, runtime=Runtime.python3_9
        )
        aws_client.s3.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        result = aws_client.lambda_.create_function(
            FunctionName=function_name,
            Runtime=Runtime.python3_9,
            Handler="handler.handler",
            Role=lambda_su_role,
            Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
            Timeout=10,
        )
        snapshot.match("create_function_large_zip", result)

        # TODO: Test and fix deleting a non-active Lambda
        aws_client.lambda_.get_waiter("function_active_v2").wait(FunctionName=function_name)

    @markers.aws.validated
    def test_large_environment_variables_fails(self, create_lambda_function, snapshot, aws_client):
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

        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as ex:
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
            aws_client.lambda_.get_function(FunctionName=function_name)

        assert ex.match("ResourceNotFoundException")

    @markers.aws.validated
    def test_large_environment_fails_multiple_keys(
        self, create_lambda_function, snapshot, aws_client
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

        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as ex:
            create_lambda_function(
                handler_file=TEST_LAMBDA_PYTHON_ECHO,
                func_name=function_name,
                runtime=Runtime.python3_9,
                envvars=env,
            )

        snapshot.match("failured_create_fn_result_multi_key", ex.value.response)

        with pytest.raises(ClientError) as exc:
            aws_client.lambda_.get_function(FunctionName=function_name)

        assert exc.match("ResourceNotFoundException")

    @markers.aws.validated
    def test_lambda_envvars_near_limit_succeeds(self, create_lambda_function, snapshot, aws_client):
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
        aws_client.lambda_.get_function(FunctionName=function_name)


# TODO: test paging
# TODO: test function name / ARN resolving
class TestCodeSigningConfig:
    @markers.aws.validated
    def test_function_code_signing_config(
        self, create_lambda_function, snapshot, account_id, aws_client
    ):
        """Testing the API of code signing config"""

        function_name = f"lambda_func-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        response = aws_client.lambda_.create_code_signing_config(
            Description="Testing CodeSigning Config",
            AllowedPublishers={
                "SigningProfileVersionArns": [
                    f"arn:aws:signer:{aws_client.lambda_.meta.region_name}:{account_id}:/signing-profiles/test",
                ]
            },
            CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Enforce"},
        )
        snapshot.match("create_code_signing_config", response)

        code_signing_arn = response["CodeSigningConfig"]["CodeSigningConfigArn"]
        response = aws_client.lambda_.update_code_signing_config(
            CodeSigningConfigArn=code_signing_arn,
            CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Warn"},
        )
        snapshot.match("update_code_signing_config", response)

        response = aws_client.lambda_.get_code_signing_config(CodeSigningConfigArn=code_signing_arn)
        snapshot.match("get_code_signing_config", response)

        response = aws_client.lambda_.put_function_code_signing_config(
            CodeSigningConfigArn=code_signing_arn, FunctionName=function_name
        )
        snapshot.match("put_function_code_signing_config", response)

        response = aws_client.lambda_.get_function_code_signing_config(FunctionName=function_name)
        snapshot.match("get_function_code_signing_config", response)

        response = aws_client.lambda_.list_code_signing_configs()
        snapshot.match("list_code_signing_configs", response)

        response = aws_client.lambda_.list_functions_by_code_signing_config(
            CodeSigningConfigArn=code_signing_arn
        )
        snapshot.match("list_functions_by_code_signing_config", response)

        response = aws_client.lambda_.delete_function_code_signing_config(
            FunctionName=function_name
        )
        snapshot.match("delete_function_code_signing_config", response)

        response = aws_client.lambda_.delete_code_signing_config(
            CodeSigningConfigArn=code_signing_arn
        )
        snapshot.match("delete_code_signing_config", response)

    @markers.aws.validated
    def test_code_signing_not_found_excs(
        self, snapshot, create_lambda_function, account_id, aws_client
    ):
        """tests for exceptions on missing resources and related corner cases"""

        function_name = f"lambda_func-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        response = aws_client.lambda_.create_code_signing_config(
            Description="Testing CodeSigning Config",
            AllowedPublishers={
                "SigningProfileVersionArns": [
                    f"arn:aws:signer:{aws_client.lambda_.meta.region_name}:{account_id}:/signing-profiles/test",
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
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.delete_code_signing_config(CodeSigningConfigArn=csc_arn_invalid)
        snapshot.match("delete_csc_notfound", e.value.response)

        nothing_to_delete_response = aws_client.lambda_.delete_function_code_signing_config(
            FunctionName=function_name
        )
        snapshot.match("nothing_to_delete_response", nothing_to_delete_response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.delete_function_code_signing_config(
                FunctionName="csc-test-doesnotexist"
            )
        snapshot.match("delete_function_csc_fnnotfound", e.value.response)

        # put
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.put_function_code_signing_config(
                FunctionName=nonexisting_fn_name, CodeSigningConfigArn=csc_arn
            )
        snapshot.match("put_function_csc_invalid_fnname", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.CodeSigningConfigNotFoundException) as e:
            aws_client.lambda_.put_function_code_signing_config(
                FunctionName=function_name, CodeSigningConfigArn=csc_arn_invalid
            )
        snapshot.match("put_function_csc_invalid_csc_arn", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.CodeSigningConfigNotFoundException) as e:
            aws_client.lambda_.put_function_code_signing_config(
                FunctionName=nonexisting_fn_name, CodeSigningConfigArn=csc_arn_invalid
            )
        snapshot.match("put_function_csc_invalid_both", e.value.response)

        # update csc
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.update_code_signing_config(
                CodeSigningConfigArn=csc_arn_invalid, Description="new-description"
            )
        snapshot.match("update_csc_invalid_csc_arn", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.update_code_signing_config(CodeSigningConfigArn=csc_arn_invalid)
        snapshot.match("update_csc_noupdates", e.value.response)

        update_csc_noupdate_response = aws_client.lambda_.update_code_signing_config(
            CodeSigningConfigArn=csc_arn
        )
        snapshot.match("update_csc_noupdate_response", update_csc_noupdate_response)

        # get
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.get_code_signing_config(CodeSigningConfigArn=csc_arn_invalid)
        snapshot.match("get_csc_invalid", e.value.response)

        get_function_csc_fnwithoutcsc = aws_client.lambda_.get_function_code_signing_config(
            FunctionName=function_name
        )
        snapshot.match("get_function_csc_fnwithoutcsc", get_function_csc_fnwithoutcsc)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.get_function_code_signing_config(FunctionName=nonexisting_fn_name)
        snapshot.match("get_function_csc_nonexistingfn", e.value.response)

        # list
        list_functions_by_csc_fnwithoutcsc = (
            aws_client.lambda_.list_functions_by_code_signing_config(CodeSigningConfigArn=csc_arn)
        )
        snapshot.match("list_functions_by_csc_fnwithoutcsc", list_functions_by_csc_fnwithoutcsc)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.list_functions_by_code_signing_config(
                CodeSigningConfigArn=csc_arn_invalid
            )
        snapshot.match("list_functions_by_csc_invalid_cscarn", e.value.response)


class TestLambdaAccountSettings:
    @markers.aws.validated
    def test_account_settings(self, snapshot, aws_client):
        """Limitation: only checks keys because AccountLimits are specific to AWS accounts. Example limits (2022-12-05):

        "AccountLimit": {
            "TotalCodeSize": 80530636800,
            "CodeSizeUnzipped": 262144000,
            "CodeSizeZipped": 52428800,
            "ConcurrentExecutions": 10,
            "UnreservedConcurrentExecutions": 10
        }"""
        acc_settings = aws_client.lambda_.get_account_settings()
        acc_settings_modded = acc_settings
        acc_settings_modded["AccountLimit"] = sorted(list(acc_settings["AccountLimit"].keys()))
        acc_settings_modded["AccountUsage"] = sorted(list(acc_settings["AccountUsage"].keys()))
        snapshot.match("acc_settings_modded", acc_settings_modded)

    @markers.aws.validated
    def test_account_settings_total_code_size(
        self, create_lambda_function, dummylayer, cleanups, snapshot, aws_client
    ):
        """Caveat: Could be flaky if another test simultaneously deletes a lambda function or layer in the same region.
        Hence, testing for monotonically increasing `TotalCodeSize` rather than matching exact differences.
        However, the parity tests use exact matching based on zip files with deterministic size.
        """
        acc_settings0 = aws_client.lambda_.get_account_settings()

        # 1) create a new function
        function_name = f"lambda_func-{short_uid()}"
        zip_file_content = load_file(TEST_LAMBDA_PYTHON_ECHO_ZIP, mode="rb")
        create_lambda_function(
            zip_file=zip_file_content,
            handler="index.handler",
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        acc_settings1 = aws_client.lambda_.get_account_settings()
        assert (
            acc_settings1["AccountUsage"]["TotalCodeSize"]
            > acc_settings0["AccountUsage"]["TotalCodeSize"]
        )
        assert (
            acc_settings1["AccountUsage"]["FunctionCount"]
            > acc_settings0["AccountUsage"]["FunctionCount"]
        )
        snapshot.match(
            "total_code_size_diff_create_function",
            acc_settings1["AccountUsage"]["TotalCodeSize"]
            - acc_settings0["AccountUsage"]["TotalCodeSize"],
        )

        # 2) update the function
        aws_client.lambda_.update_function_code(
            FunctionName=function_name, ZipFile=zip_file_content, Publish=True
        )
        # there is no need to wait until function_updated_v2 here because TotalCodeSize changes upon publishing
        acc_settings2 = aws_client.lambda_.get_account_settings()
        assert (
            acc_settings2["AccountUsage"]["TotalCodeSize"]
            > acc_settings1["AccountUsage"]["TotalCodeSize"]
        )
        snapshot.match(
            "total_code_size_diff_update_function",
            acc_settings2["AccountUsage"]["TotalCodeSize"]
            - acc_settings1["AccountUsage"]["TotalCodeSize"],
        )

        # 3) publish a new layer
        layer_name = f"testlayer-{short_uid()}"
        publish_result1 = aws_client.lambda_.publish_layer_version(
            LayerName=layer_name, Content={"ZipFile": dummylayer}
        )
        cleanups.append(
            lambda: aws_client.lambda_.delete_layer_version(
                LayerName=layer_name, VersionNumber=publish_result1["Version"]
            )
        )
        acc_settings3 = aws_client.lambda_.get_account_settings()
        assert (
            acc_settings3["AccountUsage"]["TotalCodeSize"]
            > acc_settings2["AccountUsage"]["TotalCodeSize"]
        )
        snapshot.match(
            "total_code_size_diff_publish_layer",
            acc_settings3["AccountUsage"]["TotalCodeSize"]
            - acc_settings2["AccountUsage"]["TotalCodeSize"],
        )

        # 4) publish a new layer version
        publish_result2 = aws_client.lambda_.publish_layer_version(
            LayerName=layer_name, Content={"ZipFile": dummylayer}
        )
        cleanups.append(
            lambda: aws_client.lambda_.delete_layer_version(
                LayerName=layer_name, VersionNumber=publish_result2["Version"]
            )
        )
        acc_settings4 = aws_client.lambda_.get_account_settings()
        assert (
            acc_settings4["AccountUsage"]["TotalCodeSize"]
            > acc_settings3["AccountUsage"]["TotalCodeSize"]
        )
        snapshot.match(
            "total_code_size_diff_publish_layer_version",
            acc_settings4["AccountUsage"]["TotalCodeSize"]
            - acc_settings3["AccountUsage"]["TotalCodeSize"],
        )

    @markers.aws.validated
    def test_account_settings_total_code_size_config_update(
        self, create_lambda_function, snapshot, aws_client
    ):
        """TotalCodeSize always changes when publishing a new lambda function,
        even after config updates without code changes."""
        acc_settings0 = aws_client.lambda_.get_account_settings()

        # 1) create a new function
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_NODEJS,
            func_name=function_name,
            runtime=Runtime.nodejs16_x,
        )
        acc_settings1 = aws_client.lambda_.get_account_settings()
        assert (
            acc_settings1["AccountUsage"]["TotalCodeSize"]
            > acc_settings0["AccountUsage"]["TotalCodeSize"]
        )
        snapshot.match(
            # fuzzy matching because exact the zip size differs by OS (e.g., 368 bytes)
            "is_total_code_size_diff_create_function_more_than_200",
            (
                acc_settings1["AccountUsage"]["TotalCodeSize"]
                - acc_settings0["AccountUsage"]["TotalCodeSize"]
            )
            > 200,
        )

        # 2) update function configuration (i.e., code remains identical)
        aws_client.lambda_.update_function_configuration(
            FunctionName=function_name, Runtime=Runtime.nodejs18_x
        )
        aws_client.lambda_.get_waiter("function_updated_v2").wait(FunctionName=function_name)
        acc_settings2 = aws_client.lambda_.get_account_settings()
        assert (
            acc_settings2["AccountUsage"]["TotalCodeSize"]
            == acc_settings1["AccountUsage"]["TotalCodeSize"]
        )
        snapshot.match(
            "total_code_size_diff_update_function_configuration",
            acc_settings2["AccountUsage"]["TotalCodeSize"]
            - acc_settings1["AccountUsage"]["TotalCodeSize"],
        )

        # 3) publish updated function config
        aws_client.lambda_.publish_version(
            FunctionName=function_name, Description="actually publish the config update"
        )
        aws_client.lambda_.get_waiter("function_active_v2").wait(FunctionName=function_name)
        acc_settings3 = aws_client.lambda_.get_account_settings()
        assert (
            acc_settings3["AccountUsage"]["TotalCodeSize"]
            > acc_settings2["AccountUsage"]["TotalCodeSize"]
        )
        snapshot.match(
            "is_total_code_size_diff_publish_version_after_config_update_more_than_200",
            (
                acc_settings3["AccountUsage"]["TotalCodeSize"]
                - acc_settings2["AccountUsage"]["TotalCodeSize"]
            )
            > 200,
        )


class TestLambdaEventSourceMappings:
    @markers.aws.validated
    def test_event_source_mapping_exceptions(self, snapshot, aws_client):
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.get_event_source_mapping(UUID=long_uid())
        snapshot.match("get_unknown_uuid", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.delete_event_source_mapping(UUID=long_uid())
        snapshot.match("delete_unknown_uuid", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.update_event_source_mapping(UUID=long_uid(), Enabled=False)
        snapshot.match("update_unknown_uuid", e.value.response)

        # note: list doesn't care about the resource filters existing
        aws_client.lambda_.list_event_source_mappings()
        aws_client.lambda_.list_event_source_mappings(FunctionName="doesnotexist")
        aws_client.lambda_.list_event_source_mappings(
            EventSourceArn="arn:aws:sqs:us-east-1:111111111111:somequeue"
        )

        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.create_event_source_mapping(FunctionName="doesnotexist")
        snapshot.match("create_no_event_source_arn", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.create_event_source_mapping(
                FunctionName="doesnotexist",
                EventSourceArn="arn:aws:sqs:us-east-1:111111111111:somequeue",
            )
        snapshot.match("create_unknown_params", e.value.response)
        # TODO: add test for event source arn == failure destination
        # TODO: add test for adding success destination

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # all dynamodb service issues not related to lambda
            "$..TableDescription.DeletionProtectionEnabled",
            "$..TableDescription.ProvisionedThroughput.LastDecreaseDateTime",
            "$..TableDescription.ProvisionedThroughput.LastIncreaseDateTime",
            "$..TableDescription.TableStatus",
            "$..TableDescription.TableId",
            "$..UUID",
        ]
    )
    @markers.aws.validated
    def test_event_source_mapping_lifecycle(
        self,
        create_lambda_function,
        snapshot,
        sqs_create_queue,
        cleanups,
        lambda_su_role,
        dynamodb_create_table,
        aws_client,
    ):
        function_name = f"lambda_func-{short_uid()}"
        table_name = f"teststreamtable-{short_uid()}"

        destination_queue_url = sqs_create_queue()
        destination_queue_arn = aws_client.sqs.get_queue_attributes(
            QueueUrl=destination_queue_url, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]

        dynamodb_create_table(table_name=table_name, partition_key="id")
        _await_dynamodb_table_active(aws_client.dynamodb, table_name)
        update_table_response = aws_client.dynamodb.update_table(
            TableName=table_name,
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"},
        )
        snapshot.match("update_table_response", update_table_response)
        stream_arn = update_table_response["TableDescription"]["LatestStreamArn"]

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
        )
        # "minimal"
        create_response = aws_client.lambda_.create_event_source_mapping(
            FunctionName=function_name,
            EventSourceArn=stream_arn,
            DestinationConfig={"OnFailure": {"Destination": destination_queue_arn}},
            BatchSize=1,
            StartingPosition="TRIM_HORIZON",
            MaximumBatchingWindowInSeconds=1,
            MaximumRetryAttempts=1,
        )
        uuid = create_response["UUID"]
        cleanups.append(lambda: aws_client.lambda_.delete_event_source_mapping(UUID=uuid))
        snapshot.match("create_response", create_response)

        # the stream might not be active immediately(!)
        def check_esm_active():
            return aws_client.lambda_.get_event_source_mapping(UUID=uuid)["State"] != "Creating"

        assert wait_until(check_esm_active)

        get_response = aws_client.lambda_.get_event_source_mapping(UUID=uuid)
        snapshot.match("get_response", get_response)
        #
        delete_response = aws_client.lambda_.delete_event_source_mapping(UUID=uuid)
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

    @markers.aws.validated
    def test_function_name_variations(
        self,
        create_lambda_function,
        snapshot,
        sqs_create_queue,
        cleanups,
        lambda_su_role,
        aws_client,
    ):
        function_name = f"lambda_func-{short_uid()}"

        queue_url = sqs_create_queue()
        queue_arn = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_12,
            role=lambda_su_role,
        )

        # create version & alias pointing to the version
        v1 = aws_client.lambda_.publish_version(FunctionName=function_name)
        alias = aws_client.lambda_.create_alias(
            FunctionName=function_name, FunctionVersion=v1["Version"], Name="myalias"
        )
        fn = aws_client.lambda_.get_function(FunctionName=function_name)

        def _create_esm(snapshot_scope: str, tested_name: str):
            result = aws_client.lambda_.create_event_source_mapping(
                FunctionName=tested_name,
                EventSourceArn=queue_arn,
            )
            cleanups.append(
                lambda: aws_client.lambda_.delete_event_source_mapping(UUID=result["UUID"])
            )
            snapshot.match(f"{snapshot_scope}_create_esm", result)
            _await_event_source_mapping_enabled(aws_client.lambda_, result["UUID"])
            aws_client.lambda_.delete_event_source_mapping(UUID=result["UUID"])

        _create_esm("name_only", function_name)
        _create_esm("partial_arn_latest", f"{function_name}:$LATEST")
        _create_esm("partial_arn_version", f"{function_name}:{v1['Version']}")
        _create_esm("partial_arn_alias", f"{function_name}:{alias['Name']}")
        _create_esm("full_arn_latest", fn["Configuration"]["FunctionArn"])
        _create_esm("full_arn_version", v1["FunctionArn"])
        _create_esm("full_arn_alias", alias["AliasArn"])

    @markers.aws.validated
    def test_create_event_source_validation(
        self, create_lambda_function, lambda_su_role, dynamodb_create_table, snapshot, aws_client
    ):
        """missing required field for DynamoDb stream event source mapping"""
        function_name = f"function-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
        )

        table_name = f"table-{short_uid()}"
        dynamodb_create_table(table_name=table_name, partition_key="id")
        _await_dynamodb_table_active(aws_client.dynamodb, table_name)
        update_table_response = aws_client.dynamodb.update_table(
            TableName=table_name,
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        )
        stream_arn = update_table_response["TableDescription"]["LatestStreamArn"]

        with pytest.raises(ClientError) as e:
            aws_client.lambda_.create_event_source_mapping(
                FunctionName=function_name, EventSourceArn=stream_arn
            )

        response = e.value.response
        snapshot.match("error", response)


class TestLambdaTags:
    @markers.aws.validated
    def test_tag_exceptions(self, create_lambda_function, snapshot, account_id, aws_client):
        function_name = f"fn-tag-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        function_arn = aws_client.lambda_.get_function(FunctionName=function_name)["Configuration"][
            "FunctionArn"
        ]
        arn_prefix = f"arn:aws:lambda:{aws_client.lambda_.meta.region_name}:{account_id}:function:"

        # invalid ARN
        with pytest.raises(aws_client.lambda_.exceptions.ClientError) as e:
            aws_client.lambda_.tag_resource(Resource="arn:aws:something", Tags={"key_a": "value_a"})
        snapshot.match("tag_lambda_invalidarn", e.value.response)

        # ARN valid but lambda function doesn't exist
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.tag_resource(
                Resource=f"{arn_prefix}doesnotexist", Tags={"key_a": "value_a"}
            )
        snapshot.match("tag_lambda_doesnotexist", e.value.response)

        # function exists but the qualifier in the ARN doesn't
        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.tag_resource(
                Resource=f"{function_arn}:v1", Tags={"key_a": "value_a"}
            )
        snapshot.match("tag_lambda_qualifier_doesnotexist", e.value.response)

        # get tags for resource that never had tags
        list_tags_response = aws_client.lambda_.list_tags(Resource=function_arn)
        snapshot.match("list_tag_lambda_empty", list_tags_response)

        # delete non-existing tag key
        untag_nomatch = aws_client.lambda_.untag_resource(
            Resource=function_arn, TagKeys=["somekey"]
        )
        snapshot.match("untag_nomatch", untag_nomatch)

        # delete empty tags
        with pytest.raises(aws_client.lambda_.exceptions.ClientError) as e:
            aws_client.lambda_.untag_resource(Resource=function_arn, TagKeys=[])
        snapshot.match("untag_empty_keys", e.value.response)

        # add empty tags
        with pytest.raises(aws_client.lambda_.exceptions.ClientError) as e:
            aws_client.lambda_.tag_resource(Resource=function_arn, Tags={})
        snapshot.match("tag_empty_tags", e.value.response)

        # partial delete (one exists, one doesn't)
        aws_client.lambda_.tag_resource(
            Resource=function_arn, Tags={"a_key": "a_value", "b_key": "b_value"}
        )
        aws_client.lambda_.untag_resource(Resource=function_arn, TagKeys=["a_key", "c_key"])
        assert "a_key" not in aws_client.lambda_.list_tags(Resource=function_arn)["Tags"]
        assert "b_key" in aws_client.lambda_.list_tags(Resource=function_arn)["Tags"]

    @markers.aws.validated
    def test_tag_limits(self, create_lambda_function, snapshot, aws_client):
        """test the limit of 50 tags per resource"""
        function_name = f"fn-tag-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        function_arn = aws_client.lambda_.get_function(FunctionName=function_name)["Configuration"][
            "FunctionArn"
        ]

        # invalid
        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.tag_resource(
                Resource=function_arn, Tags={f"{k}_key": f"{k}_value" for k in range(51)}
            )
        snapshot.match("tag_lambda_too_many_tags", e.value.response)

        # valid
        tag_response = aws_client.lambda_.tag_resource(
            Resource=function_arn, Tags={f"{k}_key": f"{k}_value" for k in range(50)}
        )
        snapshot.match("tag_response", tag_response)

        list_tags_response = aws_client.lambda_.list_tags(Resource=function_arn)
        snapshot.match("list_tags_response", list_tags_response)

        get_fn_response = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_fn_response", get_fn_response)

        # try to add one more :)
        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.tag_resource(Resource=function_arn, Tags={"a_key": "a_value"})
        snapshot.match("tag_lambda_too_many_tags_additional", e.value.response)

    @markers.aws.validated
    def test_tag_versions(self, create_lambda_function, snapshot, aws_client):
        function_name = f"fn-tag-{short_uid()}"
        create_function_result = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            Tags={"key_a": "value_a"},
        )
        function_arn = create_function_result["CreateFunctionResponse"]["FunctionArn"]
        publish_version_response = aws_client.lambda_.publish_version(FunctionName=function_name)
        version_arn = publish_version_response["FunctionArn"]
        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.tag_resource(
                Resource=version_arn,
                Tags={
                    "key_b": "value_b",
                    "key_c": "value_c",
                    "key_d": "value_d",
                    "key_e": "value_e",
                },
            )
        snapshot.match("tag_resource_exception", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.tag_resource(
                Resource=f"{function_arn}:$LATEST",
                Tags={
                    "key_b": "value_b",
                    "key_c": "value_c",
                    "key_d": "value_d",
                    "key_e": "value_e",
                },
            )
        snapshot.match("tag_resource_latest_exception", e.value.response)

    @markers.aws.validated
    def test_tag_lifecycle(self, create_lambda_function, snapshot, aws_client):
        function_name = f"fn-tag-{short_uid()}"

        def snapshot_tags_for_resource(resource_arn: str, snapshot_suffix: str):
            list_tags_response = aws_client.lambda_.list_tags(Resource=resource_arn)
            snapshot.match(f"list_tags_response_{snapshot_suffix}", list_tags_response)
            get_fn_response = aws_client.lambda_.get_function(FunctionName=resource_arn)
            snapshot.match(f"get_fn_response_{snapshot_suffix}", get_fn_response)

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            Tags={"key_a": "value_a"},
        )
        fn_arn = aws_client.lambda_.get_function(FunctionName=function_name)["Configuration"][
            "FunctionArn"
        ]
        snapshot_tags_for_resource(fn_arn, "postfncreate")

        tag_resource_response = aws_client.lambda_.tag_resource(
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

        tag_resource_response = aws_client.lambda_.tag_resource(
            Resource=fn_arn,
            Tags={
                "key_b": "value_b",
                "key_c": "value_x",
            },
        )
        snapshot.match("tag_resource_overwrite", tag_resource_response)
        snapshot_tags_for_resource(fn_arn, "overwrite")

        # remove two tags
        aws_client.lambda_.untag_resource(Resource=fn_arn, TagKeys=["key_c", "key_d"])
        snapshot_tags_for_resource(fn_arn, "postuntag")

        # remove all tags
        aws_client.lambda_.untag_resource(Resource=fn_arn, TagKeys=["key_a", "key_b", "key_e"])
        snapshot_tags_for_resource(fn_arn, "postuntagall")

        aws_client.lambda_.delete_function(FunctionName=function_name)
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.list_tags(Resource=fn_arn)
        snapshot.match("list_tags_postdelete", e.value.response)


# TODO: add more tests where layername can be an ARN
# TODO: test if function has to be in same region as layer
class TestLambdaLayer:
    @markers.lambda_runtime_update
    @markers.aws.validated
    # AWS only allows a max of 15 compatible runtimes, split runtimes and run two tests
    @pytest.mark.parametrize("runtimes", [ALL_RUNTIMES[:14], ALL_RUNTIMES[14:]])
    def test_layer_compatibilities(self, snapshot, dummylayer, cleanups, aws_client, runtimes):
        """Creates a single layer which is compatible with all"""
        layer_name = f"testlayer-{short_uid()}"

        publish_result = aws_client.lambda_.publish_layer_version(
            LayerName=layer_name,
            CompatibleRuntimes=runtimes,
            Content={"ZipFile": dummylayer},
            CompatibleArchitectures=ARCHITECTURES,
        )
        cleanups.append(
            lambda: aws_client.lambda_.delete_layer_version(
                LayerName=layer_name, VersionNumber=publish_result["Version"]
            )
        )
        snapshot.match("publish_result", publish_result)

    @markers.lambda_runtime_update
    @markers.aws.validated
    def test_layer_exceptions(self, snapshot, dummylayer, cleanups, aws_client):
        """
        API-level exceptions and edge cases for lambda layers
        """
        layer_name = f"testlayer-{short_uid()}"

        publish_result = aws_client.lambda_.publish_layer_version(
            LayerName=layer_name,
            CompatibleRuntimes=[Runtime.python3_9],
            Content={"ZipFile": dummylayer},
            CompatibleArchitectures=[Architecture.x86_64],
        )
        cleanups.append(
            lambda: aws_client.lambda_.delete_layer_version(
                LayerName=layer_name, VersionNumber=publish_result["Version"]
            )
        )
        snapshot.match("publish_result", publish_result)

        with pytest.raises(aws_client.lambda_.exceptions.ClientError) as e:
            aws_client.lambda_.list_layers(CompatibleRuntime="runtimedoesnotexist")
        snapshot.match("list_layers_exc_compatibleruntime_invalid", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ClientError) as e:
            aws_client.lambda_.list_layers(CompatibleArchitecture="archdoesnotexist")
        snapshot.match("list_layers_exc_compatiblearchitecture_invalid", e.value.response)

        list_nonexistent_layer = aws_client.lambda_.list_layer_versions(
            LayerName="layerdoesnotexist"
        )
        snapshot.match("list_nonexistent_layer", list_nonexistent_layer)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.get_layer_version(LayerName="layerdoesnotexist", VersionNumber=1)
        snapshot.match("get_layer_version_exc_layer_doesnotexist", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.get_layer_version(LayerName=layer_name, VersionNumber=-1)
        snapshot.match(
            "get_layer_version_exc_layer_version_doesnotexist_negative", e.value.response
        )

        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.get_layer_version(LayerName=layer_name, VersionNumber=0)
        snapshot.match("get_layer_version_exc_layer_version_doesnotexist_zero", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.get_layer_version(LayerName=layer_name, VersionNumber=2)
        snapshot.match("get_layer_version_exc_layer_version_doesnotexist_2", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ClientError) as e:
            aws_client.lambda_.get_layer_version_by_arn(
                Arn=publish_result["LayerArn"]
            )  # doesn't include version in the arn
        snapshot.match("get_layer_version_by_arn_exc_invalidarn", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.get_layer_version_by_arn(Arn=f"{publish_result['LayerArn']}:2")
        snapshot.match("get_layer_version_by_arn_exc_nonexistentversion", e.value.response)

        # delete seem to be "idempotent"
        delete_nonexistent_response = aws_client.lambda_.delete_layer_version(
            LayerName="layerdoesnotexist", VersionNumber=1
        )
        snapshot.match("delete_nonexistent_response", delete_nonexistent_response)

        delete_nonexistent_version_response = aws_client.lambda_.delete_layer_version(
            LayerName=layer_name, VersionNumber=2
        )
        snapshot.match("delete_nonexistent_version_response", delete_nonexistent_version_response)

        # this delete has an actual side effect (deleting the published layer)
        delete_layer_response = aws_client.lambda_.delete_layer_version(
            LayerName=layer_name, VersionNumber=1
        )
        snapshot.match("delete_layer_response", delete_layer_response)
        delete_layer_again_response = aws_client.lambda_.delete_layer_version(
            LayerName=layer_name, VersionNumber=1
        )
        snapshot.match("delete_layer_again_response", delete_layer_again_response)

        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.delete_layer_version(LayerName=layer_name, VersionNumber=-1)
        snapshot.match("delete_layer_version_exc_layerversion_invalid_version", e.value.response)

        # note: empty CompatibleRuntimes and CompatibleArchitectures are actually valid (!)
        layer_empty_name = f"testlayer-empty-{short_uid()}"
        publish_empty_result = aws_client.lambda_.publish_layer_version(
            LayerName=layer_empty_name,
            Content={"ZipFile": dummylayer},
            CompatibleRuntimes=[],
            CompatibleArchitectures=[],
        )
        cleanups.append(
            lambda: aws_client.lambda_.delete_layer_version(
                LayerName=layer_empty_name, VersionNumber=publish_empty_result["Version"]
            )
        )
        snapshot.match("publish_empty_result", publish_empty_result)

        # TODO: test list_layers with invalid filter values
        with pytest.raises(aws_client.lambda_.exceptions.ClientError) as e:
            aws_client.lambda_.publish_layer_version(
                LayerName=f"testlayer-2-{short_uid()}",
                Content={"ZipFile": dummylayer},
                CompatibleRuntimes=["invalidruntime"],
                CompatibleArchitectures=["invalidarch"],
            )
        snapshot.match("publish_layer_version_exc_invalid_runtime_arch", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ClientError) as e:
            aws_client.lambda_.publish_layer_version(
                LayerName=f"testlayer-2-{short_uid()}",
                Content={"ZipFile": dummylayer},
                CompatibleRuntimes=["invalidruntime", "invalidruntime2", Runtime.nodejs16_x],
                CompatibleArchitectures=["invalidarch", Architecture.x86_64],
            )
        snapshot.match("publish_layer_version_exc_partially_invalid_values", e.value.response)

    @markers.aws.validated
    def test_layer_function_exceptions(
        self, create_lambda_function, snapshot, dummylayer, cleanups, aws_client_factory, aws_client
    ):
        """Test interaction of layers when adding them to the function"""
        function_name = f"fn-layer-{short_uid()}"
        layer_name = f"testlayer-{short_uid()}"

        publish_result = aws_client.lambda_.publish_layer_version(
            LayerName=layer_name,
            CompatibleRuntimes=[],
            Content={"ZipFile": dummylayer},
            CompatibleArchitectures=[Architecture.x86_64],
        )
        cleanups.append(
            lambda: aws_client.lambda_.delete_layer_version(
                LayerName=layer_name, VersionNumber=publish_result["Version"]
            )
        )
        snapshot.match("publish_result", publish_result)

        publish_result_2 = aws_client.lambda_.publish_layer_version(
            LayerName=layer_name,
            CompatibleRuntimes=[],
            Content={"ZipFile": dummylayer},
            CompatibleArchitectures=[Architecture.x86_64],
        )
        cleanups.append(
            lambda: aws_client.lambda_.delete_layer_version(
                LayerName=layer_name, VersionNumber=publish_result_2["Version"]
            )
        )
        snapshot.match("publish_result_2", publish_result_2)

        publish_result_3 = aws_client.lambda_.publish_layer_version(
            LayerName=layer_name,
            CompatibleRuntimes=[],
            Content={"ZipFile": dummylayer},
            CompatibleArchitectures=[Architecture.x86_64],
        )
        cleanups.append(
            lambda: aws_client.lambda_.delete_layer_version(
                LayerName=layer_name, VersionNumber=publish_result_3["Version"]
            )
        )
        snapshot.match("publish_result_3", publish_result_3)

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        get_fn_result = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_fn_result", get_fn_result)

        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.update_function_configuration(
                FunctionName=function_name,
                Layers=[
                    publish_result["LayerVersionArn"],
                    publish_result_2["LayerVersionArn"],
                ],
            )
        snapshot.match("two_layer_versions_single_function_exc", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.update_function_configuration(
                FunctionName=function_name,
                Layers=[
                    publish_result["LayerVersionArn"],
                    publish_result_2["LayerVersionArn"],
                    publish_result_3["LayerVersionArn"],
                ],
            )
        snapshot.match("three_layer_versions_single_function_exc", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.update_function_configuration(
                FunctionName=function_name,
                Layers=[
                    publish_result["LayerVersionArn"],
                    publish_result["LayerVersionArn"],
                ],
            )
        snapshot.match("two_identical_layer_versions_single_function_exc", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.update_function_configuration(
                FunctionName=function_name,
                Layers=[
                    f"{publish_result['LayerArn'].replace(layer_name, 'doesnotexist')}:1",
                ],
            )
        snapshot.match("add_nonexistent_layer_exc", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.InvalidParameterValueException) as e:
            aws_client.lambda_.update_function_configuration(
                FunctionName=function_name,
                Layers=[
                    f"{publish_result['LayerArn']}:9",
                ],
            )
        snapshot.match("add_nonexistent_layer_version_exc", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ClientError) as e:
            aws_client.lambda_.update_function_configuration(
                FunctionName=function_name, Layers=[publish_result["LayerArn"]]
            )
        snapshot.match("add_layer_arn_without_version_exc", e.value.response)

        other_region_lambda_client = aws_client_factory(
            region_name=SECONDARY_TEST_AWS_REGION_NAME
        ).lambda_
        other_region_layer_result = other_region_lambda_client.publish_layer_version(
            LayerName=layer_name,
            CompatibleRuntimes=[],
            Content={"ZipFile": dummylayer},
            CompatibleArchitectures=[Architecture.x86_64],
        )
        cleanups.append(
            lambda: other_region_lambda_client.delete_layer_version(
                LayerName=layer_name, VersionNumber=other_region_layer_result["Version"]
            )
        )
        with pytest.raises(aws_client.lambda_.exceptions.ClientError) as e:
            create_lambda_function(
                func_name=function_name,
                handler_file=TEST_LAMBDA_PYTHON_ECHO,
                layers=[other_region_layer_result["LayerVersionArn"]],
            )
        snapshot.match("create_function_with_layer_in_different_region", e.value.response)

    @markers.aws.validated
    def test_layer_function_quota_exception(
        self, create_lambda_function, snapshot, dummylayer, cleanups, aws_client
    ):
        """Test lambda quota of "up to five layers"
        Layer docs: https://docs.aws.amazon.com/lambda/latest/dg/invocation-layers.html#invocation-layers-using
        Lambda quota: https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html#function-configuration-deployment-and-execution
        """
        layer_arns = []
        for n in range(6):
            layer_name_N = f"testlayer-{n+1}-{short_uid()}"
            publish_result_N = aws_client.lambda_.publish_layer_version(
                LayerName=layer_name_N,
                CompatibleRuntimes=[],
                Content={"ZipFile": dummylayer},
                CompatibleArchitectures=[Architecture.x86_64],
            )
            cleanups.append(
                lambda: aws_client.lambda_.delete_layer_version(
                    LayerName=layer_name_N, VersionNumber=publish_result_N["Version"]
                )
            )
            layer_arns.append(publish_result_N["LayerVersionArn"])

        function_name = f"fn-layer-{short_uid()}"
        with pytest.raises(aws_client.lambda_.exceptions.ClientError) as e:
            create_lambda_function(
                func_name=function_name,
                handler_file=TEST_LAMBDA_PYTHON_ECHO,
                layers=layer_arns,
            )
        snapshot.match("create_function_with_six_layers", e.value.response)

    @markers.aws.validated
    def test_layer_lifecycle(
        self, create_lambda_function, snapshot, dummylayer, cleanups, aws_client
    ):
        """
        Tests the general lifecycle of a Lambda layer

        There are a few interesting behaviors we can observe
        1. deleting all layer versions for a layer name and then publishing a new layer version with the same layer name, still increases the previous version counter
        2. deleting a layer version that is associated with a lambda won't affect the lambda configuration

        TODO: test paging of list operations
        TODO: test list_layers

        """
        function_name = f"fn-layer-{short_uid()}"
        layer_name = f"testlayer-{short_uid()}"
        license_info = f"licenseinfo-{short_uid()}"
        description = f"description-{short_uid()}"

        snapshot.add_transformer(snapshot.transform.regex(license_info, "<license-info>"))
        snapshot.add_transformer(snapshot.transform.regex(description, "<description>"))

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        get_fn_result = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_fn_result", get_fn_result)

        get_fn_config_result = aws_client.lambda_.get_function_configuration(
            FunctionName=function_name
        )
        snapshot.match("get_fn_config_result", get_fn_config_result)

        publish_result = aws_client.lambda_.publish_layer_version(
            LayerName=layer_name,
            CompatibleRuntimes=[Runtime.python3_9],
            LicenseInfo=license_info,
            Description=description,
            Content={"ZipFile": dummylayer},
            CompatibleArchitectures=[Architecture.x86_64],
        )
        cleanups.append(
            lambda: aws_client.lambda_.delete_layer_version(
                LayerName=layer_name, VersionNumber=publish_result["Version"]
            )
        )
        snapshot.match("publish_result", publish_result)

        # note: we don't even need to change anything for a second version to be published
        publish_result_2 = aws_client.lambda_.publish_layer_version(
            LayerName=layer_name,
            CompatibleRuntimes=[Runtime.python3_9],
            LicenseInfo=license_info,
            Description=description,
            Content={"ZipFile": dummylayer},
            CompatibleArchitectures=[Architecture.x86_64],
        )
        cleanups.append(
            lambda: aws_client.lambda_.delete_layer_version(
                LayerName=layer_name, VersionNumber=publish_result_2["Version"]
            )
        )
        snapshot.match("publish_result_2", publish_result_2)

        assert publish_result["Version"] == 1
        assert publish_result_2["Version"] == 2
        assert publish_result["Content"]["CodeSha256"] == publish_result_2["Content"]["CodeSha256"]

        update_fn_config = aws_client.lambda_.update_function_configuration(
            FunctionName=function_name, Layers=[publish_result["LayerVersionArn"]]
        )
        snapshot.match("update_fn_config", update_fn_config)

        # wait for update to be finished
        aws_client.lambda_.get_waiter("function_updated_v2").wait(FunctionName=function_name)
        get_fn_config = aws_client.lambda_.get_function_configuration(FunctionName=function_name)
        snapshot.match("get_fn_config", get_fn_config)

        get_layer_ver_result = aws_client.lambda_.get_layer_version(
            LayerName=layer_name, VersionNumber=publish_result["Version"]
        )
        snapshot.match("get_layer_ver_result", get_layer_ver_result)

        get_layer_by_arn_version = aws_client.lambda_.get_layer_version_by_arn(
            Arn=publish_result["LayerVersionArn"]
        )
        snapshot.match("get_layer_by_arn_version", get_layer_by_arn_version)

        list_layer_versions_predelete = aws_client.lambda_.list_layer_versions(LayerName=layer_name)
        snapshot.match("list_layer_versions_predelete", list_layer_versions_predelete)

        # scenario: what happens if we remove the layer when it's still associated with a function?
        delete_layer_1 = aws_client.lambda_.delete_layer_version(
            LayerName=layer_name, VersionNumber=1
        )
        snapshot.match("delete_layer_1", delete_layer_1)

        # still there
        get_fn_config_postdelete = aws_client.lambda_.get_function_configuration(
            FunctionName=function_name
        )
        snapshot.match("get_fn_config_postdelete", get_fn_config_postdelete)
        delete_layer_2 = aws_client.lambda_.delete_layer_version(
            LayerName=layer_name, VersionNumber=2
        )
        snapshot.match("delete_layer_2", delete_layer_2)

        # now there's no layer version left for <layer_name>
        list_layer_versions_postdelete = aws_client.lambda_.list_layer_versions(
            LayerName=layer_name
        )
        snapshot.match("list_layer_versions_postdelete", list_layer_versions_postdelete)
        assert len(list_layer_versions_postdelete["LayerVersions"]) == 0

        # creating a new layer version should still increment the previous version
        publish_result_3 = aws_client.lambda_.publish_layer_version(
            LayerName=layer_name,
            CompatibleRuntimes=[Runtime.python3_9],
            LicenseInfo=license_info,
            Description=description,
            Content={"ZipFile": dummylayer},
            CompatibleArchitectures=[Architecture.x86_64],
        )
        cleanups.append(
            lambda: aws_client.lambda_.delete_layer_version(
                LayerName=layer_name, VersionNumber=publish_result_3["Version"]
            )
        )
        snapshot.match("publish_result_3", publish_result_3)
        assert publish_result_3["Version"] == 3

    @markers.aws.validated
    def test_layer_s3_content(
        self, s3_create_bucket, create_lambda_function, snapshot, dummylayer, cleanups, aws_client
    ):
        """Publish a layer by referencing an s3 bucket instead of uploading the content directly"""
        bucket = s3_create_bucket()

        layer_name = f"bucket-layer-{short_uid()}"

        bucket_key = "/layercontent.zip"
        aws_client.s3.upload_fileobj(Fileobj=io.BytesIO(dummylayer), Bucket=bucket, Key=bucket_key)

        publish_layer_result = aws_client.lambda_.publish_layer_version(
            LayerName=layer_name, Content={"S3Bucket": bucket, "S3Key": bucket_key}
        )
        snapshot.match("publish_layer_result", publish_layer_result)

    @markers.aws.validated
    def test_layer_policy_exceptions(self, snapshot, dummylayer, cleanups, aws_client):
        """
        API-level exceptions and edge cases for lambda layer permissions

        TODO: OrganizationId
        """
        layer_name = f"layer4policy-{short_uid()}"

        publish_result = aws_client.lambda_.publish_layer_version(
            LayerName=layer_name,
            CompatibleRuntimes=[Runtime.python3_9],
            Content={"ZipFile": dummylayer},
            CompatibleArchitectures=[Architecture.x86_64],
        )
        cleanups.append(
            lambda: aws_client.lambda_.delete_layer_version(
                LayerName=layer_name, VersionNumber=publish_result["Version"]
            )
        )
        snapshot.match("publish_result", publish_result)

        # we didn't add any permissions yet, so the policy does not exist
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.get_layer_version_policy(LayerName=layer_name, VersionNumber=1)
        snapshot.match("layer_permission_nopolicy_get", e.value.response)

        # add a policy with statement id "s1"
        add_layer_permission_result = aws_client.lambda_.add_layer_version_permission(
            LayerName=layer_name,
            VersionNumber=1,
            Action="lambda:GetLayerVersion",
            Principal="*",
            StatementId="s1",
        )
        snapshot.match("add_layer_permission_result", add_layer_permission_result)

        # action can only be lambda:GetLayerVersion
        with pytest.raises(aws_client.lambda_.exceptions.ClientError) as e:
            aws_client.lambda_.add_layer_version_permission(
                LayerName=layer_name,
                VersionNumber=1,
                Action="*",
                Principal="*",
                StatementId=f"s-{short_uid()}",
            )
        snapshot.match("layer_permission_action_invalid", e.value.response)

        # duplicate statement Id (s1)
        with pytest.raises(aws_client.lambda_.exceptions.ResourceConflictException) as e:
            aws_client.lambda_.add_layer_version_permission(
                LayerName=layer_name,
                VersionNumber=1,
                Action="lambda:GetLayerVersion",
                Principal="*",
                StatementId="s1",
            )
        snapshot.match("layer_permission_duplicate_statement", e.value.response)

        # wrong revision id
        with pytest.raises(aws_client.lambda_.exceptions.PreconditionFailedException) as e:
            aws_client.lambda_.add_layer_version_permission(
                LayerName=layer_name,
                VersionNumber=1,
                Action="lambda:GetLayerVersion",
                Principal="*",
                StatementId="s2",
                RevisionId="wrong",
            )
        snapshot.match("layer_permission_wrong_revision", e.value.response)

        # layer does not exist
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.add_layer_version_permission(
                LayerName=f"{layer_name}-doesnotexist",
                VersionNumber=1,
                Action="lambda:GetLayerVersion",
                Principal="*",
                StatementId=f"s-{short_uid()}",
            )
        snapshot.match("layer_permission_layername_doesnotexist_add", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.get_layer_version_policy(
                LayerName=f"{layer_name}-doesnotexist", VersionNumber=1
            )
        snapshot.match("layer_permission_layername_doesnotexist_get", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.remove_layer_version_permission(
                LayerName=f"{layer_name}-doesnotexist", VersionNumber=1, StatementId="s1"
            )
        snapshot.match("layer_permission_layername_doesnotexist_remove", e.value.response)

        # layer with given version does not exist
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.add_layer_version_permission(
                LayerName=layer_name,
                VersionNumber=2,
                Action="lambda:GetLayerVersion",
                Principal="*",
                StatementId=f"s-{short_uid()}",
            )
        snapshot.match("layer_permission_layerversion_doesnotexist_add", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.get_layer_version_policy(LayerName=layer_name, VersionNumber=2)
        snapshot.match("layer_permission_layerversion_doesnotexist_get", e.value.response)

        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.remove_layer_version_permission(
                LayerName=layer_name, VersionNumber=2, StatementId="s1"
            )
        snapshot.match("layer_permission_layerversion_doesnotexist_remove", e.value.response)

        # statement id does not exist for given layer version
        with pytest.raises(aws_client.lambda_.exceptions.ResourceNotFoundException) as e:
            aws_client.lambda_.remove_layer_version_permission(
                LayerName=layer_name, VersionNumber=1, StatementId="doesnotexist"
            )
        snapshot.match("layer_permission_statementid_doesnotexist_remove", e.value.response)

        # wrong revision id
        with pytest.raises(aws_client.lambda_.exceptions.PreconditionFailedException) as e:
            aws_client.lambda_.remove_layer_version_permission(
                LayerName=layer_name, VersionNumber=1, StatementId="s1", RevisionId="wrong"
            )
        snapshot.match("layer_permission_wrong_revision_remove", e.value.response)

    @markers.aws.validated
    def test_layer_policy_lifecycle(
        self, create_lambda_function, snapshot, dummylayer, cleanups, aws_client
    ):
        """
        Simple lifecycle tests for lambda layer policies

        TODO: OrganizationId
        """
        layer_name = f"testlayer-{short_uid()}"

        publish_result = aws_client.lambda_.publish_layer_version(
            LayerName=layer_name,
            CompatibleRuntimes=[Runtime.python3_9],
            Content={"ZipFile": dummylayer},
            CompatibleArchitectures=[Architecture.x86_64],
        )
        cleanups.append(
            lambda: aws_client.lambda_.delete_layer_version(
                LayerName=layer_name, VersionNumber=publish_result["Version"]
            )
        )

        snapshot.match("publish_result", publish_result)

        add_policy_s1 = aws_client.lambda_.add_layer_version_permission(
            LayerName=layer_name,
            VersionNumber=1,
            StatementId="s1",
            Action="lambda:GetLayerVersion",
            Principal="*",
        )
        snapshot.match("add_policy_s1", add_policy_s1)

        get_layer_version_policy = aws_client.lambda_.get_layer_version_policy(
            LayerName=layer_name, VersionNumber=1
        )
        snapshot.match("get_layer_version_policy", get_layer_version_policy)

        add_policy_s2 = aws_client.lambda_.add_layer_version_permission(
            LayerName=layer_name,
            VersionNumber=1,
            StatementId="s2",
            Action="lambda:GetLayerVersion",
            Principal="*",
            RevisionId=get_layer_version_policy["RevisionId"],
        )
        snapshot.match("add_policy_s2", add_policy_s2)

        get_layer_version_policy_postadd2 = aws_client.lambda_.get_layer_version_policy(
            LayerName=layer_name, VersionNumber=1
        )
        snapshot.match("get_layer_version_policy_postadd2", get_layer_version_policy_postadd2)

        remove_s2 = aws_client.lambda_.remove_layer_version_permission(
            LayerName=layer_name,
            VersionNumber=1,
            StatementId="s2",
            RevisionId=get_layer_version_policy_postadd2["RevisionId"],
        )
        snapshot.match("remove_s2", remove_s2)

        get_layer_version_policy_postdeletes2 = aws_client.lambda_.get_layer_version_policy(
            LayerName=layer_name, VersionNumber=1
        )
        snapshot.match(
            "get_layer_version_policy_postdeletes2", get_layer_version_policy_postdeletes2
        )


class TestLambdaSnapStart:
    @markers.aws.validated
    @pytest.mark.parametrize("runtime", SNAP_START_SUPPORTED_RUNTIMES)
    def test_snapstart_lifecycle(self, create_lambda_function, snapshot, aws_client, runtime):
        """Test the API of the SnapStart feature. The optimization behavior is not supported in LocalStack.
        Slow (~1-2min) against AWS.
        """
        function_name = f"fn-{short_uid()}"
        java_jar_with_lib = load_file(TEST_LAMBDA_JAVA_WITH_LIB, mode="rb")
        create_response = create_lambda_function(
            func_name=function_name,
            zip_file=java_jar_with_lib,
            runtime=runtime,
            handler="cloud.localstack.sample.LambdaHandlerWithLib",
            SnapStart={"ApplyOn": "PublishedVersions"},
        )
        snapshot.match("create_function_response", create_response)
        aws_client.lambda_.get_waiter("function_active_v2").wait(FunctionName=function_name)

        publish_response = aws_client.lambda_.publish_version(
            FunctionName=function_name, Description="version1"
        )
        version_1 = publish_response["Version"]
        aws_client.lambda_.get_waiter("published_version_active").wait(
            FunctionName=function_name, Qualifier=version_1
        )

        get_function_response = aws_client.lambda_.get_function(FunctionName=function_name)
        snapshot.match("get_function_response_latest", get_function_response)

        get_function_response = aws_client.lambda_.get_function(
            FunctionName=f"{function_name}:{version_1}"
        )
        snapshot.match("get_function_response_version_1", get_function_response)

    @markers.aws.validated
    @pytest.mark.parametrize("runtime", [Runtime.java11, Runtime.java17])
    def test_snapstart_update_function_configuration(
        self, create_lambda_function, snapshot, aws_client, runtime
    ):
        """Test enabling SnapStart when updating a function."""
        function_name = f"fn-{short_uid()}"
        java_jar_with_lib = load_file(TEST_LAMBDA_JAVA_WITH_LIB, mode="rb")
        create_response = create_lambda_function(
            func_name=function_name,
            zip_file=java_jar_with_lib,
            runtime=runtime,
            handler="cloud.localstack.sample.LambdaHandlerWithLib",
        )
        snapshot.match("create_function_response", create_response)
        aws_client.lambda_.get_waiter("function_active_v2").wait(FunctionName=function_name)

        update_function_response = aws_client.lambda_.update_function_configuration(
            FunctionName=function_name,
            SnapStart={"ApplyOn": "PublishedVersions"},
        )
        snapshot.match("update_function_response", update_function_response)

    @markers.aws.validated
    def test_snapstart_exceptions(self, lambda_su_role, snapshot, aws_client):
        function_name = f"invalid-function-{short_uid()}"
        zip_file_bytes = create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True)
        # Test unsupported runtime
        # Only supports java11 (2023-02-15): https://docs.aws.amazon.com/lambda/latest/dg/snapstart.html
        with pytest.raises(ClientError) as e:
            aws_client.lambda_.create_function(
                FunctionName=function_name,
                Handler="index.handler",
                Code={"ZipFile": zip_file_bytes},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime=Runtime.python3_9,
                SnapStart={"ApplyOn": "PublishedVersions"},
            )
        snapshot.match("create_function_unsupported_snapstart_runtime", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.lambda_.create_function(
                FunctionName=function_name,
                Handler="cloud.localstack.sample.LambdaHandlerWithLib",
                Code={"ZipFile": zip_file_bytes},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime=Runtime.java11,
                SnapStart={"ApplyOn": "invalidOption"},
            )
        snapshot.match("create_function_invalid_snapstart_apply", e.value.response)

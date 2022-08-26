import json
import logging
import os
from io import BytesIO
from typing import Dict, TypeVar

import pytest
from botocore.response import StreamingBody

from localstack.aws.api.lambda_ import Runtime
from localstack.services.awslambda.lambda_api import (
    LAMBDA_DEFAULT_HANDLER,
)
from localstack.testing.aws.lambda_utils import (
    concurrency_update_done,
    get_invoke_init_type,
    update_done, )
from localstack.utils import testutil
from localstack.utils.common import (
    load_file,
    retry,
    safe_requests,
    short_uid,
    to_bytes,
    to_str,
)
from localstack.utils.generic.wait_utils import wait_until
from localstack.utils.testutil import (
    create_lambda_archive,
)

from .functions import lambda_integration

LOG = logging.getLogger(__name__)


# TODO: find a better way to manage these handler files
THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON = os.path.join(THIS_FOLDER, "functions/lambda_integration.py")
TEST_LAMBDA_PYTHON_ECHO = os.path.join(THIS_FOLDER, "functions/lambda_echo.py")
TEST_LAMBDA_PYTHON_VERSION = os.path.join(THIS_FOLDER, "functions/lambda_python_version.py")
TEST_LAMBDA_PYTHON_UNHANDLED_ERROR = os.path.join(
    THIS_FOLDER, "functions/lambda_unhandled_error.py"
)
TEST_LAMBDA_AWS_PROXY = os.path.join(THIS_FOLDER, "functions/lambda_aws_proxy.py")
TEST_LAMBDA_PYTHON3 = os.path.join(THIS_FOLDER, "functions/lambda_python3.py")
TEST_LAMBDA_INTEGRATION_NODEJS = os.path.join(THIS_FOLDER, "functions/lambda_integration.js")
TEST_LAMBDA_NODEJS = os.path.join(THIS_FOLDER, "functions/lambda_handler.js")
TEST_LAMBDA_NODEJS_ES6 = os.path.join(THIS_FOLDER, "functions/lambda_handler_es6.mjs")
TEST_LAMBDA_HELLO_WORLD = os.path.join(THIS_FOLDER, "functions/lambda_hello_world.py")
TEST_LAMBDA_NODEJS_APIGW_INTEGRATION = os.path.join(THIS_FOLDER, "functions/apigw_integration.js")
TEST_LAMBDA_NODEJS_APIGW_502 = os.path.join(THIS_FOLDER, "functions/apigw_502.js")
TEST_LAMBDA_GOLANG_ZIP = os.path.join(THIS_FOLDER, "functions/golang/handler.zip")
TEST_LAMBDA_RUBY = os.path.join(THIS_FOLDER, "functions/lambda_integration.rb")
TEST_LAMBDA_DOTNETCORE2 = os.path.join(THIS_FOLDER, "functions/dotnetcore2/dotnetcore2.zip")
TEST_LAMBDA_DOTNETCORE31 = os.path.join(THIS_FOLDER, "functions/dotnetcore31/dotnetcore31.zip")
TEST_LAMBDA_DOTNET6 = os.path.join(THIS_FOLDER, "functions/dotnet6/dotnet6.zip")
TEST_LAMBDA_CUSTOM_RUNTIME = os.path.join(THIS_FOLDER, "functions/custom-runtime")
TEST_LAMBDA_HTTP_RUST = os.path.join(THIS_FOLDER, "functions/rust-lambda/function.zip")
TEST_LAMBDA_JAVA_WITH_LIB = os.path.join(
    THIS_FOLDER, "functions/java/lambda_echo/lambda-function-with-lib-0.0.1.jar"
)
TEST_LAMBDA_JAVA_MULTIPLE_HANDLERS = os.path.join(
    THIS_FOLDER,
    "functions",
    "java",
    "lambda_multiple_handlers",
    "build",
    "distributions",
    "lambda-function-with-multiple-handlers.zip",
)
TEST_LAMBDA_ENV = os.path.join(THIS_FOLDER, "functions/lambda_environment.py")

TEST_LAMBDA_SEND_MESSAGE_FILE = os.path.join(THIS_FOLDER, "functions/lambda_send_message.py")
TEST_LAMBDA_PUT_ITEM_FILE = os.path.join(THIS_FOLDER, "functions/lambda_put_item.py")
TEST_LAMBDA_START_EXECUTION_FILE = os.path.join(THIS_FOLDER, "functions/lambda_start_execution.py")
TEST_LAMBDA_URL = os.path.join(THIS_FOLDER, "functions/lambda_url.js")
TEST_LAMBDA_CACHE_NODEJS = os.path.join(THIS_FOLDER, "functions", "lambda_cache.js")
TEST_LAMBDA_CACHE_PYTHON = os.path.join(THIS_FOLDER, "functions", "lambda_cache.py")
TEST_LAMBDA_TIMEOUT_PYTHON = os.path.join(THIS_FOLDER, "functions", "lambda_timeout.py")
TEST_LAMBDA_INTROSPECT_PYTHON = os.path.join(THIS_FOLDER, "functions", "lambda_introspect.py")

TEST_GOLANG_LAMBDA_URL_TEMPLATE = "https://github.com/localstack/awslamba-go-runtime/releases/download/v{version}/example-handler-{os}-{arch}.tar.gz"


TEST_LAMBDA_LIBS = [
    "requests",
    "psutil",
    "urllib3",
    "chardet",
    "certifi",
    "idna",
    "pip",
    "dns",
]

T = TypeVar("T")

def read_streams(payload: T) -> T:
    new_payload = {}
    for k, v in payload.items():
        if isinstance(v, Dict):
            new_payload[k] = read_streams(v)
        elif isinstance(v, StreamingBody):
            new_payload[k] = to_str(v.read())
        else:
            new_payload[k] = v
    return new_payload


class TestLambdaBaseFeatures:


    @pytest.mark.skip_snapshot_verify(paths=["$..LogResult"])
    def test_large_payloads(self, caplog, lambda_client, create_lambda_function, snapshot):
        """Testing large payloads sent to lambda functions (~5MB)"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
        # Set the loglevel to INFO for this test to avoid breaking a CI environment (due to excessive log outputs)
        caplog.set_level(logging.INFO)

        function_name = f"large_payload-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        payload = {"test": "test123456" * 100 * 1000 * 5}  # 5MB payload
        payload_bytes = to_bytes(json.dumps(payload))
        result = lambda_client.invoke(FunctionName=function_name, Payload=payload_bytes)
        result = read_streams(result)
        snapshot.match("invocation_response", result)
        assert 200 == result["ResponseMetadata"]["HTTPStatusCode"]
        result_data = result["Payload"]
        result_data = json.loads(to_str(result_data))
        assert payload == result_data

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify  # skipped - the diff is too big
    @pytest.mark.skipif(
        os.environ.get("TEST_TARGET") != "AWS_CLOUD",
        reason="Lambda function state pending for small lambdas not supported on localstack",
    )
    def test_function_state(self, lambda_client, lambda_su_role, snapshot):
        """Tests if a lambda starts in state "Pending" but moves to "Active" at some point"""
        snapshot.add_transformer(snapshot.transform.lambda_api())
        # necessary due to changing zip timestamps. We might need a reproducible archive method for this
        snapshot.add_transformer(snapshot.transform.key_value("CodeSha256"))
        function_name = f"test-function-{short_uid()}"
        zip_file = create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True)

        try:

            def create_function():
                return lambda_client.create_function(
                    FunctionName=function_name,
                    Runtime="python3.9",
                    Handler="handler.handler",
                    Role=lambda_su_role,
                    Code={"ZipFile": zip_file},
                )

            response = retry(create_function, sleep=3, retries=5)

            snapshot.match("create-fn-response", response)
            assert response["State"] == "Pending"

            # lambda has to get active at some point
            def _check_lambda_state():
                response = lambda_client.get_function(FunctionName=function_name)
                assert response["Configuration"]["State"] == "Active"
                return response

            response = retry(_check_lambda_state)
            snapshot.match("get-fn-response", response)
        finally:
            try:
                lambda_client.delete_function(FunctionName=function_name)
            except Exception:
                LOG.debug("Unable to delete function %s", function_name)





class TestLambdaBehavior:
    @pytest.mark.parametrize(
        ["lambda_fn", "lambda_runtime"],
        [
            (
                TEST_LAMBDA_CACHE_NODEJS,
                Runtime.nodejs12_x,
            ),  # TODO: can we do some kind of nested parametrize here?
            (TEST_LAMBDA_CACHE_PYTHON, Runtime.python3_8),
        ],
        ids=["nodejs", "python"],
    )
    @pytest.mark.xfail(
        os.environ.get("TEST_TARGET") != "AWS_CLOUD",
        reason="lambda caching not supported currently",
    )  # TODO: should be removed after the lambda rework
    def test_lambda_cache_local(
        self, lambda_client, create_lambda_function, lambda_fn, lambda_runtime
    ):
        """tests the local context reuse of packages in AWS lambda"""

        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=lambda_fn,
            runtime=lambda_runtime,
            client=lambda_client,
        )

        result = lambda_client.invoke(FunctionName=func_name)
        result_data = result["Payload"].read()
        assert result["StatusCode"] == 200
        assert json.loads(result_data)["counter"] == 0

        result = lambda_client.invoke(FunctionName=func_name)
        result_data = result["Payload"].read()
        assert result["StatusCode"] == 200
        assert json.loads(result_data)["counter"] == 1

    @pytest.mark.parametrize(
        ["lambda_fn", "lambda_runtime"],
        [
            (TEST_LAMBDA_TIMEOUT_PYTHON, Runtime.python3_8),
        ],
        ids=["python"],
    )
    @pytest.mark.xfail(
        os.environ.get("TEST_TARGET") != "AWS_CLOUD",
        reason="lambda timeouts not supported currently",
    )  # TODO: should be removed after the lambda rework
    def test_lambda_timeout_logs(
        self,
        lambda_client,
        create_lambda_function,
        lambda_fn,
        lambda_runtime,
        logs_client,
        snapshot,
    ):
        """tests the local context reuse of packages in AWS lambda"""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        func_name = f"test_lambda_{short_uid()}"
        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=lambda_fn,
            runtime=lambda_runtime,
            client=lambda_client,
            timeout=1,
        )
        snapshot.match("create-result", create_result)

        result = lambda_client.invoke(FunctionName=func_name, Payload=json.dumps({"wait": 2}))
        snapshot.match("invoke-result", result)
        assert result["StatusCode"] == 200

        log_group_name = f"/aws/lambda/{func_name}"
        ls_result = logs_client.describe_log_streams(logGroupName=log_group_name)
        log_stream_name = ls_result["logStreams"][0]["logStreamName"]

        def assert_events():
            log_events = logs_client.get_log_events(
                logGroupName=log_group_name, logStreamName=log_stream_name
            )["events"]

            assert any(["starting wait" in e["message"] for e in log_events])
            assert not any(["done waiting" in e["message"] for e in log_events])

        retry(assert_events, retries=15)

    @pytest.mark.parametrize(
        ["lambda_fn", "lambda_runtime"],
        [
            (TEST_LAMBDA_TIMEOUT_PYTHON, Runtime.python3_8),
        ],
        ids=["python"],
    )
    @pytest.mark.skip_snapshot_verify
    def test_lambda_no_timeout_logs(
        self,
        lambda_client,
        create_lambda_function,
        lambda_fn,
        lambda_runtime,
        logs_client,
        snapshot,
    ):
        """tests the local context reuse of packages in AWS lambda"""
        snapshot.add_transformer(snapshot.transform.lambda_api())

        func_name = f"test_lambda_{short_uid()}"
        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=lambda_fn,
            runtime=lambda_runtime,
            client=lambda_client,
            timeout=2,
        )
        snapshot.match("create-result", create_result)

        result = lambda_client.invoke(FunctionName=func_name, Payload=json.dumps({"wait": 1}))
        snapshot.match("invoke-result", result)
        assert result["StatusCode"] == 200
        log_group_name = f"/aws/lambda/{func_name}"

        def _log_stream_available():
            result = logs_client.describe_log_streams(logGroupName=log_group_name)["logStreams"]
            return len(result) > 0

        wait_until(_log_stream_available, strategy="linear")

        ls_result = logs_client.describe_log_streams(logGroupName=log_group_name)
        log_stream_name = ls_result["logStreams"][0]["logStreamName"]

        def _assert_log_output():
            log_events = logs_client.get_log_events(
                logGroupName=log_group_name, logStreamName=log_stream_name
            )["events"]
            return any(["starting wait" in e["message"] for e in log_events]) and any(
                ["done waiting" in e["message"] for e in log_events]
            )

        wait_until(_assert_log_output, strategy="linear")

    @pytest.mark.skip(reason="very slow (only execute when needed)")
    def test_lambda_provisioned_concurrency_moves_with_alias(
        self, lambda_client, logs_client, create_lambda_function, snapshot
    ):
        """
        create fn ⇒ publish version ⇒ create alias for version ⇒ put concurrency on alias
        ⇒ new version with change ⇒ change alias to new version ⇒ concurrency moves with alias? same behavior for calls to alias/version?
        """
        snapshot.add_transformer(snapshot.transform.lambda_api())

        func_name = f"test_lambda_{short_uid()}"
        alias_name = f"test_alias_{short_uid()}"

        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_8,
            client=lambda_client,
            timeout=2,
        )
        snapshot.match("create-result", create_result)

        fn = lambda_client.get_function_configuration(FunctionName=func_name, Qualifier="$LATEST")
        snapshot.match("get-function-configuration", fn)
        assert fn["State"] == "Active"

        first_ver = lambda_client.publish_version(
            FunctionName=func_name, RevisionId=fn["RevisionId"], Description="my-first-version"
        )
        snapshot.match("publish_version_1", first_ver)
        assert first_ver["State"] == "Active"
        assert fn["RevisionId"] != first_ver["RevisionId"]

        get_function_configuration = lambda_client.get_function_configuration(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )
        snapshot.match("get_function_configuration_version_1", first_ver)
        assert get_function_configuration["RevisionId"] == first_ver["RevisionId"]

        # There's no ProvisionedConcurrencyConfiguration yet
        assert get_invoke_init_type(lambda_client, func_name, first_ver["Version"]) == "on-demand"

        # Create Alias and add ProvisionedConcurrencyConfiguration to it
        alias = lambda_client.create_alias(
            FunctionName=func_name, FunctionVersion=first_ver["Version"], Name=alias_name
        )
        snapshot.match("create_alias", alias)
        assert alias["FunctionVersion"] == first_ver["Version"]
        assert alias["RevisionId"] != first_ver["RevisionId"]
        get_function_result = lambda_client.get_function(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )
        versioned_revision_id_before = get_function_result["Configuration"]["RevisionId"]
        snapshot.match("get_function_before_provisioned", get_function_result)
        lambda_client.put_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=alias_name, ProvisionedConcurrentExecutions=1
        )
        assert wait_until(concurrency_update_done(lambda_client, func_name, alias_name))
        get_function_result = lambda_client.get_function(
            FunctionName=func_name, Qualifier=alias_name
        )
        snapshot.match("get_function_after_provisioned", get_function_result)
        versioned_revision_id_after = get_function_result["Configuration"]["RevisionId"]
        assert versioned_revision_id_before != versioned_revision_id_after

        # Alias AND Version now both use provisioned-concurrency (!)
        assert (
            get_invoke_init_type(lambda_client, func_name, first_ver["Version"])
            == "provisioned-concurrency"
        )
        assert (
            get_invoke_init_type(lambda_client, func_name, alias_name) == "provisioned-concurrency"
        )

        # Update lambda configuration and publish new version
        lambda_client.update_function_configuration(FunctionName=func_name, Timeout=10)
        assert wait_until(update_done(lambda_client, func_name))
        lambda_conf = lambda_client.get_function_configuration(FunctionName=func_name)
        snapshot.match("get_function_after_update", lambda_conf)

        # Move existing alias to the new version
        new_version = lambda_client.publish_version(
            FunctionName=func_name, RevisionId=lambda_conf["RevisionId"]
        )
        snapshot.match("publish_version_2", new_version)
        new_alias = lambda_client.update_alias(
            FunctionName=func_name, FunctionVersion=new_version["Version"], Name=alias_name
        )
        snapshot.match("update_alias", new_alias)
        assert new_alias["RevisionId"] != new_version["RevisionId"]

        # lambda should now be provisioning new "hot" execution environments for this new alias->version pointer
        # the old one should be de-provisioned
        get_provisioned_config_result = lambda_client.get_provisioned_concurrency_config(
            FunctionName=func_name, Qualifier=alias_name
        )
        snapshot.match("get_provisioned_config_after_alias_move", get_provisioned_config_result)
        assert wait_until(
            concurrency_update_done(lambda_client, func_name, alias_name),
            strategy="linear",
            wait=30,
            max_retries=20,
            _max_wait=600,
        )  # this is SLOW (~6-8 min)

        # concurrency should still only work for the alias now
        # NOTE: the old version has been de-provisioned and will run 'on-demand' now!
        assert get_invoke_init_type(lambda_client, func_name, first_ver["Version"]) == "on-demand"
        assert (
            get_invoke_init_type(lambda_client, func_name, new_version["Version"])
            == "provisioned-concurrency"
        )
        assert (
            get_invoke_init_type(lambda_client, func_name, alias_name) == "provisioned-concurrency"
        )

        # ProvisionedConcurrencyConfig should only be "registered" to the alias, not the referenced version
        with pytest.raises(Exception) as e:
            lambda_client.get_provisioned_concurrency_config(
                FunctionName=func_name, Qualifier=new_version["Version"]
            )
        e.match("ProvisionedConcurrencyConfigNotFoundException")

    @pytest.mark.skip(reason="very slow (only execute when needed)")
    def test_lambda_provisioned_concurrency_doesnt_apply_to_latest(
        self, lambda_client, logs_client, create_lambda_function
    ):
        """create fn ⇒ publish version ⇒ provisioned concurrency @version ⇒ test if it applies to call to $LATEST"""

        func_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=Runtime.python3_8,
            client=lambda_client,
            timeout=2,
        )

        fn = lambda_client.get_function_configuration(FunctionName=func_name, Qualifier="$LATEST")
        assert fn["State"] == "Active"

        first_ver = lambda_client.publish_version(
            FunctionName=func_name, RevisionId=fn["RevisionId"], Description="my-first-version"
        )
        assert first_ver["State"] == "Active"
        assert fn["RevisionId"] != first_ver["RevisionId"]
        assert (
            lambda_client.get_function_configuration(
                FunctionName=func_name, Qualifier=first_ver["Version"]
            )["RevisionId"]
            == first_ver["RevisionId"]
        )

        # Normal published version without ProvisionedConcurrencyConfiguration
        assert get_invoke_init_type(lambda_client, func_name, first_ver["Version"]) == "on-demand"

        # Create ProvisionedConcurrencyConfiguration for this Version
        versioned_revision_id_before = lambda_client.get_function(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )["Configuration"]["RevisionId"]
        lambda_client.put_provisioned_concurrency_config(
            FunctionName=func_name,
            Qualifier=first_ver["Version"],
            ProvisionedConcurrentExecutions=1,
        )
        assert wait_until(concurrency_update_done(lambda_client, func_name, first_ver["Version"]))
        versioned_revision_id_after = lambda_client.get_function(
            FunctionName=func_name, Qualifier=first_ver["Version"]
        )["Configuration"]["RevisionId"]
        assert versioned_revision_id_before != versioned_revision_id_after
        assert (
            get_invoke_init_type(lambda_client, func_name, first_ver["Version"])
            == "provisioned-concurrency"
        )

        # $LATEST does *NOT* use provisioned concurrency
        assert get_invoke_init_type(lambda_client, func_name, "$LATEST") == "on-demand"
        # TODO: why is this flaky?
        # assert lambda_client.get_function(FunctionName=func_name, Qualifier='$LATEST')['Configuration']['RevisionId'] == lambda_client.get_function(FunctionName=func_name, Qualifier=first_ver['Version'])['Configuration']['RevisionId']


# features
class TestLambdaURL:
    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..context",
            "$..event.headers.x-forwarded-proto",
            "$..event.headers.x-forwarded-for",
            "$..event.headers.x-forwarded-port",
            "$..event.headers.x-amzn-lambda-forwarded-client-ip",
            "$..event.headers.x-amzn-lambda-forwarded-host",
            "$..event.headers.x-amzn-lambda-proxy-auth",
            "$..event.headers.x-amzn-lambda-proxying-cell",
            "$..event.headers.x-amzn-trace-id",
        ]
    )
    def test_lambda_url_invocation(self, lambda_client, create_lambda_function, snapshot):
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("requestId", "uuid", reference_replacement=False),
                snapshot.transform.key_value(
                    "FunctionUrl", "lambda-url", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.requestContext.http.sourceIp",
                    "ip-address",
                    reference_replacement=False,
                ),
                snapshot.transform.jsonpath(
                    "$..event.headers.x-forwarded-for", "ip-address", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.headers.x-amzn-lambda-forwarded-client-ip",
                    "ip-address",
                    reference_replacement=False,
                ),
                snapshot.transform.jsonpath(
                    "$..event.headers.x-amzn-lambda-forwarded-host",
                    "lambda-url",
                    reference_replacement=False,
                ),
                snapshot.transform.jsonpath(
                    "$..event.headers.host", "lambda-url", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.requestContext.apiId", "api-id", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.requestContext.domainName", "lambda-url", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.requestContext.domainPrefix", "api-id", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.requestContext.time", "readable-date", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..event.requestContext.timeEpoch",
                    "epoch-milliseconds",
                    reference_replacement=False,
                ),
            ]
        )

        function_name = f"test-function-{short_uid()}"

        create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_URL, get_content=True),
            runtime=Runtime.nodejs14X,
            handler="lambda_url.handler",
        )

        url_config = lambda_client.create_function_url_config(
            FunctionName=function_name,
            AuthType="NONE",
        )

        snapshot.match("create_lambda_url_config", url_config)

        permissions_response = lambda_client.add_permission(
            FunctionName=function_name,
            StatementId="urlPermission",
            Action="lambda:InvokeFunctionUrl",
            Principal="*",
            FunctionUrlAuthType="NONE",
        )

        snapshot.match("add_permission", permissions_response)

        url = url_config["FunctionUrl"]
        url += "custom_path/extend?test_param=test_value"

        result = safe_requests.post(
            url, data=b"{'key':'value'}", headers={"User-Agent": "python-requests/testing"}
        )

        assert result.status_code == 200
        snapshot.match("lambda_url_invocation", json.loads(result.content))

        result = safe_requests.post(url, data="text", headers={"Content-Type": "text/plain"})
        event = json.loads(result.content)["event"]
        assert event["body"] == "text"
        assert event["isBase64Encoded"] is False

        result = safe_requests.post(url)
        event = json.loads(result.content)["event"]
        assert "Body" not in event
        assert event["isBase64Encoded"] is False


FUNCTION_MAX_UNZIPPED_SIZE = 262144000

def generate_sized_python_str(filepath: str, size: int) -> str:
    """Generate a text of the specified size by appending #s at the end of the file"""
    with open(filepath, "r") as f:
        py_str = f.read()
    py_str += "#" * (size - len(py_str))
    return py_str


@pytest.mark.aws_validated
class TestLambdaSizeLimits:
    def test_oversized_lambda(self, lambda_client, s3_client, s3_bucket, lambda_su_role, snapshot):
        snapshot.add_transformer(snapshot.transform.lambda_api())

        function_name = f"test_lambda_{short_uid()}"
        bucket_key = "test_lambda.zip"
        code_str = generate_sized_python_str(FUNCTION_MAX_UNZIPPED_SIZE)

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            code_str, get_content=True, runtime=Runtime.python3_7
        )
        s3_client.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.create_function(
                FunctionName=function_name,
                Runtime=Runtime.python3_7,
                Handler=LAMBDA_DEFAULT_HANDLER,
                Role=lambda_su_role,
                Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
                Timeout=10,
            )
        snapshot.match("invalid_param_exc", e.value.response)


    # TODO: snapshot
    def test_large_lambda(self, lambda_client, s3_client, s3_bucket, lambda_su_role, cleanups):
        function_name = f"test_lambda_{short_uid()}"
        cleanups.append(lambda: lambda_client.delete_function(FunctionName=function_name))
        bucket_key = "test_lambda.zip"
        code_str = generate_sized_python_str(FUNCTION_MAX_UNZIPPED_SIZE - 1000)

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            code_str, get_content=True, runtime=Runtime.python3_7
        )
        s3_client.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        result = lambda_client.create_function(
            FunctionName=function_name,
            Runtime=Runtime.python3_7,
            Handler=LAMBDA_DEFAULT_HANDLER,
            Role=lambda_su_role,
            Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
            Timeout=10,
        )

        function_arn = result["FunctionArn"]
        assert testutil.response_arn_matches_partition(lambda_client, function_arn)


LOG = logging.Logger(__name__)


# TODO: move this to fixtures / reconcile with other fixture usage
@pytest.fixture
def create_lambda_function_aws(
    lambda_client,
):
    lambda_arns = []

    def _create_lambda_function(**kwargs):
        def _create_function():
            resp = lambda_client.create_function(**kwargs)
            lambda_arns.append(resp["FunctionArn"])

            def _is_not_pending():
                try:
                    result = (
                        lambda_client.get_function(FunctionName=resp["FunctionName"])[
                            "Configuration"
                        ]["State"]
                        != "Pending"
                    )
                    return result
                except Exception as e:
                    LOG.error(e)
                    raise

            wait_until(_is_not_pending)
            return resp

        # @AWS, takes about 10s until the role/policy is "active", until then it will fail
        # localstack should normally not require the retries and will just continue here
        return retry(_create_function, retries=3, sleep=4)

    yield _create_lambda_function

    for arn in lambda_arns:
        try:
            lambda_client.delete_function(FunctionName=arn)
        except Exception:
            LOG.debug(f"Unable to delete function {arn=} in cleanup")


@pytest.mark.skip_snapshot_verify
@pytest.mark.aws_validated
class TestLambdaFeatures:
    def test_basic_invoke(
        self, lambda_client, create_lambda_function_aws, lambda_su_role, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.lambda_api())

        # predefined names
        fn_name = f"ls-fn-{short_uid()}"
        fn_name_2 = f"ls-fn-{short_uid()}"

        # infra setup (& validations)
        with open(os.path.join(os.path.dirname(__file__), "functions/echo.zip"), "rb") as f:
            response = create_lambda_function_aws(
                FunctionName=fn_name,
                Handler="index.handler",
                Code={"ZipFile": f.read()},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime="python3.9",
            )
            snapshot.match("lambda_create_fn", response)

        with open(os.path.join(os.path.dirname(__file__), "functions/echo.zip"), "rb") as f:
            response = create_lambda_function_aws(
                FunctionName=fn_name_2,
                Handler="index.handler",
                Code={"ZipFile": f.read()},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime="python3.9",
            )
            snapshot.match("lambda_create_fn_2", response)

        get_fn_result = lambda_client.get_function(FunctionName=fn_name)

        snapshot.match("lambda_get_fn", get_fn_result)

        get_fn_result_2 = lambda_client.get_function(FunctionName=fn_name_2)
        snapshot.match("lambda_get_fn_2", get_fn_result_2)

        invoke_result = lambda_client.invoke(FunctionName=fn_name, Payload=bytes("{}", "utf-8"))
        snapshot.match("lambda_invoke_result", invoke_result)

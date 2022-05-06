import base64
import json
import logging
import os
import re
import shutil
import time
from io import BytesIO
from typing import Dict, List, Pattern, TypeVar

import pytest
from botocore.exceptions import ClientError
from botocore.response import StreamingBody

from localstack.constants import LAMBDA_TEST_ROLE, TEST_AWS_ACCOUNT_ID
from localstack.services.awslambda import lambda_api
from localstack.services.awslambda.lambda_api import (
    LAMBDA_DEFAULT_HANDLER,
    get_lambda_policy_name,
    use_docker,
)
from localstack.services.awslambda.lambda_utils import (
    LAMBDA_RUNTIME_DOTNET6,
    LAMBDA_RUNTIME_DOTNETCORE31,
    LAMBDA_RUNTIME_GOLANG,
    LAMBDA_RUNTIME_JAVA8,
    LAMBDA_RUNTIME_JAVA8_AL2,
    LAMBDA_RUNTIME_JAVA11,
    LAMBDA_RUNTIME_NODEJS12X,
    LAMBDA_RUNTIME_NODEJS14X,
    LAMBDA_RUNTIME_PROVIDED,
    LAMBDA_RUNTIME_PROVIDED_AL2,
    LAMBDA_RUNTIME_PYTHON36,
    LAMBDA_RUNTIME_PYTHON37,
    LAMBDA_RUNTIME_PYTHON38,
    LAMBDA_RUNTIME_PYTHON39,
    LAMBDA_RUNTIME_RUBY27,
)
from localstack.services.install import (
    GO_RUNTIME_VERSION,
    INSTALL_PATH_LOCALSTACK_FAT_JAR,
    TEST_LAMBDA_JAVA,
    download_and_extract,
)
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    cp_r,
    get_arch,
    get_os,
    load_file,
    mkdir,
    new_tmp_dir,
    retry,
    run_safe,
    save_file,
    short_uid,
    to_bytes,
    to_str,
    unzip,
)
from localstack.utils.generic.wait_utils import wait_until
from localstack.utils.sync import poll_condition
from localstack.utils.testutil import (
    check_expected_lambda_log_events_length,
    create_lambda_archive,
    get_lambda_log_events,
)

from ..fixtures import only_localstack
from .functions import lambda_integration
from .lambda_test_util import concurrency_update_done, get_invoke_init_type, update_done

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON = os.path.join(THIS_FOLDER, "functions/lambda_integration.py")
TEST_LAMBDA_PYTHON_ECHO = os.path.join(THIS_FOLDER, "functions/lambda_echo.py")
TEST_LAMBDA_PYTHON_VERSION = os.path.join(THIS_FOLDER, "functions/lambda_python_version.py")
TEST_LAMBDA_PYTHON_UNHANDLED_ERROR = os.path.join(
    THIS_FOLDER, "functions/lambda_unhandled_error.py"
)
TEST_LAMBDA_PYTHON3 = os.path.join(THIS_FOLDER, "functions/lambda_python3.py")
TEST_LAMBDA_INTEGRATION_NODEJS = os.path.join(THIS_FOLDER, "functions/lambda_integration.js")
TEST_LAMBDA_NODEJS = os.path.join(THIS_FOLDER, "functions/lambda_handler.js")
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

TEST_LAMBDA_FUNCTION_PREFIX = "lambda-function"

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

PYTHON_TEST_RUNTIMES = (
    [
        LAMBDA_RUNTIME_PYTHON36,
        LAMBDA_RUNTIME_PYTHON37,
        LAMBDA_RUNTIME_PYTHON38,
        LAMBDA_RUNTIME_PYTHON39,
    ]
    if use_docker()
    else [LAMBDA_RUNTIME_PYTHON38]
)
NODE_TEST_RUNTIMES = (
    [
        LAMBDA_RUNTIME_NODEJS12X,
        LAMBDA_RUNTIME_NODEJS14X,
    ]
    if use_docker()
    else [LAMBDA_RUNTIME_NODEJS14X]
)
JAVA_TEST_RUNTIMES = (
    [
        LAMBDA_RUNTIME_JAVA8,
        LAMBDA_RUNTIME_JAVA8_AL2,
        LAMBDA_RUNTIME_JAVA11,
    ]
    if use_docker()
    else [LAMBDA_RUNTIME_JAVA11]
)


def is_old_provider():
    return (
        os.environ.get("TEST_TARGET") != "AWS_CLOUD"
        and os.environ.get("PROVIDER_OVERRIDE_LAMBDA") != "asf"
    )


PROVIDED_TEST_RUNTIMES = [
    LAMBDA_RUNTIME_PROVIDED,
    # TODO remove skip once we use correct images
    pytest.param(
        LAMBDA_RUNTIME_PROVIDED_AL2,
        marks=pytest.mark.skipif(
            is_old_provider(), reason="curl missing in provided.al2 lambci image"
        ),
    ),
]

# Snapshot patterns
IGNORE_LOGSTREAM_ID: Pattern[str] = re.compile(
    r"\d{4}/\d{2}/\d{2}/\[((\$LATEST)|\d+)\][0-9a-f]{32}"
)

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


@pytest.fixture
def check_lambda_logs(logs_client):
    def _check_logs(func_name: str, expected_lines: List[str] = None):
        if not expected_lines:
            expected_lines = []
        log_events = get_lambda_logs(func_name, logs_client=logs_client)
        log_messages = [e["message"] for e in log_events]
        for line in expected_lines:
            if ".*" in line:
                found = [re.match(line, m, flags=re.DOTALL) for m in log_messages]
                if any(found):
                    continue
            assert line in log_messages

    return _check_logs


def get_lambda_logs(func_name, logs_client=None):
    logs_client = logs_client or aws_stack.create_external_boto_client("logs")
    log_group_name = f"/aws/lambda/{func_name}"
    streams = logs_client.describe_log_streams(logGroupName=log_group_name)["logStreams"]
    streams = sorted(streams, key=lambda x: x["creationTime"], reverse=True)
    log_events = logs_client.get_log_events(
        logGroupName=log_group_name, logStreamName=streams[0]["logStreamName"]
    )["events"]
    return log_events


def configure_snapshot_for_context(snapshot, function_name: str):
    """
    Utility function to configure snapshot to ignore a function name and log stream ids in its body.
    Helpful if invoke calls return the context object, in which they are present
    :param snapshot: Snapshot fixture result
    :param function_name: Function name of the current function
    """
    snapshot.register_replacement(IGNORE_LOGSTREAM_ID, "<log_stream_id>")
    snapshot.register_replacement(re.compile(function_name), "<function_name>")


# API only functions (no lambda execution itself)
class TestLambdaAPI:
    @only_localstack
    def test_create_lambda_function(self, lambda_client):
        """Basic test that creates and deletes a Lambda function"""
        func_name = f"lambda_func-{short_uid()}"
        kms_key_arn = f"arn:{aws_stack.get_partition()}:kms:{aws_stack.get_region()}:{TEST_AWS_ACCOUNT_ID}:key11"
        vpc_config = {
            "SubnetIds": ["subnet-123456789"],
            "SecurityGroupIds": ["sg-123456789"],
        }
        tags = {"env": "testing"}

        kwargs = {
            "FunctionName": func_name,
            "Runtime": LAMBDA_RUNTIME_PYTHON37,
            "Handler": LAMBDA_DEFAULT_HANDLER,
            "Role": LAMBDA_TEST_ROLE,
            "KMSKeyArn": kms_key_arn,
            "Code": {
                "ZipFile": create_lambda_archive(
                    load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True
                )
            },
            "Timeout": 3,
            "VpcConfig": vpc_config,
            "Tags": tags,
            "Environment": {"Variables": {"foo": "bar"}},
        }

        result = lambda_client.create_function(**kwargs)
        function_arn = result["FunctionArn"]
        assert testutil.response_arn_matches_partition(lambda_client, function_arn)

        partial_function_arn = ":".join(function_arn.split(":")[3:])

        # Get function by Name, ARN and partial ARN
        for func_ref in [func_name, function_arn, partial_function_arn]:
            rs = lambda_client.get_function(FunctionName=func_ref)
            assert rs["Configuration"].get("KMSKeyArn", "") == kms_key_arn
            assert rs["Configuration"].get("VpcConfig", {}) == vpc_config
            assert rs["Tags"] == tags

        # clean up
        lambda_client.delete_function(FunctionName=func_name)
        with pytest.raises(Exception) as exc:
            lambda_client.delete_function(FunctionName=func_name)
        assert "ResourceNotFoundException" in str(exc)

    @pytest.mark.snapshot
    def test_add_lambda_permission_aws(
        self, lambda_client, iam_client, create_lambda_function, snapshot
    ):
        """Testing the add_permission call on lambda, by adding a new resource-based policy to a lambda function"""
        function_name = f"lambda_func-{short_uid()}"
        lambda_create_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )
        lambda_arn = lambda_create_response["CreateFunctionResponse"]["FunctionArn"]
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
        assert lambda_arn == json.loads(get_policy_result["Policy"])["Statement"][0]["Resource"]

    # TODO permissions cannot be added to $LATEST
    @pytest.mark.skipif(
        not is_old_provider(), reason="test does not make valid assertions against AWS"
    )
    def test_add_lambda_permission(self, lambda_client, iam_client, create_lambda_function):
        function_name = f"lambda_func-{short_uid()}"
        lambda_create_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )
        lambda_arn = lambda_create_response["CreateFunctionResponse"]["FunctionArn"]
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

        # fetch lambda policy
        policy = lambda_client.get_policy(FunctionName=function_name)["Policy"]
        assert isinstance(policy, str)
        policy = json.loads(to_str(policy))
        assert action == policy["Statement"][0]["Action"]
        assert sid == policy["Statement"][0]["Sid"]
        assert lambda_arn == policy["Statement"][0]["Resource"]
        assert principal == policy["Statement"][0]["Principal"]["Service"]
        assert (
            aws_stack.s3_bucket_arn("test-bucket")
            == policy["Statement"][0]["Condition"]["ArnLike"]["AWS:SourceArn"]
        )

        # fetch IAM policy
        # this is not a valid assertion in general (especially against AWS)
        policies = iam_client.list_policies(Scope="Local", MaxItems=500)["Policies"]
        policy_name = get_lambda_policy_name(function_name)
        matching = [p for p in policies if p["PolicyName"] == policy_name]
        assert len(matching) == 1
        assert ":policy/" in matching[0]["Arn"]

        # remove permission that we just added
        resp = lambda_client.remove_permission(
            FunctionName=function_name,
            StatementId=sid,
            Qualifier="qual1",
            RevisionId="r1",
        )
        assert 200 == resp["ResponseMetadata"]["HTTPStatusCode"]

    def test_remove_multi_permissions(self, lambda_client, create_lambda_function, snapshot):
        """Tests creation and subsequent removal of multiple permissions, including the changes in the policy"""
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
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

        with pytest.raises(ClientError) as e:
            lambda_client.remove_permission(
                FunctionName=function_name,
                StatementId="non-existent",
            )
        assert e.value.response["Error"]["Code"] == "ResourceNotFoundException"

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
        assert policy["Statement"][0]["Sid"] == sid

        lambda_client.remove_permission(
            FunctionName=function_name,
            StatementId=sid,
        )
        with pytest.raises(ClientError) as ctx:
            lambda_client.get_policy(FunctionName=function_name)
        assert ctx.value.response["Error"]["Code"] == "ResourceNotFoundException"

    @pytest.mark.skipif(
        not is_old_provider(), reason="test does not make valid assertions against AWS"
    )
    def test_add_lambda_multiple_permission(
        self, iam_client, lambda_client, create_lambda_function
    ):
        """Test adding multiple permissions"""
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )

        # create lambda permissions
        action = "lambda:InvokeFunction"
        principal = "s3.amazonaws.com"
        statement_ids = ["s4", "s5"]
        for sid in statement_ids:
            resp = lambda_client.add_permission(
                FunctionName=function_name,
                Action=action,
                StatementId=sid,
                Principal=principal,
                SourceArn=aws_stack.s3_bucket_arn("test-bucket"),
            )
            assert "Statement" in resp

        # fetch IAM policy
        # this is not a valid assertion in general (especially against AWS)
        policies = iam_client.list_policies(Scope="Local", MaxItems=500)["Policies"]
        policy_name = get_lambda_policy_name(function_name)
        matching = [p for p in policies if p["PolicyName"] == policy_name]
        assert 1 == len(matching)
        assert ":policy/" in matching[0]["Arn"]

        # validate both statements
        policy = matching[0]
        versions = iam_client.list_policy_versions(PolicyArn=policy["Arn"])["Versions"]
        assert 1 == len(versions)
        statements = versions[0]["Document"]["Statement"]
        for i in range(len(statement_ids)):
            assert action == statements[i]["Action"]
            assert lambda_api.func_arn(function_name) == statements[i]["Resource"]
            assert principal == statements[i]["Principal"]["Service"]
            assert (
                aws_stack.s3_bucket_arn("test-bucket")
                == statements[i]["Condition"]["ArnLike"]["AWS:SourceArn"]
            )
            # check statement_ids in reverse order
            assert statement_ids[abs(i - 1)] == statements[i]["Sid"]

        # remove permission that we just added
        resp = lambda_client.remove_permission(
            FunctionName=function_name,
            StatementId=sid,
            Qualifier="qual1",
            RevisionId="r1",
        )
        assert 200 == resp["ResponseMetadata"]["HTTPStatusCode"]

    @pytest.mark.snapshot
    def test_lambda_asynchronous_invocations(
        self,
        lambda_client,
        create_lambda_function,
        sqs_queue,
        sqs_queue_arn,
        lambda_su_role,
        snapshot,
    ):
        """Testing API actions of function event config"""
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
            role=lambda_su_role,
        )

        queue_arn = sqs_queue_arn(sqs_queue)
        destination_config = {
            "OnSuccess": {"Destination": queue_arn},
            "OnFailure": {"Destination": queue_arn},
        }

        # adding event invoke config
        response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name,
            MaximumRetryAttempts=2,
            MaximumEventAgeInSeconds=123,
            DestinationConfig=destination_config,
        )
        snapshot.match("put_function_event_invoke_config", response)

        # over writing event invoke config
        response = lambda_client.put_function_event_invoke_config(
            FunctionName=function_name,
            MaximumRetryAttempts=2,
            DestinationConfig=destination_config,
        )
        snapshot.match("put_function_event_invoke_config_overwritemaxeventage", response)

        # updating event invoke config
        response = lambda_client.update_function_event_invoke_config(
            FunctionName=function_name,
            MaximumRetryAttempts=1,
        )
        snapshot.match("put_function_event_invoke_config_maxattempt1", response)

        # clean up
        lambda_client.delete_function_event_invoke_config(FunctionName=function_name)

    def test_function_concurrency(self, lambda_client, create_lambda_function, snapshot):
        """Testing the api of the put function concurrency action"""
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )

        response = lambda_client.put_function_concurrency(
            FunctionName=function_name, ReservedConcurrentExecutions=123
        )
        snapshot.match("put_function_concurrency", response)
        assert "ReservedConcurrentExecutions" in response
        response = lambda_client.get_function_concurrency(FunctionName=function_name)
        snapshot.match("get_function_concurrency", response)
        assert "ReservedConcurrentExecutions" in response
        lambda_client.delete_function_concurrency(FunctionName=function_name)

    def test_function_code_signing_config(self, lambda_client, create_lambda_function, snapshot):
        """Testing the API of code signing config"""
        function_name = f"lambda_func-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )

        response = lambda_client.create_code_signing_config(
            Description="Testing CodeSigning Config",
            AllowedPublishers={
                "SigningProfileVersionArns": [
                    f"arn:aws:signer:{aws_stack.get_region()}:000000000000:/signing-profiles/test",
                ]
            },
            CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Enforce"},
        )
        snapshot.replace_value(re.compile(r"^csc-[0-9a-f]{17}$"), "<csc-id>")
        snapshot.match("create_code_signing_config", response)

        assert "Description" in response["CodeSigningConfig"]
        assert "SigningProfileVersionArns" in response["CodeSigningConfig"]["AllowedPublishers"]
        assert (
            "UntrustedArtifactOnDeployment" in response["CodeSigningConfig"]["CodeSigningPolicies"]
        )

        code_signing_arn = response["CodeSigningConfig"]["CodeSigningConfigArn"]
        response = lambda_client.update_code_signing_config(
            CodeSigningConfigArn=code_signing_arn,
            CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Warn"},
        )
        snapshot.match("update_code_signing_config", response)

        assert (
            "Warn"
            == response["CodeSigningConfig"]["CodeSigningPolicies"]["UntrustedArtifactOnDeployment"]
        )
        response = lambda_client.get_code_signing_config(CodeSigningConfigArn=code_signing_arn)
        assert 200 == response["ResponseMetadata"]["HTTPStatusCode"]
        snapshot.match("get_code_signing_config", response)

        response = lambda_client.put_function_code_signing_config(
            CodeSigningConfigArn=code_signing_arn, FunctionName=function_name
        )
        assert 200 == response["ResponseMetadata"]["HTTPStatusCode"]
        snapshot.match("put_function_code_signing_config", response)

        response = lambda_client.get_function_code_signing_config(FunctionName=function_name)
        assert 200 == response["ResponseMetadata"]["HTTPStatusCode"]
        snapshot.match("get_function_code_signing_config", response)
        assert code_signing_arn == response["CodeSigningConfigArn"]
        assert function_name == response["FunctionName"]

        response = lambda_client.delete_function_code_signing_config(FunctionName=function_name)
        assert 204 == response["ResponseMetadata"]["HTTPStatusCode"]

        response = lambda_client.delete_code_signing_config(CodeSigningConfigArn=code_signing_arn)
        assert 204 == response["ResponseMetadata"]["HTTPStatusCode"]

    def create_multiple_lambda_permissions(self, lambda_client, create_lambda_function, snapshot):
        """Test creating multiple lambda permissions and checking the policy"""
        function_name = f"test-function-{short_uid()}"

        create_lambda_function(
            funct_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON37,
            libs=TEST_LAMBDA_LIBS,
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
        assert "Statement" in resp

        sid = "kinesis"
        resp = lambda_client.add_permission(
            FunctionName=function_name,
            Action=action,
            StatementId=sid,
            Principal="kinesis.amazonaws.com",
        )
        snapshot.match("add_permission_response_2", resp)

        assert "Statement" in resp

        policy_response = lambda_client.get_policy(
            FunctionName=function_name,
        )
        snapshot.match("policy_after_2_add", policy_response)


class TestLambdaBaseFeatures:
    def test_dead_letter_queue(
        self,
        lambda_client,
        create_lambda_function,
        sqs_client,
        sqs_create_queue,
        sqs_queue_arn,
        lambda_su_role,
        snapshot,
    ):
        """Creates a lambda with a defined dead letter queue, and check failed lambda invocation leads to a message"""
        # create DLQ and Lambda function
        queue_name = f"test-{short_uid()}"
        lambda_name = f"test-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        queue_arn = sqs_queue_arn(queue_url)
        create_lambda_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON,
            func_name=lambda_name,
            libs=TEST_LAMBDA_LIBS,
            runtime=LAMBDA_RUNTIME_PYTHON36,
            DeadLetterConfig={"TargetArn": queue_arn},
            role=lambda_su_role,
        )
        snapshot.match("create_lambda_with_dlq", create_lambda_response)
        snapshot.skip_key(re.compile("ReceiptHandle"), "<receipt-handle>")
        snapshot.skip_key(re.compile("MD5Of.*"), "<md5-hash>")

        # invoke Lambda, triggering an error
        payload = {lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1}
        lambda_client.invoke(
            FunctionName=lambda_name,
            Payload=json.dumps(payload),
            InvocationType="Event",
        )

        # assert that message has been received on the DLQ
        def receive_dlq():
            result = sqs_client.receive_message(QueueUrl=queue_url, MessageAttributeNames=["All"])
            assert len(result["Messages"]) > 0
            msg_attrs = result["Messages"][0]["MessageAttributes"]
            assert "RequestID" in msg_attrs
            assert "ErrorCode" in msg_attrs
            assert "ErrorMessage" in msg_attrs
            snapshot.match("sqs_dlq_message", result)

        # on AWS, event retries can be quite delayed, so we have to wait up to 6 minutes here, potential flakes
        retry(receive_dlq, retries=120, sleep=3)

        # update DLQ config
        update_function_config_response = lambda_client.update_function_configuration(
            FunctionName=lambda_name, DeadLetterConfig={}
        )
        snapshot.match("delete_dlq", update_function_config_response)
        # invoke Lambda again, assert that status code is 200 and error details contained in the payload
        result = lambda_client.invoke(
            FunctionName=lambda_name, Payload=json.dumps(payload), LogType="Tail"
        )
        result = read_streams(result)
        payload = json.loads(to_str(result["Payload"]))
        snapshot.match("result_payload", payload)
        assert 200 == result["StatusCode"]
        assert "Unhandled" == result["FunctionError"]
        assert "$LATEST" == result["ExecutedVersion"]
        assert "Test exception" in payload["errorMessage"]
        assert "Exception" in payload["errorType"]
        assert isinstance(payload["stackTrace"], list)
        log_result = result.get("LogResult")
        assert log_result
        logs = to_str(base64.b64decode(to_str(log_result)))
        assert "START" in logs
        assert "Test exception" in logs
        assert "END" in logs
        assert "REPORT" in logs

    @pytest.mark.parametrize(
        "condition,payload",
        [
            ("Success", {}),
            ("RetriesExhausted", {lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1}),
        ],
    )
    def test_assess_lambda_destination_invocation(
        self,
        condition,
        payload,
        lambda_client,
        sqs_client,
        create_lambda_function,
        sqs_create_queue,
        sqs_queue_arn,
        lambda_su_role,
        snapshot,
    ):
        """Testing the destination config API and operation (for the OnSuccess case)"""
        # create DLQ and Lambda function
        queue_name = f"test-{short_uid()}"
        lambda_name = f"test-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        queue_arn = sqs_queue_arn(queue_url)
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON,
            func_name=lambda_name,
            libs=TEST_LAMBDA_LIBS,
            role=lambda_su_role,
        )

        put_event_invoke_config_response = lambda_client.put_function_event_invoke_config(
            FunctionName=lambda_name,
            DestinationConfig={
                "OnSuccess": {"Destination": queue_arn},
                "OnFailure": {"Destination": queue_arn},
            },
        )
        snapshot.match("put_function_event_invoke_config", put_event_invoke_config_response)
        snapshot.skip_key(re.compile("ReceiptHandle"), "<receipt-handle>")
        snapshot.skip_key(re.compile("MD5Of.*"), "<md5-hash>")

        lambda_client.invoke(
            FunctionName=lambda_name,
            Payload=json.dumps(payload),
            InvocationType="Event",
        )
        configure_snapshot_for_context(snapshot, lambda_name)

        def receive_message():
            rs = sqs_client.receive_message(QueueUrl=queue_url, MessageAttributeNames=["All"])
            assert len(rs["Messages"]) > 0
            msg = rs["Messages"][0]["Body"]
            msg = json.loads(msg)
            assert condition == msg["requestContext"]["condition"]
            snapshot.match("destination_message", rs)

        retry(receive_message, retries=120, sleep=3)

    def test_large_payloads(self, caplog, lambda_client, create_lambda_function, snapshot):
        """Testing large payloads sent to lambda functions (~5MB)"""
        # Set the loglevel to INFO for this test to avoid breaking a CI environment (due to excessive log outputs)
        caplog.set_level(logging.INFO)

        function_name = f"large_payload-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
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


parametrize_python_runtimes = pytest.mark.parametrize(
    "runtime",
    PYTHON_TEST_RUNTIMES,
)


class TestPythonRuntimes:
    @pytest.fixture(
        params=PYTHON_TEST_RUNTIMES,
    )
    def python_function_name(self, request, lambda_client, create_lambda_function):
        function_name = f"python-test-function-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON,
            libs=TEST_LAMBDA_LIBS,
            runtime=request.param,
        )
        return function_name

    def test_invocation_type_not_set(self, lambda_client, python_function_name, snapshot):
        """Test invocation of a lambda with no invocation type set, but LogType="Tail""" ""

        result = lambda_client.invoke(
            FunctionName=python_function_name, Payload=b"{}", LogType="Tail"
        )
        result = read_streams(result)
        snapshot.skip_key(re.compile("LogResult"), "<log_result>")
        configure_snapshot_for_context(snapshot, python_function_name)
        snapshot.match("invoke", result)
        result_data = json.loads(result["Payload"])

        # assert response details
        assert 200 == result["StatusCode"]
        assert {} == result_data["event"]

        # assert that logs are contained in response
        logs = result.get("LogResult", "")
        logs = to_str(base64.b64decode(to_str(logs)))
        snapshot.register_replacement(
            re.compile(r"Duration: \d+(\.\d{2})? ms"), "Duration: <duration> ms"
        )
        snapshot.register_replacement(re.compile(r"Used: \d+ MB"), "Used: <memory> MB")
        snapshot.match("logs", {"logs": logs})
        assert "START" in logs
        assert "Lambda log message" in logs
        assert "END" in logs
        assert "REPORT" in logs

    def test_invocation_type_request_response(self, lambda_client, python_function_name, snapshot):
        """Test invocation with InvocationType RequestResponse explicitely set"""
        result = lambda_client.invoke(
            FunctionName=python_function_name,
            Payload=b"{}",
            InvocationType="RequestResponse",
        )
        result = read_streams(result)
        configure_snapshot_for_context(snapshot, python_function_name)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]
        result_data = json.loads(result_data)
        assert "application/json" == result["ResponseMetadata"]["HTTPHeaders"]["content-type"]
        assert 200 == result["StatusCode"]
        assert isinstance(result_data, dict)

    def test_invocation_type_event(self, lambda_client, python_function_name, snapshot):
        """Check invocation response for type event"""
        result = lambda_client.invoke(
            FunctionName=python_function_name, Payload=b"{}", InvocationType="Event"
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)

        assert 202 == result["StatusCode"]

    def test_invocation_type_dry_run(self, lambda_client, python_function_name, snapshot):
        """Check invocation response for type dryrun"""
        result = lambda_client.invoke(
            FunctionName=python_function_name, Payload=b"{}", InvocationType="DryRun"
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)

        assert 204 == result["StatusCode"]

    @parametrize_python_runtimes
    def test_lambda_environment(self, lambda_client, create_lambda_function, runtime, snapshot):
        """Tests invoking a lambda function with environment variables set on creation"""
        function_name = f"env-test-function-{short_uid()}"
        env_vars = {"Hello": "World"}
        creation_result = create_lambda_function(
            handler_file=TEST_LAMBDA_ENV,
            libs=TEST_LAMBDA_LIBS,
            func_name=function_name,
            envvars=env_vars,
            runtime=runtime,
        )
        snapshot.match("creation-result", creation_result)

        # invoke function and assert result contains env vars
        result = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        result = read_streams(result)
        snapshot.match("invocation-result", result)
        result_data = result["Payload"]
        assert 200 == result["StatusCode"]
        assert json.loads(result_data) == env_vars

        # get function config and assert result contains env vars
        result = lambda_client.get_function_configuration(FunctionName=function_name)
        snapshot.match("get-configuration-result", result)
        assert result["Environment"] == {"Variables": env_vars}

    @parametrize_python_runtimes
    def test_invocation_with_qualifier(
        self,
        lambda_client,
        s3_client,
        s3_bucket,
        runtime,
        check_lambda_logs,
        lambda_su_role,
        wait_until_lambda_ready,
        snapshot,
    ):
        """Tests invocation of python lambda with a given qualifier"""
        function_name = f"test_lambda_{short_uid()}"
        bucket_key = "test_lambda.zip"

        # upload zip file to S3
        zip_file = create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON), get_content=True, libs=TEST_LAMBDA_LIBS, runtime=runtime
        )
        s3_client.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        response = lambda_client.create_function(
            FunctionName=function_name,
            Runtime=runtime,
            Role=lambda_su_role,
            Publish=True,
            Handler="handler.handler",
            Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
            Timeout=10,
        )
        snapshot.match("creation-response", response)

        configure_snapshot_for_context(snapshot, function_name)
        assert "Version" in response
        qualifier = response["Version"]

        wait_until_lambda_ready(function_name=function_name, qualifier=qualifier)

        # invoke lambda function
        data_before = b'{"foo": "bar with \'quotes\\""}'
        result = lambda_client.invoke(
            FunctionName=function_name, Payload=data_before, Qualifier=qualifier
        )
        result = read_streams(result)
        snapshot.match("invocation-response", result)
        data_after = json.loads(result["Payload"])
        assert json.loads(to_str(data_before)) == data_after["event"]

        context = data_after["context"]
        assert response["Version"] == context["function_version"]
        assert context.get("aws_request_id")
        assert function_name == context["function_name"]
        assert f"/aws/lambda/{function_name}" == context["log_group_name"]
        assert context.get("log_stream_name")
        assert context.get("memory_limit_in_mb")

        # assert that logs are present
        expected = [".*Lambda log message - print function.*"]
        if use_docker():
            # Note that during regular test execution, nosetests captures the output from
            # the logging module - hence we can only expect this when running in Docker
            expected.append(".*Lambda log message - logging module.*")

        def check_logs():
            check_lambda_logs(function_name, expected_lines=expected)

        retry(check_logs, retries=10)
        lambda_client.delete_function(FunctionName=function_name)

    @parametrize_python_runtimes
    def test_upload_lambda_from_s3(
        self,
        lambda_client,
        s3_client,
        s3_bucket,
        runtime,
        lambda_su_role,
        wait_until_lambda_ready,
        snapshot,
    ):
        """Test invocation of a python lambda with its deployment package uploaded to s3"""
        function_name = f"test_lambda_{short_uid()}"
        bucket_key = "test_lambda.zip"

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON), get_content=True, libs=TEST_LAMBDA_LIBS, runtime=runtime
        )
        s3_client.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        create_response = lambda_client.create_function(
            FunctionName=function_name,
            Runtime=runtime,
            Handler="handler.handler",
            Role=lambda_su_role,
            Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
            Timeout=10,
        )
        snapshot.match("creation-response", create_response)
        configure_snapshot_for_context(snapshot, function_name)

        wait_until_lambda_ready(function_name=function_name)

        # invoke lambda function
        data_before = b'{"foo": "bar with \'quotes\\""}'
        result = lambda_client.invoke(FunctionName=function_name, Payload=data_before)
        result = read_streams(result)
        snapshot.match("invocation-response", result)
        data_after = json.loads(result["Payload"])
        assert json.loads(to_str(data_before)) == data_after["event"]

        context = data_after["context"]
        assert "$LATEST" == context["function_version"]
        assert function_name == context["function_name"]

        # clean up
        lambda_client.delete_function(FunctionName=function_name)

    @parametrize_python_runtimes
    def test_handler_in_submodule(self, lambda_client, create_lambda_function, runtime):
        """Test invocation of a lambda handler which resides in a submodule (= not root module)"""
        function_name = f"test-function-{short_uid()}"
        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON),
            get_content=True,
            libs=TEST_LAMBDA_LIBS,
            runtime=runtime,
            file_name="localstack_package/def/main.py",
        )
        create_lambda_function(
            func_name=function_name,
            zip_file=zip_file,
            handler="localstack_package.def.main.handler",
            runtime=runtime,
        )

        # invoke function and assert result
        result = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        result_data = json.loads(result["Payload"].read())
        assert 200 == result["StatusCode"]
        assert json.loads("{}") == result_data["event"]

    @parametrize_python_runtimes
    def test_lambda_send_message_to_sqs(
        self,
        lambda_client,
        create_lambda_function,
        sqs_client,
        sqs_create_queue,
        runtime,
        lambda_su_role,
    ):
        """Send sqs message to sqs queue inside python lambda"""
        function_name = f"test-function-{short_uid()}"
        queue_name = f"lambda-queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        create_lambda_function(
            handler_file=TEST_LAMBDA_SEND_MESSAGE_FILE,
            func_name=function_name,
            runtime=runtime,
            role=lambda_su_role,
        )

        event = {
            "message": f"message-from-test-lambda-{short_uid()}",
            "queue_name": queue_name,
            "region_name": sqs_client.meta.region_name,
        }

        lambda_client.invoke(FunctionName=function_name, Payload=json.dumps(event))

        # assert that message has been received on the Queue
        def receive_message():
            rs = sqs_client.receive_message(QueueUrl=queue_url, MessageAttributeNames=["All"])
            assert len(rs["Messages"]) > 0
            return rs["Messages"][0]

        message = retry(receive_message, retries=15, sleep=2)
        assert event["message"] == message["Body"]

    @parametrize_python_runtimes
    def test_lambda_put_item_to_dynamodb(
        self,
        lambda_client,
        create_lambda_function,
        dynamodb_create_table,
        runtime,
        dynamodb_resource,
        lambda_su_role,
        dynamodb_client,
    ):
        """Put item into dynamodb from python lambda"""
        table_name = f"ddb-table-{short_uid()}"
        function_name = f"test-function-{short_uid()}"

        dynamodb_create_table(table_name=table_name, partition_key="id")

        create_lambda_function(
            handler_file=TEST_LAMBDA_PUT_ITEM_FILE,
            func_name=function_name,
            runtime=runtime,
            role=lambda_su_role,
        )

        data = {short_uid(): f"data-{i}" for i in range(3)}

        event = {
            "table_name": table_name,
            "region_name": dynamodb_client.meta.region_name,
            "items": [{"id": k, "data": v} for k, v in data.items()],
        }

        def wait_for_table_created():
            return (
                dynamodb_client.describe_table(TableName=table_name)["Table"]["TableStatus"]
                == "ACTIVE"
            )

        assert poll_condition(wait_for_table_created, timeout=30)

        lambda_client.invoke(FunctionName=function_name, Payload=json.dumps(event))

        rs = dynamodb_resource.Table(table_name).scan()

        items = rs["Items"]

        assert len(items) == len(data.keys())
        for item in items:
            assert data[item["id"]] == item["data"]

    @parametrize_python_runtimes
    def test_lambda_start_stepfunctions_execution(
        self, lambda_client, stepfunctions_client, create_lambda_function, runtime, lambda_su_role
    ):
        """Start stepfunctions machine execution from lambda"""
        function_name = f"test-function-{short_uid()}"
        resource_lambda_name = f"test-resource-{short_uid()}"
        state_machine_name = f"state-machine-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_START_EXECUTION_FILE,
            func_name=function_name,
            runtime=runtime,
            role=lambda_su_role,
        )

        resource_lambda_arn = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=resource_lambda_name,
            runtime=runtime,
            role=lambda_su_role,
        )["CreateFunctionResponse"]["FunctionArn"]

        state_machine_def = {
            "StartAt": "step1",
            "States": {
                "step1": {
                    "Type": "Task",
                    "Resource": resource_lambda_arn,
                    "ResultPath": "$.result_value",
                    "End": True,
                }
            },
        }

        rs = stepfunctions_client.create_state_machine(
            name=state_machine_name,
            definition=json.dumps(state_machine_def),
            roleArn=lambda_su_role,
        )
        sm_arn = rs["stateMachineArn"]

        try:
            lambda_client.invoke(
                FunctionName=function_name,
                Payload=json.dumps(
                    {
                        "state_machine_arn": sm_arn,
                        "region_name": stepfunctions_client.meta.region_name,
                        "input": {},
                    }
                ),
            )
            time.sleep(1)

            rs = stepfunctions_client.list_executions(stateMachineArn=sm_arn)

            # assert that state machine get executed 1 time
            assert 1 == len([ex for ex in rs["executions"] if ex["stateMachineArn"] == sm_arn])

        finally:
            # clean up
            stepfunctions_client.delete_state_machine(stateMachineArn=sm_arn)

    @pytest.mark.skipif(
        not use_docker(), reason="Test for docker python runtimes not applicable if run locally"
    )
    @parametrize_python_runtimes
    def test_python_runtime_correct_versions(self, lambda_client, create_lambda_function, runtime):
        """Test different versions of python runtimes to report back the correct python version"""
        function_name = f"test_python_executor_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_VERSION,
            runtime=runtime,
        )
        result = lambda_client.invoke(
            FunctionName=function_name,
            Payload=b"{}",
        )
        result = json.loads(to_str(result["Payload"].read()))
        assert result["version"] == runtime

    @pytest.mark.skipif(
        not use_docker(), reason="Test for docker python runtimes not applicable if run locally"
    )
    @parametrize_python_runtimes
    def test_python_runtime_unhandled_errors(
        self, lambda_client, create_lambda_function, runtime, snapshot
    ):
        """Test unhandled errors during python lambda invocation"""
        function_name = f"test_python_executor_{short_uid()}"
        creation_response = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_UNHANDLED_ERROR,
            runtime=runtime,
        )
        snapshot.match("creation_response", creation_response)
        result = lambda_client.invoke(
            FunctionName=function_name,
            Payload=b"{}",
        )
        result = read_streams(result)
        snapshot.match("invocation_response", result)
        assert result["StatusCode"] == 200
        assert result["ExecutedVersion"] == "$LATEST"
        assert result["FunctionError"] == "Unhandled"
        payload = json.loads(result["Payload"])
        assert payload["errorType"] == "CustomException"
        assert payload["errorMessage"] == "some error occurred"
        assert "stackTrace" in payload

        if (
            runtime == "python3.9" and not is_old_provider()
        ):  # TODO: remove this after the legacy provider is gone
            assert "requestId" in payload
        else:
            assert "requestId" not in payload


parametrize_node_runtimes = pytest.mark.parametrize(
    "runtime",
    NODE_TEST_RUNTIMES,
)


class TestNodeJSRuntimes:
    @pytest.mark.skipif(
        not use_docker(), reason="Test for docker nodejs runtimes not applicable if run locally"
    )
    @parametrize_node_runtimes
    def test_nodejs_lambda_with_context(
        self, lambda_client, create_lambda_function, runtime, check_lambda_logs, snapshot
    ):
        """Test context of nodejs lambda invocation"""
        function_name = f"test-function-{short_uid()}"
        creation_response = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_INTEGRATION_NODEJS,
            handler="lambda_integration.handler",
            runtime=runtime,
        )
        snapshot.match("creation", creation_response)
        ctx = {
            "custom": {"foo": "bar"},
            "client": {"snap": ["crackle", "pop"]},
            "env": {"fizz": "buzz"},
        }
        configure_snapshot_for_context(snapshot, function_name)

        result = lambda_client.invoke(
            FunctionName=function_name,
            Payload=b"{}",
            ClientContext=to_str(base64.b64encode(to_bytes(json.dumps(ctx)))),
        )
        result = read_streams(result)
        snapshot.match("invocation", result)

        result_data = result["Payload"]
        assert 200 == result["StatusCode"]
        client_context = json.loads(result_data)["context"]["clientContext"]
        # TODO in the old provider, for some reason this is necessary. That is invalid behavior
        if is_old_provider():
            client_context = json.loads(client_context)
        assert "bar" == client_context.get("custom").get("foo")

        # assert that logs are present
        expected = [".*Node.js Lambda handler executing."]

        def check_logs():
            check_lambda_logs(function_name, expected_lines=expected)

        retry(check_logs, retries=15)

    @parametrize_node_runtimes
    def test_invoke_nodejs_lambda(
        self, lambda_client, create_lambda_function, runtime, logs_client, snapshot
    ):
        """Test simple nodejs lambda invocation"""
        function_name = f"test-function-{short_uid()}"
        result = create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_NODEJS, get_content=True),
            runtime=runtime,
            handler="lambda_handler.handler",
        )
        snapshot.match("creation-result", result)

        rs = lambda_client.invoke(
            FunctionName=function_name,
            Payload=json.dumps({"event_type": "test_lambda"}),
        )
        assert 200 == rs["ResponseMetadata"]["HTTPStatusCode"]
        rs = read_streams(rs)
        snapshot.match("invocation-result", rs)

        payload = rs["Payload"]
        response = json.loads(payload)
        assert "response from localstack lambda" in response["body"]

        def assert_events():
            events = get_lambda_log_events(function_name, logs_client=logs_client)
            assert len(events) > 0

        retry(assert_events, retries=10)

    @parametrize_node_runtimes
    def test_invoke_nodejs_lambda_with_payload_containing_quotes(
        self, lambda_client, create_lambda_function, runtime, logs_client, snapshot
    ):
        """Test nodejs invocation of payload with quotes"""
        function_name = f"test_lambda_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_NODEJS, get_content=True),
            runtime=runtime,
            handler="lambda_handler.handler",
        )

        test_string = "test_string' with some quotes"
        body = f'{{"test_var": "{test_string}"}}'
        rs = lambda_client.invoke(
            FunctionName=function_name,
            Payload=body,
        )

        assert 200 == rs["ResponseMetadata"]["HTTPStatusCode"]
        rs = read_streams(rs)
        snapshot.match("invoke-result", rs)
        response = json.loads(rs["Payload"])
        assert "response from localstack lambda" in response["body"]

        def assert_events():
            events = get_lambda_log_events(function_name, logs_client=logs_client)
            assert len(events) > 0
            assert test_string in str(events[0])

        retry(assert_events, retries=10)


class TestCustomRuntimes:
    @pytest.mark.skipif(
        not use_docker(), reason="Test for docker provided runtimes not applicable if run locally"
    )
    @pytest.mark.parametrize(
        "runtime",
        PROVIDED_TEST_RUNTIMES,
    )
    def test_provided_runtimes(
        self, lambda_client, create_lambda_function, runtime, check_lambda_logs, snapshot
    ):
        """Test simple provided lambda (with curl as RIC) invocation"""
        function_name = f"test-function-{short_uid()}"
        result = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_CUSTOM_RUNTIME,
            handler="function.handler",
            runtime=runtime,
        )
        snapshot.match("create-result", result)
        result = lambda_client.invoke(
            FunctionName=function_name,
            Payload=b'{"text": "bar with \'quotes\\""}',
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]

        assert 200 == result["StatusCode"]
        result_data = result_data.strip()
        # jsonify in pro (re-)formats the event json so we allow both versions here
        assert result_data in (
            """Echoing request: '{"text": "bar with \'quotes\\""}'""",
            """Echoing request: '{"text":"bar with \'quotes\\""}'""",
        )

        # assert that logs are present
        expected = [".*Custom Runtime Lambda handler executing."]

        def check_logs():
            check_lambda_logs(function_name, expected_lines=expected)

        retry(check_logs, retries=20)


class TestDotNetCoreRuntimes:
    @pytest.mark.skipif(
        not use_docker(), reason="Dotnet functions only supported with docker executor"
    )
    @pytest.mark.parametrize(
        "zip_file,handler,runtime,expected_lines",
        [
            (
                TEST_LAMBDA_DOTNETCORE31,
                "dotnetcore31::dotnetcore31.Function::FunctionHandler",
                LAMBDA_RUNTIME_DOTNETCORE31,
                ["Running .NET Core 3.1 Lambda"],
            ),
            (
                TEST_LAMBDA_DOTNET6,
                "dotnet6::dotnet6.Function::FunctionHandler",
                LAMBDA_RUNTIME_DOTNET6,
                ["Running .NET 6 Lambda"],
            ),
        ],
        ids=["dotnetcore3.1", "dotnet6"],
    )
    def test_dotnet_lambda(
        self,
        zip_file,
        handler,
        runtime,
        expected_lines,
        lambda_client,
        create_lambda_function,
        snapshot,
    ):
        """Test simple dotnet lambda invocation"""
        function_name = f"test-function-{short_uid()}"

        create_result = create_lambda_function(
            func_name=function_name,
            zip_file=load_file(zip_file, mode="rb"),
            handler=handler,
            runtime=runtime,
        )
        snapshot.match("create-result", create_result)
        result = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        result = read_streams(result)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]

        assert 200 == result["StatusCode"]
        assert "{}" == result_data.strip()
        # TODO make lambda log checks more resilient to various formats
        # self.check_lambda_logs(func_name, expected_lines=expected_lines)


class TestRubyRuntimes:
    @pytest.mark.skipif(not use_docker(), reason="ruby runtimes not supported in local invocation")
    def test_ruby_lambda_running_in_docker(self, lambda_client, create_lambda_function, snapshot):
        """Test simple ruby lambda invocation"""
        function_name = f"test-function-{short_uid()}"
        create_result = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_RUBY,
            handler="lambda_integration.handler",
            runtime=LAMBDA_RUNTIME_RUBY27,
        )
        snapshot.match("create-result", create_result)
        result = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        result = read_streams(result)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]

        assert 200 == result["StatusCode"]
        assert "{}" == to_str(result_data).strip()


class TestGolangRuntimes:
    @pytest.mark.skip_offline
    def test_golang_lambda(self, lambda_client, tmp_path, create_lambda_function, snapshot):
        """Test simple golang lambda invocation"""
        # fetch platform-specific example handler
        url = TEST_GOLANG_LAMBDA_URL_TEMPLATE.format(
            version=GO_RUNTIME_VERSION,
            os=get_os(),
            arch=get_arch(),
        )
        handler = tmp_path / "go-handler"
        download_and_extract(url, handler)

        # create function
        func_name = f"test_lambda_{short_uid()}"
        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=handler,
            handler="handler",
            runtime=LAMBDA_RUNTIME_GOLANG,
        )
        snapshot.match("create-result", create_result)

        # invoke
        result = lambda_client.invoke(
            FunctionName=func_name, Payload=json.dumps({"name": "pytest"})
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]
        assert result["StatusCode"] == 200
        assert result_data.strip() == '"Hello pytest!"'


parametrize_java_runtimes = pytest.mark.parametrize(
    "runtime",
    JAVA_TEST_RUNTIMES,
)


class TestJavaRuntimes:
    @pytest.fixture(scope="class")
    def test_java_jar(self) -> bytes:
        # The TEST_LAMBDA_JAVA jar file is downloaded with `make init-testlibs`.
        java_file = load_file(TEST_LAMBDA_JAVA, mode="rb")
        if not java_file:
            raise Exception(
                f"Test dependency {TEST_LAMBDA_JAVA} not found."
                "Please make sure to run 'make init-testlibs' to ensure the file is available."
            )
        return java_file

    @pytest.fixture(scope="class")
    def test_java_zip(self, tmpdir_factory, test_java_jar) -> bytes:
        tmpdir = tmpdir_factory.mktemp("tmp-java-zip")
        zip_lib_dir = os.path.join(tmpdir, "lib")
        zip_jar_path = os.path.join(zip_lib_dir, "test.lambda.jar")
        mkdir(zip_lib_dir)
        cp_r(
            INSTALL_PATH_LOCALSTACK_FAT_JAR,
            os.path.join(zip_lib_dir, "executor.lambda.jar"),
        )
        save_file(zip_jar_path, test_java_jar)
        return testutil.create_zip_file(tmpdir, get_content=True)

    @pytest.fixture(
        params=JAVA_TEST_RUNTIMES,
    )
    def simple_java_lambda(self, create_lambda_function, test_java_zip, request):
        function_name = f"java-test-function-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            zip_file=test_java_zip,
            runtime=request.param,
            handler="cloud.localstack.sample.LambdaHandler",
        )
        return function_name

    def test_java_runtime(self, lambda_client, simple_java_lambda, snapshot):
        """Tests a simple java lambda invocation"""
        result = lambda_client.invoke(
            FunctionName=simple_java_lambda,
            Payload=b'{"echo":"echo"}',
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]

        assert 200 == result["StatusCode"]
        # TODO: find out why the assertion below does not work in Travis-CI! (seems to work locally)
        assert "LinkedHashMap" in to_str(result_data)
        assert result_data is not None

    def test_java_runtime_with_large_payload(
        self, lambda_client, simple_java_lambda, caplog, snapshot
    ):
        """Tests a invocation against a java lambda with a 5MB payload"""
        # Set the loglevel to INFO for this test to avoid breaking a CI environment (due to excessive log outputs)
        caplog.set_level(logging.INFO)

        payload = {"test": "test123456" * 100 * 1000 * 5}  # 5MB payload
        payload = to_bytes(json.dumps(payload))

        result = lambda_client.invoke(FunctionName=simple_java_lambda, Payload=payload)
        result = read_streams(result)
        snapshot.match("invoke-result", result)

        result_data = result["Payload"]

        assert 200 == result["StatusCode"]
        assert "LinkedHashMap" in result_data
        assert result_data is not None

    def test_java_runtime_with_lib(self, lambda_client, create_lambda_function, snapshot):
        """Test lambda creation/invocation with different deployment package types (jar, zip, zip-with-gradle)"""
        java_jar_with_lib = load_file(TEST_LAMBDA_JAVA_WITH_LIB, mode="rb")

        # create ZIP file from JAR file
        jar_dir = new_tmp_dir()
        zip_dir = new_tmp_dir()
        unzip(TEST_LAMBDA_JAVA_WITH_LIB, jar_dir)
        zip_lib_dir = os.path.join(zip_dir, "lib")
        shutil.move(os.path.join(jar_dir, "lib"), zip_lib_dir)
        jar_without_libs_file = testutil.create_zip_file(jar_dir)
        shutil.copy(jar_without_libs_file, os.path.join(zip_lib_dir, "lambda.jar"))
        java_zip_with_lib = testutil.create_zip_file(zip_dir, get_content=True)

        java_zip_with_lib_gradle = load_file(
            os.path.join(
                THIS_FOLDER,
                "functions",
                "java",
                "lambda_echo",
                "build",
                "distributions",
                "lambda-function-built-by-gradle.zip",
            ),
            mode="rb",
        )

        for archive_desc, archive in [
            ("jar-with-lib", java_jar_with_lib),
            ("zip-with-lib", java_zip_with_lib),
            ("zip-with-lib-gradle", java_zip_with_lib_gradle),
        ]:
            lambda_name = f"test-function-{short_uid()}"
            create_result = create_lambda_function(
                func_name=lambda_name,
                zip_file=archive,
                runtime=LAMBDA_RUNTIME_JAVA11,
                handler="cloud.localstack.sample.LambdaHandlerWithLib",
            )
            snapshot.match(f"create-result-{archive_desc}", create_result)

            result = lambda_client.invoke(FunctionName=lambda_name, Payload=b'{"echo":"echo"}')
            result = read_streams(result)
            snapshot.match(f"invoke-result-{archive_desc}", result)
            result_data = result["Payload"]

            assert 200 == result["StatusCode"]
            assert "echo" in to_str(result_data)

    def test_sns_event(self, lambda_client, simple_java_lambda):
        result = lambda_client.invoke(
            FunctionName=simple_java_lambda,
            InvocationType="Event",
            Payload=b'{"Records": [{"Sns": {"Message": "{}"}}]}',
        )

        assert 202 == result["StatusCode"]

    def test_ddb_event(self, lambda_client, simple_java_lambda):
        result = lambda_client.invoke(
            FunctionName=simple_java_lambda,
            InvocationType="Event",
            Payload=b'{"Records": [{"dynamodb": {"Message": "{}"}}]}',
        )

        assert 202 == result["StatusCode"]

    @parametrize_java_runtimes
    def test_kinesis_invocation(
        self, lambda_client, create_lambda_function, test_java_zip, runtime
    ):
        payload = (
            b'{"Records": [{'
            b'"kinesis": {"data": "dGVzdA==", "partitionKey": "partition"},'
            b'"eventID": "shardId-000000000001:12345678901234567890123456789012345678901234567890",'
            b'"eventSourceARN": "arn:aws:kinesis:us-east-1:123456789012:stream/test"}]}'
        )
        # deploy lambda - Java with Kinesis input object
        function_name = f"test-lambda-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            zip_file=test_java_zip,
            runtime=runtime,
            handler="cloud.localstack.awssdkv1.sample.KinesisLambdaHandler",
        )
        result = lambda_client.invoke(FunctionName=function_name, Payload=payload)
        result_data = result["Payload"].read()

        assert 200 == result["StatusCode"]
        assert '"test "' == to_str(result_data).strip()

    def test_kinesis_event(self, lambda_client, simple_java_lambda):
        payload = (
            b'{"Records": [{'
            b'"kinesis": {"data": "dGVzdA==", "partitionKey": "partition"},'
            b'"eventID": "shardId-000000000001:12345678901234567890123456789012345678901234567890",'
            b'"eventSourceARN": "arn:aws:kinesis:us-east-1:123456789012:stream/test"}]}'
        )
        result = lambda_client.invoke(
            FunctionName=simple_java_lambda,
            InvocationType="Event",
            Payload=payload,
        )
        result_data = result["Payload"].read()

        assert 202 == result["StatusCode"]
        assert "" == to_str(result_data).strip()

    @parametrize_java_runtimes
    def test_stream_handler(self, lambda_client, create_lambda_function, test_java_jar, runtime):
        function_name = f"test-lambda-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            zip_file=test_java_jar,
            runtime=runtime,
            handler="cloud.localstack.awssdkv1.sample.LambdaStreamHandler",
        )
        result = lambda_client.invoke(
            FunctionName=function_name,
            Payload=b'{"echo":"echo"}',
        )
        result_data = result["Payload"].read()

        assert 200 == result["StatusCode"]
        assert "{}" == to_str(result_data).strip()

    @parametrize_java_runtimes
    def test_serializable_input_object(
        self, lambda_client, create_lambda_function, test_java_zip, runtime, snapshot
    ):
        # deploy lambda - Java with serializable input object
        function_name = f"test-lambda-{short_uid()}"
        create_result = create_lambda_function(
            func_name=function_name,
            zip_file=test_java_zip,
            runtime=runtime,
            handler="cloud.localstack.awssdkv1.sample.SerializedInputLambdaHandler",
        )
        snapshot.match("create-result", create_result)
        result = lambda_client.invoke(
            FunctionName=function_name,
            Payload=b'{"bucket": "test_bucket", "key": "test_key"}',
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]

        assert 200 == result["StatusCode"]
        assert json.loads(result_data) == {
            "validated": True,
            "bucket": "test_bucket",
            "key": "test_key",
        }

    def test_trigger_java_lambda_through_sns(
        self,
        lambda_client,
        s3_client,
        sns_client,
        sns_subscription,
        simple_java_lambda,
        s3_bucket,
        sns_create_topic,
        logs_client,
        snapshot,
    ):
        topic_name = f"topic-{short_uid()}"
        key = f"key-{short_uid()}"
        function_name = simple_java_lambda
        function_result = lambda_client.get_function(FunctionName=function_name)
        snapshot.match("get-function", function_result)
        function_arn = function_result["Configuration"]["FunctionArn"]
        permission_id = f"test-statement-{short_uid()}"

        topic_arn = sns_create_topic(Name=topic_name)["TopicArn"]

        s3_sns_policy = f"""{{
            "Version": "2012-10-17",
            "Id": "example-ID",
            "Statement": [
                {{
                    "Sid": "Example SNS topic policy",
                    "Effect": "Allow",
                    "Principal": {{
                        "Service": "s3.amazonaws.com"
                    }},
                    "Action": [
                        "SNS:Publish"
                    ],
                    "Resource": "{topic_arn}",
                    "Condition": {{
                        "ArnLike": {{
                            "aws:SourceArn": "arn:aws:s3:*:*:{s3_bucket}"
                        }}
                    }}
                }}
            ]
        }}
        """
        sns_client.set_topic_attributes(
            TopicArn=topic_arn, AttributeName="Policy", AttributeValue=s3_sns_policy
        )

        s3_client.put_bucket_notification_configuration(
            Bucket=s3_bucket,
            NotificationConfiguration={
                "TopicConfigurations": [{"TopicArn": topic_arn, "Events": ["s3:ObjectCreated:*"]}]
            },
        )

        add_permission_response = lambda_client.add_permission(
            FunctionName=function_name,
            StatementId=permission_id,
            Action="lambda:InvokeFunction",
            Principal="sns.amazonaws.com",
            SourceArn=topic_arn,
        )
        snapshot.skip_key(re.compile(r"Sid"), "<statement-id>")
        snapshot.match("add-permission", add_permission_response)

        sns_subscription(
            TopicArn=topic_arn,
            Protocol="lambda",
            Endpoint=function_arn,
        )

        events_before = (
            run_safe(
                get_lambda_log_events,
                function_name,
                regex_filter="Records",
                logs_client=logs_client,
            )
            or []
        )

        s3_client.put_object(Bucket=s3_bucket, Key=key, Body="something")

        # We got an event that confirm lambda invoked
        retry(
            function=check_expected_lambda_log_events_length,
            retries=30,
            sleep=1,
            expected_length=len(events_before) + 1,
            function_name=function_name,
            regex_filter="Records",
            logs_client=logs_client,
        )

        # clean up
        s3_client.delete_objects(Bucket=s3_bucket, Delete={"Objects": [{"Key": key}]})

    @pytest.mark.parametrize(
        "handler,expected_result",
        [
            (
                "cloud.localstack.sample.LambdaHandlerWithInterfaceAndCustom::handleRequestCustom",
                "CUSTOM",
            ),
            ("cloud.localstack.sample.LambdaHandlerWithInterfaceAndCustom", "INTERFACE"),
            (
                "cloud.localstack.sample.LambdaHandlerWithInterfaceAndCustom::handleRequest",
                "INTERFACE",
            ),
        ],
    )
    # this test is only compiled against java 11
    def test_java_custom_handler_method_specification(
        self,
        lambda_client,
        create_lambda_function,
        handler,
        expected_result,
        check_lambda_logs,
        snapshot,
    ):
        java_handler_multiple_handlers = load_file(TEST_LAMBDA_JAVA_MULTIPLE_HANDLERS, mode="rb")
        expected = ['.*"echo": "echo".*']

        function_name = f"lambda_handler_test_{short_uid()}"
        create_result = create_lambda_function(
            func_name=function_name,
            zip_file=java_handler_multiple_handlers,
            runtime=LAMBDA_RUNTIME_JAVA11,
            handler=handler,
        )
        snapshot.match("create-result", create_result)

        result = lambda_client.invoke(FunctionName=function_name, Payload=b'{"echo":"echo"}')
        result = read_streams(result)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]

        assert 200 == result["StatusCode"]
        assert expected_result == result_data.strip('"\n ')

        def check_logs():
            check_lambda_logs(function_name, expected_lines=expected)

        retry(check_logs, retries=20)


TEST_LAMBDA_CACHE_NODEJS = os.path.join(THIS_FOLDER, "functions", "lambda_cache.js")
TEST_LAMBDA_CACHE_PYTHON = os.path.join(THIS_FOLDER, "functions", "lambda_cache.py")
TEST_LAMBDA_TIMEOUT_PYTHON = os.path.join(THIS_FOLDER, "functions", "lambda_timeout.py")
TEST_LAMBDA_INTROSPECT_PYTHON = os.path.join(THIS_FOLDER, "functions", "lambda_introspect.py")


class TestLambdaBehavior:
    @pytest.mark.parametrize(
        ["lambda_fn", "lambda_runtime"],
        [
            (
                TEST_LAMBDA_CACHE_NODEJS,
                LAMBDA_RUNTIME_NODEJS12X,
            ),  # TODO: can we do some kind of nested parametrize here?
            (TEST_LAMBDA_CACHE_PYTHON, LAMBDA_RUNTIME_PYTHON38),
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
            (TEST_LAMBDA_TIMEOUT_PYTHON, LAMBDA_RUNTIME_PYTHON38),
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
            (TEST_LAMBDA_TIMEOUT_PYTHON, LAMBDA_RUNTIME_PYTHON38),
        ],
        ids=["python"],
    )
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

        func_name = f"test_lambda_{short_uid()}"
        alias_name = f"test_alias_{short_uid()}"

        create_result = create_lambda_function(
            func_name=func_name,
            handler_file=TEST_LAMBDA_INTROSPECT_PYTHON,
            runtime=LAMBDA_RUNTIME_PYTHON38,
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
            runtime=LAMBDA_RUNTIME_PYTHON38,
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

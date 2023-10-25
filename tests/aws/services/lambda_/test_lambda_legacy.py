import base64
import json
import os.path

import pytest

from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api.lambda_ import Runtime
from localstack.constants import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME
from localstack.services.lambda_.legacy import lambda_api
from localstack.services.lambda_.legacy.lambda_api import (
    LAMBDA_TEST_ROLE,
    get_lambda_policy_name,
    use_docker,
)
from localstack.services.lambda_.legacy.lambda_utils import LAMBDA_DEFAULT_HANDLER
from localstack.services.lambda_.packages import lambda_go_runtime_package
from localstack.testing.aws.lambda_utils import is_new_provider, is_old_provider
from localstack.testing.pytest import markers
from localstack.utils import testutil
from localstack.utils.archives import download_and_extract
from localstack.utils.aws import arns, aws_stack
from localstack.utils.files import load_file
from localstack.utils.platform import get_arch, get_os
from localstack.utils.strings import short_uid, to_bytes, to_str
from localstack.utils.testutil import create_lambda_archive
from tests.aws.services.lambda_.test_lambda import (
    TEST_LAMBDA_PYTHON_ECHO,
    TEST_LAMBDA_RUBY,
    read_streams,
)

# TODO: remove these tests with 3.0 because they are only for the legacy provider and not aws-validated.
#   not worth fixing the unknown markers.
pytestmark = pytest.mark.skipif(
    condition=is_new_provider(), reason="only relevant for old provider"
)


# NOTE: We have a typo in the repository name "awslamba"
TEST_GOLANG_LAMBDA_URL_TEMPLATE = "https://github.com/localstack/awslamba-go-runtime/releases/download/v{version}/example-handler-{os}-{arch}.tar.gz"


def is_pro_enabled() -> bool:
    """Return whether the Pro extensions are enabled, i.e., restricted modules can be imported"""
    try:
        import localstack_ext.utils.common  # noqa

        return True
    except Exception:
        return False


# marker to indicate that a test should be skipped if the Pro extensions are enabled
skip_if_pro_enabled = pytest.mark.skipif(
    condition=is_pro_enabled(), reason="skipping, as Pro extensions are enabled"
)


@pytest.mark.parametrize(
    "handler_path",
    [
        os.path.join(os.path.dirname(__file__), "functions/lambda_logging.py"),
        os.path.join(os.path.dirname(__file__), "functions/lambda_print.py"),
    ],
    ids=["logging", "print"],
)
@markers.aws.unknown
def test_logging_in_local_executor(create_lambda_function, handler_path, aws_client):
    function_name = f"lambda_func-{short_uid()}"
    verification_token = f"verification_token-{short_uid()}"
    create_lambda_function(
        handler_file=handler_path,
        func_name=function_name,
        runtime=Runtime.python3_9,
    )

    invoke_result = aws_client.lambda_.invoke(
        FunctionName=function_name,
        LogType="Tail",
        Payload=to_bytes(json.dumps({"verification_token": verification_token})),
    )
    log_result = invoke_result["LogResult"]
    raw_logs = to_str(base64.b64decode(to_str(log_result)))
    assert verification_token in raw_logs
    result_payload_raw = invoke_result["Payload"].read().decode(encoding="utf-8")
    result_payload = json.loads(result_payload_raw)
    assert "verification_token" in result_payload
    assert result_payload["verification_token"] == verification_token


@pytest.mark.skipif(not is_old_provider(), reason="test does not make valid assertions against AWS")
class TestLambdaLegacyProvider:
    @markers.aws.unknown
    def test_add_lambda_multiple_permission(self, create_lambda_function, aws_client):
        """Test adding multiple permissions"""
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        # create lambda permissions
        action = "lambda:InvokeFunction"
        principal = "s3.amazonaws.com"
        statement_ids = ["s4", "s5"]
        for sid in statement_ids:
            resp = aws_client.lambda_.add_permission(
                FunctionName=function_name,
                Action=action,
                StatementId=sid,
                Principal=principal,
                SourceArn=arns.s3_bucket_arn("test-bucket"),
            )
            assert "Statement" in resp

        # fetch IAM policy
        # this is not a valid assertion in general (especially against AWS)
        policies = aws_client.iam.list_policies(Scope="Local", MaxItems=500)["Policies"]
        policy_name = get_lambda_policy_name(function_name)
        matching = [p for p in policies if p["PolicyName"] == policy_name]
        assert 1 == len(matching)
        assert ":policy/" in matching[0]["Arn"]

        # validate both statements
        policy = matching[0]
        versions = aws_client.iam.list_policy_versions(PolicyArn=policy["Arn"])["Versions"]
        assert 1 == len(versions)
        statements = versions[0]["Document"]["Statement"]
        for i in range(len(statement_ids)):
            assert action == statements[i]["Action"]
            assert (
                lambda_api.func_arn(TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME, function_name)
                == statements[i]["Resource"]
            )
            assert principal == statements[i]["Principal"]["Service"]
            assert (
                arns.s3_bucket_arn("test-bucket")
                == statements[i]["Condition"]["ArnLike"]["AWS:SourceArn"]
            )
            # check statement_ids in reverse order
            assert statement_ids[abs(i - 1)] == statements[i]["Sid"]

        # remove permission that we just added
        resp = aws_client.lambda_.remove_permission(
            FunctionName=function_name,
            StatementId=sid,
            Qualifier="qual1",
            RevisionId="r1",
        )
        assert 200 == resp["ResponseMetadata"]["HTTPStatusCode"]

    @markers.aws.unknown
    def test_add_lambda_permission(self, create_lambda_function, aws_client):
        function_name = f"lambda_func-{short_uid()}"
        lambda_create_response = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        lambda_arn = lambda_create_response["CreateFunctionResponse"]["FunctionArn"]
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

        # fetch lambda policy
        policy = aws_client.lambda_.get_policy(FunctionName=function_name)["Policy"]
        assert isinstance(policy, str)
        policy = json.loads(to_str(policy))
        assert action == policy["Statement"][0]["Action"]
        assert sid == policy["Statement"][0]["Sid"]
        assert lambda_arn == policy["Statement"][0]["Resource"]
        assert principal == policy["Statement"][0]["Principal"]["Service"]
        assert (
            arns.s3_bucket_arn("test-bucket")
            == policy["Statement"][0]["Condition"]["ArnLike"]["AWS:SourceArn"]
        )

        # fetch IAM policy
        # this is not a valid assertion in general (especially against AWS)
        policies = aws_client.iam.list_policies(Scope="Local", MaxItems=500)["Policies"]
        policy_name = get_lambda_policy_name(function_name)
        matching = [p for p in policies if p["PolicyName"] == policy_name]
        assert len(matching) == 1
        assert ":policy/" in matching[0]["Arn"]

        # remove permission that we just added
        resp = aws_client.lambda_.remove_permission(
            FunctionName=function_name,
            StatementId=sid,
            Qualifier="qual1",
            RevisionId="r1",
        )
        assert 200 == resp["ResponseMetadata"]["HTTPStatusCode"]

    # remove? be aware of partition check
    @markers.aws.unknown
    def test_create_lambda_function(self, aws_client):
        """Basic test that creates and deletes a Lambda function"""
        func_name = f"lambda_func-{short_uid()}"
        kms_key_arn = f"arn:{aws_stack.get_partition()}:kms:{aws_stack.get_region()}:{get_aws_account_id()}:key11"
        vpc_config = {
            "SubnetIds": ["subnet-123456789"],
            "SecurityGroupIds": ["sg-123456789"],
        }
        tags = {"env": "testing"}

        kwargs = {
            "FunctionName": func_name,
            "Runtime": Runtime.python3_7,
            "Handler": LAMBDA_DEFAULT_HANDLER,
            "Role": LAMBDA_TEST_ROLE.format(account_id=get_aws_account_id()),
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

        result = aws_client.lambda_.create_function(**kwargs)
        function_arn = result["FunctionArn"]
        assert testutil.response_arn_matches_partition(aws_client.lambda_, function_arn)

        partial_function_arn = ":".join(function_arn.split(":")[3:])

        # Get function by Name, ARN and partial ARN
        for func_ref in [func_name, function_arn, partial_function_arn]:
            rs = aws_client.lambda_.get_function(FunctionName=func_ref)
            assert rs["Configuration"].get("KMSKeyArn", "") == kms_key_arn
            assert rs["Configuration"].get("VpcConfig", {}) == vpc_config
            assert rs["Tags"] == tags

        # clean up
        aws_client.lambda_.delete_function(FunctionName=func_name)
        with pytest.raises(Exception) as exc:
            aws_client.lambda_.delete_function(FunctionName=func_name)
        assert "ResourceNotFoundException" in str(exc)

    @skip_if_pro_enabled
    @markers.aws.unknown
    def test_update_lambda_with_layers(self, create_lambda_function, aws_client):
        func_name = f"lambda-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=func_name,
            runtime=Runtime.python3_9,
        )

        # update function config with Layers - should be ignored (and not raise a serializer error)
        result = aws_client.lambda_.update_function_configuration(
            FunctionName=func_name, Layers=["foo:bar"]
        )
        assert "Layers" not in result


# Ruby and Golang runtimes aren't heavily used and therefore not covered by the complete test suite
# A legacy integration test can be found here
class TestRubyRuntimes:
    @pytest.mark.skipif(
        is_old_provider() and not use_docker(),
        reason="ruby runtimes not supported in local invocation",
    )
    @markers.snapshot.skip_snapshot_verify
    @markers.aws.validated
    # general invocation test
    def test_ruby_lambda_running_in_docker(self, create_lambda_function, snapshot, aws_client):
        """Test simple ruby lambda invocation"""

        function_name = f"test-function-{short_uid()}"
        create_result = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_RUBY,
            handler="lambda_integration.handler",
            runtime=Runtime.ruby2_7,
        )
        snapshot.match("create-result", create_result)
        result = aws_client.lambda_.invoke(FunctionName=function_name, Payload=b"{}")
        result = read_streams(result)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]

        assert 200 == result["StatusCode"]
        assert "{}" == to_str(result_data).strip()


class TestGolangRuntimes:
    @markers.snapshot.skip_snapshot_verify
    @markers.skip_offline
    @markers.aws.validated
    # general invocation test
    def test_golang_lambda(self, tmp_path, create_lambda_function, snapshot, aws_client):
        """Test simple golang lambda invocation"""

        # fetch platform-specific example handler
        url = TEST_GOLANG_LAMBDA_URL_TEMPLATE.format(
            version=lambda_go_runtime_package.default_version,
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
            runtime=Runtime.go1_x,
        )
        snapshot.match("create-result", create_result)

        # invoke
        result = aws_client.lambda_.invoke(
            FunctionName=func_name, Payload=json.dumps({"name": "pytest"})
        )
        result = read_streams(result)
        snapshot.match("invoke-result", result)
        result_data = result["Payload"]
        assert result["StatusCode"] == 200
        assert result_data.strip() == '"Hello pytest!"'

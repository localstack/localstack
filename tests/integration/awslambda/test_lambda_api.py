import json

import pytest
from botocore.exceptions import ClientError

from localstack.aws.api.lambda_ import Runtime
from localstack.services.awslambda import lambda_api
from localstack.services.awslambda.lambda_api import get_lambda_policy_name
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.strings import short_uid, to_str
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_PYTHON_ECHO, TEST_LAMBDA_LIBS, \
    TEST_LAMBDA_NODEJS
from localstack.testing.aws.lambda_utils import is_old_provider


@pytest.fixture(autouse=True)
def fixture_snapshot(snapshot):
    snapshot.add_transformer(snapshot.transform.lambda_api())


# API only functions (no lambda execution itself, i.e. no invoke)
class TestLambdaAPI:

    @pytest.mark.skip_snapshot_verify
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
            runtime=Runtime.python3_9,
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

    @pytest.mark.skip_snapshot_verify
    def test_remove_multi_permissions(self, lambda_client, create_lambda_function, snapshot):
        """Tests creation and subsequent removal of multiple permissions, including the changes in the policy"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
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

        with pytest.raises(ClientError) as e:
            lambda_client.remove_permission(
                FunctionName=function_name,
                StatementId="non-existent",
            )

        snapshot.match("expect_error_remove_permission", e.value.response)
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
        snapshot.match("expect_exception_get_policy", ctx.value.response)
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
            runtime=Runtime.python3_9,
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

    @pytest.mark.skip_snapshot_verify
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

        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"lambda_func-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
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

    @pytest.mark.skip(reason="Doesn't work when the account has a current global concurrency limit of < 101")
    def test_function_concurrency(self, lambda_client, create_lambda_function, snapshot):
        """Testing the api of the put function concurrency action"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"lambda_func-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )
        # TODO botocore.errorfactory.InvalidParameterValueException:
        #  An error occurred (InvalidParameterValueException) when calling the PutFunctionConcurrency operation: Specified ReservedConcurrentExecutions for function decreases account's UnreservedConcurrentExecution below its minimum value of [50].
        response = lambda_client.put_function_concurrency(
            FunctionName=function_name, ReservedConcurrentExecutions=123
        )
        snapshot.match("put_function_concurrency", response)
        assert "ReservedConcurrentExecutions" in response
        response = lambda_client.get_function_concurrency(FunctionName=function_name)
        snapshot.match("get_function_concurrency", response)
        assert "ReservedConcurrentExecutions" in response
        lambda_client.delete_function_concurrency(FunctionName=function_name)

    @pytest.mark.skip_snapshot_verify
    def test_function_code_signing_config(self, lambda_client, create_lambda_function, snapshot):
        """Testing the API of code signing config"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
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
                    f"arn:aws:signer:{aws_stack.get_region()}:000000000000:/signing-profiles/test",
                ]
            },
            CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Enforce"},
        )
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

    # TODO not executed
    def create_multiple_lambda_permissions(self, lambda_client, create_lambda_function, snapshot):
        """Test creating multiple lambda permissions and checking the policy"""

        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"test-function-{short_uid()}"

        # FIXME no zip file/function?
        create_lambda_function(
            func_name=function_name,
            runtime=Runtime.python3_7,
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

    @pytest.mark.aws_validated
    def test_url_config_lifecycle(self, lambda_client, create_lambda_function, snapshot):
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value(
                    "FunctionUrl", "lambda-url", reference_replacement=False
                ),
            ]
        )

        function_name = f"test-function-{short_uid()}"

        with pytest.raises(lambda_client.exceptions.ResourceNotFoundException) as ex:
            lambda_client.create_function_url_config(
                FunctionName=function_name,
                AuthType="NONE",
            )
        snapshot.match("failed_creation", ex.value.response)

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

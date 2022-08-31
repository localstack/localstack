import json

import pytest
from botocore.exceptions import ClientError

from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api.lambda_ import Runtime
from localstack.services.apigateway.helpers import path_based_url
from localstack.services.awslambda import lambda_api
from localstack.services.awslambda.lambda_api import (
    BATCH_SIZE_RANGES,
    INVALID_PARAMETER_VALUE_EXCEPTION,
    LAMBDA_TEST_ROLE,
    get_lambda_policy_name,
)
from localstack.services.awslambda.lambda_utils import (
    LAMBDA_DEFAULT_HANDLER,
    LAMBDA_RUNTIME_NODEJS14X,
    LAMBDA_RUNTIME_PYTHON37,
    LAMBDA_RUNTIME_PYTHON39,
)
from localstack.testing.aws.lambda_utils import _await_event_source_mapping_enabled, is_old_provider
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.files import load_file
from localstack.utils.http import safe_requests
from localstack.utils.strings import short_uid, to_str
from localstack.utils.sync import retry
from localstack.utils.testutil import (
    check_expected_lambda_log_events_length,
    create_lambda_archive,
    get_lambda_log_events,
)
from tests.integration.awslambda.test_lambda import (
    TEST_LAMBDA_LIBS,
    TEST_LAMBDA_NODEJS_APIGW_502,
    TEST_LAMBDA_PYTHON,
    TEST_LAMBDA_PYTHON_ECHO,
)


class TestLambdaHttpInvocation:
    def test_http_invocation_with_apigw_proxy(self, create_lambda_function):
        lambda_name = f"test_lambda_{short_uid()}"
        lambda_resource = "/api/v1/{proxy+}"
        lambda_path = "/api/v1/hello/world"
        lambda_request_context_path = "/" + "testing" + lambda_path
        lambda_request_context_resource_path = lambda_resource

        create_lambda_function(
            func_name=lambda_name,
            handler_file=TEST_LAMBDA_PYTHON,
            libs=TEST_LAMBDA_LIBS,
        )

        # create API Gateway and connect it to the Lambda proxy backend
        lambda_uri = aws_stack.lambda_function_arn(lambda_name)
        target_uri = f"arn:aws:apigateway:{aws_stack.get_region()}:lambda:path/2015-03-31/functions/{lambda_uri}/invocations"
        result = testutil.connect_api_gateway_to_http_with_lambda_proxy(
            "test_gateway2",
            target_uri,
            path=lambda_resource,
            stage_name="testing",
        )
        api_id = result["id"]
        url = path_based_url(api_id=api_id, stage_name="testing", path=lambda_path)
        result = safe_requests.post(
            url, data=b"{}", headers={"User-Agent": "python-requests/testing"}
        )
        content = json.loads(result.content)

        assert lambda_path == content["path"]
        assert lambda_resource == content["resource"]
        assert lambda_request_context_path == content["requestContext"]["path"]
        assert lambda_request_context_resource_path == content["requestContext"]["resourcePath"]

    def test_malformed_response_apigw_invocation(self, create_lambda_function, lambda_client):
        lambda_name = f"test_lambda_{short_uid()}"
        lambda_resource = "/api/v1/{proxy+}"
        lambda_path = "/api/v1/hello/world"

        create_lambda_function(
            func_name=lambda_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_NODEJS_APIGW_502, get_content=True),
            runtime=LAMBDA_RUNTIME_NODEJS14X,
            handler="apigw_502.handler",
        )

        lambda_uri = aws_stack.lambda_function_arn(lambda_name)
        target_uri = f"arn:aws:apigateway:{aws_stack.get_region()}:lambda:path/2015-03-31/functions/{lambda_uri}/invocations"
        result = testutil.connect_api_gateway_to_http_with_lambda_proxy(
            "test_gateway",
            target_uri,
            path=lambda_resource,
            stage_name="testing",
        )
        api_id = result["id"]
        url = path_based_url(api_id=api_id, stage_name="testing", path=lambda_path)
        result = safe_requests.get(url)

        assert result.status_code == 502
        assert result.headers.get("Content-Type") == "application/json"
        assert json.loads(result.content)["message"] == "Internal server error"


class TestSQSEventSourceMapping:
    # FIXME: refactor and move to test_lambda_sqs_integration

    @pytest.mark.skip_snapshot_verify
    def test_event_source_mapping_default_batch_size(
        self,
        create_lambda_function,
        lambda_client,
        sqs_create_queue,
        sqs_queue_arn,
        lambda_su_role,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"lambda_func-{short_uid()}"
        queue_name_1 = f"queue-{short_uid()}-1"
        queue_name_2 = f"queue-{short_uid()}-2"
        queue_url_1 = sqs_create_queue(QueueName=queue_name_1)
        queue_arn_1 = sqs_queue_arn(queue_url_1)

        try:
            create_lambda_function(
                func_name=function_name,
                handler_file=TEST_LAMBDA_PYTHON_ECHO,
                runtime=LAMBDA_RUNTIME_PYTHON39,
                role=lambda_su_role,
            )

            rs = lambda_client.create_event_source_mapping(
                EventSourceArn=queue_arn_1, FunctionName=function_name
            )
            snapshot.match("create-event-source-mapping", rs)

            uuid = rs["UUID"]
            assert BATCH_SIZE_RANGES["sqs"][0] == rs["BatchSize"]
            _await_event_source_mapping_enabled(lambda_client, uuid)

            with pytest.raises(ClientError) as e:
                # Update batch size with invalid value
                rs = lambda_client.update_event_source_mapping(
                    UUID=uuid,
                    FunctionName=function_name,
                    BatchSize=BATCH_SIZE_RANGES["sqs"][1] + 1,
                )
            snapshot.match("invalid-update-event-source-mapping", e.value.response)
            e.match(INVALID_PARAMETER_VALUE_EXCEPTION)

            queue_url_2 = sqs_create_queue(QueueName=queue_name_2)
            queue_arn_2 = sqs_queue_arn(queue_url_2)

            with pytest.raises(ClientError) as e:
                # Create event source mapping with invalid batch size value
                rs = lambda_client.create_event_source_mapping(
                    EventSourceArn=queue_arn_2,
                    FunctionName=function_name,
                    BatchSize=BATCH_SIZE_RANGES["sqs"][1] + 1,
                )
            snapshot.match("invalid-create-event-source-mapping", e.value.response)
            e.match(INVALID_PARAMETER_VALUE_EXCEPTION)
        finally:
            lambda_client.delete_event_source_mapping(UUID=uuid)

    @pytest.mark.aws_validated
    def test_sqs_event_source_mapping(
        self,
        create_lambda_function,
        lambda_client,
        sqs_client,
        sqs_create_queue,
        sqs_queue_arn,
        logs_client,
        lambda_su_role,
    ):
        function_name = f"lambda_func-{short_uid()}"
        queue_name_1 = f"queue-{short_uid()}-1"
        mapping_uuid = None

        try:
            create_lambda_function(
                func_name=function_name,
                handler_file=TEST_LAMBDA_PYTHON_ECHO,
                runtime=LAMBDA_RUNTIME_PYTHON37,
                role=lambda_su_role,
            )
            queue_url_1 = sqs_create_queue(QueueName=queue_name_1)
            queue_arn_1 = sqs_queue_arn(queue_url_1)
            mapping_uuid = lambda_client.create_event_source_mapping(
                EventSourceArn=queue_arn_1,
                FunctionName=function_name,
                MaximumBatchingWindowInSeconds=1,
            )["UUID"]
            _await_event_source_mapping_enabled(lambda_client, mapping_uuid)

            sqs_client.send_message(QueueUrl=queue_url_1, MessageBody=json.dumps({"foo": "bar"}))

            retry(
                check_expected_lambda_log_events_length,
                retries=10,
                sleep=1,
                function_name=function_name,
                expected_length=1,
                logs_client=logs_client,
            )

            rs = sqs_client.receive_message(QueueUrl=queue_url_1)
            assert rs.get("Messages") is None
        finally:
            if mapping_uuid:
                lambda_client.delete_event_source_mapping(UUID=mapping_uuid)

    @pytest.mark.aws_validated
    @pytest.mark.parametrize(
        "filter, item_matching, item_not_matching",
        [
            # test single filter
            (
                {"body": {"testItem": ["test24"]}},
                {"testItem": "test24"},
                {"testItem": "tesWER"},
            ),
            # test OR filter
            (
                {"body": {"testItem": ["test24", "test45"]}},
                {"testItem": "test45"},
                {"testItem": "WERTD"},
            ),
            # test AND filter
            (
                {"body": {"testItem": ["test24", "test45"], "test2": ["go"]}},
                {"testItem": "test45", "test2": "go"},
                {"testItem": "test67", "test2": "go"},
            ),
            # exists
            (
                {"body": {"test2": [{"exists": True}]}},
                {"test2": "7411"},
                {"test5": "74545"},
            ),
            # numeric (bigger)
            (
                {"body": {"test2": [{"numeric": [">", 100]}]}},
                {"test2": 105},
                "this is a test string",  # normal string should be dropped as well aka not fitting to filter
            ),
            # numeric (smaller)
            (
                {"body": {"test2": [{"numeric": ["<", 100]}]}},
                {"test2": 93},
                {"test2": 105},
            ),
            # numeric (range)
            (
                {"body": {"test2": [{"numeric": [">=", 100, "<", 200]}]}},
                {"test2": 105},
                {"test2": 200},
            ),
            # prefix
            (
                {"body": {"test2": [{"prefix": "us-1"}]}},
                {"test2": "us-1-48454"},
                {"test2": "eu-wert"},
            ),
        ],
    )
    def test_sqs_event_filter(
        self,
        create_lambda_function,
        lambda_client,
        sqs_client,
        sqs_create_queue,
        sqs_queue_arn,
        logs_client,
        lambda_su_role,
        filter,
        item_matching,
        item_not_matching,
    ):
        function_name = f"lambda_func-{short_uid()}"
        queue_name_1 = f"queue-{short_uid()}-1"
        mapping_uuid = None

        try:
            create_lambda_function(
                func_name=function_name,
                handler_file=TEST_LAMBDA_PYTHON_ECHO,
                runtime=LAMBDA_RUNTIME_PYTHON37,
                role=lambda_su_role,
            )
            queue_url_1 = sqs_create_queue(QueueName=queue_name_1)
            queue_arn_1 = sqs_queue_arn(queue_url_1)

            sqs_client.send_message(QueueUrl=queue_url_1, MessageBody=json.dumps(item_matching))
            sqs_client.send_message(
                QueueUrl=queue_url_1,
                MessageBody=json.dumps(item_not_matching)
                if not isinstance(item_not_matching, str)
                else item_not_matching,
            )

            def _assert_qsize():
                response = sqs_client.get_queue_attributes(
                    QueueUrl=queue_url_1, AttributeNames=["ApproximateNumberOfMessages"]
                )
                assert int(response["Attributes"]["ApproximateNumberOfMessages"]) == 2

            retry(_assert_qsize, retries=10)

            mapping_uuid = lambda_client.create_event_source_mapping(
                EventSourceArn=queue_arn_1,
                FunctionName=function_name,
                MaximumBatchingWindowInSeconds=1,
                FilterCriteria={
                    "Filters": [
                        {"Pattern": json.dumps(filter)},
                    ]
                },
            )["UUID"]
            _await_event_source_mapping_enabled(lambda_client, mapping_uuid)

            def _check_lambda_logs():
                events = get_lambda_log_events(function_name, logs_client=logs_client)
                # once invoked
                assert len(events) == 1
                records = events[0]["Records"]
                # one record processed
                assert len(records) == 1
                # check for correct record presence
                if "body" in json.dumps(filter):
                    item_matching_str = json.dumps(item_matching)
                    assert records[0]["body"] == item_matching_str

            retry(_check_lambda_logs, retries=10)

            rs = sqs_client.receive_message(QueueUrl=queue_url_1)
            assert rs.get("Messages") is None

        finally:
            if mapping_uuid:
                lambda_client.delete_event_source_mapping(UUID=mapping_uuid)

    @pytest.mark.aws_validated
    @pytest.mark.parametrize(
        "invalid_filter", [None, "simple string", {"eventSource": "aws:sqs"}, {"eventSource": []}]
    )
    def test_sqs_invalid_event_filter(
        self,
        create_lambda_function,
        sqs_create_queue,
        sqs_queue_arn,
        lambda_su_role,
        lambda_client,
        invalid_filter,
    ):
        function_name = f"lambda_func-{short_uid()}"
        queue_name_1 = f"queue-{short_uid()}"

        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=LAMBDA_RUNTIME_PYTHON37,
            role=lambda_su_role,
        )
        queue_url_1 = sqs_create_queue(QueueName=queue_name_1)
        queue_arn_1 = sqs_queue_arn(queue_url_1)

        with pytest.raises(Exception) as expected:
            lambda_client.create_event_source_mapping(
                EventSourceArn=queue_arn_1,
                FunctionName=function_name,
                MaximumBatchingWindowInSeconds=1,
                FilterCriteria={
                    "Filters": [
                        {
                            "Pattern": invalid_filter
                            if isinstance(invalid_filter, str)
                            else json.dumps(invalid_filter)
                        },
                    ]
                },
            )
        expected.match(INVALID_PARAMETER_VALUE_EXCEPTION)


class TestLambdaLegacyProvider:
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

    @pytest.mark.only_localstack
    def test_create_lambda_function(self, lambda_client):
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

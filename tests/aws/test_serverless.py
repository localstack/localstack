import json
import logging
import os

import pytest

from localstack.constants import TEST_AWS_ACCESS_KEY_ID, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.common import retry, run
from localstack.utils.testutil import get_lambda_log_events


def get_base_dir() -> str:
    return os.path.join(os.path.dirname(__file__), "serverless")


LOG = logging.getLogger(__name__)


class TestServerless:
    @pytest.fixture(scope="class")
    def delenv(self):
        # Workaround for the inability to use the standard `monkeypatch` fixture in `class` scope
        from _pytest.monkeypatch import MonkeyPatch

        mkypatch = MonkeyPatch()
        yield mkypatch.delenv
        mkypatch.undo()

    @pytest.fixture(scope="class")
    def setup_and_teardown(self, aws_client, delenv):
        if not is_aws_cloud():
            delenv("AWS_PROFILE", raising=False)
        base_dir = get_base_dir()
        if not os.path.exists(os.path.join(base_dir, "node_modules")):
            # install dependencies
            run(["npm", "install"], cwd=base_dir)

        # list apigateway before sls deployment
        apis = aws_client.apigateway.get_rest_apis()["items"]
        existing_api_ids = [api["id"] for api in apis]

        # deploy serverless app
        run(
            ["npm", "run", "deploy", "--", f"--region={TEST_AWS_REGION_NAME}"],
            cwd=base_dir,
            env_vars={"AWS_ACCESS_KEY_ID": TEST_AWS_ACCESS_KEY_ID},
        )

        yield existing_api_ids

        try:
            # TODO the cleanup still fails due to inability to find ECR service in community
            run(["npm", "run", "undeploy", "--", f"--region={TEST_AWS_REGION_NAME}"], cwd=base_dir)
        except Exception:
            LOG.error("Unable to clean up serverless stack")

    @markers.skip_offline
    @markers.aws.unknown
    def test_event_rules_deployed(self, aws_client, setup_and_teardown):
        events = aws_client.events
        rules = events.list_rules()["Rules"]

        rule = ([r for r in rules if r["Name"] == "sls-test-cf-event"] or [None])[0]
        assert rule
        assert "Arn" in rule
        pattern = json.loads(rule["EventPattern"])
        assert ["aws.cloudformation"] == pattern["source"]
        assert "detail-type" in pattern

        event_bus_name = "customBus"
        rule = events.list_rules(EventBusName=event_bus_name)["Rules"][0]
        assert rule
        assert {"source": ["customSource"]} == json.loads(rule["EventPattern"])

    @markers.skip_offline
    @markers.aws.unknown
    def test_dynamodb_stream_handler_deployed(self, aws_client, setup_and_teardown):
        function_name = "sls-test-local-dynamodbStreamHandler"
        table_name = "Test"

        lambda_client = aws_client.lambda_
        dynamodb_client = aws_client.dynamodb

        resp = lambda_client.list_functions()
        function = [fn for fn in resp["Functions"] if fn["FunctionName"] == function_name][0]
        assert "handler.processItem" == function["Handler"]

        resp = lambda_client.list_event_source_mappings(FunctionName=function_name)
        events = resp["EventSourceMappings"]
        assert 1 == len(events)
        event_source_arn = events[0]["EventSourceArn"]

        resp = dynamodb_client.describe_table(TableName=table_name)
        assert event_source_arn == resp["Table"]["LatestStreamArn"]

    @markers.skip_offline
    @markers.aws.unknown
    def test_kinesis_stream_handler_deployed(self, aws_client, setup_and_teardown):
        function_name = "sls-test-local-kinesisStreamHandler"
        function_name2 = "sls-test-local-kinesisConsumerHandler"
        stream_name = "KinesisTestStream"

        lambda_client = aws_client.lambda_
        kinesis_client = aws_client.kinesis

        resp = lambda_client.list_functions()
        function = [fn for fn in resp["Functions"] if fn["FunctionName"] == function_name][0]
        assert "handler.processKinesis" == function["Handler"]

        resp = lambda_client.list_event_source_mappings(FunctionName=function_name)
        mappings = resp["EventSourceMappings"]
        assert len(mappings) == 1
        event_source_arn = mappings[0]["EventSourceArn"]

        resp = kinesis_client.describe_stream(StreamName=stream_name)
        assert event_source_arn == resp["StreamDescription"]["StreamARN"]

        # assert that stream consumer is properly connected and Lambda gets invoked
        def assert_invocations():
            events = get_lambda_log_events(function_name2, logs_client=aws_client.logs)
            assert len(events) == 1

        kinesis_client.put_record(StreamName=stream_name, Data=b"test123", PartitionKey="key1")
        retry(assert_invocations, sleep=2, retries=20)

    @markers.skip_offline
    @markers.aws.unknown
    def test_queue_handler_deployed(self, aws_client, setup_and_teardown):
        function_name = "sls-test-local-queueHandler"
        queue_name = "sls-test-local-CreateQueue"

        lambda_client = aws_client.lambda_
        sqs_client = aws_client.sqs

        resp = lambda_client.list_functions()
        function = [fn for fn in resp["Functions"] if fn["FunctionName"] == function_name][0]
        assert "handler.createQueue" == function["Handler"]

        resp = lambda_client.list_event_source_mappings(FunctionName=function_name)
        events = resp["EventSourceMappings"]
        assert 1 == len(events)
        event_source_arn = events[0]["EventSourceArn"]

        queue_arn = arns.sqs_queue_arn(
            queue_name, account_id=TEST_AWS_ACCOUNT_ID, region_name=TEST_AWS_REGION_NAME
        )

        assert event_source_arn == queue_arn
        result = sqs_client.get_queue_attributes(
            QueueUrl=arns.sqs_queue_url_for_arn(queue_arn),
            AttributeNames=[
                "RedrivePolicy",
            ],
        )
        redrive_policy = json.loads(result["Attributes"]["RedrivePolicy"])
        assert 3 == redrive_policy["maxReceiveCount"]

    @markers.skip_offline
    @markers.aws.unknown
    def test_lambda_with_configs_deployed(self, aws_client, setup_and_teardown):
        function_name = "sls-test-local-test"

        lambda_client = aws_client.lambda_

        resp = lambda_client.list_functions()
        function = [fn for fn in resp["Functions"] if fn["FunctionName"] == function_name][0]
        assert "Version" in function
        version = function["Version"]

        resp = lambda_client.get_function_event_invoke_config(
            FunctionName=function_name, Qualifier=version
        )
        assert 2 == resp.get("MaximumRetryAttempts")
        assert 7200 == resp.get("MaximumEventAgeInSeconds")

    @markers.skip_offline
    @markers.aws.unknown
    def test_apigateway_deployed(self, aws_client, setup_and_teardown):
        function_name = "sls-test-local-router"
        existing_api_ids = setup_and_teardown

        lambda_client = aws_client.lambda_

        resp = lambda_client.list_functions()
        function = [fn for fn in resp["Functions"] if fn["FunctionName"] == function_name][0]
        assert "handler.createHttpRouter" == function["Handler"]

        apigw_client = aws_client.apigateway
        apis = apigw_client.get_rest_apis()["items"]
        api_ids = [api["id"] for api in apis if api["id"] not in existing_api_ids]
        assert 1 == len(api_ids)

        resources = apigw_client.get_resources(restApiId=api_ids[0])["items"]
        proxy_resources = [res for res in resources if res["path"] == "/foo/bar"]
        assert 1 == len(proxy_resources)

        proxy_resource = proxy_resources[0]
        for method in ["DELETE", "POST", "PUT"]:
            assert method in proxy_resource["resourceMethods"]
            resource_method = proxy_resource["resourceMethods"][method]
            assert (
                arns.lambda_function_arn(function_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)
                in resource_method["methodIntegration"]["uri"]
            )

    @markers.skip_offline
    @markers.aws.unknown
    def test_s3_bucket_deployed(self, aws_client, setup_and_teardown):
        s3_client = aws_client.s3
        bucket_name = "testing-bucket"
        response = s3_client.head_bucket(Bucket=bucket_name)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

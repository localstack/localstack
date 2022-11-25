import json
import os
import unittest

import pytest

from localstack.utils.aws import arns, aws_stack
from localstack.utils.common import retry, run
from localstack.utils.testutil import get_lambda_log_events


class TestServerless(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base_dir = cls.get_base_dir()
        if not os.path.exists(os.path.join(base_dir, "node_modules")):
            # install dependencies
            run(["npm", "install"], cwd=base_dir)

        # list apigateway before sls deployment
        apigw_client = aws_stack.create_external_boto_client("apigateway")
        apis = apigw_client.get_rest_apis()["items"]
        cls.api_ids = [api["id"] for api in apis]

        # deploy serverless app
        run(["npm", "run", "deploy", "--", f"--region={aws_stack.get_region()}"], cwd=base_dir)

    @classmethod
    def tearDownClass(cls):
        # TODO uncomment once removal via the sls plugin is fixed
        # run('cd %s; npm run undeploy -- --region=%s' % (cls.get_base_dir(), aws_stack.get_region()))
        pass

    @classmethod
    def get_base_dir(cls):
        return os.path.join(os.path.dirname(__file__), "serverless")

    @pytest.mark.skip_offline
    def test_event_rules_deployed(self):
        events = aws_stack.create_external_boto_client("events")
        rules = events.list_rules()["Rules"]

        rule = ([r for r in rules if r["Name"] == "sls-test-cf-event"] or [None])[0]
        self.assertTrue(rule)
        self.assertIn("Arn", rule)
        pattern = json.loads(rule["EventPattern"])
        self.assertEqual(["aws.cloudformation"], pattern["source"])
        self.assertIn("detail-type", pattern)

        rule = ([r for r in rules if r["EventBusName"] == "customBus"] or [None])[0]
        self.assertTrue(rule)
        self.assertEqual({"source": ["customSource"]}, json.loads(rule["EventPattern"]))

    @pytest.mark.skip_offline
    def test_dynamodb_stream_handler_deployed(self):
        function_name = "sls-test-local-dynamodbStreamHandler"
        table_name = "Test"

        lambda_client = aws_stack.create_external_boto_client("lambda")
        dynamodb_client = aws_stack.create_external_boto_client("dynamodb")

        resp = lambda_client.list_functions()
        function = [fn for fn in resp["Functions"] if fn["FunctionName"] == function_name][0]
        self.assertEqual("handler.processItem", function["Handler"])

        resp = lambda_client.list_event_source_mappings(FunctionName=function_name)
        events = resp["EventSourceMappings"]
        self.assertEqual(1, len(events))
        event_source_arn = events[0]["EventSourceArn"]

        resp = dynamodb_client.describe_table(TableName=table_name)
        self.assertEqual(event_source_arn, resp["Table"]["LatestStreamArn"])

    @pytest.mark.skip_offline
    def test_kinesis_stream_handler_deployed(self):
        function_name = "sls-test-local-kinesisStreamHandler"
        function_name2 = "sls-test-local-kinesisConsumerHandler"
        stream_name = "KinesisTestStream"

        lambda_client = aws_stack.create_external_boto_client("lambda")
        kinesis_client = aws_stack.create_external_boto_client("kinesis")

        resp = lambda_client.list_functions()
        function = [fn for fn in resp["Functions"] if fn["FunctionName"] == function_name][0]
        self.assertEqual("handler.processKinesis", function["Handler"])

        resp = lambda_client.list_event_source_mappings(FunctionName=function_name)
        mappings = resp["EventSourceMappings"]
        self.assertEqual(len(mappings), 1)
        event_source_arn = mappings[0]["EventSourceArn"]

        resp = kinesis_client.describe_stream(StreamName=stream_name)
        self.assertEqual(event_source_arn, resp["StreamDescription"]["StreamARN"])

        # assert that stream consumer is properly connected and Lambda gets invoked
        def assert_invocations():
            events = get_lambda_log_events(function_name2)
            self.assertEqual(len(events), 1)

        kinesis_client.put_record(StreamName=stream_name, Data=b"test123", PartitionKey="key1")
        retry(assert_invocations, sleep=2, retries=20)

    @pytest.mark.skip_offline
    def test_queue_handler_deployed(self):
        function_name = "sls-test-local-queueHandler"
        queue_name = "sls-test-local-CreateQueue"

        lambda_client = aws_stack.create_external_boto_client("lambda")
        sqs_client = aws_stack.create_external_boto_client("sqs")

        resp = lambda_client.list_functions()
        function = [fn for fn in resp["Functions"] if fn["FunctionName"] == function_name][0]
        self.assertEqual("handler.createQueue", function["Handler"])

        resp = lambda_client.list_event_source_mappings(FunctionName=function_name)
        events = resp["EventSourceMappings"]
        self.assertEqual(1, len(events))
        event_source_arn = events[0]["EventSourceArn"]

        self.assertEqual(event_source_arn, arns.sqs_queue_arn(queue_name))
        result = sqs_client.get_queue_attributes(
            QueueUrl=arns.get_sqs_queue_url(queue_name),
            AttributeNames=[
                "RedrivePolicy",
            ],
        )
        redrive_policy = json.loads(result["Attributes"]["RedrivePolicy"])
        self.assertEqual(3, redrive_policy["maxReceiveCount"])

    @pytest.mark.skip_offline
    def test_lambda_with_configs_deployed(self):
        function_name = "sls-test-local-test"

        lambda_client = aws_stack.create_external_boto_client("lambda")

        resp = lambda_client.list_functions()
        function = [fn for fn in resp["Functions"] if fn["FunctionName"] == function_name][0]
        self.assertIn("Version", function)
        version = function["Version"]

        resp = lambda_client.get_function_event_invoke_config(
            FunctionName=function_name, Qualifier=version
        )
        self.assertEqual(2, resp.get("MaximumRetryAttempts"))
        self.assertEqual(7200, resp.get("MaximumEventAgeInSeconds"))

    @pytest.mark.skip_offline
    def test_apigateway_deployed(self):
        function_name = "sls-test-local-router"

        lambda_client = aws_stack.create_external_boto_client("lambda")

        resp = lambda_client.list_functions()
        function = [fn for fn in resp["Functions"] if fn["FunctionName"] == function_name][0]
        self.assertEqual("handler.createHttpRouter", function["Handler"])

        apigw_client = aws_stack.create_external_boto_client("apigateway")
        apis = apigw_client.get_rest_apis()["items"]
        api_ids = [api["id"] for api in apis if api["id"] not in self.api_ids]
        self.assertEqual(1, len(api_ids))

        resources = apigw_client.get_resources(restApiId=api_ids[0])["items"]
        proxy_resources = [res for res in resources if res["path"] == "/foo/bar"]
        self.assertEqual(1, len(proxy_resources))

        proxy_resource = proxy_resources[0]
        for method in ["DELETE", "POST", "PUT"]:
            self.assertIn(method, proxy_resource["resourceMethods"])
            resource_method = proxy_resource["resourceMethods"][method]
            self.assertIn(
                arns.lambda_function_arn(function_name),
                resource_method["methodIntegration"]["uri"],
            )

    @pytest.mark.skip_offline
    def test_s3_bucket_deployed(self):
        s3_client = aws_stack.create_external_boto_client("s3")
        bucket_name = "testing-bucket"
        response = s3_client.head_bucket(Bucket=bucket_name)
        self.assertEqual(response["ResponseMetadata"]["HTTPStatusCode"], 200)

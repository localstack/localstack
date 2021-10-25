import io
import json
import os
import time
import unittest

import requests

from localstack import config
from localstack.services.generic_proxy import ProxyListener, start_proxy_server
from localstack.utils.aws import aws_stack
from localstack.utils.bootstrap import is_api_enabled
from localstack.utils.common import get_free_tcp_port, get_service_protocol, short_uid, to_str


class TestEdgeAPI(unittest.TestCase):
    def test_invoke_apis_via_edge(self):
        edge_url = config.get_edge_url()

        if is_api_enabled("s3"):
            self._invoke_s3_via_edge(edge_url)
            self._invoke_s3_via_edge_multipart_form(edge_url)
        if is_api_enabled("kinesis"):
            self._invoke_kinesis_via_edge(edge_url)
        if is_api_enabled("dynamodbstreams"):
            self._invoke_dynamodb_via_edge_go_sdk(edge_url)
        if is_api_enabled("dynamodbstreams"):
            self._invoke_dynamodbstreams_via_edge(edge_url)
        if is_api_enabled("firehose"):
            self._invoke_firehose_via_edge(edge_url)
        if is_api_enabled("stepfunctions"):
            self._invoke_stepfunctions_via_edge(edge_url)

    def _invoke_kinesis_via_edge(self, edge_url):
        client = aws_stack.connect_to_service("kinesis", endpoint_url=edge_url)
        result = client.list_streams()
        self.assertIn("StreamNames", result)

    def _invoke_dynamodbstreams_via_edge(self, edge_url):
        client = aws_stack.connect_to_service("dynamodbstreams", endpoint_url=edge_url)
        result = client.list_streams()
        self.assertIn("Streams", result)

    def _invoke_firehose_via_edge(self, edge_url):
        client = aws_stack.connect_to_service("firehose", endpoint_url=edge_url)
        result = client.list_delivery_streams()
        self.assertIn("DeliveryStreamNames", result)

    def _invoke_stepfunctions_via_edge(self, edge_url):
        client = aws_stack.connect_to_service("stepfunctions", endpoint_url=edge_url)
        result = client.list_state_machines()
        self.assertIn("stateMachines", result)

    def _invoke_dynamodb_via_edge_go_sdk(self, edge_url):
        client = aws_stack.connect_to_service("dynamodb")
        table_name = f"t-{short_uid()}"
        aws_stack.create_dynamodb_table(table_name, "id")

        # emulate a request sent from the AWS Go SDK v2
        headers = {
            "Host": "awsmock:4566",
            "User-Agent": "aws-sdk-go-v2/1.9.0 os/linux lang/go/1.16.7 md/GOOS/linux md/GOARCH/amd64 api/dynamodb/1.5.0",
            "Accept-Encoding": "identity",
            "Amz-Sdk-Invocation-Id": "af832536-dbc7-436e-9d6d-60840a0ff203",
            "Amz-Sdk-Request": "attempt=1; max=3",
            "Content-Type": "application/x-amz-json-1.0",
            "X-Amz-Target": "DynamoDB_20120810.DescribeTable",
        }
        data = json.dumps({"TableName": table_name})
        response = requests.post(edge_url, data=data, headers=headers)
        self.assertEqual(200, response.status_code)
        content = json.loads(to_str(response.content))
        assert content.get("Table")

        # clean up
        client.delete_table(TableName=table_name)

    def _invoke_s3_via_edge(self, edge_url):
        client = aws_stack.connect_to_service("s3", endpoint_url=edge_url)
        bucket_name = "edge-%s" % short_uid()

        client.create_bucket(Bucket=bucket_name)
        result = client.head_bucket(Bucket=bucket_name)
        self.assertEqual(200, result["ResponseMetadata"]["HTTPStatusCode"])
        client.delete_bucket(Bucket=bucket_name)

        bucket_name = "edge-%s" % short_uid()
        object_name = "testobject"
        bucket_url = "%s/%s" % (edge_url, bucket_name)
        result = requests.put(bucket_url, verify=False)
        self.assertEqual(200, result.status_code)
        result = client.head_bucket(Bucket=bucket_name)
        self.assertEqual(200, result["ResponseMetadata"]["HTTPStatusCode"])
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        result = requests.post(
            bucket_url,
            data="key=%s&file=file_content_123" % object_name,
            headers=headers,
            verify=False,
        )
        self.assertEqual(204, result.status_code)

        bucket_url = "%s/example" % bucket_url
        result = requests.put(bucket_url, data="hello", verify=False)
        self.assertEqual(200, result.status_code)

        result = io.BytesIO()
        client.download_fileobj(bucket_name, object_name, result)
        self.assertEqual("file_content_123", to_str(result.getvalue()))

    def _invoke_s3_via_edge_multipart_form(self, edge_url):
        client = aws_stack.connect_to_service("s3", endpoint_url=edge_url)
        bucket_name = "edge-%s" % short_uid()
        object_name = "testobject"
        object_data = b"testdata"

        client.create_bucket(Bucket=bucket_name)
        presigned_post = client.generate_presigned_post(bucket_name, object_name)

        files = {"file": object_data}
        r = requests.post(
            presigned_post["url"],
            data=presigned_post["fields"],
            files=files,
            verify=False,
        )
        self.assertEqual(204, r.status_code)

        result = io.BytesIO()
        client.download_fileobj(bucket_name, object_name, result)
        self.assertEqual(to_str(object_data), to_str(result.getvalue()))

        client.delete_object(Bucket=bucket_name, Key=object_name)
        client.delete_bucket(Bucket=bucket_name)

    def test_http2_traffic(self):
        port = get_free_tcp_port()

        class MyListener(ProxyListener):
            def forward_request(self, method, path, data, headers):
                return {"method": method, "path": path, "data": data}

        url = "https://localhost:%s/foo/bar" % port

        listener = MyListener()
        proxy = start_proxy_server(port, update_listener=listener, use_ssl=True)
        time.sleep(1)
        response = requests.post(url, verify=False)
        self.assertEqual(
            {"method": "POST", "path": "/foo/bar", "data": ""},
            json.loads(to_str(response.content)),
        )
        proxy.stop()

    def test_invoke_sns_sqs_integration_using_edge_port(self):
        edge_port = config.get_edge_port_http()
        region_original = os.environ.get("DEFAULT_REGION")
        os.environ["DEFAULT_REGION"] = "us-southeast-2"
        edge_url = "%s://localhost:%s" % (get_service_protocol(), edge_port)
        sns_client = aws_stack.connect_to_service("sns", endpoint_url=edge_url)
        sqs_client = aws_stack.connect_to_service("sqs", endpoint_url=edge_url)

        topic = sns_client.create_topic(Name="test_topic3")
        topic_arn = topic["TopicArn"]
        test_queue = sqs_client.create_queue(QueueName="test_queue3")

        queue_url = test_queue["QueueUrl"]
        sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
        sns_client.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_url)
        sns_client.publish(TargetArn=topic_arn, Message="Test msg")

        response = sqs_client.receive_message(
            QueueUrl=queue_url,
            AttributeNames=["SentTimestamp"],
            MaxNumberOfMessages=1,
            MessageAttributeNames=["All"],
            VisibilityTimeout=2,
            WaitTimeSeconds=2,
        )
        self.assertEqual(1, len(response["Messages"]))

        os.environ.pop("DEFAULT_REGION")
        if region_original is not None:
            os.environ["DEFAULT_REGION"] = region_original

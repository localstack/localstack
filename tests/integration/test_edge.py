import io
import json
import os
import time

import pytest
import requests
from requests.models import Request as RequestsRequest

from localstack import config
from localstack.constants import HEADER_LOCALSTACK_EDGE_URL
from localstack.services.generic_proxy import (
    MessageModifyingProxyListener,
    ProxyListener,
    start_proxy_server,
    update_path_in_url,
)
from localstack.services.messages import Request, Response
from localstack.utils.aws import aws_stack
from localstack.utils.bootstrap import is_api_enabled
from localstack.utils.common import get_free_tcp_port, short_uid, to_str


class TestEdgeAPI:
    @pytest.mark.skip(reason="Challenger: Test uses S3 via edge API (not supported yet)")
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
        client = aws_stack.create_external_boto_client("kinesis", endpoint_url=edge_url)
        result = client.list_streams()
        assert "StreamNames" in result

    def _invoke_dynamodbstreams_via_edge(self, edge_url):
        client = aws_stack.create_external_boto_client("dynamodbstreams", endpoint_url=edge_url)
        result = client.list_streams()
        assert "Streams" in result

    def _invoke_firehose_via_edge(self, edge_url):
        client = aws_stack.create_external_boto_client("firehose", endpoint_url=edge_url)
        result = client.list_delivery_streams()
        assert "DeliveryStreamNames" in result

    def _invoke_stepfunctions_via_edge(self, edge_url):
        client = aws_stack.create_external_boto_client("stepfunctions", endpoint_url=edge_url)
        result = client.list_state_machines()
        assert "stateMachines" in result

    def _invoke_dynamodb_via_edge_go_sdk(self, edge_url):
        client = aws_stack.create_external_boto_client("dynamodb")
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
        assert response.status_code == 200
        content = json.loads(to_str(response.content))
        assert content.get("Table")

        # clean up
        client.delete_table(TableName=table_name)

    def _invoke_s3_via_edge(self, edge_url):
        client = aws_stack.create_external_boto_client("s3", endpoint_url=edge_url)
        bucket_name = "edge-%s" % short_uid()

        client.create_bucket(Bucket=bucket_name)
        result = client.head_bucket(Bucket=bucket_name)
        assert result["ResponseMetadata"]["HTTPStatusCode"] == 200
        client.delete_bucket(Bucket=bucket_name)

        bucket_name = "edge-%s" % short_uid()
        object_name = "testobject"
        bucket_url = "%s/%s" % (edge_url, bucket_name)
        result = requests.put(bucket_url, verify=False)
        assert result.status_code == 200
        result = client.head_bucket(Bucket=bucket_name)
        assert result["ResponseMetadata"]["HTTPStatusCode"] == 200
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        result = requests.post(
            bucket_url,
            data="key=%s&file=file_content_123" % object_name,
            headers=headers,
            verify=False,
        )
        assert result.status_code == 204

        bucket_url = "%s/example" % bucket_url
        result = requests.put(bucket_url, data="hello", verify=False)
        assert result.status_code == 200

        result = io.BytesIO()
        client.download_fileobj(bucket_name, object_name, result)
        assert to_str(result.getvalue()) == "file_content_123"

    def _invoke_s3_via_edge_multipart_form(self, edge_url):
        client = aws_stack.create_external_boto_client("s3", endpoint_url=edge_url)
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
        assert r.status_code == 204

        result = io.BytesIO()
        client.download_fileobj(bucket_name, object_name, result)
        assert to_str(result.getvalue()) == to_str(object_data)

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
        expected = {"method": "POST", "path": "/foo/bar", "data": ""}
        assert json.loads(to_str(response.content)) == expected
        proxy.stop()

    def test_invoke_sns_sqs_integration_using_edge_port(
        self, sqs_create_queue, sqs_client, sns_client, sns_create_topic
    ):
        topic_name = f"topic-{short_uid()}"
        queue_name = f"queue-{short_uid()}"

        region_original = os.environ.get("DEFAULT_REGION")
        os.environ["DEFAULT_REGION"] = "us-southeast-2"

        topic = sns_client.create_topic(Name=topic_name)
        topic_arn = topic["TopicArn"]
        queue_url = sqs_create_queue(QueueName=queue_name)
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
        assert len(response["Messages"]) == 1

        os.environ.pop("DEFAULT_REGION")
        if region_original is not None:
            os.environ["DEFAULT_REGION"] = region_original

    def test_message_modifying_handler(self, s3_client, monkeypatch):
        class MessageModifier(MessageModifyingProxyListener):
            def forward_request(self, method, path: str, data, headers):
                if method != "HEAD":
                    return Request(path=path.replace(bucket_name, f"{bucket_name}-patched"))

            def return_response(self, method, path, data, headers, response):
                if method == "HEAD":
                    return Response(status_code=201)
                content = to_str(response.content or "")
                if "test content" in content:
                    return Response(content=content + " patched")

        updated_handlers = list(ProxyListener.DEFAULT_LISTENERS) + [MessageModifier()]
        monkeypatch.setattr(ProxyListener, "DEFAULT_LISTENERS", updated_handlers)

        # create S3 bucket, assert that patched bucket name is used
        bucket_name = f"b-{short_uid()}"
        s3_client.create_bucket(Bucket=bucket_name)
        buckets = [b["Name"] for b in s3_client.list_buckets()["Buckets"]]
        assert f"{bucket_name}-patched" in buckets
        assert f"{bucket_name}" not in buckets
        result = s3_client.head_bucket(Bucket=f"{bucket_name}-patched")
        assert result["ResponseMetadata"]["HTTPStatusCode"] == 201

        # put content, assert that patched content is returned
        key = "test/1/2/3"
        s3_client.put_object(Bucket=bucket_name, Key=key, Body=b"test content 123")
        result = s3_client.get_object(Bucket=bucket_name, Key=key)
        content = to_str(result["Body"].read())
        assert " patched" in content

    def test_handler_returning_none_method(self, s3_client, monkeypatch):
        class MessageModifier(ProxyListener):
            def forward_request(self, method, path: str, data, headers):
                # simple heuristic to determine whether we are in the context of an edge call, or service request
                is_edge_request = not headers.get(HEADER_LOCALSTACK_EDGE_URL)
                if not is_edge_request and method == "PUT" and len(path.split("/")) > 3:
                    # simple test that asserts we can forward a Request object with only URL and empty/None method
                    return RequestsRequest(method=None, data=to_str(data) + " patched")
                return True

        updated_handlers = list(ProxyListener.DEFAULT_LISTENERS) + [MessageModifier()]
        monkeypatch.setattr(ProxyListener, "DEFAULT_LISTENERS", updated_handlers)

        # prepare bucket and test object
        bucket_name = f"b-{short_uid()}"
        key = "test/1/2/3"
        s3_client.create_bucket(Bucket=bucket_name)
        s3_client.put_object(Bucket=bucket_name, Key=key, Body=b"test content 123")

        # get content, assert that content has been patched
        result = s3_client.get_object(Bucket=bucket_name, Key=key)
        content = to_str(result["Body"].read())
        assert " patched" in content

    def test_update_path_in_url(self):
        assert update_path_in_url("http://foo:123", "/bar/1/2/3") == "http://foo:123/bar/1/2/3"
        assert update_path_in_url("http://foo:123/", "/bar/1/2/3") == "http://foo:123/bar/1/2/3"
        assert (
            update_path_in_url("http://foo:123/test", "/bar/1/2/3?p1#h")
            == "http://foo:123/bar/1/2/3?p1#h"
        )
        assert update_path_in_url("http://foo:123/test", "bar/1/2/3") == "http://foo:123/bar/1/2/3"
        assert (
            update_path_in_url("https://foo:123/test", "bar/1/2/3") == "https://foo:123/bar/1/2/3"
        )
        assert update_path_in_url("http://foo:123/test", "/") == "http://foo:123/"
        assert update_path_in_url("//foo:123/test/123", "bar/1/2/3") == "//foo:123/bar/1/2/3"

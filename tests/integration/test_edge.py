# FIXME: these are remnants of the legacy edge proxy. these tests should somehow be migrated to
#  instead either test the LocalstackAwsGateway (integration), or functionality of the http server (unit).
import io
import json
import os

import pytest
import requests
import xmltodict

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.constants import APPLICATION_JSON
from localstack.services.generic_proxy import (
    ProxyListener,
    start_proxy_server,
    update_path_in_url,
)
from localstack.utils.aws import aws_stack, resources
from localstack.utils.common import get_free_tcp_port, short_uid, to_str
from localstack.utils.xml import strip_xmlns


class TestEdgeAPI:
    def test_invoke_kinesis(self, aws_client_factory):
        edge_url = config.get_edge_url()
        client = aws_client_factory(endpoint_url=edge_url).kinesis
        self._invoke_kinesis_via_edge(client)

    def test_invoke_dynamodb(self, aws_client_factory):
        edge_url = config.get_edge_url()
        client = aws_client_factory(endpoint_url=edge_url).dynamodb
        self._invoke_dynamodb_via_edge_go_sdk(edge_url, client)

    def test_invoke_dynamodbstreams(self, aws_client_factory):
        edge_url = config.get_edge_url()
        client = aws_client_factory(endpoint_url=edge_url).dynamodbstreams
        self._invoke_dynamodbstreams_via_edge(client)

    def test_invoke_firehose(self, aws_client_factory):
        edge_url = config.get_edge_url()
        client = aws_client_factory(endpoint_url=edge_url).firehose
        self._invoke_firehose_via_edge(client)

    def test_invoke_stepfunctions(self, aws_client_factory):
        edge_url = config.get_edge_url()
        client = aws_client_factory(endpoint_url=edge_url).stepfunctions
        self._invoke_stepfunctions_via_edge(client)

    def test_invoke_s3(self, aws_client_factory):
        edge_url = config.get_edge_url()
        client = aws_client_factory(endpoint_url=edge_url).s3
        self._invoke_s3_via_edge(edge_url, client)

    @pytest.mark.xfail(reason="failing in CI")  # TODO verify this
    def test_invoke_s3_multipart_request(self, aws_client_factory):
        edge_url = config.get_edge_url()
        client = aws_client_factory(endpoint_url=edge_url).s3
        self._invoke_s3_via_edge_multipart_form(client)

    def _invoke_kinesis_via_edge(self, client):
        result = client.list_streams()
        assert "StreamNames" in result

    def _invoke_dynamodbstreams_via_edge(self, client):
        result = client.list_streams()
        assert "Streams" in result

    def _invoke_firehose_via_edge(self, client):
        result = client.list_delivery_streams()
        assert "DeliveryStreamNames" in result

    def _invoke_stepfunctions_via_edge(self, client):
        result = client.list_state_machines()
        assert "stateMachines" in result

    def _invoke_dynamodb_via_edge_go_sdk(self, edge_url, client):
        table_name = f"t-{short_uid()}"
        resources.create_dynamodb_table(table_name, "id", client=client)

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

    def _invoke_s3_via_edge(self, edge_url, client):
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

    def _invoke_s3_via_edge_multipart_form(self, client):
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

    def test_basic_https_invocation(self):
        class MyListener(ProxyListener):
            def forward_request(self, method, path, data, headers):
                return {"method": method, "path": path, "data": data}

        port = get_free_tcp_port()
        url = f"https://localhost:{port}/foo/bar"

        listener = MyListener()
        proxy = start_proxy_server(port, update_listener=listener, use_ssl=True)
        response = requests.post(url, verify=False)
        expected = {"method": "POST", "path": "/foo/bar", "data": ""}
        assert json.loads(to_str(response.content)) == expected
        proxy.stop()

    def test_http2_relay_traffic(self):
        """Tests if HTTP2 traffic can correctly be forwarded (including url-encoded characters)."""

        # Create a simple HTTP echo server
        class MyListener(ProxyListener):
            def forward_request(self, method, path, data, headers):
                return {"method": method, "path": path, "data": data}

        listener = MyListener()
        port_http_server = get_free_tcp_port()
        http_server = start_proxy_server(port_http_server, update_listener=listener, use_ssl=True)

        # Create a relay proxy which forwards request to the HTTP echo server
        port_relay_proxy = get_free_tcp_port()
        forward_url = f"https://localhost:{port_http_server}"
        relay_proxy = start_proxy_server(port_relay_proxy, forward_url=forward_url, use_ssl=True)

        # Contact the relay proxy
        query = "%2B=%3B%2C%2F%3F%3A%40%26%3D%2B%24%21%2A%27%28%29%23"
        path = f"/foo/bar%3B%2C%2F%3F%3A%40%26%3D%2B%24%21%2A%27%28%29%23baz?{query}"
        url = f"https://localhost:{port_relay_proxy}{path}"
        response = requests.post(url, verify=False)

        # Expect the response from the HTTP echo server
        expected = {
            "method": "POST",
            "path": path,
            "data": "",
        }
        assert json.loads(to_str(response.content)) == expected

        http_server.stop()
        relay_proxy.stop()

    def test_invoke_sns_sqs_integration_using_edge_port(
        self, sqs_create_queue, sns_create_topic, sns_create_sqs_subscription, aws_client
    ):
        topic_name = f"topic-{short_uid()}"
        queue_name = f"queue-{short_uid()}"

        region_original = os.environ.get("DEFAULT_REGION")
        os.environ["DEFAULT_REGION"] = "us-southeast-2"

        topic = aws_client.sns.create_topic(Name=topic_name)
        topic_arn = topic["TopicArn"]
        queue_url = sqs_create_queue(QueueName=queue_name)
        aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        aws_client.sns.publish(TargetArn=topic_arn, Message="Test msg")

        response = aws_client.sqs.receive_message(
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

    def test_response_content_type(self):
        url = config.get_edge_url()
        data = {"Action": "GetCallerIdentity", "Version": "2011-06-15"}

        # receive response as XML (default)
        headers = aws_stack.mock_aws_request_headers("sts")
        response = requests.post(url, data=data, headers=headers)
        assert response
        content1 = to_str(response.content)
        with pytest.raises(json.decoder.JSONDecodeError):
            json.loads(content1)
        content1 = xmltodict.parse(content1)
        content1_result = content1["GetCallerIdentityResponse"]["GetCallerIdentityResult"]
        assert content1_result["Account"] == get_aws_account_id()

        # receive response as JSON (via Accept header)
        headers = aws_stack.mock_aws_request_headers("sts")
        headers["Accept"] = APPLICATION_JSON
        response = requests.post(url, data=data, headers=headers)
        assert response
        content2 = json.loads(to_str(response.content))
        content2_result = content2["GetCallerIdentityResponse"]["GetCallerIdentityResult"]
        assert content2_result["Account"] == get_aws_account_id()
        content1.get("GetCallerIdentityResponse", {}).pop("ResponseMetadata", None)
        content2.get("GetCallerIdentityResponse", {}).pop("ResponseMetadata", None)
        assert strip_xmlns(content1) == content2

    def test_request_with_custom_host_header(self):
        url = config.get_edge_url()

        headers = aws_stack.mock_aws_request_headers("lambda")

        # using a simple for-loop here (instead of pytest parametrization), for simplicity
        for host in ["localhost", "example.com"]:
            for port in ["", ":123", f":{config.EDGE_PORT}"]:
                headers["Host"] = f"{host}{port}"
                response = requests.get(f"{url}/2015-03-31/functions", headers=headers)
                assert response
                assert "Functions" in json.loads(to_str(response.content))

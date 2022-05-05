# -*- coding: utf-8 -*-
import base64
import json
import os
import re
import unittest
from collections import namedtuple
from typing import Callable, Optional
from unittest.mock import patch

import pytest
import xmltodict
from botocore.exceptions import ClientError
from jsonpatch import apply_patch
from moto.apigateway.models import APIGatewayBackend
from requests.models import Response
from requests.structures import CaseInsensitiveDict

from localstack import config
from localstack.constants import (
    APPLICATION_JSON,
    HEADER_LOCALSTACK_REQUEST_URL,
    LOCALHOST_HOSTNAME,
    TEST_AWS_ACCOUNT_ID,
)
from localstack.services.apigateway.helpers import (
    TAG_KEY_CUSTOM_ID,
    connect_api_gateway_to_sqs,
    get_resource_for_path,
    get_rest_api_paths,
    import_api_from_openapi_spec,
    path_based_url,
)
from localstack.services.awslambda.lambda_api import add_event_source, use_docker
from localstack.services.awslambda.lambda_utils import (
    LAMBDA_RUNTIME_NODEJS12X,
    LAMBDA_RUNTIME_PYTHON36,
)
from localstack.services.generic_proxy import ProxyListener
from localstack.services.infra import start_proxy
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import clone, get_free_tcp_port, json_safe, load_file
from localstack.utils.common import safe_requests as requests
from localstack.utils.common import select_attributes, short_uid, to_str

from ..unit.test_apigateway import load_test_resource
from .awslambda.test_lambda import (
    TEST_LAMBDA_HTTP_RUST,
    TEST_LAMBDA_LIBS,
    TEST_LAMBDA_NODEJS,
    TEST_LAMBDA_PYTHON,
    TEST_LAMBDA_PYTHON_ECHO,
)

APIGATEWAY_ASSUME_ROLE_POLICY = {
    "Statement": {
        "Sid": "",
        "Effect": "Allow",
        "Principal": {"Service": "apigateway.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }
}
APIGATEWAY_LAMBDA_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"}],
}

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_SWAGGER_FILE_JSON = os.path.join(THIS_FOLDER, "files", "swagger.json")
TEST_SWAGGER_FILE_YAML = os.path.join(THIS_FOLDER, "files", "swagger.yaml")
TEST_IMPORT_REST_API_FILE = os.path.join(THIS_FOLDER, "files", "pets.json")

ApiGatewayLambdaProxyIntegrationTestResult = namedtuple(
    "ApiGatewayLambdaProxyIntegrationTestResult",
    [
        "data",
        "resource",
        "result",
        "url",
        "path_with_replace",
    ],
)


class TestAPIGateway(unittest.TestCase):
    # template used to transform incoming requests at the API Gateway (stream name to be filled in later)
    APIGATEWAY_DATA_INBOUND_TEMPLATE = """{
        "StreamName": "%s",
        "Records": [
            #set( $numRecords = $input.path('$.records').size() )
            #if($numRecords > 0)
            #set( $maxIndex = $numRecords - 1 )
            #foreach( $idx in [0..$maxIndex] )
            #set( $elem = $input.path("$.records[${idx}]") )
            #set( $elemJsonB64 = $util.base64Encode($elem.data) )
            {
                "Data": "$elemJsonB64",
                "PartitionKey": #if( $elem.partitionKey != '')"$elem.partitionKey"
                                #else"$elemJsonB64.length()"#end
            }#if($foreach.hasNext),#end
            #end
            #end
        ]
    }"""

    # endpoint paths
    API_PATH_DATA_INBOUND = "/data"
    API_PATH_HTTP_BACKEND = "/hello_world"
    API_PATH_LAMBDA_PROXY_BACKEND = "/lambda/foo1"
    API_PATH_LAMBDA_PROXY_BACKEND_WITH_PATH_PARAM = "/lambda/{test_param1}"

    API_PATH_LAMBDA_PROXY_BACKEND_ANY_METHOD = "/lambda-any-method/foo1"
    API_PATH_LAMBDA_PROXY_BACKEND_ANY_METHOD_WITH_PATH_PARAM = "/lambda-any-method/{test_param1}"

    API_PATH_LAMBDA_PROXY_BACKEND_WITH_IS_BASE64 = "/lambda-is-base64/foo1"

    # name of Kinesis stream connected to API Gateway
    TEST_STREAM_KINESIS_API_GW = "test-stream-api-gw"
    TEST_STAGE_NAME = "testing"
    TEST_LAMBDA_PROXY_BACKEND = "test_lambda_apigw_backend"
    TEST_LAMBDA_PROXY_BACKEND_WITH_PATH_PARAM = "test_lambda_apigw_backend_path_param"
    TEST_LAMBDA_PROXY_BACKEND_ANY_METHOD = "test_lambda_apigw_backend_any_method"
    TEST_LAMBDA_PROXY_BACKEND_ANY_METHOD_WITH_PATH_PARAM = (
        "test_lambda_apigw_backend_any_method_path_param"
    )
    TEST_LAMBDA_PROXY_BACKEND_WITH_IS_BASE64 = "test_lambda_apigw_backend_with_is_base64"
    TEST_LAMBDA_SQS_HANDLER_NAME = "lambda_sqs_handler"
    TEST_LAMBDA_AUTHORIZER_HANDLER_NAME = "lambda_authorizer_handler"
    TEST_API_GATEWAY_ID = "fugvjdxtri"

    TEST_API_GATEWAY_AUTHORIZER = {
        "name": "test",
        "type": "TOKEN",
        "providerARNs": ["arn:aws:cognito-idp:us-east-1:123412341234:userpool/us-east-1_123412341"],
        "authType": "custom",
        "authorizerUri": "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/"
        + "arn:aws:lambda:us-east-1:123456789012:function:myApiAuthorizer/invocations",
        "authorizerCredentials": "arn:aws:iam::123456789012:role/apigAwsProxyRole",
        "identitySource": "method.request.header.Authorization",
        "identityValidationExpression": ".*",
        "authorizerResultTtlInSeconds": 300,
    }
    TEST_API_GATEWAY_AUTHORIZER_OPS = [{"op": "replace", "path": "/name", "value": "test1"}]

    def test_create_rest_api_with_custom_id(self):
        client = aws_stack.create_external_boto_client("apigateway")
        apigw_name = "gw-%s" % short_uid()
        test_id = "testId123"
        result = client.create_rest_api(name=apigw_name, tags={TAG_KEY_CUSTOM_ID: test_id})
        self.assertEqual(test_id, result["id"])
        self.assertEqual(apigw_name, result["name"])
        result = client.get_rest_api(restApiId=test_id)
        self.assertEqual(test_id, result["id"])
        self.assertEqual(apigw_name, result["name"])

    def test_api_gateway_kinesis_integration(self):
        # create target Kinesis stream
        stream = aws_stack.create_kinesis_stream(self.TEST_STREAM_KINESIS_API_GW)
        stream.wait_for()

        # create API Gateway and connect it to the target stream
        result = self.connect_api_gateway_to_kinesis(
            "test_gateway1", self.TEST_STREAM_KINESIS_API_GW
        )

        # generate test data
        test_data = {
            "records": [
                {"data": '{"foo": "bar1"}'},
                {"data": '{"foo": "bar2"}'},
                {"data": '{"foo": "bar3"}'},
            ]
        }

        url = path_based_url(
            api_id=result["id"],
            stage_name=self.TEST_STAGE_NAME,
            path=self.API_PATH_DATA_INBOUND,
        )

        # list Kinesis streams via API Gateway
        result = requests.get(url)
        result = json.loads(to_str(result.content))
        self.assertIn("StreamNames", result)

        # post test data to Kinesis via API Gateway
        result = requests.post(url, data=json.dumps(test_data))
        result = json.loads(to_str(result.content))
        self.assertEqual(0, result["FailedRecordCount"])
        self.assertEqual(len(test_data["records"]), len(result["Records"]))

        # clean up
        kinesis = aws_stack.create_external_boto_client("kinesis")
        kinesis.delete_stream(StreamName=self.TEST_STREAM_KINESIS_API_GW)

    def test_api_gateway_sqs_integration_with_event_source(self):
        # create target SQS stream
        queue_name = "queue-%s" % short_uid()
        queue_url = aws_stack.create_sqs_queue(queue_name)["QueueUrl"]

        # create API Gateway and connect it to the target queue
        result = connect_api_gateway_to_sqs(
            "test_gateway4",
            stage_name=self.TEST_STAGE_NAME,
            queue_arn=queue_name,
            path=self.API_PATH_DATA_INBOUND,
        )

        # create event source for sqs lambda processor
        self.create_lambda_function(self.TEST_LAMBDA_SQS_HANDLER_NAME)
        event_source_data = {
            "FunctionName": self.TEST_LAMBDA_SQS_HANDLER_NAME,
            "EventSourceArn": aws_stack.sqs_queue_arn(queue_name),
            "Enabled": True,
        }
        add_event_source(event_source_data)

        # generate test data
        test_data = {"spam": "eggs & beans"}

        url = path_based_url(
            api_id=result["id"],
            stage_name=self.TEST_STAGE_NAME,
            path=self.API_PATH_DATA_INBOUND,
        )
        result = requests.post(url, data=json.dumps(test_data))
        self.assertEqual(200, result.status_code)

        parsed_json = xmltodict.parse(result.content)
        result = parsed_json["SendMessageResponse"]["SendMessageResult"]

        body_md5 = result["MD5OfMessageBody"]

        self.assertEqual("b639f52308afd65866c86f274c59033f", body_md5)

        # clean up
        sqs_client = aws_stack.create_external_boto_client("sqs")
        sqs_client.delete_queue(QueueUrl=queue_url)

        lambda_client = aws_stack.create_external_boto_client("lambda")
        lambda_client.delete_function(FunctionName=self.TEST_LAMBDA_SQS_HANDLER_NAME)

    def test_api_gateway_sqs_integration(self):
        # create target SQS stream
        queue_name = "queue-%s" % short_uid()
        aws_stack.create_sqs_queue(queue_name)

        # create API Gateway and connect it to the target queue
        result = connect_api_gateway_to_sqs(
            "test_gateway4",
            stage_name=self.TEST_STAGE_NAME,
            queue_arn=queue_name,
            path=self.API_PATH_DATA_INBOUND,
        )

        # generate test data
        test_data = {"spam": "eggs"}

        url = path_based_url(
            api_id=result["id"],
            stage_name=self.TEST_STAGE_NAME,
            path=self.API_PATH_DATA_INBOUND,
        )
        result = requests.post(url, data=json.dumps(test_data))
        self.assertEqual(200, result.status_code)

        messages = aws_stack.sqs_receive_message(queue_name)["Messages"]
        self.assertEqual(1, len(messages))
        self.assertEqual(test_data, json.loads(base64.b64decode(messages[0]["Body"])))

    def test_api_gateway_http_integrations(self):
        self.run_api_gateway_http_integration("custom")
        self.run_api_gateway_http_integration("proxy")

    @patch.object(config, "DISABLE_CUSTOM_CORS_APIGATEWAY", False)
    def run_api_gateway_http_integration(self, int_type):
        test_port = get_free_tcp_port()
        backend_url = "http://localhost:%s%s" % (test_port, self.API_PATH_HTTP_BACKEND)

        # start test HTTP backend
        proxy = self.start_http_backend(test_port)

        # create API Gateway and connect it to the HTTP_PROXY/HTTP backend
        result = self.connect_api_gateway_to_http(
            int_type, "test_gateway2", backend_url, path=self.API_PATH_HTTP_BACKEND
        )

        url = path_based_url(
            api_id=result["id"],
            stage_name=self.TEST_STAGE_NAME,
            path=self.API_PATH_HTTP_BACKEND,
        )

        # make sure CORS headers are present
        origin = "localhost"
        result = requests.options(url, headers={"origin": origin})
        self.assertEqual(result.status_code, 200)
        self.assertTrue(
            re.match(result.headers["Access-Control-Allow-Origin"].replace("*", ".*"), origin)
        )
        self.assertIn("POST", result.headers["Access-Control-Allow-Methods"])
        self.assertIn("PATCH", result.headers["Access-Control-Allow-Methods"])

        custom_result = json.dumps({"foo": "bar"})

        # make test GET request to gateway
        result = requests.get(url)
        self.assertEqual(200, result.status_code)
        expected = custom_result if int_type == "custom" else "{}"
        self.assertEqual(expected, json.loads(to_str(result.content))["data"])

        # make test POST request to gateway
        data = json.dumps({"data": 123})
        result = requests.post(url, data=data)
        self.assertEqual(200, result.status_code)
        expected = custom_result if int_type == "custom" else data
        self.assertEqual(expected, json.loads(to_str(result.content))["data"])

        # make test POST request with non-JSON content type
        data = "test=123"
        ctype = "application/x-www-form-urlencoded"
        result = requests.post(url, data=data, headers={"content-type": ctype})
        self.assertEqual(200, result.status_code)
        content = json.loads(to_str(result.content))
        headers = CaseInsensitiveDict(content["headers"])
        expected = custom_result if int_type == "custom" else data
        self.assertEqual(expected, content["data"])
        self.assertEqual(ctype, headers["content-type"])

        # clean up
        proxy.stop()

    def test_api_gateway_lambda_proxy_integration(self):
        self._test_api_gateway_lambda_proxy_integration(
            self.TEST_LAMBDA_PROXY_BACKEND, self.API_PATH_LAMBDA_PROXY_BACKEND
        )

    def test_api_gateway_lambda_proxy_integration_with_path_param(self):
        self._test_api_gateway_lambda_proxy_integration(
            self.TEST_LAMBDA_PROXY_BACKEND_WITH_PATH_PARAM,
            self.API_PATH_LAMBDA_PROXY_BACKEND_WITH_PATH_PARAM,
        )

    def test_api_gateway_lambda_proxy_integration_with_is_base_64_encoded(self):
        # Test the case where `isBase64Encoded` is enabled.
        content = b"hello, please base64 encode me"

        def _mutate_data(data) -> None:
            data["return_is_base_64_encoded"] = True
            data["return_raw_body"] = base64.b64encode(content).decode("utf8")

        test_result = self._test_api_gateway_lambda_proxy_integration_no_asserts(
            self.TEST_LAMBDA_PROXY_BACKEND_WITH_IS_BASE64,
            self.API_PATH_LAMBDA_PROXY_BACKEND_WITH_IS_BASE64,
            data_mutator_fn=_mutate_data,
        )

        # Ensure that `invoke_rest_api_integration_backend` correctly decodes the base64 content
        self.assertEqual(test_result.result.status_code, 203)
        self.assertEqual(test_result.result.content, content)

    def _test_api_gateway_lambda_proxy_integration_no_asserts(
        self,
        fn_name: str,
        path: str,
        data_mutator_fn: Optional[Callable] = None,
    ) -> ApiGatewayLambdaProxyIntegrationTestResult:
        """
        Perform the setup needed to do a POST against a Lambda Proxy Integration;
        then execute the POST.

        :param data_mutator_fn: a Callable[[Dict], None] that lets us mutate the
          data dictionary before sending it off to the lambda.
        """
        self.create_lambda_function(fn_name)
        # create API Gateway and connect it to the Lambda proxy backend
        lambda_uri = aws_stack.lambda_function_arn(fn_name)
        invocation_uri = "arn:aws:apigateway:%s:lambda:path/2015-03-31/functions/%s/invocations"
        target_uri = invocation_uri % (aws_stack.get_region(), lambda_uri)

        result = testutil.connect_api_gateway_to_http_with_lambda_proxy(
            "test_gateway2", target_uri, path=path, stage_name=self.TEST_STAGE_NAME
        )

        api_id = result["id"]
        path_map = get_rest_api_paths(api_id)
        _, resource = get_resource_for_path(path, path_map)

        # make test request to gateway and check response
        path_with_replace = path.replace("{test_param1}", "foo1")
        path_with_params = path_with_replace + "?foo=foo&bar=bar&bar=baz"

        url = path_based_url(api_id=api_id, stage_name=self.TEST_STAGE_NAME, path=path_with_params)

        # These values get read in `lambda_integration.py`
        data = {"return_status_code": 203, "return_headers": {"foo": "bar123"}}
        if data_mutator_fn:
            assert callable(data_mutator_fn)
            data_mutator_fn(data)
        result = requests.post(
            url,
            data=json.dumps(data),
            headers={"User-Agent": "python-requests/testing"},
        )

        return ApiGatewayLambdaProxyIntegrationTestResult(
            data=data,
            resource=resource,
            result=result,
            url=url,
            path_with_replace=path_with_replace,
        )

    def _test_api_gateway_lambda_proxy_integration(
        self,
        fn_name: str,
        path: str,
    ) -> None:
        test_result = self._test_api_gateway_lambda_proxy_integration_no_asserts(fn_name, path)
        data, resource, result, url, path_with_replace = test_result

        self.assertEqual(result.status_code, 203)
        self.assertEqual(result.headers.get("foo"), "bar123")
        self.assertIn("set-cookie", result.headers)

        try:
            parsed_body = json.loads(to_str(result.content))
        except json.decoder.JSONDecodeError as e:
            raise Exception(
                "Couldn't json-decode content: {}".format(to_str(result.content))
            ) from e
        self.assertEqual(parsed_body.get("return_status_code"), 203)
        self.assertDictEqual(parsed_body.get("return_headers"), {"foo": "bar123"})
        self.assertDictEqual(
            parsed_body.get("queryStringParameters"),
            {"foo": "foo", "bar": ["bar", "baz"]},
        )

        request_context = parsed_body.get("requestContext")
        source_ip = request_context["identity"].pop("sourceIp")

        self.assertTrue(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", source_ip))

        expected_path = "/" + self.TEST_STAGE_NAME + "/lambda/foo1"
        self.assertEqual(expected_path, request_context["path"])
        self.assertIsNone(request_context.get("stageVariables"))
        self.assertEqual(TEST_AWS_ACCOUNT_ID, request_context["accountId"])
        self.assertEqual(resource.get("id"), request_context["resourceId"])
        self.assertEqual(self.TEST_STAGE_NAME, request_context["stage"])
        self.assertEqual("python-requests/testing", request_context["identity"]["userAgent"])
        self.assertEqual("POST", request_context["httpMethod"])
        self.assertEqual("HTTP/1.1", request_context["protocol"])
        self.assertIn("requestTimeEpoch", request_context)
        self.assertIn("requestTime", request_context)
        self.assertIn("requestId", request_context)

        # assert that header keys are lowercase (as in AWS)
        headers = parsed_body.get("headers") or {}
        header_names = list(headers.keys())
        self.assertIn("Host", header_names)
        self.assertIn("Content-Length", header_names)
        self.assertIn("User-Agent", header_names)

        result = requests.delete(url, data=json.dumps(data))
        self.assertEqual(204, result.status_code)

        # send message with non-ASCII chars
        body_msg = "🙀 - 参よ"
        result = requests.post(url, data=json.dumps({"return_raw_body": body_msg}))
        self.assertEqual(body_msg, to_str(result.content))

        # send message with binary data
        binary_msg = b"\xff \xaa \x11"
        result = requests.post(url, data=binary_msg)
        result_content = json.loads(to_str(result.content))
        self.assertEqual("/yCqIBE=", result_content["body"])
        self.assertEqual(True, result_content["isBase64Encoded"])

    def test_api_gateway_lambda_proxy_integration_any_method(self):
        self._test_api_gateway_lambda_proxy_integration_any_method(
            self.TEST_LAMBDA_PROXY_BACKEND_ANY_METHOD,
            self.API_PATH_LAMBDA_PROXY_BACKEND_ANY_METHOD,
        )

    def test_api_gateway_lambda_proxy_integration_any_method_with_path_param(self):
        self._test_api_gateway_lambda_proxy_integration_any_method(
            self.TEST_LAMBDA_PROXY_BACKEND_ANY_METHOD_WITH_PATH_PARAM,
            self.API_PATH_LAMBDA_PROXY_BACKEND_ANY_METHOD_WITH_PATH_PARAM,
        )

    def test_api_gateway_authorizer_crud(self):
        apig = aws_stack.create_external_boto_client("apigateway")

        authorizer = apig.create_authorizer(
            restApiId=self.TEST_API_GATEWAY_ID, **self.TEST_API_GATEWAY_AUTHORIZER
        )

        authorizer_id = authorizer.get("id")

        create_result = apig.get_authorizer(
            restApiId=self.TEST_API_GATEWAY_ID, authorizerId=authorizer_id
        )

        # ignore boto3 stuff
        del create_result["ResponseMetadata"]

        create_expected = clone(self.TEST_API_GATEWAY_AUTHORIZER)
        create_expected["id"] = authorizer_id

        self.assertDictEqual(create_expected, create_result)

        apig.update_authorizer(
            restApiId=self.TEST_API_GATEWAY_ID,
            authorizerId=authorizer_id,
            patchOperations=self.TEST_API_GATEWAY_AUTHORIZER_OPS,
        )

        update_result = apig.get_authorizer(
            restApiId=self.TEST_API_GATEWAY_ID, authorizerId=authorizer_id
        )

        # ignore boto3 stuff
        del update_result["ResponseMetadata"]

        update_expected = apply_patch(create_expected, self.TEST_API_GATEWAY_AUTHORIZER_OPS)

        self.assertDictEqual(update_expected, update_result)

        apig.delete_authorizer(restApiId=self.TEST_API_GATEWAY_ID, authorizerId=authorizer_id)

        self.assertRaises(Exception, apig.get_authorizer, self.TEST_API_GATEWAY_ID, authorizer_id)

    def test_apigateway_with_lambda_integration(self):
        apigw_client = aws_stack.create_external_boto_client("apigateway")

        # create Lambda function
        lambda_name = "apigw-lambda-%s" % short_uid()
        self.create_lambda_function(lambda_name)
        lambda_uri = aws_stack.lambda_function_arn(lambda_name)
        target_uri = aws_stack.apigateway_invocations_arn(lambda_uri)

        # create REST API
        api = apigw_client.create_rest_api(name="test-api", description="")
        api_id = api["id"]
        root_res_id = apigw_client.get_resources(restApiId=api_id)["items"][0]["id"]
        api_resource = apigw_client.create_resource(
            restApiId=api_id, parentId=root_res_id, pathPart="test"
        )

        apigw_client.put_method(
            restApiId=api_id,
            resourceId=api_resource["id"],
            httpMethod="GET",
            authorizationType="NONE",
        )

        rs = apigw_client.put_integration(
            restApiId=api_id,
            resourceId=api_resource["id"],
            httpMethod="GET",
            integrationHttpMethod="POST",
            type="AWS",
            uri=target_uri,
            timeoutInMillis=3000,
            contentHandling="CONVERT_TO_BINARY",
            requestTemplates={"application/json": '{"param1": "$input.params(\'param1\')"}'},
        )
        integration_keys = [
            "httpMethod",
            "type",
            "passthroughBehavior",
            "cacheKeyParameters",
            "uri",
            "cacheNamespace",
            "timeoutInMillis",
            "contentHandling",
            "requestParameters",
        ]
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])
        for key in integration_keys:
            self.assertIn(key, rs)
        self.assertNotIn("responseTemplates", rs)

        apigw_client.create_deployment(restApiId=api_id, stageName=self.TEST_STAGE_NAME)

        rs = apigw_client.get_integration(
            restApiId=api_id, resourceId=api_resource["id"], httpMethod="GET"
        )
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual("AWS", rs["type"])
        self.assertEqual("POST", rs["httpMethod"])
        self.assertEqual(target_uri, rs["uri"])

        # invoke the gateway endpoint
        url = path_based_url(api_id=api_id, stage_name=self.TEST_STAGE_NAME, path="/test")
        response = requests.get("%s?param1=foobar" % url)
        self.assertLess(response.status_code, 400)
        content = response.json()
        self.assertEqual("GET", content.get("httpMethod"))
        self.assertEqual(api_resource["id"], content.get("requestContext", {}).get("resourceId"))
        self.assertEqual(self.TEST_STAGE_NAME, content.get("requestContext", {}).get("stage"))
        self.assertEqual('{"param1": "foobar"}', content.get("body"))

        # additional checks from https://github.com/localstack/localstack/issues/5041
        # pass Signature param
        response = requests.get("%s?param1=foobar&Signature=1" % url)
        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertEqual("GET", content.get("httpMethod"))
        self.assertEqual(api_resource["id"], content.get("requestContext", {}).get("resourceId"))
        self.assertEqual(self.TEST_STAGE_NAME, content.get("requestContext", {}).get("stage"))
        self.assertEqual('{"param1": "foobar"}', content.get("body"))

        # pass TestSignature param as well
        response = requests.get("%s?param1=foobar&TestSignature=1" % url)
        self.assertEqual(response.status_code, 200)
        content = response.json()
        self.assertEqual("GET", content.get("httpMethod"))
        self.assertEqual(api_resource["id"], content.get("requestContext", {}).get("resourceId"))
        self.assertEqual(self.TEST_STAGE_NAME, content.get("requestContext", {}).get("stage"))
        self.assertEqual('{"param1": "foobar"}', content.get("body"))

        # delete integration
        rs = apigw_client.delete_integration(
            restApiId=api_id,
            resourceId=api_resource["id"],
            httpMethod="GET",
        )
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        with self.assertRaises(ClientError) as ctx:
            # This call should not be successful as the integration is deleted
            apigw_client.get_integration(
                restApiId=api_id, resourceId=api_resource["id"], httpMethod="GET"
            )
        self.assertEqual(ctx.exception.response["Error"]["Code"], "NotFoundException")

        # clean up
        lambda_client = aws_stack.create_external_boto_client("lambda")
        lambda_client.delete_function(FunctionName=lambda_name)
        apigw_client.delete_rest_api(restApiId=api_id)

    def test_api_gateway_handle_domain_name(self):
        domain_name = "%s.example.com" % short_uid()
        apigw_client = aws_stack.create_external_boto_client("apigateway")

        rs = apigw_client.create_domain_name(domainName=domain_name)
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        rs = apigw_client.get_domain_name(domainName=domain_name)
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(domain_name, rs["domainName"])

        # clean up
        apigw_client.delete_domain_name(domainName=domain_name)

    def _test_api_gateway_lambda_proxy_integration_any_method(self, fn_name, path):
        self.create_lambda_function(fn_name)

        # create API Gateway and connect it to the Lambda proxy backend
        lambda_uri = aws_stack.lambda_function_arn(fn_name)
        target_uri = aws_stack.apigateway_invocations_arn(lambda_uri)

        result = testutil.connect_api_gateway_to_http_with_lambda_proxy(
            "test_gateway3",
            target_uri,
            methods=["ANY"],
            path=path,
            stage_name=self.TEST_STAGE_NAME,
        )

        # make test request to gateway and check response
        path = path.replace("{test_param1}", "foo1")
        url = path_based_url(api_id=result["id"], stage_name=self.TEST_STAGE_NAME, path=path)
        data = {}

        for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            body = json.dumps(data) if method in ("POST", "PUT", "PATCH") else None
            result = getattr(requests, method.lower())(url, data=body)
            if method != "DELETE":
                self.assertEqual(200, result.status_code)
                parsed_body = json.loads(to_str(result.content))
                self.assertEqual(method, parsed_body.get("httpMethod"))
            else:
                self.assertEqual(204, result.status_code)

    def test_apigateway_with_custom_authorization_method(self):
        apigw_client = aws_stack.create_external_boto_client("apigateway")

        # create Lambda function
        lambda_name = "apigw-lambda-%s" % short_uid()
        self.create_lambda_function(lambda_name)
        lambda_uri = aws_stack.lambda_function_arn(lambda_name)

        # create REST API
        api = apigw_client.create_rest_api(name="test-api", description="")
        api_id = api["id"]
        root_res_id = apigw_client.get_resources(restApiId=api_id)["items"][0]["id"]

        # create authorizer at root resource
        authorizer = apigw_client.create_authorizer(
            restApiId=api_id,
            name="lambda_authorizer",
            type="TOKEN",
            authorizerUri="arn:aws:apigateway:us-east-1:lambda:path/ \
                2015-03-31/functions/{}/invocations".format(
                lambda_uri
            ),
            identitySource="method.request.header.Auth",
        )

        # create method with custom authorizer
        is_api_key_required = True
        method_response = apigw_client.put_method(
            restApiId=api_id,
            resourceId=root_res_id,
            httpMethod="GET",
            authorizationType="CUSTOM",
            authorizerId=authorizer["id"],
            apiKeyRequired=is_api_key_required,
        )

        self.assertEqual(authorizer["id"], method_response["authorizerId"])

        # clean up
        lambda_client = aws_stack.create_external_boto_client("lambda")
        lambda_client.delete_function(FunctionName=lambda_name)
        apigw_client.delete_rest_api(restApiId=api_id)

    def test_create_model(self):
        client = aws_stack.create_external_boto_client("apigateway")
        response = client.create_rest_api(name="my_api", description="this is my api")
        rest_api_id = response["id"]
        dummy_rest_api_id = "_non_existing_"
        model_name = "testModel"
        description = "test model"
        content_type = "application/json"

        # success case with valid params
        response = client.create_model(
            restApiId=rest_api_id,
            name=model_name,
            description=description,
            contentType=content_type,
        )
        self.assertEqual(model_name, response["name"])
        self.assertEqual(description, response["description"])

        with self.assertRaises(Exception) as ctx:
            client.create_model(
                restApiId=dummy_rest_api_id,
                name=model_name,
                description=description,
                contentType=content_type,
            )
        self.assertEqual("NotFoundException", ctx.exception.response["Error"]["Code"])
        self.assertEqual(
            "Invalid Rest API Id specified", ctx.exception.response["Error"]["Message"]
        )

        with self.assertRaises(Exception) as ctx:
            client.create_model(
                restApiId=dummy_rest_api_id,
                name="",
                description=description,
                contentType=content_type,
            )
        self.assertEqual("BadRequestException", ctx.exception.response["Error"]["Code"])
        self.assertEqual("No Model Name specified", ctx.exception.response["Error"]["Message"])

        # clean up
        client.delete_rest_api(restApiId=rest_api_id)

    def test_get_api_models(self):
        client = aws_stack.create_external_boto_client("apigateway")
        response = client.create_rest_api(name="my_api", description="this is my api")
        rest_api_id = response["id"]
        model_name = "testModel"
        description = "test model"
        content_type = "application/json"
        # when no models are present
        result = client.get_models(restApiId=rest_api_id)
        self.assertEqual([], result["items"])
        # add a model
        client.create_model(
            restApiId=rest_api_id,
            name=model_name,
            description=description,
            contentType=content_type,
        )

        # get models after adding
        result = client.get_models(restApiId=rest_api_id)
        self.assertEqual(model_name, result["items"][0]["name"])
        self.assertEqual(description, result["items"][0]["description"])

        # clean up
        client.delete_rest_api(restApiId=rest_api_id)

    def test_request_validator(self):
        client = aws_stack.create_external_boto_client("apigateway")
        response = client.create_rest_api(name="my_api", description="this is my api")
        rest_api_id = response["id"]
        # CREATE
        name = "validator123"
        result = client.create_request_validator(restApiId=rest_api_id, name=name)
        self.assertEqual(201, result["ResponseMetadata"]["HTTPStatusCode"])
        validator_id = result["id"]
        # LIST
        result = client.get_request_validators(restApiId=rest_api_id)
        self.assertEqual(200, result["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual([{"id": validator_id, "name": name}], result["items"])
        # GET
        result = client.get_request_validator(
            restApiId=rest_api_id, requestValidatorId=validator_id
        )
        self.assertEqual(200, result["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(
            select_attributes(result, ["id", "name"]),
            {"id": validator_id, "name": name},
        )
        # UPDATE
        result = client.update_request_validator(
            restApiId=rest_api_id, requestValidatorId=validator_id, patchOperations=[]
        )
        # DELETE
        client.delete_request_validator(restApiId=rest_api_id, requestValidatorId=validator_id)
        with self.assertRaises(Exception):
            client.get_request_validator(restApiId=rest_api_id, requestValidatorId=validator_id)
        with self.assertRaises(Exception):
            client.delete_request_validator(restApiId=rest_api_id, requestValidatorId=validator_id)

        # clean up
        client.delete_rest_api(restApiId=rest_api_id)

    def test_base_path_mapping(self):
        client = aws_stack.create_external_boto_client("apigateway")
        response = client.create_rest_api(name="my_api", description="this is my api")
        rest_api_id = response["id"]

        # CREATE
        domain_name = "domain1.example.com"
        client.create_domain_name(domainName=domain_name)
        root_res_id = client.get_resources(restApiId=rest_api_id)["items"][0]["id"]
        res_id = client.create_resource(
            restApiId=rest_api_id, parentId=root_res_id, pathPart="path"
        )["id"]
        client.put_method(
            restApiId=rest_api_id, resourceId=res_id, httpMethod="GET", authorizationType="NONE"
        )
        client.put_integration(
            restApiId=rest_api_id, resourceId=res_id, httpMethod="GET", type="MOCK"
        )
        depl_id = client.create_deployment(restApiId=rest_api_id)["id"]
        client.create_stage(restApiId=rest_api_id, deploymentId=depl_id, stageName="dev")
        base_path = "foo"
        result = client.create_base_path_mapping(
            domainName=domain_name,
            basePath=base_path,
            restApiId=rest_api_id,
            stage="dev",
        )
        self.assertIn(result["ResponseMetadata"]["HTTPStatusCode"], [200, 201])

        # LIST
        result = client.get_base_path_mappings(domainName=domain_name)
        self.assertEqual(200, result["ResponseMetadata"]["HTTPStatusCode"])
        expected = {"basePath": base_path, "restApiId": rest_api_id, "stage": "dev"}
        self.assertEqual([expected], result["items"])

        # GET
        result = client.get_base_path_mapping(domainName=domain_name, basePath=base_path)
        self.assertEqual(200, result["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(expected, select_attributes(result, ["basePath", "restApiId", "stage"]))

        # UPDATE
        result = client.update_base_path_mapping(
            domainName=domain_name, basePath=base_path, patchOperations=[]
        )
        self.assertEqual(200, result["ResponseMetadata"]["HTTPStatusCode"])

        # DELETE
        client.delete_base_path_mapping(domainName=domain_name, basePath=base_path)
        with self.assertRaises(Exception):
            client.get_base_path_mapping(domainName=domain_name, basePath=base_path)
        with self.assertRaises(Exception):
            client.delete_base_path_mapping(domainName=domain_name, basePath=base_path)

    def test_base_path_mapping_root(self):
        client = aws_stack.create_external_boto_client("apigateway")
        response = client.create_rest_api(name="my_api2", description="this is my api")
        rest_api_id = response["id"]

        # CREATE
        domain_name = "domain2.example.com"
        client.create_domain_name(domainName=domain_name)
        root_res_id = client.get_resources(restApiId=rest_api_id)["items"][0]["id"]
        res_id = client.create_resource(
            restApiId=rest_api_id, parentId=root_res_id, pathPart="path"
        )["id"]
        client.put_method(
            restApiId=rest_api_id, resourceId=res_id, httpMethod="GET", authorizationType="NONE"
        )
        client.put_integration(
            restApiId=rest_api_id, resourceId=res_id, httpMethod="GET", type="MOCK"
        )
        depl_id = client.create_deployment(restApiId=rest_api_id)["id"]
        client.create_stage(restApiId=rest_api_id, deploymentId=depl_id, stageName="dev")
        result = client.create_base_path_mapping(
            domainName=domain_name,
            basePath="",
            restApiId=rest_api_id,
            stage="dev",
        )
        self.assertIn(result["ResponseMetadata"]["HTTPStatusCode"], [200, 201])

        base_path = "(none)"
        # LIST
        result = client.get_base_path_mappings(domainName=domain_name)
        self.assertEqual(200, result["ResponseMetadata"]["HTTPStatusCode"])
        expected = {"basePath": "(none)", "restApiId": rest_api_id, "stage": "dev"}
        self.assertEqual([expected], result["items"])

        # GET
        result = client.get_base_path_mapping(domainName=domain_name, basePath=base_path)
        self.assertEqual(200, result["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(expected, select_attributes(result, ["basePath", "restApiId", "stage"]))

        # UPDATE
        result = client.update_base_path_mapping(
            domainName=domain_name, basePath=base_path, patchOperations=[]
        )
        self.assertEqual(200, result["ResponseMetadata"]["HTTPStatusCode"])

        # DELETE
        client.delete_base_path_mapping(domainName=domain_name, basePath=base_path)
        with self.assertRaises(Exception):
            client.get_base_path_mapping(domainName=domain_name, basePath=base_path)
        with self.assertRaises(Exception):
            client.delete_base_path_mapping(domainName=domain_name, basePath=base_path)

    def test_api_account(self):
        client = aws_stack.create_external_boto_client("apigateway")
        response = client.create_rest_api(name="my_api", description="test 123")
        rest_api_id = response["id"]

        result = client.get_account()
        self.assertIn("UsagePlans", result["features"])
        result = client.update_account(
            patchOperations=[{"op": "add", "path": "/features/-", "value": "foobar"}]
        )
        self.assertIn("foobar", result["features"])

        # clean up
        client.delete_rest_api(restApiId=rest_api_id)

    def test_get_model_by_name(self):
        client = aws_stack.create_external_boto_client("apigateway")
        response = client.create_rest_api(name="my_api", description="this is my api")
        rest_api_id = response["id"]
        dummy_rest_api_id = "_non_existing_"
        model_name = "testModel"
        description = "test model"
        content_type = "application/json"
        # add a model
        client.create_model(
            restApiId=rest_api_id,
            name=model_name,
            description=description,
            contentType=content_type,
        )

        # get models after adding
        result = client.get_model(restApiId=rest_api_id, modelName=model_name)
        self.assertEqual(model_name, result["name"])
        self.assertEqual(description, result["description"])

        try:
            client.get_model(restApiId=dummy_rest_api_id, modelName=model_name)
            self.fail("This call should not be successful as the model is not created.")

        except ClientError as e:
            self.assertEqual("NotFoundException", e.response["Error"]["Code"])
            self.assertEqual("Invalid Rest API Id specified", e.response["Error"]["Message"])

    def test_get_model_with_invalid_name(self):
        client = aws_stack.create_external_boto_client("apigateway")
        response = client.create_rest_api(name="my_api", description="this is my api")
        rest_api_id = response["id"]

        # test with an invalid model name
        try:
            client.get_model(restApiId=rest_api_id, modelName="fake")
            self.fail("This call should not be successful as the model is not created.")

        except ClientError as e:
            self.assertEqual("NotFoundException", e.response["Error"]["Code"])

        # clean up
        client.delete_rest_api(restApiId=rest_api_id)

    def test_put_integration_dynamodb_proxy_validation_without_response_template(self):
        api_id = self.create_api_gateway_and_deploy({})
        url = path_based_url(api_id=api_id, stage_name="staging", path="/")
        response = requests.put(
            url,
            json.dumps({"id": "id1", "data": "foobar123"}),
        )

        self.assertEqual(404, response.status_code)

    def test_put_integration_dynamodb_proxy_validation_with_response_template(self):
        response_templates = {
            "application/json": json.dumps(
                {
                    "TableName": "MusicCollection",
                    "Item": {"id": "$.Id", "data": "$.data"},
                }
            )
        }

        api_id = self.create_api_gateway_and_deploy(response_templates)
        url = path_based_url(api_id=api_id, stage_name="staging", path="/")

        response = requests.put(
            url,
            json.dumps({"id": "id1", "data": "foobar123"}),
        )

        self.assertEqual(200, response.status_code)
        dynamo_client = aws_stack.connect_to_resource("dynamodb")
        table = dynamo_client.Table("MusicCollection")
        result = table.get_item(Key={"id": "id1"})
        self.assertEqual("foobar123", result["Item"]["data"])

    def test_api_key_required_for_methods(self):
        response_templates = {
            "application/json": json.dumps(
                {
                    "TableName": "MusicCollection",
                    "Item": {"id": "$.Id", "data": "$.data"},
                }
            )
        }

        api_id = self.create_api_gateway_and_deploy(response_templates, True)
        url = path_based_url(api_id=api_id, stage_name="staging", path="/")

        payload = {
            "name": "TEST-PLAN-2",
            "description": "Description",
            "quota": {"limit": 10, "period": "DAY", "offset": 0},
            "throttle": {"rateLimit": 2, "burstLimit": 1},
            "apiStages": [{"apiId": api_id, "stage": "staging"}],
            "tags": {"tag_key": "tag_value"},
        }

        client = aws_stack.create_external_boto_client("apigateway")
        usage_plan_id = client.create_usage_plan(**payload)["id"]

        key_name = "testApiKey"
        key_type = "API_KEY"
        api_key = client.create_api_key(name=key_name)

        payload = {
            "usagePlanId": usage_plan_id,
            "keyId": api_key["id"],
            "keyType": key_type,
        }
        client.create_usage_plan_key(**payload)

        response = requests.put(
            url,
            json.dumps({"id": "id1", "data": "foobar123"}),
        )
        # when the api key is not passed as part of the header
        self.assertEqual(403, response.status_code)

        response = requests.put(
            url,
            json.dumps({"id": "id1", "data": "foobar123"}),
            headers={"X-API-Key": api_key["value"]},
        )
        # when the api key is passed as part of the header
        self.assertEqual(200, response.status_code)

    def test_multiple_api_keys_validate(self):
        response_templates = {
            "application/json": json.dumps(
                {
                    "TableName": "MusicCollection",
                    "Item": {"id": "$.Id", "data": "$.data"},
                }
            )
        }

        api_id = self.create_api_gateway_and_deploy(response_templates, True)
        url = path_based_url(api_id=api_id, stage_name="staging", path="/")

        client = aws_stack.create_external_boto_client("apigateway")

        # Create multiple usage plans
        usage_plan_ids = []
        for i in range(2):
            payload = {
                "name": "APIKEYTEST-PLAN-{}".format(i),
                "description": "Description",
                "quota": {"limit": 10, "period": "DAY", "offset": 0},
                "throttle": {"rateLimit": 2, "burstLimit": 1},
                "apiStages": [{"apiId": api_id, "stage": "staging"}],
                "tags": {"tag_key": "tag_value"},
            }
            usage_plan_ids.append(client.create_usage_plan(**payload)["id"])

        api_keys = []
        key_type = "API_KEY"
        # Create multiple API Keys in each usage plan
        for usage_plan_id in usage_plan_ids:
            for i in range(2):
                api_key = client.create_api_key(name="testMultipleApiKeys{}".format(i))
                payload = {
                    "usagePlanId": usage_plan_id,
                    "keyId": api_key["id"],
                    "keyType": key_type,
                }
                client.create_usage_plan_key(**payload)
                api_keys.append(api_key["value"])

        response = requests.put(
            url,
            json.dumps({"id": "id1", "data": "foobar123"}),
        )
        # when the api key is not passed as part of the header
        self.assertEqual(403, response.status_code)

        # check that all API keys work
        for key in api_keys:
            response = requests.put(
                url,
                json.dumps({"id": "id1", "data": "foobar123"}),
                headers={"X-API-Key": key},
            )
            # when the api key is passed as part of the header
            self.assertEqual(200, response.status_code)

    def test_import_rest_api(self):
        rest_api_name = "restapi-%s" % short_uid()

        client = aws_stack.create_external_boto_client("apigateway")
        rest_api_id = client.create_rest_api(name=rest_api_name)["id"]

        spec_file = load_file(TEST_SWAGGER_FILE_JSON)
        rs = client.put_rest_api(restApiId=rest_api_id, body=spec_file, mode="overwrite")
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        spec_file = load_file(TEST_SWAGGER_FILE_YAML)
        rs = client.put_rest_api(restApiId=rest_api_id, body=spec_file, mode="overwrite")
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        rs = client.get_resources(restApiId=rest_api_id)
        self.assertEqual(
            2, len(rs["items"])
        )  # should contain 2 resources (including the root resource)

        resource = [res for res in rs["items"] if res["path"] == "/test"][0]
        self.assertIn("GET", resource["resourceMethods"])

        url = path_based_url(api_id=rest_api_id, stage_name="dev", path="/test")
        response = requests.get(url)
        self.assertEqual(200, response.status_code)

        # clean up
        client.delete_rest_api(restApiId=rest_api_id)

        spec_file = load_file(TEST_IMPORT_REST_API_FILE)
        rs = client.import_rest_api(body=spec_file)
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        rest_api_id = rs["id"]

        rs = client.get_resources(restApiId=rest_api_id)
        resources = rs["items"]
        self.assertEqual(3, len(resources))

        paths = [res["path"] for res in resources]
        self.assertIn("/", paths)
        self.assertIn("/pets", paths)
        self.assertIn("/pets/{petId}", paths)

        # clean up
        client.delete_rest_api(restApiId=rest_api_id)

    def test_step_function_integrations(self):
        client = aws_stack.create_external_boto_client("apigateway")
        sfn_client = aws_stack.create_external_boto_client("stepfunctions")
        lambda_client = aws_stack.create_external_boto_client("lambda")

        state_machine_name = "test"
        state_machine_def = {
            "Comment": "Hello World example",
            "StartAt": "step1",
            "States": {
                "step1": {"Type": "Task", "Resource": "__tbd__", "End": True},
            },
        }

        # create state machine
        fn_name = "test-stepfunctions-apigw"
        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=fn_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )
        role_arn = aws_stack.role_arn("sfn_role")

        # create state machine definition
        definition = clone(state_machine_def)
        lambda_arn_1 = aws_stack.lambda_function_arn(fn_name)
        definition["States"]["step1"]["Resource"] = lambda_arn_1
        definition = json.dumps(definition)

        # create state machine
        result = sfn_client.create_state_machine(
            name=state_machine_name, definition=definition, roleArn=role_arn
        )
        sm_arn = result["stateMachineArn"]

        # create REST API and method
        rest_api = client.create_rest_api(name="test", description="test")
        resources = client.get_resources(restApiId=rest_api["id"])
        root_resource_id = resources["items"][0]["id"]
        client.put_method(
            restApiId=rest_api["id"],
            resourceId=root_resource_id,
            httpMethod="POST",
            authorizationType="NONE",
        )

        def _prepare_method_integration(
            integr_kwargs=None, resp_templates=None, action="StartExecution", overwrite=False
        ):
            if integr_kwargs is None:
                integr_kwargs = {}
            if resp_templates is None:
                resp_templates = {}
            if overwrite:
                client.delete_integration(
                    restApiId=rest_api["id"],
                    resourceId=resources["items"][0]["id"],
                    httpMethod="POST",
                )
            uri = f"arn:aws:apigateway:{aws_stack.get_region()}:states:action/{action}"
            client.put_integration(
                restApiId=rest_api["id"],
                resourceId=root_resource_id,
                httpMethod="POST",
                integrationHttpMethod="POST",
                type="AWS",
                uri=uri,
                **integr_kwargs,
            )
            if resp_templates:
                client.put_integration_response(
                    restApiId=rest_api["id"],
                    resourceId=root_resource_id,
                    selectionPattern="",
                    responseTemplates=resp_templates,
                    httpMethod="POST",
                    statusCode="200",
                )

        # STEP 1: test integration with request template

        _prepare_method_integration(
            integr_kwargs={
                "requestTemplates": {
                    "application/json": """
                    #set($data = $util.escapeJavaScript($input.json('$')))
                    {"input": $data, "stateMachineArn": "%s"}
                    """
                    % sm_arn
                }
            }
        )

        # invoke stepfunction via API GW, assert results
        client.create_deployment(restApiId=rest_api["id"], stageName="dev")
        url = path_based_url(api_id=rest_api["id"], stage_name="dev", path="/")
        test_data = {"test": "test-value"}
        resp = requests.post(url, data=json.dumps(test_data))
        self.assertEqual(200, resp.status_code)
        self.assertIn("executionArn", resp.content.decode())
        self.assertIn("startDate", resp.content.decode())

        # STEP 2: test integration without request template

        _prepare_method_integration(overwrite=True)

        test_data_1 = {
            "input": json.dumps(test_data),
            "name": "MyExecution",
            "stateMachineArn": sm_arn,
        }

        # invoke stepfunction via API GW, assert results
        resp = requests.post(url, data=json.dumps(test_data_1))
        self.assertEqual(200, resp.status_code)
        self.assertIn("executionArn", resp.content.decode())
        self.assertIn("startDate", resp.content.decode())

        # STEP 3: test integration with synchronous execution

        _prepare_method_integration(overwrite=True, action="StartSyncExecution")

        # invoke stepfunction via API GW, assert results
        test_data_1["name"] += "1"
        resp = requests.post(url, data=json.dumps(test_data_1))
        self.assertEqual(200, resp.status_code)
        content = json.loads(to_str(resp.content.decode()))
        self.assertEqual("SUCCEEDED", content.get("status"))
        self.assertEqual(test_data, json.loads(content.get("output")))

        # STEP 4: test integration with synchronous execution and response templates

        resp_templates = {APPLICATION_JSON: "$input.path('$.output')"}
        _prepare_method_integration(
            resp_templates=resp_templates, overwrite=True, action="StartSyncExecution"
        )

        # invoke stepfunction via API GW, assert results
        test_data_1["name"] += "2"
        resp = requests.post(url, data=json.dumps(test_data_1))
        self.assertEqual(200, resp.status_code)
        self.assertEqual(test_data, json.loads(to_str(resp.content.decode())))

        _prepare_method_integration(overwrite=True, action="DeleteStateMachine")

        # Remove state machine with API GW
        resp = requests.post(url, data=json.dumps({"stateMachineArn": sm_arn}))
        self.assertEqual(200, resp.status_code)

        # Clean up
        lambda_client.delete_function(FunctionName=fn_name)
        client.delete_rest_api(restApiId=rest_api["id"])

    def test_api_gateway_http_integration_with_path_request_parameter(self):
        client = aws_stack.create_external_boto_client("apigateway")
        test_port = get_free_tcp_port()
        backend_url = "http://localhost:%s/person/{id}" % test_port

        # start test HTTP backend
        proxy = self.start_http_backend(test_port)

        # create rest api
        api_rest = client.create_rest_api(name="test")
        api_id = api_rest["id"]
        parent_response = client.get_resources(restApiId=api_id)
        parent_id = parent_response["items"][0]["id"]
        resource_1 = client.create_resource(restApiId=api_id, parentId=parent_id, pathPart="person")
        resource_1_id = resource_1["id"]
        resource_2 = client.create_resource(
            restApiId=api_id, parentId=resource_1_id, pathPart="{id}"
        )
        resource_2_id = resource_2["id"]
        client.put_method(
            restApiId=api_id,
            resourceId=resource_2_id,
            httpMethod="GET",
            authorizationType="NONE",
            apiKeyRequired=False,
            requestParameters={"method.request.path.id": True},
        )
        client.put_integration(
            restApiId=api_id,
            resourceId=resource_2_id,
            httpMethod="GET",
            integrationHttpMethod="GET",
            type="HTTP",
            uri=backend_url,
            timeoutInMillis=3000,
            contentHandling="CONVERT_TO_BINARY",
            requestParameters={"integration.request.path.id": "method.request.path.id"},
        )
        client.create_deployment(restApiId=api_id, stageName="test")

        def _test_invoke(url):
            result = requests.get(url)
            content = json.loads(to_str(result.content))
            self.assertEqual(200, result.status_code)
            self.assertRegex(
                content["headers"].get(HEADER_LOCALSTACK_REQUEST_URL),
                "http://.*localhost.*/person/123",
            )

        for use_hostname in [True, False]:
            for use_ssl in [True, False] if use_hostname else [False]:
                url = self._get_invoke_endpoint(
                    api_id,
                    stage="test",
                    path="/person/123",
                    use_hostname=use_hostname,
                    use_ssl=use_ssl,
                )
                _test_invoke(url)

        # clean up
        client.delete_rest_api(restApiId=api_id)
        proxy.stop()

    def _get_invoke_endpoint(
        self, api_id, stage="test", path="/", use_hostname=False, use_ssl=False
    ):
        path = path or "/"
        path = path if path.startswith(path) else f"/{path}"
        proto = "https" if use_ssl else "http"
        if use_hostname:
            return f"{proto}://{api_id}.execute-api.{LOCALHOST_HOSTNAME}:{config.EDGE_PORT}/{stage}{path}"
        return (
            f"{proto}://localhost:{config.EDGE_PORT}/restapis/{api_id}/{stage}/_user_request_{path}"
        )

    def test_api_gateway_s3_get_integration(self):
        apigw_client = aws_stack.create_external_boto_client("apigateway")
        s3_client = aws_stack.create_external_boto_client("s3")

        bucket_name = f"test-bucket-{short_uid()}"
        apigateway_name = f"test-api-{short_uid()}"
        object_name = "test.json"
        object_content = '{ "success": "true" }'
        object_content_type = "application/json"

        api = apigw_client.create_rest_api(name=apigateway_name)
        api_id = api["id"]

        try:
            aws_stack.get_or_create_bucket(bucket_name)
            s3_client.put_object(
                Bucket=bucket_name,
                Key=object_name,
                Body=object_content,
                ContentType=object_content_type,
            )

            self.connect_api_gateway_to_s3(bucket_name, object_name, api_id, "GET")

            apigw_client.create_deployment(restApiId=api_id, stageName="test")
            url = path_based_url(api_id, "test", f"/{object_name}")
            result = requests.get(url)
            self.assertEqual(200, result.status_code)
            self.assertEqual(object_content, result.text)
            self.assertEqual(object_content_type, result.headers["content-type"])
        finally:
            # clean up
            apigw_client.delete_rest_api(restApiId=api_id)
            s3_client.delete_object(Bucket=bucket_name, Key=object_name)
            s3_client.delete_bucket(Bucket=bucket_name)

    def test_api_mock_integration_response_params(self):
        # apigw_client = aws_stack.create_external_boto_client('apigateway')

        resps = [
            {
                "statusCode": "204",
                "httpMethod": "OPTIONS",
                "responseParameters": {
                    "method.response.header.Access-Control-Allow-Methods": "'POST,OPTIONS'",
                    "method.response.header.Vary": "'Origin'",
                },
            }
        ]
        api_id = self.create_api_gateway_and_deploy(
            integration_type="MOCK", integration_responses=resps
        )

        url = path_based_url(api_id=api_id, stage_name=self.TEST_STAGE_NAME, path="/")
        result = requests.options(url)
        self.assertLess(result.status_code, 400)
        self.assertEqual("Origin", result.headers.get("vary"))
        self.assertEqual("POST,OPTIONS", result.headers.get("Access-Control-Allow-Methods"))

    def test_api_gateway_update_resource_path_part(self):
        apigw_client = aws_stack.connect_to_service("apigateway")
        api = apigw_client.create_rest_api(name="test-api", description="")
        api_id = api["id"]
        root_res_id = apigw_client.get_resources(restApiId=api_id)["items"][0]["id"]
        api_resource = apigw_client.create_resource(
            restApiId=api_id, parentId=root_res_id, pathPart="test"
        )

        response = apigw_client.update_resource(
            restApiId=api_id,
            resourceId=api_resource.get("id"),
            patchOperations=[
                {"op": "replace", "path": "/pathPart", "value": "demo1"},
            ],
        )
        self.assertEqual(response.get("pathPart"), "demo1")
        response = apigw_client.get_resource(restApiId=api_id, resourceId=api_resource.get("id"))
        self.assertEqual(response.get("pathPart"), "demo1")

        # clean up
        apigw_client.delete_rest_api(restApiId=api_id)

    # =====================================================================
    # Helper methods
    # =====================================================================

    def connect_api_gateway_to_s3(self, bucket_name, file_name, api_id, method):
        """Connects the root resource of an api gateway to the given object of an s3 bucket."""
        apigw_client = aws_stack.create_external_boto_client("apigateway")
        s3_uri = "arn:aws:apigateway:{}:s3:path/{}/{{proxy}}".format(
            aws_stack.get_region(), bucket_name
        )

        test_role = "test-s3-role"
        role_arn = aws_stack.role_arn(role_name=test_role)
        resources = apigw_client.get_resources(restApiId=api_id)
        # using the root resource '/' directly for this test
        root_resource_id = resources["items"][0]["id"]
        proxy_resource = apigw_client.create_resource(
            restApiId=api_id, parentId=root_resource_id, pathPart="{proxy+}"
        )
        apigw_client.put_method(
            restApiId=api_id,
            resourceId=proxy_resource["id"],
            httpMethod=method,
            authorizationType="NONE",
            apiKeyRequired=False,
            requestParameters={},
        )
        apigw_client.put_integration(
            restApiId=api_id,
            resourceId=proxy_resource["id"],
            httpMethod=method,
            type="AWS",
            integrationHttpMethod=method,
            uri=s3_uri,
            credentials=role_arn,
            requestParameters={"integration.request.path.proxy": "method.request.path.proxy"},
        )

    def connect_api_gateway_to_kinesis(self, gateway_name, kinesis_stream):
        template = self.APIGATEWAY_DATA_INBOUND_TEMPLATE % kinesis_stream
        resource_path = self.API_PATH_DATA_INBOUND.replace("/", "")
        resources = {
            resource_path: [
                {
                    "httpMethod": "POST",
                    "authorizationType": "NONE",
                    "requestModels": {"application/json": "Empty"},
                    "integrations": [
                        {
                            "type": "AWS",
                            "uri": "arn:aws:apigateway:%s:kinesis:action/PutRecords"
                            % aws_stack.get_region(),
                            "requestTemplates": {"application/json": template},
                        }
                    ],
                },
                {
                    "httpMethod": "GET",
                    "authorizationType": "NONE",
                    "requestModels": {"application/json": "Empty"},
                    "integrations": [
                        {
                            "type": "AWS",
                            "uri": "arn:aws:apigateway:%s:kinesis:action/ListStreams"
                            % aws_stack.get_region(),
                            "requestTemplates": {"application/json": "{}"},
                        }
                    ],
                },
            ]
        }
        return aws_stack.create_api_gateway(
            name=gateway_name, resources=resources, stage_name=self.TEST_STAGE_NAME
        )

    def connect_api_gateway_to_http(
        self, int_type, gateway_name, target_url, methods=None, path=None
    ):
        if methods is None:
            methods = []
        if not methods:
            methods = ["GET", "POST"]
        if not path:
            path = "/"
        resources = {}
        resource_path = path.replace("/", "")
        req_templates = (
            {"application/json": json.dumps({"foo": "bar"})} if int_type == "custom" else {}
        )
        resources[resource_path] = [
            {
                "httpMethod": method,
                "integrations": [
                    {
                        "type": "HTTP" if int_type == "custom" else "HTTP_PROXY",
                        "uri": target_url,
                        "requestTemplates": req_templates,
                        "responseTemplates": {},
                    }
                ],
            }
            for method in methods
        ]
        return aws_stack.create_api_gateway(
            name=gateway_name, resources=resources, stage_name=self.TEST_STAGE_NAME
        )

    @staticmethod
    def create_lambda_function(fn_name):
        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON, libs=TEST_LAMBDA_LIBS, func_name=fn_name
        )

    def test_apigw_test_invoke_method_api(self):
        client = aws_stack.create_external_boto_client("apigateway")
        lambda_client = aws_stack.create_external_boto_client("lambda")

        # create test Lambda
        fn_name = f"test-{short_uid()}"
        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_NODEJS, func_name=fn_name, runtime=LAMBDA_RUNTIME_NODEJS12X
        )
        lambda_arn_1 = aws_stack.lambda_function_arn(fn_name)

        # create REST API and test resource
        rest_api = client.create_rest_api(name="test", description="test")
        root_resource = client.get_resources(restApiId=rest_api["id"])
        resource = client.create_resource(
            restApiId=rest_api["id"], parentId=root_resource["items"][0]["id"], pathPart="foo"
        )

        # create method and integration
        client.put_method(
            restApiId=rest_api["id"],
            resourceId=resource["id"],
            httpMethod="GET",
            authorizationType="NONE",
        )
        client.put_integration(
            restApiId=rest_api["id"],
            resourceId=resource["id"],
            httpMethod="GET",
            integrationHttpMethod="GET",
            type="AWS",
            uri="arn:aws:apigateway:{}:lambda:path//2015-03-31/functions/{}/invocations".format(
                aws_stack.get_region(), lambda_arn_1
            ),
        )

        # run test_invoke_method API #1
        response = client.test_invoke_method(
            restApiId=rest_api["id"],
            resourceId=resource["id"],
            httpMethod="GET",
            pathWithQueryString="/foo",
        )
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(200, response.get("status"))
        self.assertIn("response from", response.get("body"))

        # run test_invoke_method API #2
        response = client.test_invoke_method(
            restApiId=rest_api["id"],
            resourceId=resource["id"],
            httpMethod="GET",
            pathWithQueryString="/foo",
            body='{"test": "val123"}',
            headers={"content-type": "application/json"},
        )
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(200, response.get("status"))
        self.assertIn("response from", response.get("body"))
        self.assertIn("val123", response.get("body"))

        # Clean up
        lambda_client.delete_function(FunctionName=fn_name)
        client.delete_rest_api(restApiId=rest_api["id"])

    @staticmethod
    def start_http_backend(test_port):
        # test listener for target HTTP backend
        class TestListener(ProxyListener):
            def forward_request(self, **kwargs):
                response = Response()
                response.status_code = 200
                result = {
                    "data": kwargs.get("data") or "{}",
                    "headers": dict(kwargs.get("headers")),
                }
                response._content = json.dumps(json_safe(result))
                return response

        proxy = start_proxy(test_port, update_listener=TestListener())
        return proxy

    @staticmethod
    def create_api_gateway_and_deploy(
        response_templates=None,
        is_api_key_required=False,
        integration_type=None,
        integration_responses=None,
    ):
        response_templates = response_templates or {}
        integration_type = integration_type or "AWS_PROXY"
        apigw_client = aws_stack.create_external_boto_client("apigateway")
        response = apigw_client.create_rest_api(name="my_api", description="this is my api")
        api_id = response["id"]
        resources = apigw_client.get_resources(restApiId=api_id)
        root_resources = [resource for resource in resources["items"] if resource["path"] == "/"]
        root_id = root_resources[0]["id"]

        kwargs = {}
        if integration_type == "AWS_PROXY":
            aws_stack.create_dynamodb_table("MusicCollection", partition_key="id")
            kwargs[
                "uri"
            ] = "arn:aws:apigateway:us-east-1:dynamodb:action/PutItem&Table=MusicCollection"

        if not integration_responses:
            integration_responses = [{"httpMethod": "PUT", "statusCode": "200"}]

        for resp_details in integration_responses:

            apigw_client.put_method(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod=resp_details["httpMethod"],
                authorizationType="NONE",
                apiKeyRequired=is_api_key_required,
            )

            apigw_client.put_method_response(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod=resp_details["httpMethod"],
                statusCode="200",
            )

            apigw_client.put_integration(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod=resp_details["httpMethod"],
                integrationHttpMethod=resp_details["httpMethod"],
                type=integration_type,
                **kwargs,
            )

            apigw_client.put_integration_response(
                restApiId=api_id,
                resourceId=root_id,
                selectionPattern="",
                responseTemplates=response_templates,
                **resp_details,
            )

        apigw_client.create_deployment(restApiId=api_id, stageName="staging")

        return api_id


def test_import_swagger_api(apigateway_client):
    apigateway_client.get_rest_apis()

    api_spec = load_test_resource("openapi.swagger.json")
    api_spec_dict = json.loads(api_spec)

    backend = APIGatewayBackend(region_name="eu-west-1")
    api_model = backend.create_rest_api(name="", description="")

    imported_api = import_api_from_openapi_spec(api_model, api_spec_dict, {})

    # test_cfn_handle_serverless_api_resource fails if we support title
    # assert imported_api.name == api_spec_dict.get("info").get("title")
    assert imported_api.description == api_spec_dict.get("info").get("description")

    paths = {v.path_part for k, v in imported_api.resources.items()}
    assert paths == {"/", "pets", "{petId}"}

    resource_methods = {v.path_part: v.resource_methods for k, v in imported_api.resources.items()}
    methods = {kk[0] for k, v in resource_methods.items() for kk in v.items()}
    assert methods == {"POST", "OPTIONS", "GET"}

    assert resource_methods.get("/").get("GET").method_responses == {
        "200": {
            "statusCode": "200",
            "responseModels": None,
            "responseParameters": {"method.response.header.Content-Type": "'text/html'"},
        }
    }

    assert resource_methods.get("pets").get("GET").method_responses == {
        "200": {
            "responseModels": {
                "application/json": {
                    "items": {
                        "properties": {
                            "id": {"type": "integer"},
                            "price": {"type": "number"},
                            "type": {"type": "string"},
                        },
                        "type": "object",
                    },
                    "type": "array",
                }
            },
            "responseParameters": {"method.response.header.Access-Control-Allow-Origin": "'*'"},
            "statusCode": "200",
        }
    }


@pytest.mark.skipif(not use_docker(), reason="Rust lambdas cannot be executed in local executor")
def test_apigateway_rust_lambda(
    apigateway_client, create_lambda_function, create_iam_role_with_policy
):
    function_name = f"test-rust-function-{short_uid()}"
    api_gateway_name = f"api_gateway_{short_uid()}"
    role_name = f"test_apigateway_role_{short_uid()}"
    policy_name = f"test_apigateway_policy_{short_uid()}"
    stage_name = "test"
    first_name = f"test_name_{short_uid()}"
    lambda_create_response = create_lambda_function(
        func_name=function_name,
        zip_file=load_file(TEST_LAMBDA_HTTP_RUST, mode="rb"),
        handler="bootstrap.is.the.handler",
        runtime="provided.al2",
    )
    role_arn = create_iam_role_with_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        RoleDefinition=APIGATEWAY_ASSUME_ROLE_POLICY,
        PolicyDefinition=APIGATEWAY_LAMBDA_POLICY,
    )
    lambda_arn = lambda_create_response["CreateFunctionResponse"]["FunctionArn"]
    rest_api_id = apigateway_client.create_rest_api(name=api_gateway_name)["id"]
    try:
        root_resource_id = apigateway_client.get_resources(restApiId=rest_api_id)["items"][0]["id"]
        apigateway_client.put_method(
            restApiId=rest_api_id,
            resourceId=root_resource_id,
            httpMethod="GET",
            authorizationType="NONE",
        )
        apigateway_client.put_method_response(
            restApiId=rest_api_id, resourceId=root_resource_id, httpMethod="GET", statusCode="200"
        )
        lambda_target_uri = aws_stack.apigateway_invocations_arn(
            lambda_uri=lambda_arn, region_name=apigateway_client.meta.region_name
        )
        apigateway_client.put_integration(
            restApiId=rest_api_id,
            resourceId=root_resource_id,
            httpMethod="GET",
            type="AWS",
            integrationHttpMethod="POST",
            uri=lambda_target_uri,
            credentials=role_arn,
        )
        apigateway_client.create_deployment(restApiId=rest_api_id, stageName=stage_name)
        url = path_based_url(
            api_id=rest_api_id, stage_name=stage_name, path=f"/?first_name={first_name}"
        )
        result = requests.get(url)
        assert result.text == f"Hello, {first_name}!"
    finally:
        apigateway_client.delete_rest_api(restApiId=rest_api_id)

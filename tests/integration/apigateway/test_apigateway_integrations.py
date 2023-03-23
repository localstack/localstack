import contextlib
import json
import textwrap
from urllib.parse import urlparse

import pytest
import requests
from botocore.exceptions import ClientError

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.constants import APPLICATION_JSON, LOCALHOST
from localstack.services.apigateway.helpers import path_based_url
from localstack.services.awslambda.lambda_utils import (
    LAMBDA_RUNTIME_PYTHON39,
    get_main_endpoint_from_container,
)
from localstack.testing.aws.lambda_utils import is_old_provider
from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.aws import arns, aws_stack
from localstack.utils.strings import short_uid, to_bytes, to_str
from localstack.utils.sync import retry
from localstack.utils.testutil import create_lambda_function
from tests.integration.apigateway.apigateway_fixtures import (
    api_invoke_url,
    create_rest_api_deployment,
    create_rest_api_integration,
    create_rest_resource,
    create_rest_resource_method,
)
from tests.integration.apigateway.conftest import DEFAULT_STAGE_NAME
from tests.integration.awslambda.test_lambda import (
    TEST_LAMBDA_AWS_PROXY,
    TEST_LAMBDA_HELLO_WORLD,
    TEST_LAMBDA_LIBS,
)


@pytest.mark.skip_offline
def test_http_integration(apigateway_client, create_rest_apigw):
    api_id, _, root_id = create_rest_apigw(name="my_api", description="this is my api")

    apigateway_client.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="none"
    )

    apigateway_client.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    apigateway_client.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="HTTP",
        # TODO: replace httpbin.org requests with httpserver/echo_http_server fixture
        uri="http://httpbin.org/robots.txt",
        integrationHttpMethod="GET",
    )

    stage_name = "staging"
    apigateway_client.create_deployment(restApiId=api_id, stageName=stage_name)

    url = path_based_url(api_id=api_id, stage_name=stage_name, path="/")
    response = requests.get(url)

    assert response.status_code == 200


def test_lambda_aws_integration(apigateway_client, create_rest_apigw):
    fn_name = f"test-{short_uid()}"
    create_lambda_function(
        func_name=fn_name,
        handler_file=TEST_LAMBDA_HELLO_WORLD,
        handler="lambda_hello_world.handler",
        runtime=LAMBDA_RUNTIME_PYTHON39,
    )
    lambda_arn = arns.lambda_function_arn(fn_name)

    api_id, _, root = create_rest_apigw(name="aws lambda api")
    resource_id, _ = create_rest_resource(
        apigateway_client, restApiId=api_id, parentId=root, pathPart="test"
    )

    # create method and integration
    create_rest_resource_method(
        apigateway_client,
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="NONE",
    )
    create_rest_api_integration(
        apigateway_client,
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        integrationHttpMethod="GET",
        type="AWS",
        uri=f"arn:aws:apigateway:{aws_stack.get_region()}:lambda:path//2015-03-31/functions/{lambda_arn}/invocations",
    )

    url = api_invoke_url(api_id=api_id, stage="local", path="/test")
    response = requests.get(url)
    assert response.json() == {"message": "Hello from Lambda"}


@pytest.mark.aws_validated
@pytest.mark.skip_snapshot_verify(
    paths=[
        "$..body",
        "$..headers.Accept",
        "$..headers.Accept-Encoding",
        "$..headers.Authorization",
        "$..headers.CloudFront-Forwarded-Proto",
        "$..headers.CloudFront-Is-Desktop-Viewer",
        "$..headers.CloudFront-Is-Mobile-Viewer",
        "$..headers.CloudFront-Is-SmartTV-Viewer",
        "$..headers.CloudFront-Is-Tablet-Viewer",
        "$..headers.CloudFront-Viewer-ASN",
        "$..headers.CloudFront-Viewer-Country",
        "$..headers.Connection",
        "$..headers.Host",
        "$..headers.Remote-Addr",
        "$..headers.Via",
        "$..headers.X-Amz-Cf-Id",
        "$..headers.X-Amzn-Trace-Id",
        "$..headers.X-Forwarded-For",
        "$..headers.X-Forwarded-Port",
        "$..headers.X-Forwarded-Proto",
        "$..headers.accept",
        "$..headers.accept-encoding",
        "$..headers.x-localstack-edge",
        "$..headers.x-localstack-request-url",
        "$..headers.x-localstack-tgt-api",
        "$..multiValueHeaders.Accept",
        "$..multiValueHeaders.Accept-Encoding",
        "$..multiValueHeaders.Authorization",
        "$..multiValueHeaders.CloudFront-Forwarded-Proto",
        "$..multiValueHeaders.CloudFront-Is-Desktop-Viewer",
        "$..multiValueHeaders.CloudFront-Is-Mobile-Viewer",
        "$..multiValueHeaders.CloudFront-Is-SmartTV-Viewer",
        "$..multiValueHeaders.CloudFront-Is-Tablet-Viewer",
        "$..multiValueHeaders.CloudFront-Viewer-ASN",
        "$..multiValueHeaders.CloudFront-Viewer-Country",
        "$..multiValueHeaders.Connection",
        "$..multiValueHeaders.Host",
        "$..multiValueHeaders.Remote-Addr",
        "$..multiValueHeaders.Via",
        "$..multiValueHeaders.X-Amz-Cf-Id",
        "$..multiValueHeaders.X-Amzn-Trace-Id",
        "$..multiValueHeaders.X-Forwarded-For",
        "$..multiValueHeaders.X-Forwarded-Port",
        "$..multiValueHeaders.X-Forwarded-Proto",
        "$..multiValueHeaders.accept",
        "$..multiValueHeaders.accept-encoding",
        "$..multiValueHeaders.x-localstack-edge",
        "$..multiValueHeaders.x-localstack-request-url",
        "$..multiValueHeaders.x-localstack-tgt-api",
        "$..pathParameters",
        "$..requestContext.authorizer",
        "$..requestContext.domainName",
        "$..requestContext.extendedRequestId",
        "$..requestContext.identity.accessKey",
        "$..requestContext.identity.accountId",
        "$..requestContext.identity.caller",
        "$..requestContext.identity.cognitoAuthenticationProvider",
        "$..requestContext.identity.cognitoAuthenticationType",
        "$..requestContext.identity.cognitoIdentityId",
        "$..requestContext.identity.cognitoIdentityPoolId",
        "$..requestContext.identity.principalOrgId",
        "$..requestContext.identity.user",
        "$..requestContext.identity.userArn",
        "$..stageVariables",
    ]
)
def test_lambda_proxy_integration(
    apigateway_client,
    create_lambda_function,
    lambda_client,
    create_role,
    create_policy,
    iam_client,
    snapshot,
    cleanups,
):
    function_name = f"test-function-{short_uid()}"
    role_name = f"test-role-{short_uid()}"
    stage_name = "test"
    snapshot.add_transformer(snapshot.transform.apigateway_api())
    snapshot.add_transformer(snapshot.transform.apigateway_proxy_event())

    # create lambda
    create_function_response = create_lambda_function(
        func_name=function_name,
        handler_file=TEST_LAMBDA_AWS_PROXY,
        handler="lambda_aws_proxy.handler",
        runtime=LAMBDA_RUNTIME_PYTHON39,
    )
    # create invocation role
    assume_role_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Principal": {"Service": "apigateway.amazonaws.com"},
                "Effect": "Allow",
            }
        ],
    }
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"}],
    }
    role_arn = create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(assume_role_doc)
    )["Role"]["Arn"]
    policy_arn = create_policy(
        PolicyName=f"test-policy-{short_uid()}", PolicyDocument=json.dumps(policy_doc)
    )["Policy"]["Arn"]
    iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    lambda_arn = create_function_response["CreateFunctionResponse"]["FunctionArn"]

    # create rest api
    rest_api_creation_response = apigateway_client.create_rest_api(
        name=f"test-api-{short_uid()}", description="Integration test API"
    )
    snapshot.match("rest-api-creation", rest_api_creation_response)
    cleanups.append(lambda: apigateway_client.delete_rest_api(restApiId=rest_api_id))
    rest_api_id = rest_api_creation_response["id"]
    root_resource_id = apigateway_client.get_resources(restApiId=rest_api_id)["items"][0]["id"]
    resource_id = apigateway_client.create_resource(
        restApiId=rest_api_id, parentId=root_resource_id, pathPart="{proxy+}"
    )["id"]
    apigateway_client.put_method(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="ANY",
        authorizationType="NONE",
    )
    apigateway_client.put_integration(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="ANY",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{apigateway_client.meta.region_name}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations",
        credentials=role_arn,
    )
    apigateway_client.create_deployment(restApiId=rest_api_id, stageName=stage_name)

    # invoke rest api
    invocation_url = api_invoke_url(
        api_id=rest_api_id,
        stage=stage_name,
        path="/test-path",
    )

    def invoke_api(url):
        # use test header with different casing to check if it is preserved in the proxy payload
        response = requests.get(
            url,
            headers={"User-Agent": "python-requests/testing", "tEsT-HEADeR": "aValUE"},
            verify=False,
        )
        assert 200 == response.status_code
        return response

    # retry is necessary against AWS, probably IAM permission delay
    response = retry(invoke_api, sleep=2, retries=10, url=invocation_url)
    snapshot.match("invocation-payload-without-trailing-slash", response.json())

    # invoke rest api with trailing slash
    response_trailing_slash = retry(invoke_api, sleep=2, retries=10, url=f"{invocation_url}/")
    snapshot.match("invocation-payload-with-trailing-slash", response_trailing_slash.json())

    response_no_trailing_slash = retry(
        invoke_api, sleep=2, retries=10, url=f"{invocation_url}?urlparam=test"
    )
    snapshot.match(
        "invocation-payload-without-trailing-slash-and-query-params",
        response_no_trailing_slash.json(),
    )

    response_trailing_slash_param = retry(
        invoke_api, sleep=2, retries=10, url=f"{invocation_url}/?urlparam=test"
    )
    snapshot.match(
        "invocation-payload-with-trailing-slash-and-query-params",
        response_trailing_slash_param.json(),
    )

    # invoke rest api with encoded information in URL path
    path_encoded_emails = "user/test%2Balias@gmail.com/plus/test+alias@gmail.com"
    response_path_encoding = retry(
        invoke_api,
        sleep=2,
        retries=10,
        url=f"{invocation_url}/api/{path_encoded_emails}",
    )
    snapshot.match(
        "invocation-payload-with-path-encoded-email",
        response_path_encoding.json(),
    )

    # invoke rest api with encoded information in URL params
    url_params = "&".join(
        [
            "dateTimeOffset=2023-06-12T18:05:10.123456+00:00",
            "email=test%2Balias@gmail.com",
            "plus=test+alias@gmail.com",
            "url=https://www.google.com/",
            "whitespace=foo bar",
            "zhash=abort/#",
            "ignored=this-does-not-appear-after-the-hash",
        ]
    )
    response_params_encoding = retry(
        invoke_api,
        sleep=2,
        retries=10,
        url=f"{invocation_url}/api?{url_params}",
    )
    snapshot.match(
        "invocation-payload-with-params-encoding",
        response_params_encoding.json(),
    )


def test_put_integration_responses(apigateway_client):
    response = apigateway_client.create_rest_api(name="my_api", description="this is my api")
    api_id = response["id"]

    resources = apigateway_client.get_resources(restApiId=api_id)
    root_id = [resource for resource in resources["items"] if resource["path"] == "/"][0]["id"]

    apigateway_client.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="none"
    )

    apigateway_client.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    apigateway_client.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="HTTP",
        # TODO: replace httpbin.org requests with httpserver/echo_http_server fixture
        uri="http://httpbin.org/robots.txt",
        integrationHttpMethod="POST",
    )

    response = apigateway_client.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        selectionPattern="foobar",
        responseTemplates={},
    )

    # this is hard to match against, so remove it
    response["ResponseMetadata"].pop("HTTPHeaders", None)
    response["ResponseMetadata"].pop("RetryAttempts", None)
    response["ResponseMetadata"].pop("RequestId", None)
    assert response == (
        {
            "statusCode": "200",
            "selectionPattern": "foobar",
            "ResponseMetadata": {"HTTPStatusCode": 201},
            "responseTemplates": {},  # Note: TF compatibility
        }
    )

    response = apigateway_client.get_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    # this is hard to match against, so remove it
    response["ResponseMetadata"].pop("HTTPHeaders", None)
    response["ResponseMetadata"].pop("RetryAttempts", None)
    response["ResponseMetadata"].pop("RequestId", None)
    assert response == (
        {
            "statusCode": "200",
            "selectionPattern": "foobar",
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "responseTemplates": {},  # Note: TF compatibility
        }
    )

    response = apigateway_client.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    # this is hard to match against, so remove it
    response["ResponseMetadata"].pop("HTTPHeaders", None)
    response["ResponseMetadata"].pop("RetryAttempts", None)
    response["ResponseMetadata"].pop("RequestId", None)
    assert response["methodIntegration"]["integrationResponses"] == (
        {
            "200": {
                "responseTemplates": {},  # Note: TF compatibility
                "selectionPattern": "foobar",
                "statusCode": "200",
            }
        }
    )

    url = path_based_url(api_id=api_id, stage_name="local", path="/")
    response = requests.get(url, data=json.dumps({"egg": "ham"}))
    assert response.ok

    apigateway_client.delete_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    response = apigateway_client.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert response["methodIntegration"]["integrationResponses"] == {}

    # adding a new method and performing put integration with contentHandling as CONVERT_TO_BINARY
    apigateway_client.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="PUT", authorizationType="none"
    )

    apigateway_client.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="PUT", statusCode="200"
    )

    apigateway_client.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="PUT",
        type="HTTP",
        # TODO: replace httpbin.org requests with httpserver/echo_http_server fixture
        uri="http://httpbin.org/robots.txt",
        integrationHttpMethod="POST",
    )

    response = apigateway_client.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="PUT",
        statusCode="200",
        selectionPattern="foobar",
        responseTemplates={},
        contentHandling="CONVERT_TO_BINARY",
    )

    # this is hard to match against, so remove it
    response["ResponseMetadata"].pop("HTTPHeaders", None)
    response["ResponseMetadata"].pop("RetryAttempts", None)
    response["ResponseMetadata"].pop("RequestId", None)
    assert response == (
        {
            "statusCode": "200",
            "selectionPattern": "foobar",
            "ResponseMetadata": {"HTTPStatusCode": 201},
            "responseTemplates": {},  # Note: TF compatibility
            "contentHandling": "CONVERT_TO_BINARY",
        }
    )

    response = apigateway_client.get_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="PUT", statusCode="200"
    )
    # this is hard to match against, so remove it
    response["ResponseMetadata"].pop("HTTPHeaders", None)
    response["ResponseMetadata"].pop("RetryAttempts", None)
    response["ResponseMetadata"].pop("RequestId", None)
    assert response == (
        {
            "statusCode": "200",
            "selectionPattern": "foobar",
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "responseTemplates": {},  # Note: TF compatibility
            "contentHandling": "CONVERT_TO_BINARY",
        }
    )


def test_put_integration_response_with_response_template(apigateway_client):
    response = apigateway_client.create_rest_api(name="my_api", description="this is my api")
    api_id = response["id"]
    resources = apigateway_client.get_resources(restApiId=api_id)
    root_id = [resource for resource in resources["items"] if resource["path"] == "/"][0]["id"]

    apigateway_client.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    apigateway_client.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    apigateway_client.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="HTTP",
        # TODO: replace httpbin.org requests with httpserver/echo_http_server fixture
        uri="http://httpbin.org/robots.txt",
        integrationHttpMethod="POST",
    )

    apigateway_client.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        selectionPattern="foobar",
        responseTemplates={"application/json": json.dumps({"data": "test"})},
    )

    response = apigateway_client.get_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    # this is hard to match against, so remove it
    response["ResponseMetadata"].pop("HTTPHeaders", None)
    response["ResponseMetadata"].pop("RetryAttempts", None)
    response["ResponseMetadata"].pop("RequestId", None)
    assert response == {
        "statusCode": "200",
        "selectionPattern": "foobar",
        "ResponseMetadata": {"HTTPStatusCode": 200},
        "responseTemplates": {"application/json": json.dumps({"data": "test"})},
    }


# TODO: add snapshot test!
def test_put_integration_validation(apigateway_client):
    response = apigateway_client.create_rest_api(name="my_api", description="this is my api")
    api_id = response["id"]
    resources = apigateway_client.get_resources(restApiId=api_id)
    root_id = [resource for resource in resources["items"] if resource["path"] == "/"][0]["id"]

    apigateway_client.put_method(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
    )
    apigateway_client.put_method_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    http_types = ["HTTP", "HTTP_PROXY"]
    aws_types = ["AWS", "AWS_PROXY"]
    types_requiring_integration_method = http_types + ["AWS"]
    types_not_requiring_integration_method = ["MOCK"]

    # TODO: replace httpbin.org requests below with httpserver/echo_http_server fixture

    for _type in types_requiring_integration_method:
        # Ensure that integrations of these types fail if no integrationHttpMethod is provided
        with pytest.raises(ClientError) as ex:
            apigateway_client.put_integration(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="GET",
                type=_type,
                uri="http://httpbin.org/robots.txt",
            )
        assert ex.value.response["Error"]["Code"] == "BadRequestException"
        assert (
            ex.value.response["Error"]["Message"]
            == "Enumeration value for HttpMethod must be non-empty"
        )

    for _type in types_not_requiring_integration_method:
        # Ensure that integrations of these types do not need the integrationHttpMethod
        apigateway_client.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            type=_type,
            uri="http://httpbin.org/robots.txt",
        )
    for _type in http_types:
        # Ensure that it works fine when providing the integrationHttpMethod-argument
        apigateway_client.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            type=_type,
            uri="http://httpbin.org/robots.txt",
            integrationHttpMethod="POST",
        )
    for _type in ["AWS"]:
        # Ensure that it works fine when providing the integrationHttpMethod + credentials
        apigateway_client.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            credentials="arn:aws:iam::{}:role/service-role/testfunction-role-oe783psq".format(
                get_aws_account_id()
            ),
            httpMethod="GET",
            type=_type,
            uri="arn:aws:apigateway:us-west-2:s3:path/b/k",
            integrationHttpMethod="POST",
        )
    for _type in aws_types:
        # Ensure that credentials are not required when URI points to a Lambda stream
        apigateway_client.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            type=_type,
            uri="arn:aws:apigateway:eu-west-1:lambda:path/2015-03-31/functions/arn:aws:lambda:eu"
            "-west-1:012345678901:function:MyLambda/invocations",
            integrationHttpMethod="POST",
        )
    for _type in ["AWS_PROXY"]:
        # Ensure that aws_proxy does not support S3
        with pytest.raises(ClientError) as ex:
            apigateway_client.put_integration(
                restApiId=api_id,
                resourceId=root_id,
                credentials="arn:aws:iam::{}:role/service-role/testfunction-role-oe783psq".format(
                    get_aws_account_id()
                ),
                httpMethod="GET",
                type=_type,
                uri="arn:aws:apigateway:us-west-2:s3:path/b/k",
                integrationHttpMethod="POST",
            )
        assert ex.value.response["Error"]["Code"] == "BadRequestException"
        assert (
            ex.value.response["Error"]["Message"] == "Integrations of type 'AWS_PROXY' "
            "currently only supports Lambda function "
            "and Firehose stream invocations."
        )
    for _type in http_types:
        # Ensure that the URI is valid HTTP
        with pytest.raises(ClientError) as ex:
            apigateway_client.put_integration(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="GET",
                type=_type,
                uri="non-valid-http",
                integrationHttpMethod="POST",
            )
        assert ex.value.response["Error"]["Code"] == "BadRequestException"
        assert ex.value.response["Error"]["Message"] == "Invalid HTTP endpoint specified for URI"

    # Ensure that the URI is an ARN
    with pytest.raises(ClientError) as ex:
        apigateway_client.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            type="AWS",
            uri="non-valid-arn",
            integrationHttpMethod="POST",
        )
    assert ex.value.response["Error"]["Code"] == "BadRequestException"
    assert ex.value.response["Error"]["Message"] == "Invalid ARN specified in the request"

    # Ensure that the URI is a valid ARN
    with pytest.raises(ClientError) as ex:
        apigateway_client.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            type="AWS",
            uri="arn:aws:iam::0000000000:role/service-role/asdf",
            integrationHttpMethod="POST",
        )
    assert ex.value.response["Error"]["Code"] == "BadRequestException"
    assert (
        ex.value.response["Error"]["Message"] == "AWS ARN for integration must contain path or "
        "action"
    )


@pytest.fixture
def default_vpc(ec2_client):
    vpcs = ec2_client.describe_vpcs()
    for vpc in vpcs["Vpcs"]:
        if vpc.get("IsDefault"):
            return vpc
    raise Exception("Default VPC not found")


@pytest.fixture
def create_vpc_endpoint(ec2_client, default_vpc):
    endpoints = []

    def _create(**kwargs):
        kwargs.setdefault("VpcId", default_vpc["VpcId"])
        result = ec2_client.create_vpc_endpoint(**kwargs)
        endpoints.append(result["VpcEndpoint"]["VpcEndpointId"])
        return result["VpcEndpoint"]

    yield _create

    for endpoint in endpoints:
        with contextlib.suppress(Exception):
            ec2_client.delete_vpc_endpoints(VpcEndpointIds=[endpoint])


@pytest.mark.skip_snapshot_verify(
    paths=["$..endpointConfiguration.types", "$..policy.Statement..Resource"]
)
def test_create_execute_api_vpc_endpoint(
    create_rest_api_with_integration,
    dynamodb_create_table,
    create_vpc_endpoint,
    default_vpc,
    create_lambda_function,
    ec2_create_security_group,
    ec2_client,
    apigateway_client,
    dynamodb_resource,
    lambda_client,
    snapshot,
):
    poll_sleep = 5 if is_aws_cloud() else 1
    # TODO: create a re-usable ec2_api() transformer
    snapshot.add_transformer(snapshot.transform.key_value("DnsName"))
    snapshot.add_transformer(snapshot.transform.key_value("GroupId"))
    snapshot.add_transformer(snapshot.transform.key_value("GroupName"))
    snapshot.add_transformer(snapshot.transform.key_value("SubnetIds"))
    snapshot.add_transformer(snapshot.transform.key_value("VpcId"))
    snapshot.add_transformer(snapshot.transform.key_value("VpcEndpointId"))
    snapshot.add_transformer(snapshot.transform.key_value("HostedZoneId"))
    snapshot.add_transformer(snapshot.transform.key_value("id"))
    snapshot.add_transformer(snapshot.transform.key_value("name"))

    # create table
    table = dynamodb_create_table()["TableDescription"]
    table_name = table["TableName"]

    # insert items
    dynamodb_table = dynamodb_resource.Table(table_name)
    item_ids = ("test", "test2", "test 3")
    for item_id in item_ids:
        dynamodb_table.put_item(Item={"id": item_id})

    # construct request mapping template
    request_templates = {APPLICATION_JSON: json.dumps({"TableName": table_name})}

    # deploy REST API with integration
    region_name = apigateway_client.meta.region_name
    integration_uri = f"arn:aws:apigateway:{region_name}:dynamodb:action/Scan"
    api_id = create_rest_api_with_integration(
        integration_uri=integration_uri,
        req_templates=request_templates,
        integration_type="AWS",
    )

    # get service names
    service_name = f"com.amazonaws.{region_name}.execute-api"
    service_names = ec2_client.describe_vpc_endpoint_services()["ServiceNames"]
    assert service_name in service_names

    # create security group
    vpc_id = default_vpc["VpcId"]
    security_group = ec2_create_security_group(
        VpcId=vpc_id, Description="Test SG for API GW", ports=[443]
    )
    security_group = security_group["GroupId"]
    subnets = ec2_client.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    subnets = [sub["SubnetId"] for sub in subnets["Subnets"]]

    # get or create execute-api VPC endpoint
    endpoints = ec2_client.describe_vpc_endpoints(MaxResults=1000)["VpcEndpoints"]
    matching = [ep for ep in endpoints if ep["ServiceName"] == service_name]
    if matching:
        endpoint_id = matching[0]["VpcEndpointId"]
    else:
        result = create_vpc_endpoint(
            ServiceName=service_name,
            VpcEndpointType="Interface",
            SubnetIds=subnets,
            SecurityGroupIds=[security_group],
        )
        endpoint_id = result["VpcEndpointId"]

    # wait until VPC endpoint is in state "available"
    def _check_available():
        result = ec2_client.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])
        endpoint_details = result["VpcEndpoints"][0]
        # may have multiple entries in AWS
        endpoint_details["DnsEntries"] = endpoint_details["DnsEntries"][:1]
        endpoint_details.pop("SubnetIds", None)
        endpoint_details.pop("NetworkInterfaceIds", None)
        assert endpoint_details["State"] == "available"
        snapshot.match("endpoint-details", endpoint_details)

    retry(_check_available, retries=30, sleep=poll_sleep)

    # update API with VPC endpoint
    patches = [
        {"op": "replace", "path": "/endpointConfiguration/types/EDGE", "value": "PRIVATE"},
        {"op": "add", "path": "/endpointConfiguration/vpcEndpointIds", "value": endpoint_id},
    ]
    apigateway_client.update_rest_api(restApiId=api_id, patchOperations=patches)

    # create Lambda that invokes API via VPC endpoint (required as the endpoint is only accessible within the VPC)
    subdomain = f"{api_id}-{endpoint_id}"
    endpoint = api_invoke_url(subdomain, stage=DEFAULT_STAGE_NAME, path="/test")
    host_header = urlparse(endpoint).netloc

    # create Lambda function that invokes the API GW (private VPC endpoint not accessible from outside of AWS)
    if not is_aws_cloud():
        if config.LAMBDA_EXECUTOR == "local" and is_old_provider():
            # special case: return localhost for local Lambda executor (TODO remove after full switch to v2 provider)
            api_host = LOCALHOST
        else:
            api_host = get_main_endpoint_from_container()
        endpoint = endpoint.replace(host_header, f"{api_host}:{config.get_edge_port_http()}")
    lambda_code = textwrap.dedent(
        f"""
    def handler(event, context):
        import requests
        headers = {{"content-type": "application/json", "host": "{host_header}"}}
        result = requests.post("{endpoint}", headers=headers)
        return {{"content": result.content.decode("utf-8"), "code": result.status_code}}
    """
    )
    func_name = f"test-{short_uid()}"
    vpc_config = {
        "SubnetIds": subnets,
        "SecurityGroupIds": [security_group],
    }
    create_lambda_function(
        func_name=func_name,
        handler_file=lambda_code,
        libs=TEST_LAMBDA_LIBS,
        timeout=10,
        VpcConfig=vpc_config,
    )

    # create resource policy
    statement = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "execute-api:Invoke",
                "Resource": ["execute-api:/*"],
            }
        ],
    }
    patches = [{"op": "replace", "path": "/policy", "value": json.dumps(statement)}]
    result = apigateway_client.update_rest_api(restApiId=api_id, patchOperations=patches)
    result["policy"] = json.loads(to_bytes(result["policy"]).decode("unicode_escape"))
    snapshot.match("api-details", result)

    # re-deploy API
    create_rest_api_deployment(apigateway_client, restApiId=api_id, stageName=DEFAULT_STAGE_NAME)

    def _invoke_api():
        result = lambda_client.invoke(FunctionName=func_name, Payload="{}")
        result = json.loads(to_str(result["Payload"].read()))
        items = json.loads(result["content"])["Items"]
        assert len(items) == len(item_ids)

    # invoke Lambda and assert result
    retry(_invoke_api, retries=15, sleep=poll_sleep)


# TODO - remove the code below?
#
# def test_aws_integration_dynamodb(apigateway_client):
#     if settings.TEST_SERVER_MODE:
#         raise SkipTest("Cannot test mock of execute-api.apigateway in ServerMode")
#
#     client = boto3.client("apigateway", region_name="us-west-2")
#     dynamodb = boto3.client("dynamodb", region_name="us-west-2")
#     table_name = "test_1"
#     integration_action = "arn:aws:apigateway:us-west-2:dynamodb:action/PutItem"
#     stage_name = "staging"
#
#     create_table(dynamodb, table_name)
#     api_id, _ = create_integration_test_api(client, integration_action)
#
#     client.create_deployment(restApiId=api_id, stageName=stage_name)
#
#     res = requests.put(
#         f"https://{api_id}.execute-api.us-west-2.amazonaws.com/{stage_name}",
#         json={"TableName": table_name, "Item": {"name": {"S": "the-key"}}},
#     )
#     res.status_code.should.equal(200)
#     res.content.should.equal(b"{}")
#
#
# def test_aws_integration_dynamodb_multiple_stages(apigateway_client):
#     if settings.TEST_SERVER_MODE:
#         raise SkipTest("Cannot test mock of execute-api.apigateway in ServerMode")
#
#     client = boto3.client("apigateway", region_name="us-west-2")
#     dynamodb = boto3.client("dynamodb", region_name="us-west-2")
#     table_name = "test_1"
#     integration_action = "arn:aws:apigateway:us-west-2:dynamodb:action/PutItem"
#
#     create_table(dynamodb, table_name)
#     api_id, _ = create_integration_test_api(client, integration_action)
#
#     client.create_deployment(restApiId=api_id, stageName="dev")
#     client.create_deployment(restApiId=api_id, stageName="staging")
#
#     res = requests.put(
#         f"https://{api_id}.execute-api.us-west-2.amazonaws.com/dev",
#         json={"TableName": table_name, "Item": {"name": {"S": "the-key"}}},
#     )
#     res.status_code.should.equal(200)
#
#     res = requests.put(
#         f"https://{api_id}.execute-api.us-west-2.amazonaws.com/staging",
#         json={"TableName": table_name, "Item": {"name": {"S": "the-key"}}},
#     )
#     res.status_code.should.equal(200)
#
#     # We haven't pushed to prod yet
#     res = requests.put(
#         f"https://{api_id}.execute-api.us-west-2.amazonaws.com/prod",
#         json={"TableName": table_name, "Item": {"name": {"S": "the-key"}}},
#     )
#     res.status_code.should.equal(400)
#
#
# @mock_apigateway
# @mock_dynamodb
# def test_aws_integration_dynamodb_multiple_resources():
#     if settings.TEST_SERVER_MODE:
#         raise SkipTest("Cannot test mock of execute-api.apigateway in ServerMode")
#
#     client = boto3.client("apigateway", region_name="us-west-2")
#     dynamodb = boto3.client("dynamodb", region_name="us-west-2")
#     table_name = "test_1"
#     create_table(dynamodb, table_name)
#
#     # Create API integration to PutItem
#     integration_action = "arn:aws:apigateway:us-west-2:dynamodb:action/PutItem"
#     api_id, root_id = create_integration_test_api(client, integration_action)
#
#     # Create API integration to GetItem
#     res = client.create_resource(restApiId=api_id, parentId=root_id, pathPart="item")
#     parent_id = res["id"]
#     integration_action = "arn:aws:apigateway:us-west-2:dynamodb:action/GetItem"
#     api_id, root_id = create_integration_test_api(
#         client,
#         integration_action,
#         api_id=api_id,
#         parent_id=parent_id,
#         http_method="GET",
#     )
#
#     client.create_deployment(restApiId=api_id, stageName="dev")
#
#     # Put item at the root resource
#     res = requests.put(
#         f"https://{api_id}.execute-api.us-west-2.amazonaws.com/dev",
#         json={
#             "TableName": table_name,
#             "Item": {"name": {"S": "the-key"}, "attr2": {"S": "sth"}},
#         },
#     )
#     res.status_code.should.equal(200)
#
#     # Get item from child resource
#     res = requests.get(
#         f"https://{api_id}.execute-api.us-west-2.amazonaws.com/dev/item",
#         json={"TableName": table_name, "Key": {"name": {"S": "the-key"}}},
#     )
#     res.status_code.should.equal(200)
#     json.loads(res.content).should.equal(
#         {"Item": {"name": {"S": "the-key"}, "attr2": {"S": "sth"}}}
#     )
#
#
# def create_table(dynamodb, table_name):
#     # Create DynamoDB table
#     dynamodb.create_table(
#         TableName=table_name,
#         KeySchema=[{"AttributeName": "name", "KeyType": "HASH"}],
#         AttributeDefinitions=[{"AttributeName": "name", "AttributeType": "S"}],
#         BillingMode="PAY_PER_REQUEST",
#     )
#
#
# def create_integration_test_api(
#     client, integration_action, api_id=None, parent_id=None, http_method="PUT"
# ):
#     if not api_id:
#         # We do not have a root yet - create the API first
#         response = client.create_rest_api(name="my_api", description="this is my api")
#         api_id = response["id"]
#     if not parent_id:
#         resources = client.get_resources(restApiId=api_id)
#         parent_id = [
#             resource for resource in resources["items"] if resource["path"] == "/"
#         ][0]["id"]
#
#     client.put_method(
#         restApiId=api_id,
#         resourceId=parent_id,
#         httpMethod=http_method,
#         authorizationType="NONE",
#     )
#     client.put_method_response(
#         restApiId=api_id, resourceId=parent_id, httpMethod=http_method, statusCode="200"
#     )
#     client.put_integration(
#         restApiId=api_id,
#         resourceId=parent_id,
#         httpMethod=http_method,
#         type="AWS",
#         uri=integration_action,
#         integrationHttpMethod=http_method,
#     )
#     client.put_integration_response(
#         restApiId=api_id,
#         resourceId=parent_id,
#         httpMethod=http_method,
#         statusCode="200",
#         selectionPattern="",
#         responseTemplates={"application/json": "{}"},
#     )
#     return api_id, parent_id

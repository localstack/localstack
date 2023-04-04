import json

import pytest
import requests

from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON39
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.integration.apigateway.apigateway_fixtures import (
    api_invoke_url,
    create_rest_api_integration,
    create_rest_api_integration_response,
    create_rest_api_method_response,
    create_rest_resource,
    create_rest_resource_method,
)
from tests.integration.apigateway.conftest import APIGATEWAY_ASSUME_ROLE_POLICY
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_AWS_PROXY, TEST_LAMBDA_PYTHON_ECHO


@pytest.mark.aws_validated
@pytest.mark.skip_snapshot_verify(
    paths=[
        "$..body",
        "$..headers.Accept",
        "$..headers.Content-Length",
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
        "$..multiValueHeaders.Content-Length",
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
        "$..requestContext.apiId",
        "$..requestContext.authorizer",
        "$..requestContext.domainName",
        "$..requestContext.domainPrefix",
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
def test_lambda_aws_proxy_integration(
    apigateway_client,
    create_rest_apigw,
    create_lambda_function,
    create_role_with_policy,
    snapshot,
):
    function_name = f"test-function-{short_uid()}"
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
    _, role_arn = create_role_with_policy(
        "Allow", "lambda:InvokeFunction", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )
    lambda_arn = create_function_response["CreateFunctionResponse"]["FunctionArn"]
    # create rest api
    api_id, _, root = create_rest_apigw(
        name=f"test-api-{short_uid()}",
        description="Integration test API",
    )
    resource_id = apigateway_client.create_resource(
        restApiId=api_id, parentId=root, pathPart="{proxy+}"
    )["id"]
    apigateway_client.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="ANY",
        authorizationType="NONE",
    )

    # Lambda AWS_PROXY integration
    apigateway_client.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="ANY",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{apigateway_client.meta.region_name}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations",
        credentials=role_arn,
    )
    apigateway_client.create_deployment(restApiId=api_id, stageName=stage_name)

    # invoke rest api
    invocation_url = api_invoke_url(
        api_id=api_id,
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

    def invoke_api_with_multi_value_header(url):
        headers = {
            "Content-Type": "application/json;charset=utf-8",
            "Authorization": "Bearer token123;API key456",
        }

        params = {"category": ["electronics", "books"], "price": ["10", "20", "30"]}
        response = requests.post(
            url,
            data=json.dumps({"message": "hello world"}),
            headers=headers,
            params=params,
            verify=False,
        )
        assert response.ok
        return response

    responses = retry(invoke_api_with_multi_value_header, sleep=2, retries=10, url=invocation_url)
    snapshot.match("invocation-payload-with-params-encoding-multi", responses.json())


@pytest.mark.aws_validated
def test_lambda_aws_integration(
    apigateway_client, create_rest_apigw, create_lambda_function, create_role_with_policy, snapshot
):
    function_name = f"test-{short_uid()}"
    stage_name = "api"
    create_function_response = create_lambda_function(
        func_name=function_name,
        handler_file=TEST_LAMBDA_PYTHON_ECHO,
        handler="lambda_echo.handler",
        runtime=LAMBDA_RUNTIME_PYTHON39,
    )
    # create invocation role
    _, role_arn = create_role_with_policy(
        "Allow", "lambda:InvokeFunction", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )
    lambda_arn = create_function_response["CreateFunctionResponse"]["FunctionArn"]

    api_id, _, root = create_rest_apigw(name=f"test-api-{short_uid()}")
    resource_id, _ = create_rest_resource(
        apigateway_client, restApiId=api_id, parentId=root, pathPart="test"
    )
    create_rest_resource_method(
        apigateway_client,
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        authorizationType="NONE",
    )
    create_rest_api_integration(
        apigateway_client,
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        type="AWS",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{apigateway_client.meta.region_name}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations",
        credentials=role_arn,
    )
    create_rest_api_integration_response(
        apigateway_client,
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        statusCode="200",
    )
    create_rest_api_method_response(
        apigateway_client,
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        statusCode="200",
    )
    apigateway_client.create_deployment(restApiId=api_id, stageName=stage_name)
    invocation_url = api_invoke_url(api_id=api_id, stage=stage_name, path="/test")

    def invoke_api(url):
        response = requests.post(url, data=json.dumps({"message": "hello world"}), verify=False)
        assert response.ok
        assert response.json() == {"message": "hello world"}
        return response

    response = retry(invoke_api, sleep=2, retries=10, url=invocation_url)
    snapshot.match("lambda-aws-integration", response.json())

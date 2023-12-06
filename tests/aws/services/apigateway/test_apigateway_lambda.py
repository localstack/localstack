import json
import os

import pytest
import requests
from botocore.exceptions import ClientError

from localstack.aws.api.lambda_ import Runtime
from localstack.constants import TEST_AWS_REGION_NAME
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.aws.services.apigateway.apigateway_fixtures import api_invoke_url, create_rest_resource
from tests.aws.services.apigateway.conftest import APIGATEWAY_ASSUME_ROLE_POLICY
from tests.aws.services.lambda_.test_lambda import (
    TEST_LAMBDA_AWS_PROXY,
    TEST_LAMBDA_MAPPING_RESPONSES,
    TEST_LAMBDA_PYTHON_ECHO,
    TEST_LAMBDA_PYTHON_SELECT_PATTERN,
)

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
REQUEST_TEMPLATE_VM = os.path.join(THIS_FOLDER, "../../files/request-template.vm")
RESPONSE_TEMPLATE_VM = os.path.join(THIS_FOLDER, "../../files/response-template.vm")


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
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
    create_rest_apigw, create_lambda_function, create_role_with_policy, snapshot, aws_client
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
        runtime=Runtime.python3_9,
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
    # use a regex transform as create_rest_apigw fixture does not return the original response
    snapshot.add_transformer(snapshot.transform.regex(api_id, replacement="<api-id>"), priority=-1)
    resource_id = aws_client.apigateway.create_resource(
        restApiId=api_id, parentId=root, pathPart="{proxy+}"
    )["id"]
    aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="ANY",
        authorizationType="NONE",
    )

    # Lambda AWS_PROXY integration
    aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="ANY",
        type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=f"arn:aws:apigateway:{aws_client.apigateway.meta.region_name}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations",
        credentials=role_arn,
    )
    aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)

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
            "User-Agent": "python-requests/testing",
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


@markers.aws.validated
def test_lambda_aws_integration(
    create_rest_apigw, create_lambda_function, create_role_with_policy, snapshot, aws_client
):
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("cacheNamespace"),
            snapshot.transform.key_value("credentials"),
            snapshot.transform.key_value("uri"),
        ]
    )
    function_name = f"test-{short_uid()}"
    stage_name = "api"
    create_function_response = create_lambda_function(
        func_name=function_name,
        handler_file=TEST_LAMBDA_PYTHON_ECHO,
        handler="lambda_echo.handler",
        runtime=Runtime.python3_9,
    )
    # create invocation role
    _, role_arn = create_role_with_policy(
        "Allow", "lambda:InvokeFunction", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )
    lambda_arn = create_function_response["CreateFunctionResponse"]["FunctionArn"]
    target_uri = arns.apigateway_invocations_arn(lambda_arn, TEST_AWS_REGION_NAME)

    api_id, _, root = create_rest_apigw(name=f"test-api-{short_uid()}")
    resource_id, _ = create_rest_resource(
        aws_client.apigateway, restApiId=api_id, parentId=root, pathPart="test"
    )

    response = aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        authorizationType="NONE",
    )
    snapshot.match("put-method", response)

    response = aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        type="AWS",
        integrationHttpMethod="POST",
        uri=target_uri,
        credentials=role_arn,
    )
    snapshot.match("put-integration", response)

    response = aws_client.apigateway.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        statusCode="200",
    )
    snapshot.match("put-integration-response", response)

    response = aws_client.apigateway.put_method_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        statusCode="200",
    )
    snapshot.match("put-method-response", response)

    aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)
    invocation_url = api_invoke_url(api_id=api_id, stage=stage_name, path="/test")

    def invoke_api(url):
        _response = requests.post(url, data=json.dumps({"message": "hello world"}), verify=False)
        assert _response.ok
        response_content = _response.json()
        assert response_content == {"message": "hello world"}
        return response_content

    response_data = retry(invoke_api, sleep=2, retries=10, url=invocation_url)
    snapshot.match("lambda-aws-integration", response_data)


@markers.aws.validated
def test_lambda_aws_integration_with_request_template(
    create_rest_apigw, create_lambda_function, create_role_with_policy, snapshot, aws_client
):
    # this test almost follow
    # https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-custom-integrations.html
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("cacheNamespace"),
            snapshot.transform.key_value("credentials"),
            snapshot.transform.key_value("uri"),
        ]
    )
    function_name = f"test-{short_uid()}"
    stage_name = "api"
    create_function_response = create_lambda_function(
        func_name=function_name,
        handler_file=TEST_LAMBDA_PYTHON_ECHO,
        handler="lambda_echo.handler",
        runtime=Runtime.python3_9,
    )
    # create invocation role
    _, role_arn = create_role_with_policy(
        "Allow", "lambda:InvokeFunction", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )

    lambda_arn = create_function_response["CreateFunctionResponse"]["FunctionArn"]
    target_uri = arns.apigateway_invocations_arn(lambda_arn, TEST_AWS_REGION_NAME)

    api_id, _, root = create_rest_apigw(name=f"test-api-{short_uid()}")
    resource_id, _ = create_rest_resource(
        aws_client.apigateway, restApiId=api_id, parentId=root, pathPart="test"
    )

    response = aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="NONE",
        requestParameters={
            "method.request.querystring.param1": False,
        },
    )
    snapshot.match("put-method", response)

    response = aws_client.apigateway.put_method_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
    )
    snapshot.match("put-method-response", response)

    response = aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        integrationHttpMethod="POST",
        type="AWS",
        uri=target_uri,
        credentials=role_arn,
        requestTemplates={"application/json": '{"param1": "$input.params(\'param1\')"}'},
    )
    snapshot.match("put-integration", response)

    response = aws_client.apigateway.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        selectionPattern="",
    )
    snapshot.match("put-integration-response", response)

    aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)
    invocation_url = api_invoke_url(api_id=api_id, stage=stage_name, path="/test")

    def invoke_api(url):
        _response = requests.get(url, verify=False)
        assert _response.ok
        content = _response.json()
        assert content == {"param1": "foobar"}
        return content

    invoke_param_1 = f"{invocation_url}?param1=foobar"
    response_data = retry(invoke_api, sleep=2, retries=10, url=invoke_param_1)
    snapshot.match("lambda-aws-integration-1", response_data)

    # additional checks from https://github.com/localstack/localstack/issues/5041
    # pass Signature param
    invoke_param_2 = f"{invocation_url}?param1=foobar&Signature=1"
    response_data = retry(invoke_api, sleep=2, retries=10, url=invoke_param_2)
    snapshot.match("lambda-aws-integration-2", response_data)

    response = aws_client.apigateway.delete_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
    )
    snapshot.match("delete-integration", response)

    with pytest.raises(ClientError) as e:
        # This call should not be successful as the integration is deleted
        aws_client.apigateway.get_integration(
            restApiId=api_id, resourceId=resource_id, httpMethod="GET"
        )
    snapshot.match("get-integration-after-delete", e.value.response)


@markers.aws.validated
def test_lambda_aws_integration_response_with_mapping_templates(
    create_rest_apigw, create_lambda_function, create_role_with_policy, snapshot, aws_client, region
):
    function_name = f"test-{short_uid()}"
    stage_name = "api"
    create_function_response = create_lambda_function(
        func_name=function_name,
        handler_file=TEST_LAMBDA_MAPPING_RESPONSES,
        handler="lambda_mapping_responses.handler",
        runtime=Runtime.python3_9,
    )
    # create invocation role
    _, role_arn = create_role_with_policy(
        "Allow", "lambda:InvokeFunction", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )

    lambda_arn = create_function_response["CreateFunctionResponse"]["FunctionArn"]
    target_uri = arns.apigateway_invocations_arn(lambda_arn, region)

    api_id, _, root = create_rest_apigw(name=f"test-api-{short_uid()}")
    resource_id, _ = create_rest_resource(
        aws_client.apigateway, restApiId=api_id, parentId=root, pathPart="test"
    )

    aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        authorizationType="NONE",
    )

    aws_client.apigateway.put_method_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        statusCode="200",
    )

    aws_client.apigateway.put_method_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        statusCode="400",
    )

    aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        integrationHttpMethod="POST",
        type="AWS",
        uri=target_uri,
        credentials=role_arn,
        requestTemplates={
            "application/json": load_file(REQUEST_TEMPLATE_VM),
        },
    )

    aws_client.apigateway.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        statusCode="200",
        selectionPattern="",
        responseTemplates={
            "application/json": load_file(RESPONSE_TEMPLATE_VM),
        },
    )

    aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)
    invocation_url = api_invoke_url(api_id=api_id, stage=stage_name, path="/test")

    def invoke_api(url, body, status_code):
        _response = requests.post(
            url, data=json.dumps(body), verify=False, headers={"Content-Type": "application/json"}
        )
        content = _response.json()

        assert _response.status_code == status_code
        return {"statusCode": _response.status_code, "body": content}

    response = retry(
        invoke_api,
        sleep=2,
        retries=10,
        url=invocation_url,
        body={"httpStatus": "200"},
        status_code=202,
    )
    snapshot.match("response-template-202", response)
    response = retry(
        invoke_api,
        sleep=2,
        retries=10,
        url=invocation_url,
        body={"httpStatus": "400", "errorMessage": "Test Bad request"},
        status_code=400,
    )
    snapshot.match("response-template-400", response)


@markers.aws.validated
def test_lambda_selection_patterns(
    aws_client, create_rest_apigw, create_lambda_function, create_role_with_policy, snapshot
):
    # create invocation role
    _, role_arn = create_role_with_policy(
        "Allow", "lambda:InvokeFunction", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )

    function_name = f"test-{short_uid()}"
    create_function_response = create_lambda_function(
        func_name=function_name,
        handler_file=TEST_LAMBDA_PYTHON_SELECT_PATTERN,
        handler="lambda_select_pattern.handler",
        runtime=Runtime.python3_10,
    )

    lambda_arn = create_function_response["CreateFunctionResponse"]["FunctionArn"]
    target_uri = arns.apigateway_invocations_arn(lambda_arn, aws_client.apigateway.meta.region_name)

    api_id, _, root = create_rest_apigw(name=f"test-api-{short_uid()}")
    resource_id, _ = create_rest_resource(
        aws_client.apigateway, restApiId=api_id, parentId=root, pathPart="{statusCode}"
    )

    aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="NONE",
    )

    aws_client.apigateway.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        integrationHttpMethod="POST",
        type="AWS",
        uri=target_uri,
        credentials=role_arn,
        requestTemplates={"application/json": '{"statusCode": "$input.params(\'statusCode\')"}'},
    )

    # apigw 200 response
    aws_client.apigateway.put_method_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
    )

    # apigw 405 response
    aws_client.apigateway.put_method_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="405",
    )

    # apigw 502 response
    aws_client.apigateway.put_method_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="502",
    )

    # this is where selection patterns come into play
    aws_client.apigateway.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
    )
    # 4xx
    aws_client.apigateway.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="405",
        selectionPattern=".*400.*",
    )
    # 5xx
    aws_client.apigateway.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="502",
        selectionPattern=".*5\\d\\d.*",
    )

    aws_client.apigateway.create_deployment(restApiId=api_id, stageName="dev")

    expected_codes = {
        200: 200,
        400: 405,
        500: 502,
    }

    def invoke_api(status_code):
        url = api_invoke_url(
            api_id=api_id,
            stage="dev",
            path=f"/{status_code}",
        )
        resp = requests.get(url, verify=False)
        assert resp.status_code == expected_codes[status_code]
        return resp

    # retry is necessary against AWS, probably IAM permission delay
    status_codes = [200, 400, 500]
    for status_code in status_codes:
        response = retry(invoke_api, sleep=2, retries=10, status_code=status_code)
        snapshot.match(f"lambda-selection-pattern-{status_code}", response.json())

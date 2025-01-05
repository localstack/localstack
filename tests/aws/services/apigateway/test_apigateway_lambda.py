import base64
import json
import os

import pytest
import requests
from botocore.exceptions import ClientError

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.aws.services.apigateway.apigateway_fixtures import api_invoke_url, create_rest_resource
from tests.aws.services.apigateway.conftest import (
    APIGATEWAY_ASSUME_ROLE_POLICY,
    APIGATEWAY_LAMBDA_POLICY,
    is_next_gen_api,
)
from tests.aws.services.lambda_.test_lambda import (
    TEST_LAMBDA_AWS_PROXY,
    TEST_LAMBDA_AWS_PROXY_FORMAT,
    TEST_LAMBDA_HTTP_RUST,
    TEST_LAMBDA_MAPPING_RESPONSES,
    TEST_LAMBDA_PYTHON_ECHO,
    TEST_LAMBDA_PYTHON_SELECT_PATTERN,
)

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
REQUEST_TEMPLATE_VM = os.path.join(THIS_FOLDER, "../../files/request-template.vm")
RESPONSE_TEMPLATE_VM = os.path.join(THIS_FOLDER, "../../files/response-template.vm")

CLOUDFRONT_SKIP_HEADERS = [
    "$..Via",
    "$..X-Amz-Cf-Id",
    "$..X-Amz-Cf-Pop",
    "$..X-Cache",
    "$..CloudFront-Forwarded-Proto",
    "$..CloudFront-Is-Desktop-Viewer",
    "$..CloudFront-Is-Mobile-Viewer",
    "$..CloudFront-Is-SmartTV-Viewer",
    "$..CloudFront-Is-Tablet-Viewer",
    "$..CloudFront-Viewer-ASN",
    "$..CloudFront-Viewer-Country",
]

LAMBDA_RESPONSE_FROM_BODY = """
import json
import base64
def handler(event, context, *args):
    body = event["body"]
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body)
    return json.loads(body)
"""


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(paths=CLOUDFRONT_SKIP_HEADERS)
@markers.snapshot.skip_snapshot_verify(
    condition=lambda: not is_next_gen_api(),
    paths=[
        "$..body",
        "$..Accept",
        "$..accept",
        "$..Content-Length",
        "$..Accept-Encoding",
        "$..Connection",
        "$..accept-encoding",
        "$..x-localstack-edge",
        "$..pathParameters",
        "$..requestContext.authorizer",
        "$..requestContext.deploymentId",
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
        "$..X-Amzn-Trace-Id",
        "$..X-Forwarded-For",
        "$..X-Forwarded-Port",
        "$..X-Forwarded-Proto",
    ],
)
def test_lambda_aws_proxy_integration(
    create_rest_apigw, create_lambda_function, create_role_with_policy, snapshot, aws_client
):
    function_name = f"test-function-{short_uid()}"
    stage_name = "stage"
    snapshot.add_transformer(snapshot.transform.apigateway_api())
    snapshot.add_transformer(snapshot.transform.apigateway_proxy_event())
    # TODO: update global transformers, but we will need to regenerate all snapshots at once
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("deploymentId"),
            snapshot.transform.jsonpath("$..headers.Host", value_replacement="host"),
            snapshot.transform.jsonpath("$..multiValueHeaders.Host[0]", value_replacement="host"),
            snapshot.transform.key_value(
                "X-Forwarded-For",
                value_replacement="<X-Forwarded-For>",
                reference_replacement=False,
            ),
            snapshot.transform.key_value(
                "X-Forwarded-Port",
                value_replacement="<X-Forwarded-Port>",
                reference_replacement=False,
            ),
            snapshot.transform.key_value(
                "X-Forwarded-Proto",
                value_replacement="<X-Forwarded-Proto>",
                reference_replacement=False,
            ),
        ],
        priority=-1,
    )

    # create lambda
    create_function_response = create_lambda_function(
        func_name=function_name,
        handler_file=TEST_LAMBDA_AWS_PROXY,
        handler="lambda_aws_proxy.handler",
        runtime=Runtime.python3_12,
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
    resource_id_proxy = aws_client.apigateway.create_resource(
        restApiId=api_id, parentId=root, pathPart="{proxy+}"
    )["id"]
    resource_id_hardcoded = aws_client.apigateway.create_resource(
        restApiId=api_id, parentId=root, pathPart="hardcoded"
    )["id"]
    for resource_id in (resource_id_proxy, resource_id_hardcoded):
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

    def get_invoke_url(path: str) -> str:
        return api_invoke_url(
            api_id=api_id,
            stage=stage_name,
            path=path,
        )

    def invoke_api(url):
        # use test header with different casing to check if it is preserved in the proxy payload
        # authorization is a weird case, it will get Pascal cased by default
        _response = requests.get(
            url,
            headers={
                "User-Agent": "python-requests/testing",
                "tEsT-HEADeR": "aValUE",
                "authorization": "random-value",
            },
            verify=False,
        )
        if not _response.ok:
            print(f"{_response.content=}")
        assert _response.status_code == 200
        return _response

    invocation_url = get_invoke_url(path="/proxy-value")
    # retry is necessary against AWS, probably IAM permission delay
    response = retry(invoke_api, sleep=2, retries=10, url=invocation_url)
    snapshot.match("invocation-payload-without-trailing-slash", response.json())

    # invoke rest api with trailing slash
    invocation_url = get_invoke_url(path="/proxy-value/")
    response_trailing_slash = invoke_api(url=invocation_url)
    snapshot.match("invocation-payload-with-trailing-slash", response_trailing_slash.json())

    # invoke rest api with double slash in proxy param
    invocation_url = get_invoke_url(path="/proxy-value//double-slash")
    response_double_slash = invoke_api(url=invocation_url)
    snapshot.match("invocation-payload-with-double-slash", response_double_slash.json())

    # invoke rest api with prepended slash to the stage (//<stage>/<path>)
    invocation_url = get_invoke_url(path="/proxy-value")
    double_slash_before_stage = invocation_url.replace(f"/{stage_name}/", f"//{stage_name}/")
    response_prepend_slash = invoke_api(url=double_slash_before_stage)
    snapshot.match(
        "invocation-payload-with-prepended-slash-to-stage", response_prepend_slash.json()
    )

    # invoke rest api with prepended slash
    slash_between_stage_and_path = get_invoke_url(path="//proxy-value")
    response_prepend_slash = invoke_api(url=slash_between_stage_and_path)
    snapshot.match("invocation-payload-with-prepended-slash", response_prepend_slash.json())

    response_no_trailing_slash = invoke_api(url=f"{invocation_url}?urlparam=test")
    snapshot.match(
        "invocation-payload-without-trailing-slash-and-query-params",
        response_no_trailing_slash.json(),
    )

    response_trailing_slash_param = invoke_api(url=f"{invocation_url}/?urlparam=test")
    snapshot.match(
        "invocation-payload-with-trailing-slash-and-query-params",
        response_trailing_slash_param.json(),
    )

    # invoke rest api with encoded information in URL path
    path_encoded_emails = "user/test%2Balias@gmail.com/plus/test+alias@gmail.com"
    response_path_encoding = invoke_api(url=f"{invocation_url}/api/{path_encoded_emails}")
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
    response_params_encoding = invoke_api(url=f"{invocation_url}/api?{url_params}")
    snapshot.match(
        "invocation-payload-with-params-encoding",
        response_params_encoding.json(),
    )

    def invoke_api_with_multi_value_header(url):
        headers = {
            "Content-Type": "application/json;charset=utf-8",
            "aUThorization": "Bearer token123;API key456",  # test the casing of the Authorization header
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

    # invoke the hardcoded path with prepended slashes
    invocation_url_hardcoded = api_invoke_url(
        api_id=api_id,
        stage=stage_name,
        path="//hardcoded",
    )
    response_hardcoded = retry(invoke_api, sleep=2, retries=10, url=invocation_url_hardcoded)
    snapshot.match("invocation-hardcoded", response_hardcoded.json())


@markers.aws.validated
def test_lambda_aws_proxy_integration_non_post_method(
    create_rest_apigw, create_lambda_function, create_role_with_policy, snapshot, aws_client
):
    function_name = f"test-function-{short_uid()}"
    stage_name = "test"

    # create lambda
    create_function_response = create_lambda_function(
        func_name=function_name,
        handler_file=TEST_LAMBDA_AWS_PROXY,
        handler="lambda_aws_proxy.handler",
        runtime=Runtime.python3_12,
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
        integrationHttpMethod="GET",  # GET is not allowed. We expect this to fail
        uri=f"arn:aws:apigateway:{aws_client.apigateway.meta.region_name}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations",
        credentials=role_arn,
    )

    # Note: we are adding a GatewayResponse here to test a weird AWS bug: when the AWS_PROXY integration fails, it
    # internally raises an IntegrationFailure error.
    # However, in the documentation, it is written than this error should return 504. But like this test shows, when the
    # user does not update the status code, it returns 500, unlike what the documentation and APIGW returns when calling
    # `GetGatewayResponse`.
    # TODO: in the future, write a specific test for this behavior
    aws_client.apigateway.put_gateway_response(
        restApiId=api_id,
        responseType="INTEGRATION_FAILURE",
        responseParameters={},
    )

    aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)
    # invoke rest api
    invocation_url = api_invoke_url(
        api_id=api_id,
        stage=stage_name,
        path="/test-path",
    )

    def invoke_api(url):
        invoke_response = requests.get(
            url,
            headers={
                "User-Agent": "python-requests/testing",
            },
            verify=False,
        )
        assert invoke_response.status_code == 500
        return invoke_response

    # retry is necessary against AWS, probably IAM permission delay
    response = retry(invoke_api, sleep=2, retries=10, url=invocation_url)
    snapshot.match("invocation-payload-with-get-proxy-method", response.json())


@markers.aws.validated
def test_lambda_aws_integration(
    create_rest_apigw,
    create_lambda_function,
    create_role_with_policy,
    snapshot,
    aws_client,
    region_name,
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
        runtime=Runtime.python3_12,
    )
    # create invocation role
    _, role_arn = create_role_with_policy(
        "Allow", "lambda:InvokeFunction", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )
    lambda_arn = create_function_response["CreateFunctionResponse"]["FunctionArn"]
    target_uri = arns.apigateway_invocations_arn(lambda_arn, region_name)

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
    create_rest_apigw,
    create_lambda_function,
    create_role_with_policy,
    snapshot,
    aws_client,
    region_name,
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
        runtime=Runtime.python3_12,
    )
    # create invocation role
    _, role_arn = create_role_with_policy(
        "Allow", "lambda:InvokeFunction", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )

    lambda_arn = create_function_response["CreateFunctionResponse"]["FunctionArn"]
    target_uri = arns.apigateway_invocations_arn(lambda_arn, region_name)

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
    create_rest_apigw,
    create_lambda_function,
    create_role_with_policy,
    snapshot,
    aws_client,
    region_name,
):
    function_name = f"test-{short_uid()}"
    stage_name = "api"
    create_function_response = create_lambda_function(
        func_name=function_name,
        handler_file=TEST_LAMBDA_MAPPING_RESPONSES,
        handler="lambda_mapping_responses.handler",
        runtime=Runtime.python3_12,
    )
    # create invocation role
    _, role_arn = create_role_with_policy(
        "Allow", "lambda:InvokeFunction", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )

    lambda_arn = create_function_response["CreateFunctionResponse"]["FunctionArn"]
    target_uri = arns.apigateway_invocations_arn(lambda_arn, region_name)

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
        runtime=Runtime.python3_12,
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


@markers.aws.validated
def test_lambda_aws_proxy_response_format(
    create_rest_apigw, create_lambda_function, create_role_with_policy, aws_client
):
    stage_name = "test"
    _, role_arn = create_role_with_policy(
        "Allow", "lambda:InvokeFunction", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )

    # create 2 lambdas
    function_name = f"test-function-{short_uid()}"
    create_function_response = create_lambda_function(
        func_name=function_name,
        handler_file=TEST_LAMBDA_AWS_PROXY_FORMAT,
        handler="lambda_aws_proxy_format.handler",
        runtime=Runtime.python3_12,
    )
    # create invocation role
    lambda_arn = create_function_response["CreateFunctionResponse"]["FunctionArn"]

    # create rest api
    api_id, _, root = create_rest_apigw(
        name=f"test-api-{short_uid()}",
        description="Integration test API",
    )

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

    format_types = [
        "no-body",
        "only-headers",
        "wrong-format",
        "empty-response",
    ]
    # TODO: refactor the test to use a lambda that returns whatever we pass it to instead of pre-defined responses
    for lambda_format_type in format_types:
        # invoke rest api
        invocation_url = api_invoke_url(
            api_id=api_id,
            stage=stage_name,
            path=f"/{lambda_format_type}",
        )

        def invoke_api(url):
            # use test header with different casing to check if it is preserved in the proxy payload
            response = requests.get(
                url,
                headers={"User-Agent": "python-requests/testing"},
                verify=False,
            )
            if lambda_format_type == "wrong-format":
                assert response.status_code == 502
            else:
                assert response.status_code == 200
            return response

        # retry is necessary against AWS, probably IAM permission delay
        response = retry(invoke_api, sleep=2, retries=10, url=invocation_url)

        if lambda_format_type in ("no-body", "only-headers", "empty-response"):
            assert response.content == b""
            if lambda_format_type == "only-headers":
                assert response.headers["test-header"] == "value"

        elif lambda_format_type == "wrong-format":
            assert response.status_code == 502
            assert response.json() == {"message": "Internal server error"}


@markers.snapshot.skip_snapshot_verify(
    paths=[
        *CLOUDFRONT_SKIP_HEADERS,
        # returned by LocalStack by default
        "$..headers.Server",
    ]
)
@markers.aws.validated
def test_aws_proxy_response_payload_format_validation(
    create_rest_apigw,
    create_lambda_function,
    create_role_with_policy,
    aws_client,
    region_name,
    snapshot,
):
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("Via"),
            snapshot.transform.key_value("X-Cache"),
            snapshot.transform.key_value("x-amz-apigw-id"),
            snapshot.transform.key_value("X-Amz-Cf-Pop"),
            snapshot.transform.key_value("X-Amz-Cf-Id"),
            snapshot.transform.key_value("X-Amzn-Trace-Id"),
            snapshot.transform.key_value(
                "Date", reference_replacement=False, value_replacement="<date>"
            ),
        ]
    )
    snapshot.add_transformers_list(
        [
            snapshot.transform.jsonpath("$..headers.Host", value_replacement="host"),
            snapshot.transform.jsonpath("$..multiValueHeaders.Host[0]", value_replacement="host"),
            snapshot.transform.key_value(
                "X-Forwarded-For",
                value_replacement="<X-Forwarded-For>",
                reference_replacement=False,
            ),
            snapshot.transform.key_value(
                "X-Forwarded-Port",
                value_replacement="<X-Forwarded-Port>",
                reference_replacement=False,
            ),
            snapshot.transform.key_value(
                "X-Forwarded-Proto",
                value_replacement="<X-Forwarded-Proto>",
                reference_replacement=False,
            ),
        ],
        priority=-1,
    )

    stage_name = "test"
    _, role_arn = create_role_with_policy(
        "Allow", "lambda:InvokeFunction", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )

    function_name = f"response-format-apigw-{short_uid()}"
    create_function_response = create_lambda_function(
        handler_file=LAMBDA_RESPONSE_FROM_BODY,
        func_name=function_name,
        runtime=Runtime.python3_12,
    )
    # create invocation role
    lambda_arn = create_function_response["CreateFunctionResponse"]["FunctionArn"]

    # create rest api
    api_id, _, root = create_rest_apigw(
        name=f"test-api-{short_uid()}",
        description="Integration test API",
    )

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
        uri=f"arn:aws:apigateway:{region_name}:lambda:path/2015-03-31/functions/{lambda_arn}/invocations",
        credentials=role_arn,
    )

    aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)
    endpoint = api_invoke_url(api_id=api_id, path="/test", stage=stage_name)

    def _invoke(
        body: dict | str, expected_status_code: int = 200, return_headers: bool = False
    ) -> dict:
        kwargs = {}
        if body:
            kwargs["json"] = body

        _response = requests.post(
            url=endpoint,
            headers={"User-Agent": "python/test"},
            verify=False,
            **kwargs,
        )

        assert _response.status_code == expected_status_code

        try:
            content = _response.json()
        except json.JSONDecodeError:
            content = _response.content.decode()

        dict_resp = {"content": content}
        if return_headers:
            dict_resp["headers"] = dict(_response.headers)

        return dict_resp

    response = retry(_invoke, sleep=1, retries=10, body={"statusCode": 200})
    snapshot.match("invoke-api-no-body", response)

    response = _invoke(
        body={"statusCode": 200, "headers": {"test-header": "value", "header-bool": True}},
        return_headers=True,
    )
    snapshot.match("invoke-api-with-headers", response)

    response = _invoke(
        body={"statusCode": 200, "headers": None},
        return_headers=True,
    )
    snapshot.match("invoke-api-with-headers-null", response)

    response = _invoke(body={"statusCode": 200, "wrongValue": "value"}, expected_status_code=502)
    snapshot.match("invoke-api-wrong-format", response)

    response = _invoke(body={}, expected_status_code=502)
    snapshot.match("invoke-api-empty-response", response)

    response = _invoke(
        body={
            "statusCode": 200,
            "body": base64.b64encode(b"test-data").decode(),
            "isBase64Encoded": True,
        }
    )
    snapshot.match("invoke-api-b64-encoded-true", response)

    response = _invoke(body={"statusCode": 200, "body": base64.b64encode(b"test-data").decode()})
    snapshot.match("invoke-api-b64-encoded-false", response)

    response = _invoke(
        body={"statusCode": 200, "multiValueHeaders": {"test-multi": ["value1", "value2"]}},
        return_headers=True,
    )
    snapshot.match("invoke-api-multi-headers-valid", response)

    response = _invoke(
        body={
            "statusCode": 200,
            "multiValueHeaders": {"test-multi": ["value-multi"]},
            "headers": {"test-multi": "value-solo"},
        },
        return_headers=True,
    )
    snapshot.match("invoke-api-multi-headers-overwrite", response)

    response = _invoke(
        body={
            "statusCode": 200,
            "multiValueHeaders": {"tesT-Multi": ["value-multi"]},
            "headers": {"test-multi": "value-solo"},
        },
        return_headers=True,
    )
    snapshot.match("invoke-api-multi-headers-overwrite-casing", response)

    response = _invoke(
        body={"statusCode": 200, "multiValueHeaders": {"test-multi-invalid": "value1"}},
        expected_status_code=502,
    )
    snapshot.match("invoke-api-multi-headers-invalid", response)

    response = _invoke(body={"statusCode": "test"}, expected_status_code=502)
    snapshot.match("invoke-api-invalid-status-code", response)

    response = _invoke(body={"statusCode": "201"}, expected_status_code=201)
    snapshot.match("invoke-api-status-code-str", response)

    response = _invoke(body="justAString", expected_status_code=502)
    snapshot.match("invoke-api-just-string", response)

    response = _invoke(body={"headers": {"test-header": "value"}}, expected_status_code=200)
    snapshot.match("invoke-api-only-headers", response)


# Testing the integration with Rust to prevent future regression with strongly typed language integration
# TODO make the test compatible for ARM
@markers.aws.validated
@markers.only_on_amd64
def test_lambda_rust_proxy_integration(
    create_rest_apigw, create_lambda_function, create_iam_role_with_policy, aws_client, snapshot
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
    rest_api_id, _, _ = create_rest_apigw(name=api_gateway_name)

    root_resource_id = aws_client.apigateway.get_resources(restApiId=rest_api_id)["items"][0]["id"]
    aws_client.apigateway.put_method(
        restApiId=rest_api_id,
        resourceId=root_resource_id,
        httpMethod="GET",
        authorizationType="NONE",
    )
    aws_client.apigateway.put_method_response(
        restApiId=rest_api_id, resourceId=root_resource_id, httpMethod="GET", statusCode="200"
    )
    lambda_target_uri = arns.apigateway_invocations_arn(
        lambda_uri=lambda_arn, region_name=aws_client.apigateway.meta.region_name
    )
    aws_client.apigateway.put_integration(
        restApiId=rest_api_id,
        resourceId=root_resource_id,
        httpMethod="GET",
        integrationHttpMethod="POST",
        type="AWS_PROXY",
        uri=lambda_target_uri,
        credentials=role_arn,
    )
    aws_client.apigateway.create_deployment(restApiId=rest_api_id, stageName=stage_name)
    url = api_invoke_url(api_id=rest_api_id, stage=stage_name, path=f"/?first_name={first_name}")

    def _invoke_url(url):
        invoker_response = requests.get(url)
        assert invoker_response.status_code == 200
        return invoker_response

    result = retry(_invoke_url, retries=20, sleep=2, url=url)
    assert result.text == f"Hello, {first_name}!"


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(paths=CLOUDFRONT_SKIP_HEADERS)
@markers.snapshot.skip_snapshot_verify(
    condition=lambda: not is_next_gen_api(),
    paths=[
        "$..body",
        "$..accept",
        "$..Accept",
        "$..accept-encoding",
        "$..Accept-Encoding",
        "$..Content-Length",
        "$..Connection",
        "$..user-Agent",
        "$..User-Agent",
        "$..x-localstack-edge",
        "$..pathParameters",
        "$..requestContext.authorizer",
        "$..requestContext.deploymentId",
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
        "$..X-Amzn-Trace-Id",
        "$..X-Forwarded-For",
        "$..X-Forwarded-Port",
        "$..X-Forwarded-Proto",
    ],
)
def test_lambda_aws_proxy_integration_request_data_mapping(
    create_rest_apigw,
    create_lambda_function,
    create_role_with_policy,
    snapshot,
    aws_client,
    create_rest_api_with_integration,
):
    function_name = f"test-function-{short_uid()}"
    stage_name = "test"
    snapshot.add_transformer(snapshot.transform.apigateway_api())
    snapshot.add_transformer(snapshot.transform.apigateway_proxy_event())
    # TODO: update global transformers, but we will need to regenerate all snapshots at once
    snapshot.add_transformer(snapshot.transform.key_value("rest_api_id"))
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("deploymentId"),
            snapshot.transform.jsonpath("$..headers.Host", value_replacement="host"),
            snapshot.transform.jsonpath("$..multiValueHeaders.Host[0]", value_replacement="host"),
            snapshot.transform.key_value(
                "X-Forwarded-For",
                value_replacement="<X-Forwarded-For>",
                reference_replacement=False,
            ),
            snapshot.transform.key_value(
                "X-Forwarded-Port",
                value_replacement="<X-Forwarded-Port>",
                reference_replacement=False,
            ),
            snapshot.transform.key_value(
                "X-Forwarded-Proto",
                value_replacement="<X-Forwarded-Proto>",
                reference_replacement=False,
            ),
        ],
        priority=-1,
    )

    # create lambda
    create_function_response = create_lambda_function(
        func_name=function_name,
        handler_file=TEST_LAMBDA_AWS_PROXY,
        handler="lambda_aws_proxy.handler",
        runtime=Runtime.python3_12,
    )
    # create invocation role
    _, role_arn = create_role_with_policy(
        "Allow", "lambda:InvokeFunction", json.dumps(APIGATEWAY_ASSUME_ROLE_POLICY), "*"
    )
    lambda_arn = create_function_response["CreateFunctionResponse"]["FunctionArn"]

    api_id, _, root = create_rest_apigw(
        name=f"test-api-{short_uid()}",
        description="Integration test API",
    )

    snapshot.match("api_id", {"rest_api_id": api_id})

    resource_id = aws_client.apigateway.create_resource(
        restApiId=api_id, parentId=root, pathPart="{pathVariable}"
    )["id"]

    # This test is there to verify that AWS_PROXY does not use the requestParameters
    req_parameters = {
        "integration.request.header.headerVar": "method.request.header.foobar",
        "integration.request.path.qsVar": "method.request.querystring.testVar",
        "integration.request.path.pathVar": "method.request.path.pathVariable",
        "integration.request.querystring.queryString": "method.request.querystring.testQueryString",
        "integration.request.querystring.testQs": "method.request.querystring.testQueryString",
        "integration.request.querystring.testEmptyQs": "method.request.header.emptyheader",
    }

    aws_client.apigateway.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="ANY",
        authorizationType="NONE",
        requestParameters={value: True for value in req_parameters.values()},
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
        requestParameters=req_parameters,
    )
    aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)

    stage_name = "test"

    invocation_url = api_invoke_url(
        api_id=api_id,
        stage=stage_name,
        path="/foobar",
    )

    def invoke_api(url):
        response = requests.post(
            url,
            data=json.dumps({"message": "hello world"}),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "foobar": "mapped-value",
                "user-Agent": "test/integration",
                "headerVar": "request-value",
            },
            params={
                "testQueryString": "foo",
                "testVar": "bar",
            },
            verify=False,
        )
        assert response.status_code == 200
        return {
            "content": response.json(),
            "status_code": response.status_code,
        }

    # retry is necessary against AWS, probably IAM permission delay
    invoke_response = retry(invoke_api, sleep=2, retries=10, url=invocation_url)
    snapshot.match("http-proxy-invocation-data-mapping", invoke_response)

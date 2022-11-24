import json

import pytest
import requests

from localstack.services.apigateway.helpers import path_based_url
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON39
from localstack.utils.aws import arns, aws_stack
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from localstack.utils.testutil import create_lambda_function
from tests.integration.apigateway_fixtures import (
    api_invoke_url,
    create_rest_api_integration,
    create_rest_resource,
    create_rest_resource_method,
)
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_AWS_PROXY, TEST_LAMBDA_HELLO_WORLD


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
        restApiId=rest_api_id, parentId=root_resource_id, pathPart="test-path"
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
    response_trailing_slash = retry(
        invoke_api, sleep=2, retries=10, url=f"{invocation_url}?urlparam=test"
    )
    snapshot.match(
        "invocation-payload-without-trailing-slash-and-query-params",
        response_trailing_slash.json(),
    )
    response_trailing_slash = retry(
        invoke_api, sleep=2, retries=10, url=f"{invocation_url}/?urlparam=test"
    )
    snapshot.match(
        "invocation-payload-with-trailing-slash-and-query-params",
        response_trailing_slash.json(),
    )


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

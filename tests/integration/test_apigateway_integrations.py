import pytest
import requests

from localstack.services.apigateway.helpers import path_based_url
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON39
from localstack.utils.aws import aws_stack
from localstack.utils.strings import short_uid
from localstack.utils.testutil import create_lambda_function
from tests.integration.apigateway_fixtures import (
    api_invoke_url,
    create_rest_api,
    create_rest_api_integration,
    create_rest_resource,
    create_rest_resource_method,
)
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_HELLO_WORLD


@pytest.mark.skip_offline
def test_http_integration(apigateway_client):
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

    response = apigateway_client.put_integration(
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


def test_lambda_aws_integration(apigateway_client):
    fn_name = f"test-{short_uid()}"
    create_lambda_function(
        func_name=fn_name,
        handler_file=TEST_LAMBDA_HELLO_WORLD,
        handler="lambda_hello_world.handler",
        runtime=LAMBDA_RUNTIME_PYTHON39,
    )
    lambda_arn = aws_stack.lambda_function_arn(fn_name)

    api_id, _, root = create_rest_api(apigateway_client, name="aws lambda api")
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
    assert response._content == b'{"message":"Hello from Lambda"}'


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

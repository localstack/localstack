import json

import pytest
import requests
from botocore.exceptions import ClientError
from localstack.services.apigateway.helpers import path_based_url

from localstack.constants import LOCALHOST


def test_create_and_get_rest_api(apigateway_client):
    response = apigateway_client.create_rest_api(name="my_api", description="this is my api")
    api_id = response["id"]

    response = apigateway_client.get_rest_api(restApiId=api_id)

    response.pop("ResponseMetadata")
    response.pop("createdDate")

    assert response == {
        "id": api_id,
        "name": "my_api",
        "description": "this is my api",
        "version": "V1",
        "binaryMediaTypes": [],
        "apiKeySource": "HEADER",
        "endpointConfiguration": {"types": ["EDGE"]},
        "tags": {},
        "disableExecuteApiEndpoint": False,
    }


def test_update_rest_api(apigateway_client):
    response = apigateway_client.create_rest_api(name="my_api", description="this is my api")
    api_id = response["id"]
    patchOperations = [
        {"op": "replace", "path": "/name", "value": "new-name"},
        {"op": "replace", "path": "/description", "value": "new-description"},
        {"op": "replace", "path": "/apiKeySource", "value": "AUTHORIZER"},
        {"op": "replace", "path": "/binaryMediaTypes", "value": "image/jpeg"},
        {"op": "replace", "path": "/disableExecuteApiEndpoint", "value": "True"},
    ]

    response = apigateway_client.update_rest_api(restApiId=api_id, patchOperations=patchOperations)
    response.pop("ResponseMetadata")
    response.pop("createdDate")
    response.pop("binaryMediaTypes")
    assert response == {
        "id": api_id,
        "name": "new-name",
        "version": "V1",
        "description": "new-description",
        "apiKeySource": "AUTHORIZER",
        "endpointConfiguration": {"types": ["EDGE"]},
        "tags": {},
        "disableExecuteApiEndpoint": True,
    }
    # should fail with wrong apikeysoruce
    patchOperations = [
        {"op": "replace", "path": "/apiKeySource", "value": "Wrong-value-AUTHORIZER"}
    ]
    with pytest.raises(ClientError) as ex:
        response = apigateway_client.update_rest_api(
            restApiId=api_id, patchOperations=patchOperations
        )

    assert ex.value.response["Error"]["Message"] == (
        "1 validation error detected: Value 'Wrong-value-AUTHORIZER' at "
        "'createRestApiInput.apiKeySource' failed to satisfy constraint: Member must satisfy enum "
        "value set: [AUTHORIZER, HEADER]"
    )
    assert ex.value.response["Error"]["Code"] == "ValidationException"


def test_update_rest_api_invalid_api_id(apigateway_client):
    patchOperations = [
        {"op": "replace", "path": "/apiKeySource", "value": "AUTHORIZER"}
    ]
    with pytest.raises(ClientError) as ex:
        apigateway_client.update_rest_api(restApiId="api_id", patchOperations=patchOperations)
    assert ex.value.response["Error"]["Code"] == "NotFoundException"


def test_update_rest_api_operation_add_remove(apigateway_client):
    response = apigateway_client.create_rest_api(name="my_api", description="this is my api")
    api_id = response["id"]
    patchOperations = [
        {"op": "add", "path": "/binaryMediaTypes", "value": "image/png"},
        {"op": "add", "path": "/binaryMediaTypes", "value": "image/jpeg"},
    ]
    response = apigateway_client.update_rest_api(restApiId=api_id, patchOperations=patchOperations)
    assert response["binaryMediaTypes"] == ["image/png", "image/jpeg"]
    assert response["description"] == "this is my api"
    patchOperations = [
        {"op": "remove", "path": "/binaryMediaTypes", "value": "image/png"},
        {"op": "remove", "path": "/description"},
    ]
    response = apigateway_client.update_rest_api(restApiId=api_id, patchOperations=patchOperations)
    assert response["binaryMediaTypes"] == ["image/jpeg"]
    assert response["description"] == ""


def test_list_and_delete_apis(apigateway_client):
    response = apigateway_client.create_rest_api(name="my_api", description="this is my api")
    api_id = response["id"]
    apigateway_client.create_rest_api(name="my_api2", description="this is my api2")

    response = apigateway_client.get_rest_apis()
    assert len(response["items"]) == (2)

    apigateway_client.delete_rest_api(restApiId=api_id)

    response = apigateway_client.get_rest_apis()
    assert len(response["items"]) == 1


def test_create_rest_api_with_tags(apigateway_client):
    response = apigateway_client.create_rest_api(
        name="my_api", description="this is my api", tags={"MY_TAG1": "MY_VALUE1"}
    )
    api_id = response["id"]

    response = apigateway_client.get_rest_api(restApiId=api_id)

    assert "tags" in response
    assert response["tags"] == {"MY_TAG1": "MY_VALUE1"}


@pytest.mark.skip
def test_create_authorizer(apigateway_client, cognito_idp_client):
    authorizer_name = "my_authorizer"
    response = apigateway_client.create_rest_api(name="my_api", description="this is my api")
    api_id = response["id"]

    user_pool_arn = cognito_idp_client.create_user_pool(PoolName="my_cognito_pool")[
        "UserPool"
    ]["Arn"]

    response = apigateway_client.create_authorizer(
        restApiId=api_id,
        name=authorizer_name,
        type="COGNITO_USER_POOLS",
        providerARNs=[user_pool_arn],
        identitySource="method.request.header.Authorization",
    )
    authorizer_id = response["id"]

    response = apigateway_client.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    # createdDate is hard to match against, remove it
    response.pop("createdDate", None)
    # this is hard to match against, so remove it
    response["ResponseMetadata"].pop("HTTPHeaders", None)
    response["ResponseMetadata"].pop("RetryAttempts", None)
    assert response == {
        "id": authorizer_id,
        "name": authorizer_name,
        "type": "COGNITO_USER_POOLS",
        "providerARNs": [user_pool_arn],
        "identitySource": "method.request.header.Authorization",
        "authorizerResultTtlInSeconds": 300,
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }

    authorizer_name2 = "my_authorizer2"
    response = apigateway_client.create_authorizer(
        restApiId=api_id,
        name=authorizer_name2,
        type="COGNITO_USER_POOLS",
        providerARNs=[user_pool_arn],
        identitySource="method.request.header.Authorization",
    )
    authorizer_id2 = response["id"]

    response = apigateway_client.get_authorizers(restApiId=api_id)

    # this is hard to match against, so remove it
    response["ResponseMetadata"].pop("HTTPHeaders", None)
    response["ResponseMetadata"].pop("RetryAttempts", None)

    assert response["items"][0]["id"] == (
        r"{0}|{1}".format(authorizer_id2, authorizer_id)
    )
    assert response["items"][1]["id"] == (
        r"{0}|{1}".format(authorizer_id2, authorizer_id)
    )

    new_authorizer_name_with_vars = "authorizer_with_vars"
    response = apigateway_client.create_authorizer(
        restApiId=api_id,
        name=new_authorizer_name_with_vars,
        type="COGNITO_USER_POOLS",
        providerARNs=[user_pool_arn],
        identitySource="method.request.header.Authorization",
    )
    authorizer_id3 = response["id"]

    # this is hard to match against, so remove it
    response["ResponseMetadata"].pop("HTTPHeaders", None)
    response["ResponseMetadata"].pop("RetryAttempts", None)

    assert response == {
        "name": new_authorizer_name_with_vars,
        "id": authorizer_id3,
        "type": "COGNITO_USER_POOLS",
        "providerARNs": [user_pool_arn],
        "identitySource": "method.request.header.Authorization",
        "authorizerResultTtlInSeconds": 300,
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }

    stage = apigateway_client.get_authorizer(restApiId=api_id, authorizerId=authorizer_id3)
    assert stage["name"] == new_authorizer_name_with_vars
    assert stage["id"] == authorizer_id3
    assert stage["type"] == "COGNITO_USER_POOLS"
    assert stage["providerARNs"] == [user_pool_arn]
    assert stage["identitySource"] == "method.request.header.Authorization"
    assert stage["authorizerResultTtlInSeconds"] == 300


def test_integration_response(apigateway_client):
    response = apigateway_client.create_rest_api(name="my_api", description="this is my api")
    api_id = response["id"]

    resources = apigateway_client.get_resources(restApiId=api_id)
    root_id = [resource for resource in resources["items"] if resource["path"] == "/"][
        0
    ]["id"]

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
    assert response == (
        {
            "statusCode": "200",
            "selectionPattern": "foobar",
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "responseTemplates": {},  # Note: TF compatibility
        }
    )

    response = apigateway_client.get_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )
    # this is hard to match against, so remove it
    response["ResponseMetadata"].pop("HTTPHeaders", None)
    response["ResponseMetadata"].pop("RetryAttempts", None)
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

    response = apigateway_client.delete_integration_response(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200"
    )

    response = apigateway_client.get_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    assert response["methodIntegration"]["integrationResponses"] == {}

    # adding a new method and perfomring put intergration with contentHandling as CONVERT_TO_BINARY
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
    assert response == (
        {
            "statusCode": "200",
            "selectionPattern": "foobar",
            "ResponseMetadata": {"HTTPStatusCode": 200},
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
    assert response == (
        {
            "statusCode": "200",
            "selectionPattern": "foobar",
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "responseTemplates": {},  # Note: TF compatibility
            "contentHandling": "CONVERT_TO_BINARY",
        }
    )

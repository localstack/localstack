import json

import pytest
import requests
from botocore.exceptions import ClientError
from moto.core import ACCOUNT_ID

from localstack.services.apigateway.helpers import path_based_url
from localstack.utils.strings import short_uid


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
        "minimumCompressionSize": -1,
    }

    # should fail with wrong apikeysoruce - TODO enable!
    # patchOperations = [
    #     {"op": "replace", "path": "/apiKeySource", "value": "Wrong-value-AUTHORIZER"}
    # ]
    # with pytest.raises(ClientError) as ex:
    #     apigateway_client.update_rest_api(
    #         restApiId=api_id, patchOperations=patchOperations
    #     )
    #
    # assert ex.value.response["Error"]["Message"] == (
    #     "1 validation error detected: Value 'Wrong-value-AUTHORIZER' at "
    #     "'createRestApiInput.apiKeySource' failed to satisfy constraint: Member must satisfy enum "
    #     "value set: [AUTHORIZER, HEADER]"
    # )
    # assert ex.value.response["Error"]["Code"] == "ValidationException"


def test_update_rest_api_invalid_api_id(apigateway_client):
    patchOperations = [{"op": "replace", "path": "/apiKeySource", "value": "AUTHORIZER"}]
    with pytest.raises(ClientError) as ex:
        apigateway_client.update_rest_api(restApiId="api_id", patchOperations=patchOperations)
    assert ex.value.response["Error"]["Code"] == "NotFoundException"


# TODO enable/fix test!
@pytest.mark.skip
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
    api_name1 = short_uid()
    api_name2 = short_uid()

    response = apigateway_client.create_rest_api(name=api_name1, description="this is my api")
    api_id = response["id"]
    apigateway_client.create_rest_api(name=api_name2, description="this is my api2")

    response = apigateway_client.get_rest_apis()
    items = [item for item in response["items"] if item["name"] in [api_name1, api_name2]]
    assert len(items) == (2)

    apigateway_client.delete_rest_api(restApiId=api_id)

    response = apigateway_client.get_rest_apis()
    items = [item for item in response["items"] if item["name"] in [api_name1, api_name2]]
    assert len(items) == 1


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

    user_pool_arn = cognito_idp_client.create_user_pool(PoolName="my_cognito_pool")["UserPool"][
        "Arn"
    ]

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

    assert response["items"][0]["id"] == (r"{0}|{1}".format(authorizer_id2, authorizer_id))
    assert response["items"][1]["id"] == (r"{0}|{1}".format(authorizer_id2, authorizer_id))

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
    assert response == {
        "statusCode": "200",
        "selectionPattern": "foobar",
        "ResponseMetadata": {"HTTPStatusCode": 200},
        "responseTemplates": {"application/json": json.dumps({"data": "test"})},
    }


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
    types_requiring_integration_method = http_types + aws_types
    types_not_requiring_integration_method = ["MOCK"]

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
                ACCOUNT_ID
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
                    ACCOUNT_ID
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
    for _type in aws_types:
        # Ensure that the URI is an ARN
        with pytest.raises(ClientError) as ex:
            apigateway_client.put_integration(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="GET",
                type=_type,
                uri="non-valid-arn",
                integrationHttpMethod="POST",
            )
        assert ex.value.response["Error"]["Code"] == "BadRequestException"
        assert ex.value.response["Error"]["Message"] == "Invalid ARN specified in the request"
    for _type in aws_types:
        # Ensure that the URI is a valid ARN
        with pytest.raises(ClientError) as ex:
            apigateway_client.put_integration(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="GET",
                type=_type,
                uri="arn:aws:iam::0000000000:role/service-role/asdf",
                integrationHttpMethod="POST",
            )
        assert ex.value.response["Error"]["Code"] == "BadRequestException"
        assert (
            ex.value.response["Error"]["Message"] == "AWS ARN for integration must contain path or "
            "action"
        )


def test_create_domain_names(apigateway_client):
    domain_name = "testDomain"
    test_certificate_name = "test.certificate"
    test_certificate_private_key = "testPrivateKey"
    # success case with valid params
    response = apigateway_client.create_domain_name(
        domainName=domain_name,
        certificateName=test_certificate_name,
        certificatePrivateKey=test_certificate_private_key,
    )
    assert response["domainName"] == domain_name
    assert response["certificateName"] == test_certificate_name
    # without domain name it should throw BadRequestException
    with pytest.raises(ClientError) as ex:
        apigateway_client.create_domain_name(domainName="")

    assert ex.value.response["Error"]["Message"] == "No Domain Name specified"
    assert ex.value.response["Error"]["Code"] == "BadRequestException"


def test_get_domain_names(apigateway_client):
    # create domain name
    domain_name = f"domain-{short_uid()}"
    test_certificate_name = "test.certificate"
    response = apigateway_client.create_domain_name(
        domainName=domain_name, certificateName=test_certificate_name
    )
    assert response["domainName"] == domain_name
    assert response["certificateName"] == test_certificate_name
    assert response["domainNameStatus"] == "AVAILABLE"

    # get new domain name
    result = apigateway_client.get_domain_names()
    added = [dom for dom in result["items"] if dom["domainName"] == domain_name]
    assert added
    assert added[0]["domainName"] == domain_name
    assert added[0]["certificateName"] == test_certificate_name
    assert added[0]["domainNameStatus"] == "AVAILABLE"


def test_get_domain_name(apigateway_client):
    domain_name = "testDomain"
    # adding a domain name
    apigateway_client.create_domain_name(domainName=domain_name)
    # retrieving the data of added domain name.
    result = apigateway_client.get_domain_name(domainName=domain_name)
    assert result["domainName"] == domain_name
    assert result["domainNameStatus"] == "AVAILABLE"


def test_create_model(apigateway_client):
    response = apigateway_client.create_rest_api(name="my_api", description="this is my api")
    rest_api_id = response["id"]
    dummy_rest_api_id = "a12b3c4d"
    model_name = "testModel"
    description = "test model"
    content_type = "application/json"
    # success case with valid params
    response = apigateway_client.create_model(
        restApiId=rest_api_id,
        name=model_name,
        description=description,
        contentType=content_type,
    )
    assert response["name"] == model_name
    assert response["description"] == description

    # with an invalid rest_api_id it should throw NotFoundException
    with pytest.raises(ClientError) as ex:
        apigateway_client.create_model(
            restApiId=dummy_rest_api_id,
            name=model_name,
            description=description,
            contentType=content_type,
        )
    assert ex.value.response["Error"]["Message"] == "Invalid Rest API Id specified"
    assert ex.value.response["Error"]["Code"] == "NotFoundException"

    with pytest.raises(ClientError) as ex:
        apigateway_client.create_model(
            restApiId=rest_api_id,
            name="",
            description=description,
            contentType=content_type,
        )

    assert ex.value.response["Error"]["Message"] == "No Model Name specified"
    assert ex.value.response["Error"]["Code"] == "BadRequestException"


def test_get_api_models(apigateway_client):
    response = apigateway_client.create_rest_api(name="my_api", description="this is my api")
    rest_api_id = response["id"]
    model_name = "testModel"
    description = "test model"
    content_type = "application/json"
    # when no models are present
    result = apigateway_client.get_models(restApiId=rest_api_id)
    assert result["items"] == []
    # add a model
    apigateway_client.create_model(
        restApiId=rest_api_id,
        name=model_name,
        description=description,
        contentType=content_type,
    )
    # get models after adding
    result = apigateway_client.get_models(restApiId=rest_api_id)
    assert result["items"][0]["name"] == model_name
    assert result["items"][0]["description"] == description


def test_get_model_by_name(apigateway_client):
    response = apigateway_client.create_rest_api(name="my_api", description="this is my api")
    rest_api_id = response["id"]
    dummy_rest_api_id = "a12b3c4d"
    model_name = "testModel"
    description = "test model"
    content_type = "application/json"
    # add a model
    apigateway_client.create_model(
        restApiId=rest_api_id,
        name=model_name,
        description=description,
        contentType=content_type,
    )
    # get models after adding
    result = apigateway_client.get_model(restApiId=rest_api_id, modelName=model_name)
    result["name"] = model_name
    result["description"] = description

    with pytest.raises(ClientError) as ex:
        apigateway_client.get_model(restApiId=dummy_rest_api_id, modelName=model_name)
    assert ex.value.response["Error"]["Message"] == "Invalid Rest API Id specified"
    assert ex.value.response["Error"]["Code"] == "NotFoundException"


def test_get_model_with_invalid_name(apigateway_client):
    response = apigateway_client.create_rest_api(name="my_api", description="this is my api")
    rest_api_id = response["id"]
    # test with an invalid model name
    with pytest.raises(ClientError) as ex:
        apigateway_client.get_model(restApiId=rest_api_id, modelName="fake")
    assert ex.value.response["Error"]["Message"] == "Invalid Model Name specified"
    assert ex.value.response["Error"]["Code"] == "NotFoundException"

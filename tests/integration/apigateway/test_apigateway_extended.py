# TODO: find a more meaningful name for this file, further refactor tests into different functional areas
import json
import os

import pytest
from botocore.exceptions import ClientError

from localstack.utils.files import load_file
from localstack.utils.strings import short_uid

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_IMPORT_PETSTORE_SWAGGER = os.path.join(THIS_FOLDER, "../files", "petstore-swagger.json")


def test_export_swagger_openapi(apigateway_client):
    spec_file = load_file(TEST_IMPORT_PETSTORE_SWAGGER)
    response = apigateway_client.import_rest_api(failOnWarnings=True, body=spec_file)
    assert response.get("ResponseMetadata").get("HTTPStatusCode") == 201

    response = apigateway_client.get_export(
        restApiId=response["id"], stageName="local", exportType="swagger"
    )
    spec_object = json.loads(response["body"].read())

    # required keys
    expected_keys = [
        "swagger",
        "info",
        "paths",
    ]
    assert all(k in spec_object.keys() for k in expected_keys)
    assert spec_object["info"]["title"] == "PetStore"
    assert spec_object["info"]["version"] is not None
    assert spec_object["paths"] == {
        "/": {"get": {"responses": {"200": {}}}},
        "/pets": {
            "get": {"responses": {"200": {}}},
            "post": {"responses": {"200": {}}},
            "options": {"responses": {"200": {}}},
        },
        "/pets/{petId}": {"get": {"responses": {"200": {}}}, "options": {"responses": {"200": {}}}},
    }

    # optional keys
    optional_keys = ["basePath"]
    assert all(k in spec_object.keys() for k in optional_keys)


def test_export_oas30_openapi(apigateway_client):
    spec_file = load_file(TEST_IMPORT_PETSTORE_SWAGGER)
    response = apigateway_client.import_rest_api(failOnWarnings=True, body=spec_file)
    assert response.get("ResponseMetadata").get("HTTPStatusCode") == 201

    response = apigateway_client.get_export(
        restApiId=response["id"], stageName="local", exportType="oas30"
    )
    spec_object = json.loads(response["body"].read())
    # required keys
    expected_keys = [
        "openapi",
        "info",
    ]
    assert all(k in spec_object.keys() for k in expected_keys)
    assert spec_object["info"]["title"] == "PetStore"
    assert spec_object["info"]["version"] is not None
    # optional keys
    optional_keys = ["paths"]
    assert all(k in spec_object.keys() for k in optional_keys)


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


@pytest.mark.aws_validated
def test_get_api_keys(apigateway_client):
    api_key_name = f"test-key-{short_uid()}"
    api_key_name_2 = f"test-key-{short_uid()}"
    list_response = apigateway_client.get_api_keys()
    api_keys_before = len(list_response["items"])
    try:
        creation_response = apigateway_client.create_api_key(name=api_key_name)
        api_key_id = creation_response["id"]
        api_keys = apigateway_client.get_api_keys()["items"]
        assert len(api_keys) == api_keys_before + 1
        assert api_key_id in [api_key["id"] for api_key in api_keys]
        # test not created api key
        api_keys_filtered = apigateway_client.get_api_keys(nameQuery=api_key_name_2)["items"]
        assert len(api_keys_filtered) == 0
        # test prefix
        api_keys_prefix_filtered = apigateway_client.get_api_keys(nameQuery=api_key_name[:8])[
            "items"
        ]
        assert len(api_keys_prefix_filtered) == 1
        assert api_key_id in [api_key["id"] for api_key in api_keys]
        # test postfix
        api_keys_prefix_filtered = apigateway_client.get_api_keys(nameQuery=api_key_name[2:])[
            "items"
        ]
        assert len(api_keys_prefix_filtered) == 0
        # test infix
        api_keys_prefix_filtered = apigateway_client.get_api_keys(nameQuery=api_key_name[2:8])[
            "items"
        ]
        assert len(api_keys_prefix_filtered) == 0
        creation_response = apigateway_client.create_api_key(name=api_key_name_2)
        api_key_id_2 = creation_response["id"]
        api_keys = apigateway_client.get_api_keys()["items"]
        assert len(api_keys) == api_keys_before + 2
        assert api_key_id in [api_key["id"] for api_key in api_keys]
        assert api_key_id_2 in [api_key["id"] for api_key in api_keys]
        api_keys_filtered = apigateway_client.get_api_keys(nameQuery=api_key_name_2)["items"]
        assert len(api_keys_filtered) == 1
        assert api_key_id_2 in [api_key["id"] for api_key in api_keys]
        api_keys_filtered = apigateway_client.get_api_keys(nameQuery=api_key_name)["items"]
        assert len(api_keys_filtered) == 1
        assert api_key_id in [api_key["id"] for api_key in api_keys]
        # test prefix
        api_keys_filtered = apigateway_client.get_api_keys(nameQuery=api_key_name[:8])["items"]
        assert len(api_keys_filtered) == 2
        assert api_key_id in [api_key["id"] for api_key in api_keys]
        assert api_key_id_2 in [api_key["id"] for api_key in api_keys]
        # some minor paging testing
        api_keys_page = apigateway_client.get_api_keys(limit=1)
        assert len(api_keys_page["items"]) == 1
        api_keys_page_2 = apigateway_client.get_api_keys(
            limit=1, position=api_keys_page["position"]
        )
        assert len(api_keys_page_2["items"]) == 1
        assert api_keys_page["items"][0]["id"] != api_keys_page_2["items"][0]["id"]
    finally:
        apigateway_client.delete_api_key(apiKey=api_key_id)
        apigateway_client.delete_api_key(apiKey=api_key_id_2)

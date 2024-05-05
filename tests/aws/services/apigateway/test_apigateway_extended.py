# TODO: find a more meaningful name for this file, further refactor tests into different functional areas
import os

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_IMPORT_PETSTORE_SWAGGER = os.path.join(THIS_FOLDER, "../../files/petstore-swagger.json")
TEST_IMPORT_PETS = os.path.join(THIS_FOLDER, "../../files/pets.json")


@markers.aws.validated
@pytest.mark.parametrize(
    "import_file",
    [TEST_IMPORT_PETSTORE_SWAGGER, TEST_IMPORT_PETS],
    ids=["TEST_IMPORT_PETSTORE_SWAGGER", "TEST_IMPORT_PETS"],
)
@markers.snapshot.skip_snapshot_verify(paths=["$..body.host"])
def test_export_swagger_openapi(aws_client, snapshot, import_apigw, import_file, region_name):
    snapshot.add_transformer(
        [
            snapshot.transform.jsonpath("$.import-api.id", value_replacement="api-id"),
            snapshot.transform.key_value("rootResourceId"),
        ]
    )
    spec_file = load_file(import_file)
    spec_file = spec_file.replace(
        "${uri}", f"http://petstore.execute-api.{region_name}.amazonaws.com/petstore/pets"
    )

    response, _ = import_apigw(body=spec_file, failOnWarnings=True)
    snapshot.match("import-api", response)
    api_id = response["id"]

    aws_client.apigateway.create_deployment(restApiId=api_id, stageName="local")

    response = aws_client.apigateway.get_export(
        restApiId=api_id, stageName="local", exportType="swagger"
    )
    snapshot.match("get-export", response)

    response = aws_client.apigateway.get_export(
        restApiId=api_id,
        stageName="local",
        exportType="swagger",
        parameters={"extensions": "apigateway"},
    )
    snapshot.match("get-export-with-extensions", response)


@markers.aws.validated
@pytest.mark.parametrize(
    "import_file",
    [TEST_IMPORT_PETSTORE_SWAGGER, TEST_IMPORT_PETS],
    ids=["TEST_IMPORT_PETSTORE_SWAGGER", "TEST_IMPORT_PETS"],
)
@markers.snapshot.skip_snapshot_verify(paths=["$..body.servers..url"])
def test_export_oas30_openapi(aws_client, snapshot, import_apigw, region_name, import_file):
    snapshot.add_transformer(
        [
            snapshot.transform.jsonpath("$.import-api.id", value_replacement="api-id"),
            snapshot.transform.key_value("rootResourceId"),
        ]
    )

    spec_file = load_file(import_file)
    spec_file = spec_file.replace(
        "${uri}", f"http://petstore.execute-api.{region_name}.amazonaws.com/petstore/pets"
    )

    response, _ = import_apigw(body=spec_file, failOnWarnings=True)
    snapshot.match("import-api", response)
    api_id = response["id"]

    aws_client.apigateway.create_deployment(restApiId=api_id, stageName="local")

    response = aws_client.apigateway.get_export(
        restApiId=api_id, stageName="local", exportType="oas30"
    )
    snapshot.match("get-export", response)

    response = aws_client.apigateway.get_export(
        restApiId=api_id,
        stageName="local",
        exportType="oas30",
        parameters={"extensions": "apigateway"},
    )
    snapshot.match("get-export-with-extensions", response)


@markers.aws.needs_fixing
def test_create_domain_names(aws_client):
    domain_name = f"{short_uid()}-testDomain"
    test_certificate_name = "test.certificate"
    test_certificate_private_key = "testPrivateKey"
    # success case with valid params
    response = aws_client.apigateway.create_domain_name(
        domainName=domain_name,
        certificateName=test_certificate_name,
        certificatePrivateKey=test_certificate_private_key,
    )
    assert response["domainName"] == domain_name
    assert response["certificateName"] == test_certificate_name
    # without domain name it should throw BadRequestException
    with pytest.raises(ClientError) as ex:
        aws_client.apigateway.create_domain_name(domainName="")

    assert ex.value.response["Error"]["Message"] == "No Domain Name specified"
    assert ex.value.response["Error"]["Code"] == "BadRequestException"


@markers.aws.needs_fixing
def test_get_domain_names(aws_client):
    # create domain name
    domain_name = f"domain-{short_uid()}"
    test_certificate_name = "test.certificate"
    response = aws_client.apigateway.create_domain_name(
        domainName=domain_name, certificateName=test_certificate_name
    )
    assert response["domainName"] == domain_name
    assert response["certificateName"] == test_certificate_name
    assert response["domainNameStatus"] == "AVAILABLE"

    # get new domain name
    result = aws_client.apigateway.get_domain_names()
    added = [dom for dom in result["items"] if dom["domainName"] == domain_name]
    assert added
    assert added[0]["domainName"] == domain_name
    assert added[0]["certificateName"] == test_certificate_name
    assert added[0]["domainNameStatus"] == "AVAILABLE"


@markers.aws.needs_fixing
def test_get_domain_name(aws_client):
    domain_name = f"{short_uid()}-testDomain"
    # adding a domain name
    aws_client.apigateway.create_domain_name(domainName=domain_name)
    # retrieving the data of added domain name.
    result = aws_client.apigateway.get_domain_name(domainName=domain_name)
    assert result["domainName"] == domain_name
    assert result["domainNameStatus"] == "AVAILABLE"


@markers.aws.validated
def test_get_api_keys(aws_client):
    api_key_name = f"test-key-{short_uid()}"
    api_key_name_2 = f"test-key-{short_uid()}"
    list_response = aws_client.apigateway.get_api_keys()
    api_keys_before = len(list_response["items"])
    try:
        creation_response = aws_client.apigateway.create_api_key(name=api_key_name)
        api_key_id = creation_response["id"]
        api_keys = aws_client.apigateway.get_api_keys()["items"]
        assert len(api_keys) == api_keys_before + 1
        assert api_key_id in [api_key["id"] for api_key in api_keys]
        # test not created api key
        api_keys_filtered = aws_client.apigateway.get_api_keys(nameQuery=api_key_name_2)["items"]
        assert len(api_keys_filtered) == 0
        # test prefix
        api_keys_prefix_filtered = aws_client.apigateway.get_api_keys(nameQuery=api_key_name[:8])[
            "items"
        ]
        assert len(api_keys_prefix_filtered) == 1
        assert api_key_id in [api_key["id"] for api_key in api_keys]
        # test postfix
        api_keys_prefix_filtered = aws_client.apigateway.get_api_keys(nameQuery=api_key_name[2:])[
            "items"
        ]
        assert len(api_keys_prefix_filtered) == 0
        # test infix
        api_keys_prefix_filtered = aws_client.apigateway.get_api_keys(nameQuery=api_key_name[2:8])[
            "items"
        ]
        assert len(api_keys_prefix_filtered) == 0
        creation_response = aws_client.apigateway.create_api_key(name=api_key_name_2)
        api_key_id_2 = creation_response["id"]
        api_keys = aws_client.apigateway.get_api_keys()["items"]
        assert len(api_keys) == api_keys_before + 2
        assert api_key_id in [api_key["id"] for api_key in api_keys]
        assert api_key_id_2 in [api_key["id"] for api_key in api_keys]
        api_keys_filtered = aws_client.apigateway.get_api_keys(nameQuery=api_key_name_2)["items"]
        assert len(api_keys_filtered) == 1
        assert api_key_id_2 in [api_key["id"] for api_key in api_keys]
        api_keys_filtered = aws_client.apigateway.get_api_keys(nameQuery=api_key_name)["items"]
        assert len(api_keys_filtered) == 1
        assert api_key_id in [api_key["id"] for api_key in api_keys]
        # test prefix
        api_keys_filtered = aws_client.apigateway.get_api_keys(nameQuery=api_key_name[:8])["items"]
        assert len(api_keys_filtered) == 2
        assert api_key_id in [api_key["id"] for api_key in api_keys]
        assert api_key_id_2 in [api_key["id"] for api_key in api_keys]
        # some minor paging testing
        api_keys_page = aws_client.apigateway.get_api_keys(limit=1)
        assert len(api_keys_page["items"]) == 1
        api_keys_page_2 = aws_client.apigateway.get_api_keys(
            limit=1, position=api_keys_page["position"]
        )
        assert len(api_keys_page_2["items"]) == 1
        assert api_keys_page["items"][0]["id"] != api_keys_page_2["items"][0]["id"]
    finally:
        aws_client.apigateway.delete_api_key(apiKey=api_key_id)
        aws_client.apigateway.delete_api_key(apiKey=api_key_id_2)

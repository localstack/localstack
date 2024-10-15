# TODO: find a more meaningful name for this file, further refactor tests into different functional areas
import logging
import os

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)


THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_IMPORT_PETSTORE_SWAGGER = os.path.join(THIS_FOLDER, "../../files/petstore-swagger.json")
TEST_IMPORT_PETS = os.path.join(THIS_FOLDER, "../../files/pets.json")


@pytest.fixture
def apigw_create_api_key(aws_client):
    api_keys = []

    def _create(**kwargs):
        response = aws_client.apigateway.create_api_key(**kwargs)
        api_keys.append(response["id"])
        return response

    yield _create

    for api_key_id in api_keys:
        try:
            aws_client.apigateway.delete_api_key(apiKey=api_key_id)
        except aws_client.apigateway.exceptions.NotFoundException:
            pass
        except Exception as e:
            LOG.warning("Error while cleaning up APIGW API Key %s: %s", api_key_id, e)


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


class TestApigatewayApiKeysCrud:
    @pytest.fixture(scope="class", autouse=True)
    def cleanup_api_keys(self, aws_client):
        for api_key in aws_client.apigateway.get_api_keys()["items"]:
            aws_client.apigateway.delete_api_key(apiKey=api_key["id"])

    @markers.aws.validated
    def test_get_api_keys(self, aws_client, apigw_create_api_key, snapshot):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("id"),
                snapshot.transform.key_value("value"),
                snapshot.transform.key_value("name"),
                snapshot.transform.key_value("position"),
            ]
        )
        api_key_name = f"test-key-{short_uid()}"
        api_key_name_2 = f"test-key-{short_uid()}"

        get_api_keys = aws_client.apigateway.get_api_keys()
        snapshot.match("get-api-keys", get_api_keys)

        create_api_key = apigw_create_api_key(name=api_key_name)
        snapshot.match("create-api-key", create_api_key)

        get_api_keys_after_create = aws_client.apigateway.get_api_keys()
        snapshot.match("get-api-keys-after-create-1", get_api_keys_after_create)

        # test not created api key
        api_keys_wrong_name = aws_client.apigateway.get_api_keys(nameQuery=api_key_name_2)
        snapshot.match("get-api-keys-wrong-name-query", api_keys_wrong_name)

        # test prefix
        api_keys_prefix = aws_client.apigateway.get_api_keys(nameQuery=api_key_name[:8])
        snapshot.match("get-api-keys-prefix-name-query", api_keys_prefix)

        # test prefix cased
        api_keys_prefix_cased = aws_client.apigateway.get_api_keys(
            nameQuery=api_key_name[:8].upper()
        )
        snapshot.match("get-api-keys-prefix-name-query-cased", api_keys_prefix_cased)

        # test postfix
        api_keys_postfix = aws_client.apigateway.get_api_keys(nameQuery=api_key_name[2:])
        snapshot.match("get-api-keys-postfix-name-query", api_keys_postfix)

        # test infix
        api_keys_infix = aws_client.apigateway.get_api_keys(nameQuery=api_key_name[2:8])
        snapshot.match("get-api-keys-infix-name-query", api_keys_infix)

        create_api_key_2 = apigw_create_api_key(name=api_key_name_2)
        snapshot.match("create-api-key-2", create_api_key_2)

        get_api_keys_after_create_2 = aws_client.apigateway.get_api_keys()
        snapshot.match("get-api-keys-after-create-2", get_api_keys_after_create_2)

        api_keys_full_name_2 = aws_client.apigateway.get_api_keys(nameQuery=api_key_name_2)
        snapshot.match("get-api-keys-name-query", api_keys_full_name_2)

        # the 2 keys share the same prefix
        api_keys_prefix = aws_client.apigateway.get_api_keys(nameQuery=api_key_name[:8])
        snapshot.match("get-api-keys-prefix-name-query-2", api_keys_prefix)

        # some minor paging testing
        api_keys_page = aws_client.apigateway.get_api_keys(limit=1)
        snapshot.match("get-apis-keys-pagination", api_keys_page)

        api_keys_page_2 = aws_client.apigateway.get_api_keys(
            limit=1, position=api_keys_page["position"]
        )
        snapshot.match("get-apis-keys-pagination-2", api_keys_page_2)

    @markers.aws.validated
    def test_get_usage_plan_api_keys(self, aws_client, apigw_create_api_key, snapshot, cleanups):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("id"),
                snapshot.transform.key_value("value"),
                snapshot.transform.key_value("name"),
            ]
        )
        api_key_name = f"test-key-{short_uid()}"
        api_key_name_2 = f"test-key-{short_uid()}"

        get_api_keys = aws_client.apigateway.get_api_keys()
        snapshot.match("get-api-keys", get_api_keys)

        create_api_key = apigw_create_api_key(name=api_key_name)
        snapshot.match("create-api-key", create_api_key)

        create_api_key_2 = apigw_create_api_key(name=api_key_name_2)
        snapshot.match("create-api-key-2", create_api_key)

        get_api_keys_after_create = aws_client.apigateway.get_api_keys()
        snapshot.match("get-api-keys-after-create-1", get_api_keys_after_create)

        create_usage_plan = aws_client.apigateway.create_usage_plan(
            name=f"usage-plan-{short_uid()}"
        )
        usage_plan_id = create_usage_plan["id"]
        cleanups.append(lambda: aws_client.apigateway.delete_usage_plan(usagePlanId=usage_plan_id))
        snapshot.match("create-usage-plan", create_usage_plan)

        get_up_keys_before_create = aws_client.apigateway.get_usage_plan_keys(
            usagePlanId=usage_plan_id
        )
        snapshot.match("get-up-keys-before-create", get_up_keys_before_create)

        create_up_key = aws_client.apigateway.create_usage_plan_key(
            usagePlanId=usage_plan_id, keyId=create_api_key["id"], keyType="API_KEY"
        )
        snapshot.match("create-up-key", create_up_key)

        create_up_key_2 = aws_client.apigateway.create_usage_plan_key(
            usagePlanId=usage_plan_id, keyId=create_api_key_2["id"], keyType="API_KEY"
        )
        snapshot.match("create-up-key-2", create_up_key_2)

        get_up_keys = aws_client.apigateway.get_usage_plan_keys(usagePlanId=usage_plan_id)
        snapshot.match("get-up-keys", get_up_keys)

        get_up_keys_query = aws_client.apigateway.get_usage_plan_keys(
            usagePlanId=usage_plan_id, nameQuery="test-key"
        )
        snapshot.match("get-up-keys-name-query", get_up_keys_query)

        get_up_keys_query_cased = aws_client.apigateway.get_usage_plan_keys(
            usagePlanId=usage_plan_id, nameQuery="TEST-key"
        )
        snapshot.match("get-up-keys-name-query-cased", get_up_keys_query_cased)

        get_up_keys_query_name = aws_client.apigateway.get_usage_plan_keys(
            usagePlanId=usage_plan_id, nameQuery=api_key_name
        )
        snapshot.match("get-up-keys-name-query-key-name", get_up_keys_query_name)

        get_up_keys_bad_query = aws_client.apigateway.get_usage_plan_keys(
            usagePlanId=usage_plan_id, nameQuery="nothing"
        )
        snapshot.match("get-up-keys-bad-query", get_up_keys_bad_query)

        aws_client.apigateway.delete_api_key(apiKey=create_api_key["id"])
        aws_client.apigateway.delete_api_key(apiKey=create_api_key_2["id"])

        get_up_keys_after_delete = aws_client.apigateway.get_usage_plan_keys(
            usagePlanId=usage_plan_id
        )
        snapshot.match("get-up-keys-after-delete", get_up_keys_after_delete)

        get_up_keys_bad_d = aws_client.apigateway.get_usage_plan_keys(usagePlanId="bad-id")
        snapshot.match("get-up-keys-bad-usage-plan", get_up_keys_bad_d)

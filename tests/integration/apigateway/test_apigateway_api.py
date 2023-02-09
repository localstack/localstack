import logging
import os
import time
from operator import itemgetter

import pytest
from botocore.exceptions import ClientError

from localstack.services.apigateway.helpers import TAG_KEY_CUSTOM_ID
from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)

# parent directory of this file
PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPENAPI_SPEC_PULUMI_JSON = os.path.join(PARENT_DIR, "files", "openapi.spec.pulumi.json")


@pytest.fixture(autouse=True)
def apigw_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.apigateway_api())


@pytest.fixture(scope="class", autouse=True)
def apigw_cleanup_before_run(apigateway_client):
    # TODO: remove this once all tests are properly cleaning up and using fixtures
    rest_apis = apigateway_client.get_rest_apis()
    for rest_api in rest_apis["items"]:
        delete_rest_api_retry(apigateway_client, rest_api["id"])


def delete_rest_api_retry(client, rest_api_id: str):
    try:
        if is_aws_cloud():
            # This is ugly but API GW returns 429 very quickly, and we want to be sure to clean up properly
            cleaned = False
            while not cleaned:
                try:
                    client.delete_rest_api(restApiId=rest_api_id)
                    cleaned = True
                except ClientError as e:
                    error_message = str(e)
                    if "TooManyRequestsException" in error_message:
                        time.sleep(10)
                    elif "NotFoundException" in error_message:
                        break
                    else:
                        raise
        else:
            client.delete_rest_api(restApiId=rest_api_id)

    except Exception as e:
        LOG.debug("Error cleaning up rest API: %s, %s", rest_api_id, e)


@pytest.fixture
def apigw_create_rest_api(apigateway_client):
    rest_apis = []

    def _factory(*args, **kwargs):
        if "name" not in kwargs:
            kwargs["name"] = f"test-api-{short_uid()}"
        response = apigateway_client.create_rest_api(*args, **kwargs)
        rest_apis.append(response["id"])
        return response

    yield _factory

    # TODO: might clean up even more resources as we learn? integrations and such?
    for rest_api_id in rest_apis:
        delete_rest_api_retry(apigateway_client, rest_api_id)


def test_import_rest_api(import_apigw, snapshot):
    snapshot.add_transformer(snapshot.transform.apigateway_api())

    spec_file = load_file(OPENAPI_SPEC_PULUMI_JSON)
    response, root_id = import_apigw(body=spec_file, failOnWarnings=True)

    snapshot.match("import_rest_api", response)


class TestApiGatewayApi:
    @pytest.mark.aws_validated
    def test_list_and_delete_apis(self, apigateway_client, apigw_create_rest_api, snapshot):
        api_name1 = f"test-list-and-delete-apis-{short_uid()}"
        api_name2 = f"test-list-and-delete-apis-{short_uid()}"

        response = apigw_create_rest_api(name=api_name1, description="this is my api")
        snapshot.match("create-rest-api-1", response)
        api_id = response["id"]

        response_2 = apigw_create_rest_api(name=api_name2, description="this is my api2")
        snapshot.match("create-rest-api-2", response_2)

        response = apigateway_client.get_rest_apis()
        # sort the response by creation date, to ensure order for snapshot matching
        response["items"].sort(key=itemgetter("createdDate"))
        snapshot.match("get-rest-api-before-delete", response)

        response = apigateway_client.delete_rest_api(restApiId=api_id)
        snapshot.match("delete-rest-api", response)

        response = apigateway_client.get_rest_apis()
        snapshot.match("get-rest-api-after-delete", response)

    @pytest.mark.aws_validated
    def test_create_rest_api_with_optional_params(
        self,
        apigateway_client,
        apigw_create_rest_api,
        snapshot,
    ):
        # create only with mandatory name
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
        )
        snapshot.match("create-only-name", response)

        # create with empty description
        with pytest.raises(ClientError) as e:
            apigw_create_rest_api(
                name=f"test-api-{short_uid()}",
                description="",
            )
        snapshot.match("create-empty-desc", e.value.response)

        # create with random version
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
            version="v1",
        )
        snapshot.match("create-with-version", response)

        # create with empty binaryMediaTypes
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
            binaryMediaTypes=[],
        )
        snapshot.match("create-with-empty-binary-media", response)

    @pytest.mark.aws_validated
    def test_create_rest_api_with_tags(self, apigateway_client, apigw_create_rest_api, snapshot):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
            description="this is my api",
            tags={"MY_TAG1": "MY_VALUE1"},
        )
        snapshot.match("create-rest-api-w-tags", response)
        api_id = response["id"]

        response = apigateway_client.get_rest_api(restApiId=api_id)
        snapshot.match("get-rest-api-w-tags", response)

        assert "tags" in response
        assert response["tags"] == {"MY_TAG1": "MY_VALUE1"}

        response = apigateway_client.get_rest_apis()
        snapshot.match("get-rest-apis-w-tags", response)

    @pytest.mark.only_localstack
    def test_create_rest_api_with_custom_id_tag(self, apigw_create_rest_api):
        custom_id_tag = "testid123"
        response = apigw_create_rest_api(
            name="my_api", description="this is my api", tags={TAG_KEY_CUSTOM_ID: custom_id_tag}
        )
        api_id = response["id"]
        assert api_id == custom_id_tag

    @pytest.mark.aws_validated
    def test_update_rest_api_operation_add_remove(
        self, apigateway_client, apigw_create_rest_api, snapshot
    ):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="this is my api"
        )
        api_id = response["id"]
        # binaryMediaTypes is an array but is modified like an object
        patch_operations = [
            {"op": "add", "path": "/binaryMediaTypes/image~1png"},
            {"op": "add", "path": "/binaryMediaTypes/image~1jpeg"},
        ]
        response = apigateway_client.update_rest_api(
            restApiId=api_id, patchOperations=patch_operations
        )
        snapshot.match("update-rest-api-add", response)
        assert response["binaryMediaTypes"] == ["image/png", "image/jpeg"]
        assert response["description"] == "this is my api"

        patch_operations = [
            {"op": "replace", "path": "/binaryMediaTypes/image~1png", "value": "image/gif"},
        ]
        response = apigateway_client.update_rest_api(
            restApiId=api_id, patchOperations=patch_operations
        )
        snapshot.match("update-rest-api-replace", response)
        assert response["binaryMediaTypes"] == ["image/jpeg", "image/gif"]

        patch_operations = [
            {"op": "remove", "path": "/binaryMediaTypes/image~1gif"},
            {"op": "remove", "path": "/description"},
        ]
        response = apigateway_client.update_rest_api(
            restApiId=api_id, patchOperations=patch_operations
        )
        snapshot.match("update-rest-api-remove", response)
        assert response["binaryMediaTypes"] == ["image/jpeg"]
        assert "description" not in response

    @pytest.mark.aws_validated
    def test_update_rest_api_behaviour(self, apigateway_client, apigw_create_rest_api, snapshot):
        # TODO: add more negative testing
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="this is my api"
        )
        api_id = response["id"]
        # binaryMediaTypes is an array but is modified like an object, if you try accessing like an array, it will
        # lead to weird behaviour
        patch_operations = [
            {"op": "add", "path": "/binaryMediaTypes/-", "value": "image/png"},
        ]
        response = apigateway_client.update_rest_api(
            restApiId=api_id, patchOperations=patch_operations
        )
        snapshot.match("update-rest-api-array", response)
        assert response["binaryMediaTypes"] == ["-"]

        with pytest.raises(ClientError) as e:
            patch_operations = [
                {"op": "add", "path": "/binaryMediaTypes", "value": "image/gif"},
            ]
            apigateway_client.update_rest_api(restApiId=api_id, patchOperations=patch_operations)
        snapshot.match("update-rest-api-add-base-path", e.value.response)

        with pytest.raises(ClientError) as e:
            patch_operations = [
                {"op": "replace", "path": "/binaryMediaTypes", "value": "image/gif"},
            ]
            apigateway_client.update_rest_api(restApiId=api_id, patchOperations=patch_operations)
        snapshot.match("update-rest-api-replace-base-path", e.value.response)

        with pytest.raises(ClientError) as e:
            patch_operations = [
                {"op": "remove", "path": "/binaryMediaTypes"},
            ]
            apigateway_client.update_rest_api(restApiId=api_id, patchOperations=patch_operations)
        snapshot.match("update-rest-api-remove-base-path", e.value.response)

    @pytest.mark.aws_validated
    def test_update_rest_api_invalid_api_id(self, apigateway_client, snapshot):
        patch_operations = [{"op": "replace", "path": "/apiKeySource", "value": "AUTHORIZER"}]
        with pytest.raises(ClientError) as ex:
            apigateway_client.update_rest_api(restApiId="api_id", patchOperations=patch_operations)
        snapshot.match("not-found-update-rest-api", ex.value.response)
        assert ex.value.response["Error"]["Code"] == "NotFoundException"

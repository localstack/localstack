import json
import logging
import os.path
import time
from operator import itemgetter

import pytest
from botocore.config import Config
from botocore.exceptions import ClientError
from localstack_snapshot.snapshots.transformer import KeyValueBasedTransformer, SortingTransformer

from localstack.aws.api.apigateway import PutMode
from localstack.constants import TAG_KEY_CUSTOM_ID
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.aws.services.apigateway.apigateway_fixtures import (
    create_rest_api_integration,
    create_rest_api_integration_response,
    create_rest_api_method_response,
    create_rest_resource,
    create_rest_resource_method,
)
from tests.aws.services.apigateway.conftest import is_next_gen_api

LOG = logging.getLogger(__name__)

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
OAS_30_DOCUMENTATION_PARTS = os.path.join(THIS_DIR, "../../files/oas30_documentation_parts.json")


@pytest.fixture(autouse=True)
def apigw_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.apigateway_api())


@pytest.fixture(scope="class", autouse=True)
def apigw_cleanup_before_run(aws_client):
    # TODO: remove this once all tests are properly cleaning up and using fixtures
    rest_apis = aws_client.apigateway.get_rest_apis()
    for rest_api in rest_apis["items"]:
        delete_rest_api_retry(aws_client.apigateway, rest_api["id"])


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
def apigw_create_rest_api(aws_client, aws_client_factory):
    if is_aws_cloud():
        client_config = (
            Config(
                # Api gateway can throttle requests pretty heavily. Leading to potentially undeleted apis
                retries={"max_attempts": 10, "mode": "adaptive"}
            )
            if is_aws_cloud()
            else None
        )

        apigateway_client = aws_client_factory(config=client_config).apigateway
    else:
        apigateway_client = aws_client.apigateway

    rest_apis = []

    def _factory(*args, **kwargs):
        if "name" not in kwargs:
            kwargs["name"] = f"test-api-{short_uid()}"
        response = apigateway_client.create_rest_api(*args, **kwargs)
        rest_apis.append(response["id"])
        return response

    yield _factory

    for rest_api_id in rest_apis:
        delete_rest_api_retry(apigateway_client, rest_api_id)


class TestApiGatewayApiRestApi:
    @markers.aws.validated
    def test_list_and_delete_apis(self, apigw_create_rest_api, snapshot, aws_client):
        api_name1 = f"test-list-and-delete-apis-{short_uid()}"
        api_name2 = f"test-list-and-delete-apis-{short_uid()}"

        response = apigw_create_rest_api(name=api_name1, description="this is my api")
        snapshot.match("create-rest-api-1", response)
        api_id = response["id"]

        response_2 = apigw_create_rest_api(name=api_name2, description="this is my api2")
        snapshot.match("create-rest-api-2", response_2)

        response = aws_client.apigateway.get_rest_apis()
        # sort the response by creation date, to ensure order for snapshot matching
        response["items"].sort(key=itemgetter("createdDate"))
        snapshot.match("get-rest-api-before-delete", response)

        response = aws_client.apigateway.delete_rest_api(restApiId=api_id)
        snapshot.match("delete-rest-api", response)

        response = aws_client.apigateway.get_rest_apis()
        snapshot.match("get-rest-api-after-delete", response)

    @markers.aws.validated
    @pytest.mark.skip(reason="rest apis are case insensitive for now because of custom id tags")
    def test_get_api_case_insensitive(self, apigw_create_rest_api, snapshot, aws_client):
        api_name1 = f"test-case-sensitive-apis-{short_uid()}"

        response = apigw_create_rest_api(name=api_name1, description="lower case api")
        snapshot.match("create-rest-api", response)
        api_id = response["id"]

        snapshot.add_transformer(snapshot.transform.regex(api_id.upper(), "<upper-id>"))

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.get_rest_api(restApiId=api_id.upper())
        snapshot.match("get-api-upper-case", e.value.response)

    @markers.aws.validated
    def test_create_rest_api_with_optional_params(self, apigw_create_rest_api, snapshot):
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

        # create with negative minimumCompressionSize
        with pytest.raises(ClientError) as e:
            apigw_create_rest_api(name=f"test-api-{short_uid()}", minimumCompressionSize=-1)
        snapshot.match("string-compression-size", e.value.response)

    @markers.aws.validated
    def test_create_rest_api_with_tags(self, apigw_create_rest_api, snapshot, aws_client):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
            description="this is my api",
            tags={"MY_TAG1": "MY_VALUE1"},
        )
        snapshot.match("create-rest-api-w-tags", response)
        api_id = response["id"]

        response = aws_client.apigateway.get_rest_api(restApiId=api_id)
        snapshot.match("get-rest-api-w-tags", response)

        assert "tags" in response
        assert response["tags"] == {"MY_TAG1": "MY_VALUE1"}

        response = aws_client.apigateway.get_rest_apis()
        snapshot.match("get-rest-apis-w-tags", response)

    @markers.aws.only_localstack
    def test_create_rest_api_with_custom_id_tag(self, apigw_create_rest_api):
        custom_id_tag = "testid123"
        response = apigw_create_rest_api(
            name="my_api", description="this is my api", tags={TAG_KEY_CUSTOM_ID: custom_id_tag}
        )
        api_id = response["id"]
        assert api_id == custom_id_tag

    @markers.aws.validated
    def test_update_rest_api_operation_add_remove(
        self, apigw_create_rest_api, snapshot, aws_client
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
        response = aws_client.apigateway.update_rest_api(
            restApiId=api_id, patchOperations=patch_operations
        )
        snapshot.match("update-rest-api-add", response)
        assert response["binaryMediaTypes"] == ["image/png", "image/jpeg"]
        assert response["description"] == "this is my api"

        patch_operations = [
            {"op": "replace", "path": "/binaryMediaTypes/image~1png", "value": "image/gif"},
        ]
        response = aws_client.apigateway.update_rest_api(
            restApiId=api_id, patchOperations=patch_operations
        )
        snapshot.match("update-rest-api-replace", response)
        assert response["binaryMediaTypes"] == ["image/jpeg", "image/gif"]

        patch_operations = [
            {"op": "remove", "path": "/binaryMediaTypes/image~1gif"},
            {"op": "remove", "path": "/description"},
        ]
        response = aws_client.apigateway.update_rest_api(
            restApiId=api_id, patchOperations=patch_operations
        )
        snapshot.match("update-rest-api-remove", response)
        assert response["binaryMediaTypes"] == ["image/jpeg"]
        assert "description" not in response

    @markers.aws.validated
    def test_update_rest_api_compression(self, apigw_create_rest_api, snapshot, aws_client):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="this is my api"
        )
        api_id = response["id"]

        # we can enable compression by setting a non-negative integer between 0 and 10485760
        patch_operations_enable = [
            {"op": "replace", "path": "/minimumCompressionSize", "value": "10"},
        ]
        response = aws_client.apigateway.update_rest_api(
            restApiId=api_id, patchOperations=patch_operations_enable
        )
        snapshot.match("enable-compression", response)

        # check that listing is not exploding after update, null -> 10
        response = aws_client.apigateway.get_rest_api(restApiId=api_id)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        # from the docs: to disable compression, apply a replace operation with the value property set to null or
        # omit the value property.
        # it seems an empty string is accepted as well
        patch_operations = [
            {"op": "replace", "path": "/minimumCompressionSize", "value": ""},
        ]
        response = aws_client.apigateway.update_rest_api(
            restApiId=api_id, patchOperations=patch_operations
        )
        snapshot.match("disable-compression", response)

        # check that listing is not exploding after update, 10 -> null
        response = aws_client.apigateway.get_rest_api(restApiId=api_id)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        patch_operations = [
            {"op": "replace", "path": "/minimumCompressionSize", "value": "0"},
        ]
        response = aws_client.apigateway.update_rest_api(
            restApiId=api_id, patchOperations=patch_operations
        )
        snapshot.match("set-compression-zero", response)

        # check that listing is not exploding after update, null -> 0
        response = aws_client.apigateway.get_rest_api(restApiId=api_id)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        with pytest.raises(ClientError) as e:
            patch_operations = [
                {"op": "replace", "path": "/minimumCompressionSize", "value": "-1"},
            ]
            aws_client.apigateway.update_rest_api(
                restApiId=api_id, patchOperations=patch_operations
            )
        snapshot.match("set-negative-compression", e.value.response)

        with pytest.raises(ClientError) as e:
            patch_operations = [
                {"op": "replace", "path": "/minimumCompressionSize", "value": "test"},
            ]
            aws_client.apigateway.update_rest_api(
                restApiId=api_id, patchOperations=patch_operations
            )
        snapshot.match("set-string-compression", e.value.response)

        with pytest.raises(ClientError) as e:
            patch_operations = [
                {"op": "add", "path": "/minimumCompressionSize", "value": "10"},
            ]
            aws_client.apigateway.update_rest_api(
                restApiId=api_id, patchOperations=patch_operations
            )
        snapshot.match("unsupported-operation", e.value.response)

    @markers.aws.validated
    def test_update_rest_api_behaviour(self, apigw_create_rest_api, snapshot, aws_client):
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
        response = aws_client.apigateway.update_rest_api(
            restApiId=api_id, patchOperations=patch_operations
        )
        snapshot.match("update-rest-api-array", response)
        assert response["binaryMediaTypes"] == ["-"]

        with pytest.raises(ClientError) as e:
            patch_operations = [
                {"op": "add", "path": "/binaryMediaTypes", "value": "image/gif"},
            ]
            aws_client.apigateway.update_rest_api(
                restApiId=api_id, patchOperations=patch_operations
            )
        snapshot.match("update-rest-api-add-base-path", e.value.response)

        with pytest.raises(ClientError) as e:
            patch_operations = [
                {"op": "replace", "path": "/binaryMediaTypes", "value": "image/gif"},
            ]
            aws_client.apigateway.update_rest_api(
                restApiId=api_id, patchOperations=patch_operations
            )
        snapshot.match("update-rest-api-replace-base-path", e.value.response)

        with pytest.raises(ClientError) as e:
            patch_operations = [
                {"op": "remove", "path": "/binaryMediaTypes"},
            ]
            aws_client.apigateway.update_rest_api(
                restApiId=api_id, patchOperations=patch_operations
            )
        snapshot.match("update-rest-api-remove-base-path", e.value.response)

    @markers.aws.validated
    def test_update_rest_api_invalid_api_id(self, snapshot, aws_client):
        patch_operations = [{"op": "replace", "path": "/apiKeySource", "value": "AUTHORIZER"}]
        with pytest.raises(ClientError) as ex:
            aws_client.apigateway.update_rest_api(
                restApiId="api_id", patchOperations=patch_operations
            )
        snapshot.match("not-found-update-rest-api", ex.value.response)
        assert ex.value.response["Error"]["Code"] == "NotFoundException"


class TestApiGatewayApiResource:
    @markers.aws.validated
    def test_resource_lifecycle(self, apigw_create_rest_api, snapshot, aws_client):
        snapshot.add_transformer(SortingTransformer("items", lambda x: x["path"]))
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource lifecycle"
        )
        api_id = response["id"]

        root_rest_api_resource = aws_client.apigateway.get_resources(restApiId=api_id)
        snapshot.match("rest-api-root-resource", root_rest_api_resource)

        root_id = root_rest_api_resource["items"][0]["id"]

        resource_response = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="pets"
        )
        resource_id = resource_response["id"]

        snapshot.match("create-resource", resource_response)

        rest_api_resources = aws_client.apigateway.get_resources(restApiId=api_id)
        snapshot.match("rest-api-resources-after-create", rest_api_resources)

        # create subresource
        subresource_response = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=resource_id, pathPart="subpets"
        )
        snapshot.match("create-subresource", subresource_response)

        rest_api_resources = aws_client.apigateway.get_resources(restApiId=api_id)
        snapshot.match("rest-api-resources-after-create-sub", rest_api_resources)

        # only supported path are /parentId and /pathPart with operation `replace`
        patch_operations = [
            {"op": "replace", "path": "/pathPart", "value": "dogs"},
        ]

        update_response = aws_client.apigateway.update_resource(
            restApiId=api_id, resourceId=resource_id, patchOperations=patch_operations
        )
        snapshot.match("update-path-part", update_response)

        get_resource_response = aws_client.apigateway.get_resource(
            restApiId=api_id, resourceId=resource_id
        )
        snapshot.match("get-resp-after-update-path-part", get_resource_response)

        delete_resource_response = aws_client.apigateway.delete_resource(
            restApiId=api_id, resourceId=resource_id
        )
        snapshot.match("del-resource", delete_resource_response)

        rest_api_resources = aws_client.apigateway.get_resources(restApiId=api_id)
        snapshot.match("rest-api-resources-after-delete", rest_api_resources)

    @markers.aws.validated
    def test_update_resource_behaviour(self, apigw_create_rest_api, snapshot, aws_client):
        snapshot.add_transformer(SortingTransformer("items", lambda x: x["path"]))
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource behaviour"
        )
        api_id = response["id"]

        root_rest_api_resource = aws_client.apigateway.get_resources(restApiId=api_id)
        root_id = root_rest_api_resource["items"][0]["id"]

        resource_response = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="pets"
        )
        resource_id = resource_response["id"]

        # try updating a non-existent resource
        patch_operations = [
            {"op": "replace", "path": "/pathPart", "value": "dogs"},
        ]
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_resource(
                restApiId=api_id, resourceId="fake-resource", patchOperations=patch_operations
            )
        snapshot.match("nonexistent-resource", e.value.response)

        # only supported path are /parentId and /pathPart with operation `replace`
        patch_operations = [
            {"op": "replace", "path": "/invalid", "value": "dogs"},
        ]
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_resource(
                restApiId=api_id, resourceId=resource_id, patchOperations=patch_operations
            )
        snapshot.match("invalid-path-part", e.value.response)

        # try updating a resource with a non-existent parentId
        patch_operations = [
            {"op": "replace", "path": "/parentId", "value": "fake-parent-id"},
        ]
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_resource(
                restApiId=api_id, resourceId=resource_id, patchOperations=patch_operations
            )
        snapshot.match("invalid-parent-id", e.value.response)

        # create subresource `subpets` under `/pets`
        subresource_response = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=resource_id, pathPart="subpets"
        )
        snapshot.match("create-subresource", subresource_response)
        subresource_id = subresource_response["id"]

        # create subresource `pets` under `/pets/subpets`
        subresource_child_response = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=subresource_id, pathPart="pets"
        )
        snapshot.match("create-subresource-child", subresource_child_response)
        subresource_child_id = subresource_child_response["id"]

        # try moving a subresource under the root id but with the same name as an existing future sibling
        # move last resource of `pets/subpets/pets` to `/pets`, already exists
        patch_operations = [
            {"op": "replace", "path": "/parentId", "value": root_id},
        ]
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_resource(
                restApiId=api_id, resourceId=subresource_child_id, patchOperations=patch_operations
            )
        snapshot.match("existing-future-sibling-path", e.value.response)
        # clean up that for the rest of the test
        aws_client.apigateway.delete_resource(restApiId=api_id, resourceId=subresource_child_id)

        # try setting the parent id of the pets to its own subresource?
        patch_operations = [
            {"op": "replace", "path": "/parentId", "value": subresource_id},
        ]
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_resource(
                restApiId=api_id, resourceId=resource_id, patchOperations=patch_operations
            )
        snapshot.match("update-parent-id-to-subresource-id", e.value.response)

        # move the subresource to be under the root id
        # we had root -> resource -> subresource - /pets/subpets
        # we now have root -> resource and root -> subresource -> /pets and /subpets
        patch_operations = [
            {"op": "replace", "path": "/parentId", "value": root_id},
        ]
        update_parent_id_to_root = aws_client.apigateway.update_resource(
            restApiId=api_id, resourceId=subresource_id, patchOperations=patch_operations
        )

        snapshot.match("update-parent-id-to-root-id", update_parent_id_to_root)

        # try changing `/subpets` to `/pets`, but it already exists under  `root`
        patch_operations = [
            {"op": "replace", "path": "/pathPart", "value": "pets"},
        ]
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_resource(
                restApiId=api_id, resourceId=subresource_id, patchOperations=patch_operations
            )
        snapshot.match("update-path-already-exists", e.value.response)

        # test deleting the resource `/pets`, its old child (`/subpets`) should not be deleted
        aws_client.apigateway.delete_resource(restApiId=api_id, resourceId=resource_id)
        api_resources = aws_client.apigateway.get_resources(restApiId=api_id)
        snapshot.match("resources-after-deletion", api_resources)

        # try using a non-supported operation `remove`
        patch_operations = [
            {"op": "remove", "path": "/pathPart"},
        ]
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_resource(
                restApiId=api_id, resourceId=subresource_id, patchOperations=patch_operations
            )
        snapshot.match("remove-unsupported", e.value.response)

        # try using a non-supported operation `add`
        patch_operations = [
            {"op": "add", "path": "/pathPart", "value": "added-pets"},
        ]
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_resource(
                restApiId=api_id, resourceId=subresource_id, patchOperations=patch_operations
            )
        snapshot.match("add-unsupported", e.value.response)

    @markers.aws.validated
    def test_delete_resource(self, apigw_create_rest_api, snapshot, aws_client):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource behaviour"
        )
        api_id = response["id"]

        root_rest_api_resource = aws_client.apigateway.get_resources(restApiId=api_id)
        root_id = root_rest_api_resource["items"][0]["id"]

        resource_response = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="pets"
        )
        resource_id = resource_response["id"]

        # create subresource
        subresource_response = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=resource_id, pathPart="subpets"
        )
        subresource_id = subresource_response["id"]

        delete_resource_response = aws_client.apigateway.delete_resource(
            restApiId=api_id, resourceId=resource_id
        )
        snapshot.match("delete-resource", delete_resource_response)

        api_resources = aws_client.apigateway.get_resources(restApiId=api_id)
        snapshot.match("get-resources", api_resources)

        # try deleting already deleted subresource
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.delete_resource(restApiId=api_id, resourceId=subresource_id)
        snapshot.match("delete-subresource", e.value.response)

    @markers.aws.validated
    def test_create_resource_parent_invalid(self, apigw_create_rest_api, snapshot, aws_client):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource parent"
        )
        api_id = response["id"]

        # create subresource with wrong parent
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_resource(
                restApiId=api_id, parentId="fake-resource-id", pathPart="subpets"
            )
        snapshot.match("wrong-resource-parent-id", e.value.response)

    @markers.aws.validated
    def test_create_proxy_resource(self, apigw_create_rest_api, snapshot, aws_client):
        # test following docs
        # https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-settings-method-request.html#api-gateway-proxy-resource
        snapshot.add_transformer(SortingTransformer("items", lambda x: x["path"]))
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource proxy"
        )
        api_id = response["id"]
        root_rest_api_resource = aws_client.apigateway.get_resources(restApiId=api_id)
        root_id = root_rest_api_resource["items"][0]["id"]

        # creating `/{proxy+}` resource
        base_proxy_response = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="{proxy+}"
        )
        snapshot.match("create-base-proxy-resource", base_proxy_response)

        # creating `/parent` resource, sibling to `/{proxy+}`
        proxy_sibling_response = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="parent"
        )
        proxy_sibling_id = proxy_sibling_response["id"]
        snapshot.match("create-proxy-sibling-resource", proxy_sibling_id)

        # creating `/parent/{proxy+}` resource
        proxy_sibling_proxy_child_response = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=proxy_sibling_id, pathPart="{proxy+}"
        )
        proxy_child_id = proxy_sibling_proxy_child_response["id"]
        snapshot.match(
            "create-proxy-sibling-proxy-child-resource", proxy_sibling_proxy_child_response
        )

        # creating `/parent/child` resource, sibling to `/parent/{proxy+}`
        proxy_sibling_static_child_response = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=proxy_sibling_id, pathPart="child"
        )
        dynamic_child_id = proxy_sibling_static_child_response["id"]
        snapshot.match(
            "create-proxy-sibling-static-child-resource", proxy_sibling_static_child_response
        )

        # creating `/parent/child/{proxy+}` resource
        dynamic_child_proxy_child_response = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=dynamic_child_id, pathPart="{proxy+}"
        )
        snapshot.match("create-static-child-proxy-resource", dynamic_child_proxy_child_response)

        # list all resources
        result_api_resource = aws_client.apigateway.get_resources(restApiId=api_id)
        snapshot.match("all-resources", result_api_resource)

        # to allow nested route testing, we will delete `/parent/{proxy+}` to allow creation of a dynamic {child}
        aws_client.apigateway.delete_resource(restApiId=api_id, resourceId=proxy_child_id)

        # creating `/parent/{child}` resource, as its sibling `/parent/{proxy+}` is now deleted
        proxy_sibling_dynamic_child_response = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=proxy_sibling_id, pathPart="{child}"
        )
        dynamic_child_id = proxy_sibling_dynamic_child_response["id"]
        snapshot.match(
            "create-proxy-sibling-dynamic-child-resource", proxy_sibling_dynamic_child_response
        )

        # creating `/parent/{child}/{proxy+}` resource
        dynamic_child_proxy_child_response = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=dynamic_child_id, pathPart="{proxy+}"
        )
        snapshot.match("create-dynamic-child-proxy-resource", dynamic_child_proxy_child_response)

        result_api_resource = aws_client.apigateway.get_resources(restApiId=api_id)
        snapshot.match("all-resources-2", result_api_resource)

    @markers.aws.validated
    def test_create_proxy_resource_validation(self, apigw_create_rest_api, snapshot, aws_client):
        # test following docs
        # https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-settings-method-request.html#api-gateway-proxy-resource
        snapshot.add_transformer(SortingTransformer("items", lambda x: x["path"]))
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource proxy"
        )
        api_id = response["id"]
        root_rest_api_resource = aws_client.apigateway.get_resources(restApiId=api_id)
        root_id = root_rest_api_resource["items"][0]["id"]

        # creating `/{proxy+}` resource
        base_proxy_response = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="{proxy+}"
        )
        base_proxy_id = base_proxy_response["id"]
        snapshot.match("create-base-proxy-resource", base_proxy_response)

        # try creating `/{dynamic}` resource, sibling to `/{proxy+}`
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_resource(
                restApiId=api_id, parentId=root_id, pathPart="{dynamic}"
            )
        snapshot.match("create-proxy-dynamic-sibling-resource", e.value.response)

        # try creating `/{proxy+}/child` resource, child to `/{proxy+}`
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_resource(
                restApiId=api_id, parentId=base_proxy_id, pathPart="child"
            )
        snapshot.match("create-proxy-static-child-resource", e.value.response)

        # try creating `/{proxy+}/{child}` resource, dynamic child to `/{proxy+}`
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_resource(
                restApiId=api_id, parentId=base_proxy_id, pathPart="{child}"
            )
        snapshot.match("create-proxy-dynamic-child-resource", e.value.response)

        # creating `/parent` static resource
        parent_response = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="parent"
        )
        parent_id = parent_response["id"]

        # create `/parent/{child+}` resource, dynamic greedy child to `/parent`
        greedy_child_response = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=parent_id, pathPart="{child+}"
        )
        snapshot.match("create-greedy-child-resource", greedy_child_response)


class TestApiGatewayApiAuthorizer:
    @markers.aws.validated
    def test_authorizer_crud_no_api(self, snapshot, aws_client):
        # maybe move this test to a full lifecycle one
        # AWS validates the format of the authorizerUri before the restApi existence
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_authorizer(
                restApiId="test-fake-rest-id",
                name="fake-auth-name",
                type="TOKEN",
                authorizerUri="arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:myApiAuthorizer/invocations",
                identitySource="method.request.header.Authorization",
            )
        snapshot.match("wrong-rest-api-id-create-authorizer", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.get_authorizers(restApiId="test-fake-rest-id")
        snapshot.match("wrong-rest-api-id-get-authorizers", e.value.response)


class TestApiGatewayApiMethod:
    @markers.aws.validated
    def test_method_lifecycle(self, apigw_create_rest_api, snapshot, aws_client):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource method lifecycle"
        )
        api_id = response["id"]
        root_id = response["rootResourceId"]

        put_base_method_response = aws_client.apigateway.put_method(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="ANY",
            authorizationType="NONE",
        )
        snapshot.match("put-base-method-response", put_base_method_response)

        get_base_method_response = aws_client.apigateway.get_method(
            restApiId=api_id, resourceId=root_id, httpMethod="ANY"
        )
        snapshot.match("get-base-method-response", get_base_method_response)

        del_base_method_response = aws_client.apigateway.delete_method(
            restApiId=api_id, resourceId=root_id, httpMethod="ANY"
        )
        snapshot.match("del-base-method-response", del_base_method_response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.get_method(restApiId=api_id, resourceId=root_id, httpMethod="ANY")
        snapshot.match("get-deleted-method-response", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.delete_method(
                restApiId=api_id, resourceId=root_id, httpMethod="ANY"
            )
        snapshot.match("delete-deleted-method-response", e.value.response)

    @markers.aws.validated
    def test_method_request_parameters(self, apigw_create_rest_api, snapshot, aws_client):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource method request params"
        )
        api_id = response["id"]
        root_id = response["rootResourceId"]

        put_method_response = aws_client.apigateway.put_method(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="ANY",
            authorizationType="NONE",
            requestParameters={
                "method.request.querystring.q_optional": False,
                "method.request.querystring.q_required": True,
                "method.request.header.h_optional": False,
                "method.request.header.h_required": True,
            },
        )
        snapshot.match("put-method-request-params-response", put_method_response)

        get_method_response = aws_client.apigateway.get_method(
            restApiId=api_id, resourceId=root_id, httpMethod="ANY"
        )
        snapshot.match("get-method-request-params-response", get_method_response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.put_method(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="GET",
                authorizationType="NONE",
                requestParameters={
                    "method.request.querystring.optional": False,
                    "method.request.header.optional": False,
                },
            )

        snapshot.match("req-params-same-name", e.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$.delete-model-used-by-2-method.Error.Message",
            "$.delete-model-used-by-2-method.message",  # we can't guarantee the last method will be the same as AWS
        ]
    )
    def test_put_method_model(self, apigw_create_rest_api, snapshot, aws_client):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource method model"
        )
        api_id = response["id"]
        root_id = response["rootResourceId"]

        create_model = aws_client.apigateway.create_model(
            name="MySchema",
            restApiId=api_id,
            contentType="application/json",
            description="",
            schema=json.dumps({"title": "MySchema", "type": "object"}),
        )
        snapshot.match("create-model", create_model)

        create_model_2 = aws_client.apigateway.create_model(
            name="MySchemaTwo",
            restApiId=api_id,
            contentType="application/json",
            description="",
            schema=json.dumps({"title": "MySchemaTwo", "type": "object"}),
        )
        snapshot.match("create-model-2", create_model_2)

        put_method_response = aws_client.apigateway.put_method(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="ANY",
            authorizationType="NONE",
            requestModels={"application/json": "MySchema"},
        )
        snapshot.match("put-method-request-models", put_method_response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.delete_model(restApiId=api_id, modelName="MySchema")
        snapshot.match("delete-model-used", e.value.response)

        patch_operations = [
            {"op": "replace", "path": "/requestModels/application~1json", "value": "MySchemaTwo"},
        ]

        update_method_model = aws_client.apigateway.update_method(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="ANY",
            patchOperations=patch_operations,
        )
        snapshot.match("update-method-model", update_method_model)

        delete_model = aws_client.apigateway.delete_model(restApiId=api_id, modelName="MySchema")
        snapshot.match("delete-model-unused", delete_model)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.delete_model(restApiId=api_id, modelName="MySchemaTwo")
        snapshot.match("delete-model-used-2", e.value.response)

        # create a subresource using MySchemaTwo
        resource = aws_client.apigateway.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="test"
        )
        put_method_response = aws_client.apigateway.put_method(
            restApiId=api_id,
            resourceId=resource["id"],
            httpMethod="ANY",
            authorizationType="NONE",
            requestModels={"application/json": "MySchemaTwo"},
        )
        snapshot.match("put-method-2-request-models", put_method_response)

        # assert that the error raised gives the path of the subresource
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.delete_model(restApiId=api_id, modelName="MySchemaTwo")
        snapshot.match("delete-model-used-by-2-method", e.value.response)

        patch_operations = [
            {"op": "remove", "path": "/requestModels/application~1json", "value": "MySchemaTwo"},
        ]

        # remove the Model from the subresource
        update_method_model = aws_client.apigateway.update_method(
            restApiId=api_id,
            resourceId=resource["id"],
            httpMethod="ANY",
            patchOperations=patch_operations,
        )
        snapshot.match("update-method-model-2", update_method_model)

        if is_aws_cloud():
            # just to be sure the change is properly set in AWS
            time.sleep(3)

        # assert that the error raised gives the path of the resource now
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.delete_model(restApiId=api_id, modelName="MySchemaTwo")
        snapshot.match("delete-model-used-by-method-1", e.value.response)

        # delete the Method using MySchemaTwo
        delete_method = aws_client.apigateway.delete_method(
            restApiId=api_id, resourceId=root_id, httpMethod="ANY"
        )
        snapshot.match("delete-method-using-model-2", delete_method)

        # assert we can now delete MySchemaTwo
        delete_model = aws_client.apigateway.delete_model(restApiId=api_id, modelName="MySchemaTwo")
        snapshot.match("delete-model-unused-2", delete_model)

    @markers.aws.validated
    def test_put_method_validation(self, apigw_create_rest_api, snapshot, aws_client):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource method request params"
        )
        api_id = response["id"]
        root_id = response["rootResourceId"]

        # wrong RestApiId
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.put_method(
                restApiId="fake-api",
                resourceId=root_id,
                httpMethod="WRONG",
                authorizationType="NONE",
            )
        snapshot.match("wrong-api", e.value.response)

        # wrong resourceId
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.put_method(
                restApiId=api_id,
                resourceId="fake-resource-id",
                httpMethod="WRONG",
                authorizationType="NONE",
            )
        snapshot.match("wrong-resource", e.value.response)

        # wrong httpMethod
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.put_method(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="WRONG",
                authorizationType="NONE",
            )
        snapshot.match("wrong-method", e.value.response)

        # missing AuthorizerId when setting authorizationType="CUSTOM"
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.put_method(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="ANY",
                authorizationType="CUSTOM",
            )
        snapshot.match("missing-authorizer-id", e.value.response)

        # invalid RequestValidatorId
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.put_method(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="ANY",
                authorizationType="NONE",
                requestValidatorId="fake-validator",
            )
        snapshot.match("invalid-request-validator", e.value.response)

        # invalid Model id
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.put_method(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="ANY",
                authorizationType="NONE",
                requestModels={"application/json": "petModel"},
            )
        snapshot.match("invalid-model-name", e.value.response)

        # TODO: validate authorizationScopes?
        # TODO: add more validation on methods once its subresources are tested
        # Authorizer, RequestValidator, Model

    @markers.aws.validated
    def test_update_method(self, apigw_create_rest_api, snapshot, aws_client):
        # see https://www.linkedin.com/pulse/updating-aws-cli-patch-operations-rest-api-yitzchak-meirovich/
        # for patch path
        snapshot.add_transformer(snapshot.transform.key_value("authorizerId"))
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing update method"
        )
        api_id = response["id"]
        root_id = response["rootResourceId"]

        put_method_response = aws_client.apigateway.put_method(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="ANY",
            authorizationType="NONE",
        )
        snapshot.match("put-method-response", put_method_response)

        patch_operations_add = [
            {
                "op": "add",
                "path": "/requestParameters/method.request.querystring.optional",
                "value": "true",
            },
            {"op": "add", "path": "/requestModels/application~1json", "value": "Empty"},
        ]

        update_method_response_add = aws_client.apigateway.update_method(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="ANY",
            patchOperations=patch_operations_add,
        )
        snapshot.match("update-method-add", update_method_response_add)

        patch_operations_replace = [
            {"op": "replace", "path": "/operationName", "value": "ReplacedOperationName"},
            {"op": "replace", "path": "/apiKeyRequired", "value": "true"},
            {"op": "replace", "path": "/authorizationType", "value": "AWS_IAM"},
            {
                "op": "replace",
                "path": "/requestParameters/method.request.querystring.optional",
                "value": "false",
            },
        ]

        update_method_response_replace = aws_client.apigateway.update_method(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="ANY",
            patchOperations=patch_operations_replace,
        )
        snapshot.match("update-method-replace", update_method_response_replace)

        authorizer = aws_client.apigateway.create_authorizer(
            restApiId=api_id,
            name="authorizer-test",
            type="TOKEN",
            authorizerUri="arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:myApiAuthorizer/invocations",
            identitySource="method.request.header.Authorization",
        )

        patch_operations_replace_auth = [
            {"op": "replace", "path": "/authorizerId", "value": authorizer["id"]},
            {"op": "replace", "path": "/authorizationType", "value": "CUSTOM"},
        ]

        update_method_response_replace_auth = aws_client.apigateway.update_method(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="ANY",
            patchOperations=patch_operations_replace_auth,
        )
        snapshot.match("update-method-replace-authorizer", update_method_response_replace_auth)

        patch_operations_remove = [
            {
                "op": "remove",
                "path": "/requestParameters/method.request.querystring.optional",
                "value": "true",
            },
            {"op": "remove", "path": "/requestModels/application~1json", "value": "Empty"},
        ]

        update_method_response_remove = aws_client.apigateway.update_method(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="ANY",
            patchOperations=patch_operations_remove,
        )
        snapshot.match("update-method-remove", update_method_response_remove)

    @markers.aws.validated
    def test_update_method_validation(self, apigw_create_rest_api, snapshot, aws_client):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource method request params"
        )
        api_id = response["id"]
        root_id = response["rootResourceId"]

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_method(
                restApiId="fake-api",
                resourceId=root_id,
                httpMethod="ANY",
                patchOperations=[],
            )
        snapshot.match("wrong-rest-api", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_method(
                restApiId=api_id,
                resourceId="fake-resource-id",
                httpMethod="ANY",
                patchOperations=[],
            )
        snapshot.match("wrong-resource-id", e.value.response)

        # method is not set for the resource?
        with pytest.raises(ClientError) as e:
            patch_operations_add = [
                {"op": "replace", "path": "/operationName", "value": "methodDoesNotExist"},
            ]
            aws_client.apigateway.update_method(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="GET",
                patchOperations=patch_operations_add,
            )
        snapshot.match("method-does-not-exist", e.value.response)

        put_method_response = aws_client.apigateway.put_method(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="ANY",
            authorizationType="NONE",
            apiKeyRequired=True,
        )
        snapshot.match("put-method-response", put_method_response)

        # unsupported operation
        patch_operations_add = [
            {"op": "add", "path": "/operationName", "value": "operationName"},
        ]
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_method(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="ANY",
                patchOperations=patch_operations_add,
            )
        snapshot.match("unsupported-operation", e.value.response)

        # unsupported operation
        patch_operations_add_2 = [
            {"op": "add", "path": "/requestValidatorId", "value": "wrong-id"},
        ]
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_method(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="ANY",
                patchOperations=patch_operations_add_2,
            )
        snapshot.match("unsupported-operation-2", e.value.response)

        # unsupported path
        with pytest.raises(ClientError) as e:
            patch_operations_add = [
                {"op": "add", "path": "/httpMethod", "value": "PUT"},
            ]
            aws_client.apigateway.update_method(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="ANY",
                patchOperations=patch_operations_add,
            )
        snapshot.match("unsupported-path", e.value.response)

        # wrong path for requestParameters
        with pytest.raises(ClientError) as e:
            patch_operations_add = [
                {
                    "op": "replace",
                    "path": "/requestParameters",
                    "value": "method.request.querystring.optional=false",
                },
            ]
            aws_client.apigateway.update_method(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="ANY",
                patchOperations=patch_operations_add,
            )
        snapshot.match("wrong-path-request-parameters", e.value.response)

        # wrong path for requestModels
        with pytest.raises(ClientError) as e:
            patch_operations_add = [
                {"op": "add", "path": "/requestModels/application/json", "value": "Empty"},
            ]
            aws_client.apigateway.update_method(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="ANY",
                patchOperations=patch_operations_add,
            )
        snapshot.match("wrong-path-request-models", e.value.response)

        # wrong value type
        patch_operations_add = [
            {"op": "replace", "path": "/apiKeyRequired", "value": "whatever"},
        ]
        wrong_value_type_resp = aws_client.apigateway.update_method(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="ANY",
            patchOperations=patch_operations_add,
        )
        snapshot.match("wrong-value-type", wrong_value_type_resp)

        # add auth type without authorizer?
        with pytest.raises(ClientError) as e:
            patch_operations_add = [
                {"op": "replace", "path": "/authorizationType", "value": "CUSTOM"},
            ]
            aws_client.apigateway.update_method(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="ANY",
                patchOperations=patch_operations_add,
            )
        snapshot.match("wrong-auth-type", e.value.response)

        # add auth id when method has NONE, AWS will ignore it
        patch_operations_add = [
            {"op": "replace", "path": "/authorizerId", "value": "abc123"},
        ]
        response = aws_client.apigateway.update_method(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="ANY",
            patchOperations=patch_operations_add,
        )
        snapshot.match("skip-auth-id-with-wrong-type", response)

        # add auth type without real authorizer id?
        with pytest.raises(ClientError) as e:
            patch_operations_add = [
                {"op": "replace", "path": "/authorizationType", "value": "CUSTOM"},
                {"op": "replace", "path": "/authorizerId", "value": "abc123"},
            ]
            aws_client.apigateway.update_method(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="ANY",
                patchOperations=patch_operations_add,
            )
        snapshot.match("wrong-auth-id", e.value.response)

        # replace wrong validator id
        with pytest.raises(ClientError) as e:
            patch_operations_add = [
                {"op": "replace", "path": "/requestValidatorId", "value": "fake-id"},
            ]
            aws_client.apigateway.update_method(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="ANY",
                patchOperations=patch_operations_add,
            )
        snapshot.match("wrong-req-validator-id", e.value.response)


class TestApiGatewayApiModels:
    @markers.aws.validated
    def test_model_lifecycle(self, apigw_create_rest_api, snapshot, aws_client):
        # taken from https://docs.aws.amazon.com/apigateway/latest/api/API_CreateModel.html#API_CreateModel_Examples
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource model lifecycle"
        )
        api_id = response["id"]

        create_model_response = aws_client.apigateway.create_model(
            name="CalcOutput",
            restApiId=api_id,
            contentType="application/json",
            description="Calc output model",
            schema='{\n\t"title": "Calc output",\n\t"type": "object",\n\t"properties": {\n\t\t"a": {\n\t\t\t"type": "number"\n\t\t},\n\t\t"b": {\n\t\t\t"type": "number"\n\t\t},\n\t\t"op": {\n\t\t\t"description": "operation of +, -, * or /",\n\t\t\t"type": "string"\n\t\t},\n\t\t"c": {\n\t\t    "type": "number"\n\t\t}\n\t},\n\t"required": ["a", "b", "op"]\n}\n',
        )
        snapshot.match("create-model", create_model_response)

        get_models_response = aws_client.apigateway.get_models(restApiId=api_id)
        get_models_response["items"].sort(key=lambda x: x["name"])
        snapshot.match("get-models", get_models_response)

        # manually assert the presence of 2 default models, Error and Empty, as snapshots will replace names
        model_names = [model["name"] for model in get_models_response["items"]]
        assert "Error" in model_names
        assert "Empty" in model_names

        get_model_response = aws_client.apigateway.get_model(
            restApiId=api_id, modelName="CalcOutput"
        )
        snapshot.match("get-model", get_model_response)

        del_model_response = aws_client.apigateway.delete_model(
            restApiId=api_id, modelName="CalcOutput"
        )
        snapshot.match("del-model", del_model_response)

    @markers.aws.validated
    def test_model_validation(self, apigw_create_rest_api, snapshot, aws_client):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource model lifecycle"
        )
        api_id = response["id"]

        fake_api_id = "abcde0"

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_model(
                name="MySchema",
                restApiId=fake_api_id,
                contentType="application/json",
                description="Test model",
                schema=json.dumps({"title": "MySchema", "type": "object"}),
            )

        snapshot.match("create-model-wrong-id", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.get_models(restApiId=fake_api_id)
        snapshot.match("get-models-wrong-id", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.get_model(restApiId=fake_api_id, modelName="MySchema")
        snapshot.match("get-model-wrong-id", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.delete_model(restApiId=fake_api_id, modelName="MySchema")
        snapshot.match("del-model-wrong-id", e.value.response)

        # assert that creating a model with an empty description works
        response = aws_client.apigateway.create_model(
            name="MySchema",
            restApiId=api_id,
            contentType="application/json",
            description="",
            schema=json.dumps({"title": "MySchema", "type": "object"}),
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 201

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_model(
                name="MySchema",
                restApiId=api_id,
                contentType="application/json",
                description="",
                schema=json.dumps({"title": "MySchema", "type": "object"}),
            )
        snapshot.match("create-model-already-exists", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_model(
                name="",
                restApiId=api_id,
                contentType="application/json",
                description="",
                schema=json.dumps({"title": "MySchema", "type": "object"}),
            )
        snapshot.match("create-model-empty-name", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_model(
                name="MyEmptySchema",
                restApiId=api_id,
                contentType="application/json",
                description="",
                schema="",
            )

        snapshot.match("create-model-empty-schema", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_model(
                name="MyEmptySchema",
                restApiId=api_id,
                contentType="application/json",
                description="",
            )

        snapshot.match("create-model-no-schema-json", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_model(
                name="MyEmptySchemaXml",
                restApiId=api_id,
                contentType="application/xml",
                description="",
            )

        snapshot.match("create-model-no-schema-xml", e.value.response)

    @markers.aws.validated
    def test_update_model(self, apigw_create_rest_api, snapshot, aws_client):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing update resource model"
        )
        api_id = response["id"]

        fake_api_id = "abcde0"
        updated_schema = json.dumps({"title": "Updated schema", "type": "object"})
        patch_operations = [
            {"op": "replace", "path": "/schema", "value": updated_schema},
            {"op": "replace", "path": "/description", "value": ""},
        ]

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_model(
                restApiId=fake_api_id,
                modelName="mySchema",
                patchOperations=patch_operations,
            )

        snapshot.match("update-model-wrong-id", e.value.response)

        response = aws_client.apigateway.create_model(
            name="MySchema",
            restApiId=api_id,
            contentType="application/json",
            description="",
            schema=json.dumps({"title": "MySchema", "type": "object"}),
        )
        snapshot.match("create-model", response)

        response = aws_client.apigateway.update_model(
            restApiId=api_id,
            modelName="MySchema",
            patchOperations=patch_operations,
        )
        snapshot.match("update-model", response)

        with pytest.raises(ClientError) as e:
            patch_operations = [{"op": "add", "path": "/wrong-path", "value": "not supported op"}]
            aws_client.apigateway.update_model(
                restApiId=api_id,
                modelName="MySchema",
                patchOperations=patch_operations,
            )

        snapshot.match("update-model-invalid-op", e.value.response)

        with pytest.raises(ClientError) as e:
            patch_operations = [
                {"op": "replace", "path": "/name", "value": "invalid"},
            ]
            aws_client.apigateway.update_model(
                restApiId=api_id,
                modelName="MySchema",
                patchOperations=patch_operations,
            )

        snapshot.match("update-model-invalid-path", e.value.response)

        with pytest.raises(ClientError) as e:
            patch_operations = [
                {"op": "replace", "path": "/schema", "value": ""},
            ]
            aws_client.apigateway.update_model(
                restApiId=api_id,
                modelName="MySchema",
                patchOperations=patch_operations,
            )
        snapshot.match("update-model-empty-schema", e.value.response)


class TestApiGatewayApiRequestValidator:
    @markers.aws.validated
    def test_validators_crud_no_api(self, snapshot, aws_client):
        # maybe move this test to a full lifecycle one
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_request_validator(
                restApiId="test-fake-rest-id",
                name="test-validator",
                validateRequestBody=True,
                validateRequestParameters=False,
            )
        snapshot.match("wrong-rest-api-id-create-validator", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.get_request_validators(restApiId="test-fake-rest-id")
        snapshot.match("wrong-rest-api-id-get-validators", e.value.response)

    @markers.aws.validated
    def test_request_validator_lifecycle(self, apigw_create_rest_api, snapshot, aws_client):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
            description="my api",
        )
        snapshot.match("create-rest-api", response)
        api_id = response["id"]

        # create a request validator for an API
        response = aws_client.apigateway.create_request_validator(
            restApiId=api_id, name=f"test-validator-{short_uid()}"
        )
        snapshot.match("create-request-validator", response)
        validator_id = response["id"]

        # get detail of a specific request validator corresponding to an API
        response = aws_client.apigateway.get_request_validator(
            restApiId=api_id, requestValidatorId=validator_id
        )
        snapshot.match("get-request-validator", response)

        # get list of all request validators in the API
        response = aws_client.apigateway.get_request_validators(restApiId=api_id)
        snapshot.match("get-request-validators", response)

        # update request validators with different set of patch operations
        patch_operations = [
            {"op": "replace", "path": "/validateRequestBody", "value": "true"},
        ]
        response = aws_client.apigateway.update_request_validator(
            restApiId=api_id, requestValidatorId=validator_id, patchOperations=patch_operations
        )
        snapshot.match("update-request-validator-with-value", response)

        patch_operations = [
            {"op": "replace", "path": "/validateRequestBody"},
        ]
        response = aws_client.apigateway.update_request_validator(
            restApiId=api_id, requestValidatorId=validator_id, patchOperations=patch_operations
        )
        snapshot.match("update-request-validator-without-value", response)

        response = aws_client.apigateway.get_request_validator(
            restApiId=api_id, requestValidatorId=validator_id
        )
        snapshot.match("get-request-validators-after-update-operation", response)

        # delete request validator
        response = aws_client.apigateway.delete_request_validator(
            restApiId=api_id, requestValidatorId=validator_id
        )
        snapshot.match("delete-request-validator", response)

        # try fetching details of the deleted request validator
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.get_request_validator(
                restApiId=api_id, requestValidatorId=validator_id
            )
        snapshot.match("get-deleted-request-validator", e.value.response)

        # check list of all request validators in the API
        response = aws_client.apigateway.get_request_validators(restApiId=api_id)
        snapshot.match("get-request-validators-after-delete", response)

    @markers.aws.validated
    def test_invalid_get_request_validator(self, apigw_create_rest_api, snapshot, aws_client):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
            description="my api",
        )
        api_id = response["id"]

        response = aws_client.apigateway.create_request_validator(
            restApiId=api_id, name=f"test-validator-{short_uid()}"
        )
        validator_id = response["id"]

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.get_request_validator(
                restApiId="api_id", requestValidatorId=validator_id
            )
        snapshot.match("get-request-validators-invalid-api-id", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.get_request_validator(
                restApiId=api_id, requestValidatorId="validator_id"
            )
        snapshot.match("get-request-validators-invalid-validator-id", e.value.response)

    @markers.aws.validated
    def test_invalid_get_request_validators(self, apigw_create_rest_api, snapshot, aws_client):
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.get_request_validators(restApiId="api_id")
        snapshot.match("get-invalid-request-validators", e.value.response)

    @markers.aws.validated
    def test_invalid_delete_request_validator(self, apigw_create_rest_api, snapshot, aws_client):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
            description="my api",
        )
        api_id = response["id"]

        response = aws_client.apigateway.create_request_validator(
            restApiId=api_id, name=f"test-validator-{short_uid()}"
        )
        validator_id = response["id"]

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.delete_request_validator(
                restApiId="api_id", requestValidatorId=validator_id
            )
        snapshot.match("delete-request-validator-invalid-api-id", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.delete_request_validator(
                restApiId=api_id, requestValidatorId="validator_id"
            )
        snapshot.match("delete-request-validator-invalid-validator-id", e.value.response)

    @markers.aws.validated
    def test_create_request_validator_invalid_api_id(
        self, apigw_create_rest_api, snapshot, aws_client
    ):
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_request_validator(
                restApiId="api_id", name=f"test-validator-{short_uid()}"
            )
        snapshot.match("invalid-create-request-validator", e.value.response)

    @markers.aws.validated
    def test_invalid_update_request_validator_operations(
        self, apigw_create_rest_api, snapshot, aws_client
    ):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
            description="my api",
        )
        snapshot.match("create-rest-api", response)
        api_id = response["id"]

        response = aws_client.apigateway.create_request_validator(
            restApiId=api_id, name=f"test-validator-{short_uid()}"
        )
        snapshot.match("create-request-validator", response)
        validator_id = response["id"]

        patch_operations = [
            {"op": "add", "path": "/validateRequestBody", "value": "true"},
        ]
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_request_validator(
                restApiId=api_id, requestValidatorId=validator_id, patchOperations=patch_operations
            )
        snapshot.match("update-request-validator-invalid-add-operation", e.value.response)

        patch_operations = [
            {"op": "remove", "path": "/validateRequestBody", "value": "true"},
        ]
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_request_validator(
                restApiId=api_id, requestValidatorId=validator_id, patchOperations=patch_operations
            )
        snapshot.match("update-request-validator-invalid-remove-operation", e.value.response)

        patch_operations = [
            {"op": "replace", "path": "/invalidPath", "value": "true"},
        ]
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_request_validator(
                restApiId=api_id, requestValidatorId=validator_id, patchOperations=patch_operations
            )
        snapshot.match("update-request-validator-invalid-path", e.value.response)

        patch_operations = [
            {"op": "replace", "path": "/name"},
        ]

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_request_validator(
                restApiId=api_id, requestValidatorId=validator_id, patchOperations=patch_operations
            )
        snapshot.match("update-request-validator-empty-name-value", e.value.response)


class TestApiGatewayApiDocumentationPart:
    @markers.aws.validated
    def test_doc_parts_crud_no_api(self, snapshot, aws_client):
        # maybe move this test to a full lifecycle one
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_documentation_part(
                restApiId="test-fake-rest-id",
                location={"type": "API"},
                properties='{\n\t"info": {\n\t\t"description" : "Your first API with Amazon API Gateway."\n\t}\n}',
            )
        snapshot.match("wrong-rest-api-id-create-doc-part", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.get_documentation_parts(restApiId="test-fake-rest-id")
        snapshot.match("wrong-rest-api-id-get-doc-parts", e.value.response)

    @markers.aws.validated
    def test_documentation_part_lifecycle(self, apigw_create_rest_api, snapshot, aws_client):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
            description="this is my api",
        )
        api_id = response["id"]

        # create documentation part
        response = aws_client.apigateway.create_documentation_part(
            restApiId=api_id,
            location={"type": "API"},
            properties='{ "description": "Sample API description" }',
        )
        snapshot.match("create-documentation-part", response)
        documentation_part_id = response["id"]

        # get detail of a specific documentation part corresponding to an API
        response = aws_client.apigateway.get_documentation_part(
            restApiId=api_id, documentationPartId=documentation_part_id
        )
        snapshot.match("get-documentation-part", response)

        # get list of all documentation parts in an API
        response = aws_client.apigateway.get_documentation_parts(
            restApiId=api_id,
        )
        snapshot.match("get-documentation-parts", response)

        # update documentation part
        patch_operations = [
            {
                "op": "replace",
                "path": "/properties",
                "value": '{ "description": "Updated Sample API description" }',
            },
        ]
        response = aws_client.apigateway.update_documentation_part(
            restApiId=api_id,
            documentationPartId=documentation_part_id,
            patchOperations=patch_operations,
        )
        snapshot.match("update-documentation-part", response)

        # get detail of documentation part after update
        response = aws_client.apigateway.get_documentation_part(
            restApiId=api_id, documentationPartId=documentation_part_id
        )
        snapshot.match("get-documentation-part-after-update", response)

        # delete documentation part
        response = aws_client.apigateway.delete_documentation_part(
            restApiId=api_id, documentationPartId=documentation_part_id
        )
        snapshot.match("delete_documentation_part", response)

    @markers.aws.validated
    def test_invalid_get_documentation_part(self, apigw_create_rest_api, snapshot, aws_client):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
            description="this is my api",
        )
        api_id = response["id"]

        response = aws_client.apigateway.create_documentation_part(
            restApiId=api_id,
            location={"type": "API"},
            properties='{ "description": "Sample API description" }',
        )
        documentation_part_id = response["id"]

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.get_documentation_part(
                restApiId="api_id", documentationPartId=documentation_part_id
            )
        snapshot.match("get-documentation-part-invalid-api-id", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.get_documentation_part(
                restApiId=api_id, documentationPartId="documentation_part_id"
            )
        snapshot.match("get-documentation-part-invalid-doc-id", e.value.response)

    @markers.aws.validated
    def test_invalid_get_documentation_parts(self, snapshot, aws_client):
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.get_documentation_parts(
                restApiId="api_id",
            )
        snapshot.match("get-inavlid-documentation-parts", e.value.response)

    @markers.aws.validated
    def test_invalid_update_documentation_part(self, apigw_create_rest_api, snapshot, aws_client):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
            description="this is my api",
        )
        api_id = response["id"]

        response = aws_client.apigateway.create_documentation_part(
            restApiId=api_id,
            location={"type": "API"},
            properties='{ "description": "Sample API description" }',
        )
        documentation_part_id = response["id"]

        patch_operations = [
            {
                "op": "replace",
                "path": "/properties",
                "value": '{ "description": "Updated Sample API description" }',
            },
        ]
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_documentation_part(
                restApiId="api_id",
                documentationPartId=documentation_part_id,
                patchOperations=patch_operations,
            )
        snapshot.match("update-documentation-part-invalid-api-id", e.value.response)

        patch_operations = [
            {
                "op": "add",
                "path": "/properties",
                "value": '{ "description": "Updated Sample API description" }',
            },
        ]
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_documentation_part(
                restApiId=api_id,
                documentationPartId=documentation_part_id,
                patchOperations=patch_operations,
            )
        snapshot.match("update-documentation-part-invalid-add-operation", e.value.response)

        patch_operations = [
            {
                "op": "replace",
                "path": "/invalidPath",
                "value": '{ "description": "Updated Sample API description" }',
            },
        ]
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_documentation_part(
                restApiId=api_id,
                documentationPartId=documentation_part_id,
                patchOperations=patch_operations,
            )
        snapshot.match("update-documentation-part-invalid-path", e.value.response)

    @markers.aws.validated
    def test_invalid_create_documentation_part_operations(
        self, apigw_create_rest_api, snapshot, aws_client
    ):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
            description="this is my api",
        )
        api_id = response["id"]

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_documentation_part(
                restApiId="api_id",
                location={"type": "API"},
                properties='{ "description": "Sample API description" }',
            )
        snapshot.match("create_documentation_part_invalid_api_id", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_documentation_part(
                restApiId=api_id,
                location={"type": "INVALID"},
                properties='{ "description": "Sample API description" }',
            )
        snapshot.match("create_documentation_part_invalid_location_type", e.value.response)

    @markers.aws.validated
    def test_invalid_delete_documentation_part(self, apigw_create_rest_api, snapshot, aws_client):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
            description="this is my api",
        )
        api_id = response["id"]

        response = aws_client.apigateway.create_documentation_part(
            restApiId=api_id,
            location={"type": "API"},
            properties='{ "description": "Sample API description" }',
        )
        documentation_part_id = response["id"]

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.delete_documentation_part(
                restApiId="api_id",
                documentationPartId=documentation_part_id,
            )
        snapshot.match("delete_documentation_part_wrong_api_id", e.value.response)

        response = aws_client.apigateway.delete_documentation_part(
            restApiId=api_id,
            documentationPartId=documentation_part_id,
        )
        snapshot.match("delete_documentation_part", response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.delete_documentation_part(
                restApiId=api_id,
                documentationPartId=documentation_part_id,
            )
        snapshot.match("delete_already_deleted_documentation_part", e.value.response)

    @markers.aws.validated
    def test_import_documentation_parts(self, aws_client, import_apigw, snapshot):
        # snapshot array "ids"
        snapshot.add_transformer(snapshot.transform.jsonpath("$..ids[*]", "id"))
        # create api with documentation imports
        spec_file = load_file(OAS_30_DOCUMENTATION_PARTS)
        response, root_id = import_apigw(body=spec_file, failOnWarnings=True)
        rest_api_id = response["id"]

        # get documentation parts to make sure import worked
        response = aws_client.apigateway.get_documentation_parts(restApiId=rest_api_id)
        snapshot.match("create-import-documentations_parts", response["items"])

        # delete documentation parts
        for doc_part_item in response["items"]:
            response = aws_client.apigateway.delete_documentation_part(
                restApiId=rest_api_id,
                documentationPartId=doc_part_item["id"],
            )
            assert response["ResponseMetadata"]["HTTPStatusCode"] == 202

        # make sure delete parts are gone
        response = aws_client.apigateway.get_documentation_parts(restApiId=rest_api_id)
        assert len(response["items"]) == 0

        # import documentation parts using import documentation parts api
        response = aws_client.apigateway.import_documentation_parts(
            restApiId=rest_api_id,
            mode=PutMode.overwrite,
            body=spec_file,
        )
        snapshot.match("import-documentation-parts", response)


class TestApiGatewayGatewayResponse:
    @markers.aws.validated
    def test_gateway_response_crud(self, aws_client, apigw_create_rest_api, snapshot):
        snapshot.add_transformer(
            SortingTransformer(key="items", sorting_fn=itemgetter("responseType"))
        )
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
            description="APIGW test GatewayResponse",
        )
        api_id = response["id"]

        response = aws_client.apigateway.get_gateway_response(
            restApiId=api_id, responseType="MISSING_AUTHENTICATION_TOKEN"
        )
        snapshot.match("get-gateway-response-default", response)

        # example from https://docs.aws.amazon.com/apigateway/latest/api/API_PutGatewayResponse.html
        response = aws_client.apigateway.put_gateway_response(
            restApiId=api_id,
            responseType="MISSING_AUTHENTICATION_TOKEN",
            statusCode="404",
            responseParameters={
                "gatewayresponse.header.x-request-path": "method.request.path.petId",
                "gatewayresponse.header.Access-Control-Allow-Origin": "'a.b.c'",
                "gatewayresponse.header.x-request-query": "method.request.querystring.q",
                "gatewayresponse.header.x-request-header": "method.request.header.Accept",
            },
            responseTemplates={
                "application/json": '{\n     "message": $context.error.messageString,\n     "type":  "$context.error.responseType",\n     "stage":  "$context.stage",\n     "resourcePath":  "$context.resourcePath",\n     "stageVariables.a":  "$stageVariables.a",\n     "statusCode": "\'404\'"\n}'
            },
        )
        snapshot.match("put-gateway-response", response)

        response = aws_client.apigateway.get_gateway_responses(restApiId=api_id)
        snapshot.match("get-gateway-responses", response)

        response = aws_client.apigateway.get_gateway_response(
            restApiId=api_id, responseType="MISSING_AUTHENTICATION_TOKEN"
        )
        snapshot.match("get-gateway-response", response)

        response = aws_client.apigateway.delete_gateway_response(
            restApiId=api_id, responseType="MISSING_AUTHENTICATION_TOKEN"
        )
        snapshot.match("delete-gateway-response", response)

        response = aws_client.apigateway.get_gateway_response(
            restApiId=api_id, responseType="MISSING_AUTHENTICATION_TOKEN"
        )

        snapshot.match("get-deleted-gw-response", response)

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=not is_next_gen_api(), reason="Behaviour only present in next gen api"
    )
    def test_gateway_response_put(self, aws_client, apigw_create_rest_api, snapshot):
        snapshot.add_transformer(
            SortingTransformer(key="items", sorting_fn=itemgetter("responseType"))
        )
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
            description="APIGW test GatewayResponse",
        )
        api_id = response["id"]

        # Put all values
        response = aws_client.apigateway.put_gateway_response(
            restApiId=api_id,
            responseType="MISSING_AUTHENTICATION_TOKEN",
            statusCode="404",
            responseParameters={
                "gatewayresponse.header.x-request-path": "method.request.path.petId",
                "gatewayresponse.header.Access-Control-Allow-Origin": "'a.b.c'",
                "gatewayresponse.header.x-request-query": "method.request.querystring.q",
                "gatewayresponse.header.x-request-header": "method.request.header.Accept",
            },
            responseTemplates={
                "application/json": '{\n     "message": $context.error.messageString,\n     "type":  "$context.error.responseType",\n     "stage":  "$context.stage",\n     "resourcePath":  "$context.resourcePath",\n     "stageVariables.a":  "$stageVariables.a",\n     "statusCode": "\'404\'"\n}'
            },
        )
        snapshot.match("put-gateway-response-all-value", response)

        # Put only status code
        response = aws_client.apigateway.put_gateway_response(
            restApiId=api_id,
            responseType="MISSING_AUTHENTICATION_TOKEN",
            statusCode="404",
        )
        snapshot.match("put-gateway-response-status-only", response)

        # Put only response parameters
        response = aws_client.apigateway.put_gateway_response(
            restApiId=api_id,
            responseType="MISSING_AUTHENTICATION_TOKEN",
            responseParameters={
                "gatewayresponse.header.x-request-header": "method.request.header.Accept"
            },
        )
        snapshot.match("put-gateway-response-response-parameters-only", response)

        # Put only response templates
        response = aws_client.apigateway.put_gateway_response(
            restApiId=api_id,
            responseType="MISSING_AUTHENTICATION_TOKEN",
            responseTemplates={
                "application/json": '{\n     "message": $context.error.messageString,\n     "type":  "$context.error.responseType",\n     "stage":  "$context.stage",\n     "resourcePath":  "$context.resourcePath",\n     "stageVariables.a":  "$stageVariables.a",\n     "statusCode": "\'404\'"\n}'
            },
        )
        snapshot.match("put-gateway-response-response-templates-only", response)

        # Put default response
        response = aws_client.apigateway.put_gateway_response(
            restApiId=api_id,
            responseType="DEFAULT_5XX",
            statusCode="599",
            responseParameters={
                "gatewayresponse.header.x-request-header": "method.request.header.Accept"
            },
            responseTemplates={
                "application/json": '{\n     "message": $context.error.messageString,\n     "type":  "$context.error.responseType",\n     "stage":  "$context.stage",\n     "resourcePath":  "$context.resourcePath",\n     "stageVariables.a":  "$stageVariables.a",\n     "statusCode": "\'404\'"\n}'
            },
        )
        snapshot.match("put-gateway-response-default-5xx", response)

        # Put 500 after default set
        response = aws_client.apigateway.put_gateway_response(
            restApiId=api_id,
            responseType="AUTHORIZER_FAILURE",
            responseParameters={"gatewayresponse.header.foo": "'bar'"},
        )
        snapshot.match("put-gateway-response-default-ignored", response)

        # Get all, default should affect all 500
        response = aws_client.apigateway.get_gateway_responses(restApiId=api_id)
        snapshot.match("get-gateway-responses", response)

    @markers.aws.validated
    def test_gateway_response_validation(self, aws_client_factory, apigw_create_rest_api, snapshot):
        apigw_client = aws_client_factory(config=Config(parameter_validation=False)).apigateway
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
            description="APIGW test GatewayResponse",
        )
        api_id = response["id"]
        fake_id = f"apiid123{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(fake_id, "fake-api-id"))

        with pytest.raises(ClientError) as e:
            apigw_client.get_gateway_responses(restApiId=fake_id)
        snapshot.match("get-gateway-responses-no-api", e.value.response)

        with pytest.raises(ClientError) as e:
            apigw_client.get_gateway_response(restApiId=fake_id, responseType="DEFAULT_4XX")
        snapshot.match("get-gateway-response-no-api", e.value.response)

        with pytest.raises(ClientError) as e:
            apigw_client.delete_gateway_response(restApiId=fake_id, responseType="DEFAULT_4XX")
        snapshot.match("delete-gateway-response-no-api", e.value.response)

        with pytest.raises(ClientError) as e:
            apigw_client.update_gateway_response(
                restApiId=fake_id, responseType="DEFAULT_4XX", patchOperations=[]
            )
        snapshot.match("update-gateway-response-no-api", e.value.response)

        with pytest.raises(ClientError) as e:
            apigw_client.delete_gateway_response(restApiId=api_id, responseType="DEFAULT_4XX")
        snapshot.match("delete-gateway-response-not-set", e.value.response)

        with pytest.raises(ClientError) as e:
            apigw_client.get_gateway_response(restApiId=api_id, responseType="FAKE_RESPONSE_TYPE")
        snapshot.match("get-gateway-response-wrong-response-type", e.value.response)

        with pytest.raises(ClientError) as e:
            apigw_client.delete_gateway_response(
                restApiId=api_id, responseType="FAKE_RESPONSE_TYPE"
            )
        snapshot.match("delete-gateway-response-wrong-response-type", e.value.response)

        with pytest.raises(ClientError) as e:
            apigw_client.update_gateway_response(
                restApiId=api_id, responseType="FAKE_RESPONSE_TYPE", patchOperations=[]
            )
        snapshot.match("update-gateway-response-wrong-response-type", e.value.response)

        with pytest.raises(ClientError) as e:
            apigw_client.put_gateway_response(
                restApiId=api_id,
                responseType="FAKE_RESPONSE_TYPE",
                statusCode="404",
                responseParameters={},
                responseTemplates={},
            )
        snapshot.match("put-gateway-response-wrong-response-type", e.value.response)

    @markers.aws.validated
    def test_update_gateway_response(
        self, aws_client, aws_client_factory, apigw_create_rest_api, snapshot
    ):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
            description="APIGW test GatewayResponse",
        )
        api_id = response["id"]
        apigw_client = aws_client_factory(config=Config(parameter_validation=False)).apigateway

        response = apigw_client.update_gateway_response(
            restApiId=api_id,
            responseType="DEFAULT_4XX",
            patchOperations=[{"op": "replace", "path": "/statusCode", "value": "444"}],
        )
        snapshot.match("update-gateway-response-not-set", response)

        response = apigw_client.get_gateway_response(restApiId=api_id, responseType="DEFAULT_4XX")
        snapshot.match("default-get-gateway-response", response)

        response = apigw_client.put_gateway_response(
            restApiId=api_id,
            responseType="DEFAULT_4XX",
            statusCode="404",
            responseParameters={
                "gatewayresponse.header.x-request-path": "method.request.path.petId",
                "gatewayresponse.header.Access-Control-Allow-Origin": "'a.b.c'",
                "gatewayresponse.header.x-request-query": "method.request.querystring.q",
                "gatewayresponse.header.x-request-header": "method.request.header.Accept",
            },
            responseTemplates={
                "application/json": json.dumps(
                    {"application/json": '{"message":$context.error.messageString}'}
                )
            },
        )
        snapshot.match("put-gateway-response", response)

        response = apigw_client.update_gateway_response(
            restApiId=api_id,
            responseType="DEFAULT_4XX",
            patchOperations=[
                {"op": "replace", "path": "/statusCode", "value": "444"},
                {
                    "op": "replace",
                    "path": "/responseParameters/gatewayresponse.header.Access-Control-Allow-Origin",
                    "value": "'example.com'",
                },
                {
                    "op": "add",
                    "path": "/responseTemplates/application~1xml",
                    "value": "<gatewayResponse><message>$context.error.messageString</message><type>$context.error.responseType</type></gatewayResponse>",
                },
            ],
        )
        snapshot.match("update-gateway-response", response)

        response = apigw_client.get_gateway_response(restApiId=api_id, responseType="DEFAULT_4XX")
        snapshot.match("get-gateway-response", response)

        with pytest.raises(ClientError) as e:
            apigw_client.update_gateway_response(
                restApiId=api_id,
                responseType="DEFAULT_4XX",
                patchOperations=[{"op": "add", "path": "/statusCode", "value": "444"}],
            )

        snapshot.match("update-gateway-add-status-code", e.value.response)

        with pytest.raises(ClientError) as e:
            apigw_client.update_gateway_response(
                restApiId=api_id,
                responseType="DEFAULT_4XX",
                patchOperations=[
                    {
                        "op": "remove",
                        "path": "/statusCode",
                    }
                ],
            )

        snapshot.match("update-gateway-remove-status-code", e.value.response)

        with pytest.raises(ClientError) as e:
            apigw_client.update_gateway_response(
                restApiId=api_id,
                responseType="DEFAULT_5XX",
                patchOperations=[
                    {
                        "op": "replace",
                        "path": "/responseParameters/gatewayresponse.header.Access-Control-Allow-Origin",
                        "value": "'example.com'",
                    }
                ],
            )

        snapshot.match("update-gateway-replace-invalid-parameter", e.value.response)

        with pytest.raises(ClientError) as e:
            apigw_client.update_gateway_response(
                restApiId=api_id,
                responseType="DEFAULT_4XX",
                patchOperations=[{"op": "add", "value": "'example.com'"}],
            )

        snapshot.match("update-gateway-no-path", e.value.response)

        with pytest.raises(ClientError) as e:
            apigw_client.update_gateway_response(
                restApiId=api_id,
                responseType="DEFAULT_4XX",
                patchOperations=[
                    {"op": "wrong-op", "path": "/statusCode", "value": "'example.com'"}
                ],
            )

        snapshot.match("update-gateway-wrong-op", e.value.response)

        with pytest.raises(ClientError) as e:
            apigw_client.update_gateway_response(
                restApiId=api_id,
                responseType="DEFAULT_4XX",
                patchOperations=[{"op": "add", "path": "/wrongPath", "value": "'example.com'"}],
            )

        snapshot.match("update-gateway-wrong-path", e.value.response)

        for index, path in enumerate(
            (
                "/responseTemplates/application~1xml",
                "/responseParameters/gatewayresponse.header.Access-Control-Allow-Origin",
            )
        ):
            with pytest.raises(ClientError) as e:
                apigw_client.update_gateway_response(
                    restApiId=api_id,
                    responseType="DEFAULT_4XX",
                    patchOperations=[{"op": "replace", "path": path, "value": None}],
                )

            snapshot.match(
                f"update-gateway-replace-invalid-parameter-{index}-none", e.value.response
            )


class TestApigatewayTestInvoke:
    @markers.aws.validated
    def test_invoke_test_method(self, create_rest_apigw, snapshot, aws_client):
        snapshot.add_transformer(
            KeyValueBasedTransformer(
                lambda k, v: str(v) if k == "latency" else None, "latency", replace_reference=False
            )
        )
        snapshot.add_transformer(
            snapshot.transform.key_value("log", "log", reference_replacement=False)
        )

        api_id, _, root = create_rest_apigw(name="aws lambda api")

        # Create the /pets resource
        root_resource_id, _ = create_rest_resource(
            aws_client.apigateway, restApiId=api_id, parentId=root, pathPart="pets"
        )
        # Create the /pets/{petId} resource
        resource_id, _ = create_rest_resource(
            aws_client.apigateway, restApiId=api_id, parentId=root_resource_id, pathPart="{petId}"
        )
        # Create the GET method for /pets/{petId}
        create_rest_resource_method(
            aws_client.apigateway,
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            authorizationType="NONE",
            requestParameters={
                "method.request.path.petId": True,
            },
        )
        # Create the POST method for /pets/{petId}
        create_rest_resource_method(
            aws_client.apigateway,
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            authorizationType="NONE",
            requestParameters={
                "method.request.path.petId": True,
            },
        )
        # Create the response for method GET /pets/{petId}
        create_rest_api_method_response(
            aws_client.apigateway,
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            statusCode="200",
        )
        # Create the response for method POST /pets/{petId}
        create_rest_api_method_response(
            aws_client.apigateway,
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            statusCode="200",
        )
        # Create the integration to connect GET /pets/{petId} to a backend
        create_rest_api_integration(
            aws_client.apigateway,
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            type="MOCK",
            integrationHttpMethod="GET",
            requestParameters={
                "integration.request.path.id": "method.request.path.petId",
            },
            requestTemplates={"application/json": json.dumps({"statusCode": 200})},
        )
        # Create the integration to connect POST /pets/{petId} to a backend
        create_rest_api_integration(
            aws_client.apigateway,
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            type="MOCK",
            integrationHttpMethod="POST",
            requestParameters={
                "integration.request.path.id": "method.request.path.petId",
            },
            requestTemplates={"application/json": json.dumps({"statusCode": 200})},
        )
        # Create the 200 integration response for GET /pets/{petId}
        create_rest_api_integration_response(
            aws_client.apigateway,
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            statusCode="200",
            responseTemplates={"application/json": json.dumps({"petId": "$input.params('petId')"})},
        )
        # Create the 200 integration response for POST /pets/{petId}
        create_rest_api_integration_response(
            aws_client.apigateway,
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            statusCode="200",
            responseTemplates={"application/json": json.dumps({"petId": "$input.params('petId')"})},
        )

        def invoke_method(api_id, resource_id, path_with_query_string, method, body=""):
            res = aws_client.apigateway.test_invoke_method(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=method,
                pathWithQueryString=path_with_query_string,
                body=body,
            )
            assert 200 == res.get("status")
            return res

        response = retry(
            invoke_method,
            retries=10,
            sleep=5,
            api_id=api_id,
            resource_id=resource_id,
            path_with_query_string="/pets/123",
            method="GET",
        )
        assert "HTTP Method: GET, Resource Path: /pets/123" in response["log"]
        snapshot.match("test-invoke-method-get", response)

        response = retry(
            invoke_method,
            retries=10,
            sleep=5,
            api_id=api_id,
            resource_id=resource_id,
            path_with_query_string="/pets/123?foo=bar",
            method="GET",
        )
        snapshot.match("test-invoke-method-get-with-qs", response)

        response = retry(
            invoke_method,
            retries=10,
            sleep=5,
            api_id=api_id,
            resource_id=resource_id,
            path_with_query_string="/pets/123",
            method="POST",
            body=json.dumps({"foo": "bar"}),
        )
        assert "HTTP Method: POST, Resource Path: /pets/123" in response["log"]
        snapshot.match("test-invoke-method-post-with-body", response)

        # assert resource and rest api doesn't exist
        with pytest.raises(ClientError) as ex:
            aws_client.apigateway.test_invoke_method(
                restApiId=api_id,
                resourceId="invalid_res",
                httpMethod="POST",
                pathWithQueryString="/pets/123",
                body=json.dumps({"foo": "bar"}),
            )
        snapshot.match("resource-id-not-found", ex.value.response)
        assert ex.value.response["Error"]["Code"] == "NotFoundException"

        with pytest.raises(ClientError) as ex:
            aws_client.apigateway.test_invoke_method(
                restApiId=api_id,
                resourceId="invalid_res",
                httpMethod="POST",
                pathWithQueryString="/pets/123",
                body=json.dumps({"foo": "bar"}),
            )
        snapshot.match("rest-api-not-found", ex.value.response)
        assert ex.value.response["Error"]["Code"] == "NotFoundException"


class TestApigatewayIntegration:
    @markers.aws.validated
    def test_put_integration_wrong_type(
        self, aws_client, apigw_create_rest_api, aws_client_factory, snapshot
    ):
        apigw_client = aws_client_factory(config=Config(parameter_validation=False)).apigateway
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}",
            description="APIGW test PutIntegration Types",
        )
        api_id = response["id"]
        root_resource_id = response["rootResourceId"]

        with pytest.raises(ClientError) as e:
            apigw_client.put_integration(
                restApiId=api_id, resourceId=root_resource_id, httpMethod="GET", type="HTTPS_PROXY"
            )
        snapshot.match("put-integration-wrong-type", e.value.response)

    @markers.aws.validated
    def test_put_integration_response_validation(
        self, aws_client, apigw_create_rest_api, aws_client_factory, snapshot
    ):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing PutIntegrationResponse method exc"
        )
        api_id = response["id"]
        root_id = response["rootResourceId"]

        aws_client.apigateway.put_method(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="POST",
            authorizationType="NONE",
        )

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.put_integration(
                restApiId=api_id,
                resourceId=root_id,
                httpMethod="GET",
                integrationHttpMethod="GET",
                type="MOCK",
                requestTemplates={"application/json": '{"statusCode": 200}'},
            )
        snapshot.match("put-integration-wrong-method", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.put_integration(
                restApiId=api_id,
                resourceId="badresource",
                httpMethod="GET",
                integrationHttpMethod="GET",
                type="MOCK",
                requestTemplates={"application/json": '{"statusCode": 200}'},
            )
        snapshot.match("put-integration-wrong-resource", e.value.response)

        aws_client.apigateway.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="POST",
            integrationHttpMethod="GET",
            type="MOCK",
            requestTemplates={"application/json": '{"statusCode": 200}'},
        )

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.put_integration_response(
                restApiId=api_id,
                resourceId=root_id,
                # put the integrationHttpMethod instead of the `httpMethod` should result in an error
                httpMethod="GET",
                statusCode="200",
                selectionPattern="",
                responseTemplates={"application/json": json.dumps({})},
            )

        snapshot.match("put-integration-response-wrong-method", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.put_integration_response(
                restApiId=api_id,
                resourceId="badresource",
                # put the integrationHttpMethod instead of the `httpMethod` should result in an error
                httpMethod="GET",
                statusCode="200",
                selectionPattern="",
                responseTemplates={"application/json": json.dumps({})},
            )

        snapshot.match("put-integration-response-wrong-resource", e.value.response)

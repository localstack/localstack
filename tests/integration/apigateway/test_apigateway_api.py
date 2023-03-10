import logging
import os
import time
from operator import itemgetter

import pytest
from botocore.exceptions import ClientError

from localstack.services.apigateway.helpers import TAG_KEY_CUSTOM_ID
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.snapshots.transformer import SortingTransformer
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)

# parent directory of this file
PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPENAPI_SPEC_PULUMI_JSON = os.path.join(PARENT_DIR, "files", "openapi.spec.pulumi.json")
OPENAPI_SPEC_TF_JSON = os.path.join(PARENT_DIR, "files", "openapi.spec.tf.json")


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


@pytest.mark.aws_validated
def test_import_rest_api(import_apigw, snapshot):
    snapshot.add_transformer(snapshot.transform.apigateway_api())

    spec_file = load_file(OPENAPI_SPEC_PULUMI_JSON)
    response, root_id = import_apigw(body=spec_file, failOnWarnings=True)

    snapshot.match("import_rest_api", response)


@pytest.mark.aws_validated
@pytest.mark.skip_snapshot_verify(
    paths=[
        "$.resources.items..resourceMethods",
        "$.method-response-get.responseModels",
        "$.method-response-get.responseParameters",
        "$.integration-get.cacheNamespace",
        "$.integration-get.contentHandling",
        "$.integration-get.httpMethod",
        "$.integration-get.integrationResponses",
        "$.integration-get.passthroughBehavior",
        "$.integration-get.requestParameters",
        "$.integration-get.requestTemplates",
        "$.integration-get.timeoutInMillis",
        "$.integration-get.type",
        "$.integration-get.uri",
        "$.integration-response-get.responseParameters",
        "$.integration-response-get.responseTemplates",
        "$.method-response-options.responseModels",
        "$.method-response-options.responseParameters",
        "$.integration-options.cacheNamespace",
        "$.integration-options.passthroughBehavior",
        "$.integration-options.timeoutInMillis",
        "$.integration-options.type",
        "$.integration-options.httpMethod",
        "$.integration-options.integrationResponses",
        "$.integration-options.requestParameters",
        "$.integration-response-options.responseParameters",
        "$.integration-response-options.responseTemplates",
    ]
)
def test_import_tf_rest_api(apigateway_client, import_apigw, snapshot):
    snapshot.add_transformer(snapshot.transform.apigateway_api())

    spec_file = load_file(OPENAPI_SPEC_TF_JSON)
    response, root_id = import_apigw(body=spec_file, failOnWarnings=True)

    snapshot.match("import_tf_rest_api", response)
    rest_api_id = response["id"]

    response = apigateway_client.get_resources(restApiId=rest_api_id)
    snapshot.match("resources", response)

    for http_method in response["items"][0]["resourceMethods"]:
        snapshot_http_key = http_method.lower()
        response = apigateway_client.get_method_response(
            restApiId=rest_api_id,
            resourceId=root_id,
            httpMethod=http_method,
            statusCode="200",
        )
        snapshot.match(f"method-response-{snapshot_http_key}", response)

        response = apigateway_client.get_integration(
            restApiId=rest_api_id,
            resourceId=root_id,
            httpMethod=http_method,
        )
        snapshot.match(f"integration-{snapshot_http_key}", response)

        response = apigateway_client.get_integration_response(
            restApiId=rest_api_id,
            resourceId=root_id,
            httpMethod=http_method,
            statusCode="200",
        )
        snapshot.match(f"integration-response-{snapshot_http_key}", response)


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
    @pytest.mark.xfail(reason="rest apis are case insensitive for now because of custom id tags")
    def test_get_api_case_insensitive(self, apigateway_client, apigw_create_rest_api, snapshot):
        api_name1 = f"test-case-sensitive-apis-{short_uid()}"

        response = apigw_create_rest_api(name=api_name1, description="lower case api")
        snapshot.match("create-rest-api", response)
        api_id = response["id"]

        snapshot.add_transformer(snapshot.transform.regex(api_id.upper(), "<upper-id>"))

        with pytest.raises(ClientError) as e:
            apigateway_client.get_rest_api(restApiId=api_id.upper())
        snapshot.match("get-api-upper-case", e.value.response)

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

    @pytest.mark.aws_validated
    def test_resource_lifecycle(self, apigateway_client, apigw_create_rest_api, snapshot):
        snapshot.add_transformer(SortingTransformer("items", lambda x: x["path"]))
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource lifecycle"
        )
        api_id = response["id"]

        root_rest_api_resource = apigateway_client.get_resources(restApiId=api_id)
        snapshot.match("rest-api-root-resource", root_rest_api_resource)

        root_id = root_rest_api_resource["items"][0]["id"]

        resource_response = apigateway_client.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="pets"
        )
        resource_id = resource_response["id"]

        snapshot.match("create-resource", resource_response)

        rest_api_resources = apigateway_client.get_resources(restApiId=api_id)
        snapshot.match("rest-api-resources-after-create", rest_api_resources)

        # create subresource
        subresource_response = apigateway_client.create_resource(
            restApiId=api_id, parentId=resource_id, pathPart="subpets"
        )
        snapshot.match("create-subresource", subresource_response)

        rest_api_resources = apigateway_client.get_resources(restApiId=api_id)
        snapshot.match("rest-api-resources-after-create-sub", rest_api_resources)

        # only supported path are /parentId and /pathPart with operation `replace`
        patch_operations = [
            {"op": "replace", "path": "/pathPart", "value": "dogs"},
        ]

        update_response = apigateway_client.update_resource(
            restApiId=api_id, resourceId=resource_id, patchOperations=patch_operations
        )
        snapshot.match("update-path-part", update_response)

        get_resource_response = apigateway_client.get_resource(
            restApiId=api_id, resourceId=resource_id
        )
        snapshot.match("get-resp-after-update-path-part", get_resource_response)

        delete_resource_response = apigateway_client.delete_resource(
            restApiId=api_id, resourceId=resource_id
        )
        snapshot.match("del-resource", delete_resource_response)

        rest_api_resources = apigateway_client.get_resources(restApiId=api_id)
        snapshot.match("rest-api-resources-after-delete", rest_api_resources)

    @pytest.mark.aws_validated
    def test_update_resource_behaviour(self, apigateway_client, apigw_create_rest_api, snapshot):
        snapshot.add_transformer(SortingTransformer("items", lambda x: x["path"]))
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource behaviour"
        )
        api_id = response["id"]

        root_rest_api_resource = apigateway_client.get_resources(restApiId=api_id)
        root_id = root_rest_api_resource["items"][0]["id"]

        resource_response = apigateway_client.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="pets"
        )
        resource_id = resource_response["id"]

        # try updating a non-existent resource
        patch_operations = [
            {"op": "replace", "path": "/pathPart", "value": "dogs"},
        ]
        with pytest.raises(ClientError) as e:
            apigateway_client.update_resource(
                restApiId=api_id, resourceId="fake-resource", patchOperations=patch_operations
            )
        snapshot.match("nonexistent-resource", e.value.response)

        # only supported path are /parentId and /pathPart with operation `replace`
        patch_operations = [
            {"op": "replace", "path": "/invalid", "value": "dogs"},
        ]
        with pytest.raises(ClientError) as e:
            apigateway_client.update_resource(
                restApiId=api_id, resourceId=resource_id, patchOperations=patch_operations
            )
        snapshot.match("invalid-path-part", e.value.response)

        # try updating a resource with a non-existent parentId
        patch_operations = [
            {"op": "replace", "path": "/parentId", "value": "fake-parent-id"},
        ]
        with pytest.raises(ClientError) as e:
            apigateway_client.update_resource(
                restApiId=api_id, resourceId=resource_id, patchOperations=patch_operations
            )
        snapshot.match("invalid-parent-id", e.value.response)

        # create subresource `subpets` under `/pets`
        subresource_response = apigateway_client.create_resource(
            restApiId=api_id, parentId=resource_id, pathPart="subpets"
        )
        snapshot.match("create-subresource", subresource_response)
        subresource_id = subresource_response["id"]

        # create subresource `pets` under `/pets/subpets`
        subresource_child_response = apigateway_client.create_resource(
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
            apigateway_client.update_resource(
                restApiId=api_id, resourceId=subresource_child_id, patchOperations=patch_operations
            )
        snapshot.match("existing-future-sibling-path", e.value.response)
        # clean up that for the rest of the test
        apigateway_client.delete_resource(restApiId=api_id, resourceId=subresource_child_id)

        # try setting the parent id of the pets to its own subresource?
        patch_operations = [
            {"op": "replace", "path": "/parentId", "value": subresource_id},
        ]
        with pytest.raises(ClientError) as e:
            apigateway_client.update_resource(
                restApiId=api_id, resourceId=resource_id, patchOperations=patch_operations
            )
        snapshot.match("update-parent-id-to-subresource-id", e.value.response)

        # move the subresource to be under the root id
        # we had root -> resource -> subresource - /pets/subpets
        # we now have root -> resource and root -> subresource -> /pets and /subpets
        patch_operations = [
            {"op": "replace", "path": "/parentId", "value": root_id},
        ]
        update_parent_id_to_root = apigateway_client.update_resource(
            restApiId=api_id, resourceId=subresource_id, patchOperations=patch_operations
        )

        snapshot.match("update-parent-id-to-root-id", update_parent_id_to_root)

        # try changing `/subpets` to `/pets`, but it already exists under  `root`
        patch_operations = [
            {"op": "replace", "path": "/pathPart", "value": "pets"},
        ]
        with pytest.raises(ClientError) as e:
            apigateway_client.update_resource(
                restApiId=api_id, resourceId=subresource_id, patchOperations=patch_operations
            )
        snapshot.match("update-path-already-exists", e.value.response)

        # test deleting the resource `/pets`, its old child (`/subpets`) should not be deleted
        apigateway_client.delete_resource(restApiId=api_id, resourceId=resource_id)
        api_resources = apigateway_client.get_resources(restApiId=api_id)
        snapshot.match("resources-after-deletion", api_resources)

        # try using a non-supported operation `remove`
        patch_operations = [
            {"op": "remove", "path": "/pathPart"},
        ]
        with pytest.raises(ClientError) as e:
            apigateway_client.update_resource(
                restApiId=api_id, resourceId=subresource_id, patchOperations=patch_operations
            )
        snapshot.match("remove-unsupported", e.value.response)

        # try using a non-supported operation `add`
        patch_operations = [
            {"op": "add", "path": "/pathPart", "value": "added-pets"},
        ]
        with pytest.raises(ClientError) as e:
            apigateway_client.update_resource(
                restApiId=api_id, resourceId=subresource_id, patchOperations=patch_operations
            )
        snapshot.match("add-unsupported", e.value.response)

    @pytest.mark.aws_validated
    def test_delete_resource(self, apigateway_client, apigw_create_rest_api, snapshot):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource behaviour"
        )
        api_id = response["id"]

        root_rest_api_resource = apigateway_client.get_resources(restApiId=api_id)
        root_id = root_rest_api_resource["items"][0]["id"]

        resource_response = apigateway_client.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="pets"
        )
        resource_id = resource_response["id"]

        # create subresource
        subresource_response = apigateway_client.create_resource(
            restApiId=api_id, parentId=resource_id, pathPart="subpets"
        )
        subresource_id = subresource_response["id"]

        delete_resource_response = apigateway_client.delete_resource(
            restApiId=api_id, resourceId=resource_id
        )
        snapshot.match("delete-resource", delete_resource_response)

        api_resources = apigateway_client.get_resources(restApiId=api_id)
        snapshot.match("get-resources", api_resources)

        # try deleting already deleted subresource
        with pytest.raises(ClientError) as e:
            apigateway_client.delete_resource(restApiId=api_id, resourceId=subresource_id)
        snapshot.match("delete-subresource", e.value.response)

    @pytest.mark.aws_validated
    def test_create_resource_parent_invalid(
        self, apigateway_client, apigw_create_rest_api, snapshot
    ):
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource parent"
        )
        api_id = response["id"]

        # create subresource with wrong parent
        with pytest.raises(ClientError) as e:
            apigateway_client.create_resource(
                restApiId=api_id, parentId="fake-resource-id", pathPart="subpets"
            )
        snapshot.match("wrong-resource-parent-id", e.value.response)

    @pytest.mark.aws_validated
    def test_create_proxy_resource(self, apigateway_client, apigw_create_rest_api, snapshot):
        # test following docs
        # https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-settings-method-request.html#api-gateway-proxy-resource
        snapshot.add_transformer(SortingTransformer("items", lambda x: x["path"]))
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource proxy"
        )
        api_id = response["id"]
        root_rest_api_resource = apigateway_client.get_resources(restApiId=api_id)
        root_id = root_rest_api_resource["items"][0]["id"]

        # creating `/{proxy+}` resource
        base_proxy_response = apigateway_client.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="{proxy+}"
        )
        snapshot.match("create-base-proxy-resource", base_proxy_response)

        # creating `/parent` resource, sibling to `/{proxy+}`
        proxy_sibling_response = apigateway_client.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="parent"
        )
        proxy_sibling_id = proxy_sibling_response["id"]
        snapshot.match("create-proxy-sibling-resource", proxy_sibling_id)

        # creating `/parent/{proxy+}` resource
        proxy_sibling_proxy_child_response = apigateway_client.create_resource(
            restApiId=api_id, parentId=proxy_sibling_id, pathPart="{proxy+}"
        )
        proxy_child_id = proxy_sibling_proxy_child_response["id"]
        snapshot.match(
            "create-proxy-sibling-proxy-child-resource", proxy_sibling_proxy_child_response
        )

        # creating `/parent/child` resource, sibling to `/parent/{proxy+}`
        proxy_sibling_static_child_response = apigateway_client.create_resource(
            restApiId=api_id, parentId=proxy_sibling_id, pathPart="child"
        )
        dynamic_child_id = proxy_sibling_static_child_response["id"]
        snapshot.match(
            "create-proxy-sibling-static-child-resource", proxy_sibling_static_child_response
        )

        # creating `/parent/child/{proxy+}` resource
        dynamic_child_proxy_child_response = apigateway_client.create_resource(
            restApiId=api_id, parentId=dynamic_child_id, pathPart="{proxy+}"
        )
        snapshot.match("create-static-child-proxy-resource", dynamic_child_proxy_child_response)

        # list all resources
        result_api_resource = apigateway_client.get_resources(restApiId=api_id)
        snapshot.match("all-resources", result_api_resource)

        # to allow nested route testing, we will delete `/parent/{proxy+}` to allow creation of a dynamic {child}
        apigateway_client.delete_resource(restApiId=api_id, resourceId=proxy_child_id)

        # creating `/parent/{child}` resource, as its sibling `/parent/{proxy+}` is now deleted
        proxy_sibling_dynamic_child_response = apigateway_client.create_resource(
            restApiId=api_id, parentId=proxy_sibling_id, pathPart="{child}"
        )
        dynamic_child_id = proxy_sibling_dynamic_child_response["id"]
        snapshot.match(
            "create-proxy-sibling-dynamic-child-resource", proxy_sibling_dynamic_child_response
        )

        # creating `/parent/{child}/{proxy+}` resource
        dynamic_child_proxy_child_response = apigateway_client.create_resource(
            restApiId=api_id, parentId=dynamic_child_id, pathPart="{proxy+}"
        )
        snapshot.match("create-dynamic-child-proxy-resource", dynamic_child_proxy_child_response)

        result_api_resource = apigateway_client.get_resources(restApiId=api_id)
        snapshot.match("all-resources-2", result_api_resource)

    @pytest.mark.aws_validated
    def test_create_proxy_resource_validation(
        self, apigateway_client, apigw_create_rest_api, snapshot
    ):
        # test following docs
        # https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-settings-method-request.html#api-gateway-proxy-resource
        snapshot.add_transformer(SortingTransformer("items", lambda x: x["path"]))
        response = apigw_create_rest_api(
            name=f"test-api-{short_uid()}", description="testing resource proxy"
        )
        api_id = response["id"]
        root_rest_api_resource = apigateway_client.get_resources(restApiId=api_id)
        root_id = root_rest_api_resource["items"][0]["id"]

        # creating `/{proxy+}` resource
        base_proxy_response = apigateway_client.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="{proxy+}"
        )
        base_proxy_id = base_proxy_response["id"]
        snapshot.match("create-base-proxy-resource", base_proxy_response)

        # try creating `/{dynamic}` resource, sibling to `/{proxy+}`
        with pytest.raises(ClientError) as e:
            apigateway_client.create_resource(
                restApiId=api_id, parentId=root_id, pathPart="{dynamic}"
            )
        snapshot.match("create-proxy-dynamic-sibling-resource", e.value.response)

        # try creating `/{proxy+}/child` resource, child to `/{proxy+}`
        with pytest.raises(ClientError) as e:
            apigateway_client.create_resource(
                restApiId=api_id, parentId=base_proxy_id, pathPart="child"
            )
        snapshot.match("create-proxy-static-child-resource", e.value.response)

        # try creating `/{proxy+}/{child}` resource, dynamic child to `/{proxy+}`
        with pytest.raises(ClientError) as e:
            apigateway_client.create_resource(
                restApiId=api_id, parentId=base_proxy_id, pathPart="{child}"
            )
        snapshot.match("create-proxy-dynamic-child-resource", e.value.response)

        # creating `/parent` static resource
        parent_response = apigateway_client.create_resource(
            restApiId=api_id, parentId=root_id, pathPart="parent"
        )
        parent_id = parent_response["id"]

        # create `/parent/{child+}` resource, dynamic greedy child to `/parent`
        greedy_child_response = apigateway_client.create_resource(
            restApiId=api_id, parentId=parent_id, pathPart="{child+}"
        )
        snapshot.match("create-greedy-child-resource", greedy_child_response)

    @pytest.mark.aws_validated
    def test_authorizer_crud_no_api(self, apigateway_client, snapshot):
        # maybe move this test to a full lifecycle one
        # AWS validates the format of the authorizerUri before the restApi existence
        with pytest.raises(ClientError) as e:
            apigateway_client.create_authorizer(
                restApiId="test-fake-rest-id",
                name="fake-auth-name",
                type="TOKEN",
                authorizerUri="arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:myApiAuthorizer/invocations",
                identitySource="method.request.header.Authorization",
            )
        snapshot.match("wrong-rest-api-id-create-authorizer", e.value.response)

        with pytest.raises(ClientError) as e:
            apigateway_client.get_authorizers(restApiId="test-fake-rest-id")
        snapshot.match("wrong-rest-api-id-get-authorizers", e.value.response)

    @pytest.mark.aws_validated
    def test_doc_arts_crud_no_api(self, apigateway_client, snapshot):
        # maybe move this test to a full lifecycle one
        with pytest.raises(ClientError) as e:
            apigateway_client.create_documentation_part(
                restApiId="test-fake-rest-id",
                location={"type": "API"},
                properties='{\n\t"info": {\n\t\t"description" : "Your first API with Amazon API Gateway."\n\t}\n}',
            )
        snapshot.match("wrong-rest-api-id-create-doc-part", e.value.response)

        with pytest.raises(ClientError) as e:
            apigateway_client.get_documentation_parts(restApiId="test-fake-rest-id")
        snapshot.match("wrong-rest-api-id-get-doc-parts", e.value.response)

    @pytest.mark.aws_validated
    def test_validators_crud_no_api(self, apigateway_client, snapshot):
        # maybe move this test to a full lifecycle one
        with pytest.raises(ClientError) as e:
            apigateway_client.create_request_validator(
                restApiId="test-fake-rest-id",
                name="test-validator",
                validateRequestBody=True,
                validateRequestParameters=False,
            )
        snapshot.match("wrong-rest-api-id-create-validator", e.value.response)

        with pytest.raises(ClientError) as e:
            apigateway_client.get_request_validators(restApiId="test-fake-rest-id")
        snapshot.match("wrong-rest-api-id-get-validators", e.value.response)

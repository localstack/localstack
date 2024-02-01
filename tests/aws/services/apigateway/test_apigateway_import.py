import logging
import os
import re
import time
from operator import itemgetter

import pytest
import requests
from botocore.exceptions import ClientError
from localstack_snapshot.snapshots import SortingTransformer

from localstack import config
from localstack.aws.api.apigateway import Resources
from localstack.aws.api.lambda_ import Runtime
from localstack.constants import TEST_AWS_REGION_NAME
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry, wait_until
from localstack.utils.testutil import create_lambda_archive
from localstack.utils.urls import localstack_host
from tests.aws.services.apigateway.apigateway_fixtures import api_invoke_url

LOG = logging.getLogger(__name__)

# parent directory of this file
PARENT_DIR = os.path.dirname(os.path.abspath(__file__))
OPENAPI_SPEC_PULUMI_JSON = os.path.join(PARENT_DIR, "../../files/openapi.spec.pulumi.json")
OPENAPI_SPEC_TF_JSON = os.path.join(PARENT_DIR, "../../files/openapi.spec.tf.json")
SWAGGER_MOCK_CORS_JSON = os.path.join(PARENT_DIR, "../../files/swagger-mock-cors.json")
PETSTORE_SWAGGER_JSON = os.path.join(PARENT_DIR, "../../files/petstore-authorizer.swagger.json")
TEST_SWAGGER_FILE_JSON = os.path.join(PARENT_DIR, "../../files/swagger.json")
TEST_OAS30_BASE_PATH_SERVER_VAR_FILE_YAML = os.path.join(
    PARENT_DIR, "../../files/openapi-basepath-server-variable.yaml"
)
TEST_OAS30_BASE_PATH_SERVER_URL_FILE_YAML = os.path.join(
    PARENT_DIR, "../../files/openapi-basepath-url.yaml"
)
TEST_IMPORT_REST_API_FILE = os.path.join(PARENT_DIR, "../../files/pets.json")
TEST_IMPORT_OPEN_API_GLOBAL_API_KEY_AUTHORIZER = os.path.join(
    PARENT_DIR, "../../files/openapi.spec.global-auth.json"
)
OAS_30_CIRCULAR_REF = os.path.join(PARENT_DIR, "../../files/openapi.spec.circular-ref.json")
OAS_30_CIRCULAR_REF_WITH_REQUEST_BODY = os.path.join(
    PARENT_DIR, "../../files/openapi.spec.circular-ref-with-request-body.json"
)
OAS_30_STAGE_VARIABLES = os.path.join(PARENT_DIR, "../../files/openapi.spec.stage-variables.json")
OAS30_HTTP_METHOD_INT = os.path.join(PARENT_DIR, "../../files/openapi-http-method-integration.json")
TEST_LAMBDA_PYTHON_ECHO = os.path.join(PARENT_DIR, "../lambda_/functions/lambda_echo.py")


@pytest.fixture
def apigw_snapshot_imported_resources(snapshot, aws_client):
    def _get_resources_and_snapshot(
        rest_api_id: str, resources: Resources, snapshot_prefix: str = ""
    ):
        """

        :param rest_api_id: The RestAPI ID
        :param resources: the response from GetResources
        :param snapshot_prefix: optional snapshot prefix for every snapshot
        :return:
        """
        for resource in resources["items"]:
            for http_method in resource.get("resourceMethods", []):
                snapshot_http_key = f"{resource['path'][1:] if resource['path'] != '/' else 'root'}-{http_method.lower()}"
                resource_id = resource["id"]
                try:
                    response = aws_client.apigateway.get_method(
                        restApiId=rest_api_id,
                        resourceId=resource_id,
                        httpMethod=http_method,
                    )
                    snapshot.match(f"{snapshot_prefix}method-{snapshot_http_key}", response)
                except ClientError as e:
                    snapshot.match(f"{snapshot_prefix}method-{snapshot_http_key}", e.response)

                try:
                    response = aws_client.apigateway.get_method_response(
                        restApiId=rest_api_id,
                        resourceId=resource_id,
                        httpMethod=http_method,
                        statusCode="200",
                    )
                    snapshot.match(
                        f"{snapshot_prefix}method-response-{snapshot_http_key}", response
                    )
                except ClientError as e:
                    snapshot.match(
                        f"{snapshot_prefix}method-response-{snapshot_http_key}", e.response
                    )

                try:
                    response = aws_client.apigateway.get_integration(
                        restApiId=rest_api_id,
                        resourceId=resource_id,
                        httpMethod=http_method,
                    )
                    snapshot.match(f"{snapshot_prefix}integration-{snapshot_http_key}", response)
                except ClientError as e:
                    snapshot.match(f"{snapshot_prefix}integration-{snapshot_http_key}", e.response)

                try:
                    response = aws_client.apigateway.get_integration_response(
                        restApiId=rest_api_id,
                        resourceId=resource_id,
                        httpMethod=http_method,
                        statusCode="200",
                    )
                    snapshot.match(
                        f"{snapshot_prefix}integration-response-{snapshot_http_key}", response
                    )
                except ClientError as e:
                    snapshot.match(
                        f"{snapshot_prefix}integration-response-{snapshot_http_key}", e.response
                    )

    return _get_resources_and_snapshot


@pytest.fixture(autouse=True)
def apigw_snapshot_transformer(request, snapshot):
    if is_aws_cloud():
        model_base_url = "https://apigateway.amazonaws.com"
    else:
        host_definition = localstack_host()
        model_base_url = f"{config.get_protocol()}://apigateway.{host_definition.host_and_port()}"

    snapshot.add_transformer(snapshot.transform.regex(model_base_url, "<model-base-url>"))

    if "no_apigw_snap_transformers" in request.keywords:
        return

    snapshot.add_transformer(snapshot.transform.apigateway_api())


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
def apigw_create_rest_api(aws_client):
    rest_apis = []

    def _factory(*args, **kwargs):
        if "name" not in kwargs:
            kwargs["name"] = f"test-api-{short_uid()}"
        response = aws_client.apigateway.create_rest_api(*args, **kwargs)
        rest_apis.append(response["id"])
        return response

    yield _factory

    for rest_api_id in rest_apis:
        delete_rest_api_retry(aws_client.apigateway, rest_api_id)


@pytest.fixture(scope="class")
def apigateway_placeholder_authorizer_lambda_invocation_arn(aws_client, lambda_su_role):
    """
    Using this fixture to create only one lambda in AWS to be used for every test, as we need a real lambda ARN
    to be able to import an API. We need a class scoped fixture here, so the code is pulled from
    `create_lambda_function_aws`

    LocalStack does not validate the ARN here, so we can simply return a placeholder
    """
    if not is_aws_cloud():
        yield "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:account-id:function:function-name/invocations"

    else:
        lambda_arns = []

        def _create_function():
            zip_file = create_lambda_archive(load_file(TEST_LAMBDA_PYTHON_ECHO), get_content=True)

            # create_response is the original create call response, even though the fixture waits until it's not pending
            create_response = aws_client.lambda_.create_function(
                FunctionName=f"test-authorizer-import-{short_uid()}",
                Runtime=Runtime.python3_10,
                Handler="handler.handler",
                Role=lambda_su_role,
                Code={"ZipFile": zip_file},
                MemorySize=256,
                Timeout=5,
            )
            lambda_arns.append(create_response["FunctionArn"])

            def _is_not_pending():
                try:
                    result = (
                        aws_client.lambda_.get_function(
                            FunctionName=create_response["FunctionName"]
                        )["Configuration"]["State"]
                        != "Pending"
                    )
                    return result
                except Exception as e:
                    LOG.error(e)
                    raise

            wait_until(_is_not_pending)
            return create_response

        # @AWS, takes about 10s until the role/policy is "active", until then it will fail
        # localstack should normally not require the retries and will just continue here
        response = retry(_create_function, retries=3, sleep=4)

        lambda_invocation_arn = arns.apigateway_invocations_arn(
            response["FunctionArn"], TEST_AWS_REGION_NAME
        )

        yield lambda_invocation_arn

        for arn in lambda_arns:
            try:
                aws_client.lambda_.delete_function(FunctionName=arn)
            except Exception:
                LOG.debug(f"Unable to delete function {arn=} in cleanup")


@pytest.fixture
def apigw_deploy_rest_api(aws_client):
    # AWS returns 429 sometimes (TooManyRequests)
    def _deploy(rest_api_id, stage_name):
        response = retry(
            lambda: aws_client.apigateway.create_deployment(
                restApiId=rest_api_id,
                stageName=stage_name,
            ),
            sleep=10,
        )
        return response

    return _deploy


class TestApiGatewayImportRestApi:
    @markers.aws.validated
    def test_import_rest_api(self, import_apigw, snapshot):
        spec_file = load_file(OPENAPI_SPEC_PULUMI_JSON)
        response, root_id = import_apigw(body=spec_file, failOnWarnings=True)

        snapshot.match("import_rest_api", response)

    @markers.aws.validated
    @pytest.mark.no_apigw_snap_transformers  # not using the API Gateway default transformers
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$.resources.items..resourceMethods.GET",  # TODO: this is really weird, after importing, AWS returns them empty?
            "$.resources.items..resourceMethods.OPTIONS",
            "$.resources.items..resourceMethods.POST",
            "$.get-authorizers.items[1].authorizerResultTtlInSeconds",
        ]
    )
    def test_import_swagger_api(
        self,
        import_apigw,
        snapshot,
        aws_client,
        apigateway_placeholder_authorizer_lambda_invocation_arn,
        lambda_su_role,
        apigw_snapshot_imported_resources,
    ):
        # manually add all transformers, as the default will mess up Model names and such
        snapshot.add_transformers_list(
            [
                snapshot.transform.jsonpath("$.import-swagger.id", value_replacement="rest-id"),
                snapshot.transform.jsonpath(
                    "$.get-authorizers.items..id", value_replacement="authorizer-id"
                ),
                snapshot.transform.key_value("authorizerCredentials"),
                snapshot.transform.key_value("authorizerUri"),
                snapshot.transform.jsonpath(
                    "$.resources.items..id", value_replacement="resource-id"
                ),
                snapshot.transform.jsonpath("$.get-models.items..id", value_replacement="model-id"),
            ]
        )
        spec_file = load_file(PETSTORE_SWAGGER_JSON)
        spec_file = spec_file.replace(
            "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:account-id:function:function-name/invocations",
            apigateway_placeholder_authorizer_lambda_invocation_arn,
        ).replace(
            "arn:aws:iam::account-id:role", lambda_su_role
        )  # we just need a placeholder role

        response, root_id = import_apigw(body=spec_file, failOnWarnings=True)

        snapshot.match("import-swagger", response)

        rest_api_id = response["id"]

        # assert that are no multiple authorizers
        authorizers = aws_client.apigateway.get_authorizers(restApiId=rest_api_id)
        snapshot.match("get-authorizers", authorizers)

        models = aws_client.apigateway.get_models(restApiId=rest_api_id)
        models["items"] = sorted(models["items"], key=itemgetter("name"))

        snapshot.match("get-models", models)

        response = aws_client.apigateway.get_resources(restApiId=rest_api_id)
        response["items"] = sorted(response["items"], key=itemgetter("path"))
        snapshot.match("resources", response)

        # this fixture will iterate over every resource and match its method, methodResponse, integration and
        # integrationResponse
        apigw_snapshot_imported_resources(rest_api_id=rest_api_id, resources=response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$.resources.items..resourceMethods.GET",  # TODO: this is really weird, after importing, AWS returns them empty?
            "$.resources.items..resourceMethods.OPTIONS",
            "$..uri",  # TODO: investigate snapshot pattern matching with account id?
        ]
    )
    @pytest.mark.parametrize(
        "import_file",
        [OPENAPI_SPEC_TF_JSON, SWAGGER_MOCK_CORS_JSON],
        ids=lambda x: x.rsplit("/", maxsplit=1)[-1],
    )
    def test_import_and_validate_rest_api(
        self,
        import_apigw,
        snapshot,
        aws_client,
        import_file,
        apigw_snapshot_imported_resources,
    ):
        # OPENAPI_SPEC_TF_JSON was used from a Terraform example with a JSON file directly used by Terraform
        # SWAGGER_MOCK_CORS_JSON is a synthesized Swagger file created by AWS SAM in an AWS sample
        spec_file = load_file(import_file)
        response, root_id = import_apigw(body=spec_file, failOnWarnings=True)

        snapshot.match("import_tf_rest_api", response)
        rest_api_id = response["id"]

        models = aws_client.apigateway.get_models(restApiId=rest_api_id)
        models["items"] = sorted(models["items"], key=itemgetter("name"))
        snapshot.match("get-models", models)

        response = aws_client.apigateway.get_resources(restApiId=rest_api_id)
        response["items"] = sorted(response["items"], key=itemgetter("path"))
        snapshot.match("resources", response)

        # this fixture will iterate over every resource and match its method, methodResponse, integration and
        # integrationResponse
        apigw_snapshot_imported_resources(rest_api_id=rest_api_id, resources=response)

        if is_aws_cloud():
            # waiting before cleaning up to avoid TooManyRequests, as we create multiple REST APIs
            time.sleep(15)

    @markers.aws.validated
    @pytest.mark.parametrize("base_path_type", ["ignore", "prepend", "split"])
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$.get-resources-swagger-json.items..resourceMethods.GET",  # TODO: this is really weird, after importing, AWS returns them empty?
            "$.get-resources-swagger-json.items..resourceMethods.OPTIONS",
            "$.get-resources-no-base-path-swagger.items..resourceMethods.GET",
            "$.get-resources-no-base-path-swagger.items..resourceMethods.OPTIONS",
        ]
    )
    def test_import_rest_apis_with_base_path_swagger(
        self,
        base_path_type,
        create_rest_apigw,
        apigw_create_rest_api,
        import_apigw,
        aws_client,
        snapshot,
        apigateway_placeholder_authorizer_lambda_invocation_arn,
        lambda_su_role,
        apigw_snapshot_imported_resources,
    ):
        snapshot.add_transformers_list([snapshot.transform.key_value("authorizerId")])

        rest_api_name = f"restapi-{short_uid()}"
        response = apigw_create_rest_api(name=rest_api_name)
        rest_api_id = response["id"]

        spec_file = load_file(TEST_SWAGGER_FILE_JSON)
        spec_file = spec_file.replace(
            "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:000000000000:function:myapi-authorizer-0-22ad13b/invocations",
            apigateway_placeholder_authorizer_lambda_invocation_arn,
        ).replace(
            "arn:aws:iam::000000000000:role/myapi-authorizer-0-authorizer-role-3bd761a",
            lambda_su_role,
        )  # we just need a placeholder role

        api_params = {"basepath": base_path_type}

        if is_aws_cloud():
            # to avoid TooManyRequests, as we are creating and importing many RestAPI and AWS is very strict on
            # API rate limiting
            time.sleep(10)

        response = aws_client.apigateway.put_rest_api(
            restApiId=rest_api_id,
            body=spec_file,
            mode="overwrite",
            parameters=api_params,
        )
        snapshot.match("put-rest-api-swagger-json", response)

        response = aws_client.apigateway.get_resources(restApiId=rest_api_id)
        response["items"] = sorted(response["items"], key=itemgetter("path"))
        snapshot.match("get-resources-swagger-json", response)

        # this fixture will iterate over every resource and match its method, methodResponse, integration and
        # integrationResponse
        apigw_snapshot_imported_resources(rest_api_id=rest_api_id, resources=response)

        if is_aws_cloud():
            # to avoid TooManyRequests
            time.sleep(10)

        # This file does not have a `base_path` defined
        spec_file = load_file(TEST_IMPORT_REST_API_FILE)
        response, _ = import_apigw(body=spec_file, parameters=api_params)
        rest_api_id_2 = response["id"]

        response = aws_client.apigateway.get_resources(restApiId=rest_api_id_2)
        response["items"] = sorted(response["items"], key=itemgetter("path"))
        snapshot.match("get-resources-no-base-path-swagger", response)

        apigw_snapshot_imported_resources(rest_api_id=rest_api_id_2, resources=response)

        if is_aws_cloud():
            # to avoid TooManyRequests for parametrized test
            # then you realize LocalStack is needed!
            time.sleep(20)

    @markers.aws.validated
    @pytest.mark.parametrize("base_path_type", ["ignore", "prepend", "split"])
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$.get-resources-oas30-srv-var.items..resourceMethods.GET",  # TODO: this is really weird, after importing, AWS returns them empty?
            "$.get-resources-oas30-srv-var.items..resourceMethods.OPTIONS",
            "$.get-resources-oas30-srv-url.items..resourceMethods.GET",
            "$.get-resources-oas30-srv-url.items..resourceMethods.OPTIONS",
            "$..cacheNamespace",  # TODO: investigate why it's different
            "$.get-resources-oas30-srv-url.items..id",  # TODO: even in overwrite, APIGW keeps the same ID if same path
            "$.get-resources-oas30-srv-url.items..parentId",  # TODO: even in overwrite, APIGW keeps the same ID if same path
        ]
    )
    def test_import_rest_api_with_base_path_oas30(
        self,
        base_path_type,
        apigw_create_rest_api,
        aws_client,
        snapshot,
        apigateway_placeholder_authorizer_lambda_invocation_arn,
        apigw_snapshot_imported_resources,
        apigw_deploy_rest_api,
    ):
        snapshot.add_transformer(snapshot.transform.key_value("cacheNamespace"))
        # test for https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-import-api-basePath.html
        # having either the basePath as in the server URL path or as a variable
        rest_api_name = f"restapi-{short_uid()}"
        response = apigw_create_rest_api(name=rest_api_name)
        rest_api_id = response["id"]

        api_params = {"basepath": base_path_type}

        if is_aws_cloud():
            # to avoid TooManyRequests, as we are creating and importing many RestAPI and AWS is very strict on
            # API rate limiting
            time.sleep(10)

        spec_file = load_file(TEST_OAS30_BASE_PATH_SERVER_VAR_FILE_YAML)

        response = aws_client.apigateway.put_rest_api(
            restApiId=rest_api_id,
            body=spec_file,
            mode="overwrite",
            parameters=api_params,
        )
        snapshot.match("put-rest-api-oas30-srv-var", response)

        response = aws_client.apigateway.get_resources(restApiId=rest_api_id)
        response["items"] = sorted(response["items"], key=itemgetter("path"))
        snapshot.match("get-resources-oas30-srv-var", response)

        # this fixture will iterate over every resource and match its method, methodResponse, integration and
        # integrationResponse

        apigw_snapshot_imported_resources(
            rest_api_id=rest_api_id, resources=response, snapshot_prefix="srv-var-"
        )

        stage_name = "dev"

        # the basePath for this OpenAPI file is "/base-var"
        resource_path = "/test" if base_path_type != "prepend" else "/base-var/test"

        # AWS raises 429 sometimes
        apigw_deploy_rest_api(rest_api_id, stage_name)

        def assert_request_ok(request_url: str) -> requests.Response:
            _response = requests.get(url)
            assert _response.ok
            return _response

        url = api_invoke_url(rest_api_id, stage=stage_name, path=resource_path)
        retry(assert_request_ok, retries=10, sleep=2, request_url=url)

        spec_file = load_file(TEST_OAS30_BASE_PATH_SERVER_URL_FILE_YAML)

        response = aws_client.apigateway.put_rest_api(
            restApiId=rest_api_id,
            body=spec_file,
            mode="overwrite",
            parameters=api_params,
        )
        snapshot.match("put-rest-api-oas30-srv-url", response)

        response = aws_client.apigateway.get_resources(restApiId=rest_api_id)
        response["items"] = sorted(response["items"], key=itemgetter("path"))
        snapshot.match("get-resources-oas30-srv-url", response)

        apigw_snapshot_imported_resources(
            rest_api_id=rest_api_id, resources=response, snapshot_prefix="srv-url-"
        )

        apigw_deploy_rest_api(rest_api_id=rest_api_id, stage_name=stage_name)

        # the basePath for this OpenAPI file is "/base-url/part/"
        resource_path = ""
        match base_path_type:
            case "ignore":
                resource_path = "/test"
            case "prepend":
                resource_path = "/base-url/part/test"
            case "split":
                # split removes the top most path part of the basePath
                resource_path = "/part/test"

        url = api_invoke_url(rest_api_id, stage=stage_name, path=resource_path)
        retry(assert_request_ok, retries=10, sleep=2, request_url=url)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$.resources.items..resourceMethods.GET",  # AWS does not show them after import
            "$.resources.items..resourceMethods.ANY",
        ]
    )
    def test_import_with_global_api_key_authorizer(
        self,
        import_apigw,
        aws_client,
        snapshot,
        apigateway_placeholder_authorizer_lambda_invocation_arn,
        apigw_snapshot_imported_resources,
    ):
        snapshot.add_transformer(snapshot.transform.key_value("authorizerUri"))

        spec_file = load_file(TEST_IMPORT_OPEN_API_GLOBAL_API_KEY_AUTHORIZER)
        spec_file = spec_file.replace(
            "${authorizer_lambda_invocation_arn}",
            apigateway_placeholder_authorizer_lambda_invocation_arn,
        )

        response, root_id = import_apigw(body=spec_file, failOnWarnings=True)

        snapshot.match("import-swagger", response)

        rest_api_id = response["id"]

        authorizers = aws_client.apigateway.get_authorizers(restApiId=rest_api_id)
        snapshot.match("get-authorizers", authorizers)

        response = aws_client.apigateway.get_resources(restApiId=rest_api_id)
        response["items"] = sorted(response["items"], key=itemgetter("path"))
        snapshot.match("resources", response)

        # this fixture will iterate over every resource and match its method, methodResponse, integration and
        # integrationResponse
        apigw_snapshot_imported_resources(rest_api_id=rest_api_id, resources=response)

    @markers.aws.validated
    @pytest.mark.no_apigw_snap_transformers  # not using the API Gateway default transformers
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$.resources.items..resourceMethods.POST",  # TODO: this is really weird, after importing, AWS returns them empty?
        ]
    )
    def test_import_with_circular_models(
        self, import_apigw, apigw_snapshot_imported_resources, aws_client, snapshot
    ):
        snapshot.add_transformers_list(
            [
                snapshot.transform.jsonpath("$.import-api.id", value_replacement="rest-id"),
                snapshot.transform.jsonpath(
                    "$.resources.items..id", value_replacement="resource-id"
                ),
                snapshot.transform.jsonpath("$.get-models.items..id", value_replacement="model-id"),
                SortingTransformer("required"),
            ]
        )
        spec_file = load_file(OAS_30_CIRCULAR_REF)

        response, root_id = import_apigw(body=spec_file, failOnWarnings=True)

        snapshot.match("import-api", response)
        rest_api_id = response["id"]

        models = aws_client.apigateway.get_models(restApiId=rest_api_id)
        models["items"] = sorted(models["items"], key=itemgetter("name"))

        snapshot.match("get-models", models)

        response = aws_client.apigateway.get_resources(restApiId=rest_api_id)
        response["items"] = sorted(response["items"], key=itemgetter("path"))
        snapshot.match("resources", response)

        # this fixture will iterate over every resource and match its method, methodResponse, integration and
        # integrationResponse
        apigw_snapshot_imported_resources(rest_api_id=rest_api_id, resources=response)

    @pytest.mark.no_apigw_snap_transformers  # not using the API Gateway default transformers
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$.resources.items..resourceMethods.POST",
            # TODO: this is really weird, after importing, AWS returns them empty?
            "$..rootResourceId",  # TODO: newly added
        ]
    )
    @markers.aws.validated
    def test_import_with_circular_models_and_request_validation(
        self, import_apigw, apigw_snapshot_imported_resources, aws_client, snapshot
    ):
        # manually add all transformers, as the default will mess up Model names and such
        snapshot.add_transformers_list(
            [
                snapshot.transform.jsonpath("$.import-api.id", value_replacement="rest-id"),
                snapshot.transform.jsonpath(
                    "$.resources.items..id", value_replacement="resource-id"
                ),
                snapshot.transform.jsonpath("$.get-models.items..id", value_replacement="model-id"),
                snapshot.transform.jsonpath(
                    "$.request-validators.items..id", value_replacement="request-validator-id"
                ),
                SortingTransformer("required"),
            ]
        )
        spec_file = load_file(OAS_30_CIRCULAR_REF_WITH_REQUEST_BODY)

        response, root_id = import_apigw(body=spec_file, failOnWarnings=True)

        snapshot.match("import-api", response)
        rest_api_id = response["id"]

        models = aws_client.apigateway.get_models(restApiId=rest_api_id)
        models["items"] = sorted(models["items"], key=itemgetter("name"))

        snapshot.match("get-models", models)

        response = aws_client.apigateway.get_request_validators(restApiId=rest_api_id)
        snapshot.match("request-validators", response)

        response = aws_client.apigateway.get_resources(restApiId=rest_api_id)
        response["items"] = sorted(response["items"], key=itemgetter("path"))
        snapshot.match("resources", response)

        # this fixture will iterate over every resource and match its method, methodResponse, integration and
        # integrationResponse
        apigw_snapshot_imported_resources(rest_api_id=rest_api_id, resources=response)

        stage_name = "dev"
        aws_client.apigateway.create_deployment(restApiId=rest_api_id, stageName=stage_name)

        url = api_invoke_url(api_id=rest_api_id, stage=stage_name, path="/person")

        request_data = {
            "name": "Person1",
            "b": 2,
            "house": {
                "randomProperty": "this is random",
                "contains": [{"name": "Person2", "b": 3}],
            },
        }
        if is_aws_cloud():
            time.sleep(5)

        request = requests.post(url, json=request_data)
        assert request.ok
        # we cannot make the body passthrough, because MOCK integrations don't allow to pass the body from the
        # request to the response: https://stackoverflow.com/a/47945574/6998584
        # the MOCK integration requestTemplate returns {"statusCode": 200}, but AWS does not pass it to $input.json('$')
        # TODO: get parity with the MOCK integration

        wrong_request = {"random": "blabla"}

        request = requests.post(url, json=wrong_request)
        assert request.status_code == 400
        assert request.json().get("message") == "Invalid request body"

        wrong_request_schema = {
            "name": "Person1",
            "b": 2,
            "house": {
                "randomProperty": "this is random, but I follow House schema except for contains",
                "contains": [{"randomObject": "I am not following Person schema"}],
            },
        }
        request = requests.post(url, json=wrong_request_schema)
        assert request.status_code == 400
        assert request.json().get("message") == "Invalid request body"

    @markers.aws.validated
    def test_import_with_stage_variables(self, import_apigw, aws_client, echo_http_server_post):
        spec_file = load_file(OAS_30_STAGE_VARIABLES)
        import_resp, root_id = import_apigw(body=spec_file, failOnWarnings=True)
        rest_api_id = import_resp["id"]

        response = aws_client.apigateway.create_deployment(restApiId=rest_api_id)
        # workaround to remove the fixture scheme prefix. AWS won't allow stage variables
        # on the OpenAPI uri without the scheme. So we let the scheme on the spec, "http://{stageVariables.url}",
        # and remove it from the fixture
        endpoint = re.sub(r"https?://", "", echo_http_server_post)
        aws_client.apigateway.create_stage(
            restApiId=rest_api_id,
            stageName="v1",
            variables={"url": endpoint},
            deploymentId=response["id"],
        )

        def call_api():
            url = api_invoke_url(api_id=rest_api_id, stage="v1", path="/path1")
            res = requests.get(url)
            assert res.ok

        retry(call_api, retries=5, sleep=2)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$.resources.items..resourceMethods.GET",
            "$.resources.items..resourceMethods.OPTIONS",
        ]
    )
    def test_import_with_http_method_integration(
        self,
        import_apigw,
        aws_client,
        apigw_snapshot_imported_resources,
        apigateway_placeholder_authorizer_lambda_invocation_arn,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.key_value("uri"))
        spec_file = load_file(OAS30_HTTP_METHOD_INT)
        spec_file = spec_file.replace(
            "${lambda_invocation_arn}", apigateway_placeholder_authorizer_lambda_invocation_arn
        )
        import_resp, root_id = import_apigw(body=spec_file, failOnWarnings=True)
        rest_api_id = import_resp["id"]

        response = aws_client.apigateway.get_resources(restApiId=rest_api_id)
        response["items"] = sorted(response["items"], key=itemgetter("path"))
        snapshot.match("resources", response)

        # this fixture will iterate over every resource and match its method, methodResponse, integration and
        # integrationResponse
        apigw_snapshot_imported_resources(rest_api_id=rest_api_id, resources=response)

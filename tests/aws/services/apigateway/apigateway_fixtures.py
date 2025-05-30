from enum import Enum
from typing import Dict

from localstack.services.apigateway.helpers import (
    host_based_url,
    localstack_path_based_url,
    path_based_url,
)
from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.aws import aws_stack

# TODO convert the test util functions in this file to pytest fixtures


def assert_response_status(response: Dict, status: int):
    assert response.get("ResponseMetadata").get("HTTPStatusCode") == status


def assert_response_is_200(response: Dict) -> bool:
    assert_response_status(response, 200)
    return True


def assert_response_is_201(response: Dict) -> bool:
    assert_response_status(response, 201)
    return True


def import_rest_api(apigateway_client, **kwargs):
    response = apigateway_client.import_rest_api(**kwargs)
    assert_response_is_201(response)
    resources = apigateway_client.get_resources(restApiId=response.get("id"))
    root_id = next(item for item in resources["items"] if item["path"] == "/")["id"]

    return response, root_id


def create_rest_resource(apigateway_client, **kwargs):
    response = apigateway_client.create_resource(**kwargs)
    assert_response_is_201(response)
    return response.get("id"), response.get("parentId")


def create_rest_resource_method(apigateway_client, **kwargs):
    response = apigateway_client.put_method(**kwargs)
    assert_response_is_201(response)
    return response.get("httpMethod"), response.get("authorizerId")


def create_rest_api_integration(apigateway_client, **kwargs):
    response = apigateway_client.put_integration(**kwargs)
    assert_response_is_201(response)
    return response.get("uri"), response.get("type")


def create_rest_api_method_response(apigateway_client, **kwargs):
    response = apigateway_client.put_method_response(**kwargs)
    assert_response_is_201(response)
    return response.get("statusCode")


def create_rest_api_integration_response(apigateway_client, **kwargs):
    response = apigateway_client.put_integration_response(**kwargs)
    assert_response_is_201(response)
    return response.get("statusCode")


def create_rest_api_deployment(apigateway_client, **kwargs):
    response = apigateway_client.create_deployment(**kwargs)
    assert_response_is_201(response)
    return response.get("id"), response.get("createdDate")


def update_rest_api_deployment(apigateway_client, **kwargs):
    response = apigateway_client.update_deployment(**kwargs)
    assert_response_is_200(response)
    return response


def create_rest_api_stage(apigateway_client, **kwargs):
    response = apigateway_client.create_stage(**kwargs)
    assert_response_is_201(response)
    return response.get("stageName")


def update_rest_api_stage(apigateway_client, **kwargs):
    response = apigateway_client.update_stage(**kwargs)
    assert_response_is_200(response)
    return response.get("stageName")


#
# Common utilities
#


class UrlType(Enum):
    HOST_BASED = 0
    PATH_BASED = 1
    LS_PATH_BASED = 2


def api_invoke_url(
    api_id: str,
    stage: str = "",
    path: str = "/",
    url_type: UrlType = UrlType.HOST_BASED,
    region: str = "",
):
    if is_aws_cloud():
        if not region:
            region = aws_stack.get_boto3_region()
        stage = f"/{stage}" if stage else ""
        return f"https://{api_id}.execute-api.{region}.amazonaws.com{stage}{path}"

    if url_type == UrlType.HOST_BASED:
        return host_based_url(api_id, stage_name=stage, path=path)
    elif url_type == UrlType.PATH_BASED:
        return path_based_url(api_id, stage_name=stage, path=path)
    else:
        return localstack_path_based_url(api_id, stage_name=stage, path=path)

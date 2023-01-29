import os
from enum import Enum
from typing import Dict

import boto3
import botocore

from localstack.services.apigateway.helpers import host_based_url, path_based_url
from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.aws import aws_stack


def _client(service, region_name=None, aws_access_key_id=None):
    if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
        return boto3.client(service)
    # can't set the timeouts to 0 like in the AWS CLI because the underlying http client requires values > 0
    config = (
        botocore.config.Config(
            connect_timeout=1_000, read_timeout=1_000, retries={"total_max_attempts": 1}
        )
        if os.environ.get("TEST_DISABLE_RETRIES_AND_TIMEOUTS")
        else None
    )
    return aws_stack.create_external_boto_client(
        service, config=config, region_name=region_name, aws_access_key_id=aws_access_key_id
    )


def assert_response_status(response: Dict, status: int):
    assert response.get("ResponseMetadata").get("HTTPStatusCode") == status


def assert_response_is_200(response: Dict) -> bool:
    assert_response_status(response, 200)
    return True


def assert_response_is_201(response: Dict) -> bool:
    assert_response_status(response, 201)
    return True


def create_rest_api(apigateway_client, **kwargs):
    response = apigateway_client.create_rest_api(**kwargs)
    assert_response_is_201(response)

    resources = apigateway_client.get_resources(restApiId=response.get("id"))
    root_id = next(item for item in resources["items"] if item["path"] == "/")["id"]
    return response.get("id"), response.get("name"), root_id


def import_rest_api(apigateway_client, **kwargs):
    response = apigateway_client.import_rest_api(**kwargs)
    assert_response_is_201(response)
    resources = apigateway_client.get_resources(restApiId=response.get("id"))
    root_id = next(item for item in resources["items"] if item["path"] == "/")["id"]
    return response, root_id


def get_rest_api(apigateway_client, **kwargs):
    response = apigateway_client.get_rest_api(**kwargs)
    assert_response_is_200(response)
    return response.get("id"), response.get("name")


def put_rest_api(apigateway_client, **kwargs):
    response = apigateway_client.put_rest_api(**kwargs)
    assert_response_is_200(response)
    return response.get("id"), response.get("name")


def get_rest_apis(apigateway_client, **kwargs):
    response = apigateway_client.get_rest_apis(**kwargs)
    assert_response_is_200(response)
    return response.get("items")


def delete_rest_api(apigateway_client, **kwargs):
    response = apigateway_client.delete_rest_api(**kwargs)
    assert_response_status(response, 202)


def create_rest_resource(apigateway_client, **kwargs):
    response = apigateway_client.create_resource(**kwargs)
    assert_response_is_201(response)
    return response.get("id"), response.get("parentId")


def delete_rest_resource(apigateway_client, **kwargs):
    response = apigateway_client.delete_resource(**kwargs)
    assert_response_is_200(response)


def create_rest_resource_method(apigateway_client, **kwargs):
    response = apigateway_client.put_method(**kwargs)
    assert_response_is_201(response)
    return response.get("httpMethod"), response.get("authorizerId")


def create_rest_authorizer(apigateway_client, **kwargs):
    response = apigateway_client.create_authorizer(**kwargs)
    assert_response_is_201(response)
    return response.get("id"), response.get("type")


def create_rest_api_integration(apigateway_client, **kwargs):
    response = apigateway_client.put_integration(**kwargs)
    assert_response_is_201(response)
    return response.get("uri"), response.get("type")


def get_rest_api_resources(apigateway_client, **kwargs):
    response = apigateway_client.get_resources(**kwargs)
    assert_response_is_200(response)
    return response.get("items")


def delete_rest_api_integration(apigateway_client, **kwargs):
    response = apigateway_client.delete_integration(**kwargs)
    assert_response_is_200(response)


def get_rest_api_integration(apigateway_client, **kwargs):
    response = apigateway_client.get_integration(**kwargs)
    assert_response_is_200(response)


def create_rest_api_method_response(apigateway_client, **kwargs):
    response = apigateway_client.put_method_response(**kwargs)
    assert_response_is_201(response)
    return response.get("statusCode")


def create_rest_api_integration_response(apigateway_client, **kwargs):
    response = apigateway_client.put_integration_response(**kwargs)
    assert_response_is_201(response)
    return response.get("statusCode")


def create_domain_name(apigateway_client, **kwargs):
    response = apigateway_client.create_domain_name(**kwargs)
    assert_response_is_201(response)


def create_base_path_mapping(apigateway_client, **kwargs):
    response = apigateway_client.create_base_path_mapping(**kwargs)
    assert_response_is_201(response)
    return response.get("basePath"), response.get("stage")


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


def create_cognito_user_pool(cognito_idp, **kwargs):
    response = cognito_idp.create_user_pool(**kwargs)
    assert_response_is_200(response)
    return response.get("UserPool").get("Id"), response.get("UserPool").get("Arn")


def delete_cognito_user_pool(cognito_idp, **kwargs):
    response = cognito_idp.delete_user_pool(**kwargs)
    assert_response_is_200(response)


def create_cognito_user_pool_client(cognito_idp, **kwargs):
    response = cognito_idp.create_user_pool_client(**kwargs)
    assert_response_is_200(response)
    return (
        response.get("UserPoolClient").get("ClientId"),
        response.get("UserPoolClient").get("ClientName"),
    )


def create_cognito_user(cognito_idp, **kwargs):
    response = cognito_idp.sign_up(**kwargs)
    assert_response_is_200(response)


def create_cognito_sign_up_confirmation(cognito_idp, **kwargs):
    response = cognito_idp.admin_confirm_sign_up(**kwargs)
    assert_response_is_200(response)


def create_initiate_auth(cognito_idp, **kwargs):
    response = cognito_idp.initiate_auth(**kwargs)
    assert_response_is_200(response)
    return response.get("AuthenticationResult").get("IdToken")


def delete_cognito_user_pool_client(cognito_idp, **kwargs):
    response = cognito_idp.delete_user_pool_client(**kwargs)
    assert_response_is_200(response)


#
# Common utilities
#


class UrlType(Enum):
    HOST_BASED = 0
    PATH_BASED = 1


def api_invoke_url(
    api_id: str, stage: str = "", path: str = "/", url_type: UrlType = UrlType.HOST_BASED
):
    if is_aws_cloud():
        stage = f"/{stage}" if stage else ""
        return f"https://{api_id}.execute-api.{aws_stack.get_boto3_region()}.amazonaws.com{stage}{path}"
    if url_type == UrlType.HOST_BASED:
        return host_based_url(api_id, stage_name=stage, path=path)
    return path_based_url(api_id, stage_name=stage, path=path)

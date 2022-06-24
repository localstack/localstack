from enum import Enum
from typing import Dict

from localstack.services.apigateway.helpers import host_based_url, path_based_url


def assert_response_is_200(response: Dict) -> bool:
    assert response.get("ResponseMetadata").get("HTTPStatusCode") == 200
    return True


def assert_response_is_201(response: Dict) -> bool:
    assert response.get("ResponseMetadata").get("HTTPStatusCode") == 201
    return True


def create_rest_api(apigateway_client, **kwargs):
    response = apigateway_client.create_rest_api(**kwargs)
    assert_response_is_201(response)

    resources = apigateway_client.get_resources(restApiId=response.get("id"))
    root_id = next(item for item in resources["items"] if item["path"] == "/")["id"]
    return response.get("id"), response.get("name"), root_id


def get_rest_apis(apigateway_client, **kwargs):
    response = apigateway_client.get_rest_apis(**kwargs)
    assert_response_is_200(response)


def delete_rest_api(apigateway_client, **kwargs):
    response = apigateway_client.delete_rest_api(**kwargs)
    assert_response_is_200(response)


def create_rest_resource(apigateway_client, **kwargs):
    response = apigateway_client.create_resource(**kwargs)
    assert_response_is_200(response)
    return response.get("id"), response.get("parentId")


def delete_rest_resource(apigateway_client, **kwargs):
    response = apigateway_client.delete_resource(**kwargs)
    assert_response_is_200(response)


def create_rest_resource_method(apigateway_client, **kwargs):
    response = apigateway_client.put_method(**kwargs)
    assert_response_is_200(response)
    return response.get("httpMethod"), response.get("authorizerId")


def create_rest_authorizer(apigateway_client, **kwargs):
    response = apigateway_client.create_authorizer(**kwargs)
    assert_response_is_200(response)
    return response.get("id"), response.get("type")


def create_rest_api_integration(apigateway_client, **kwargs):
    response = apigateway_client.put_integration(**kwargs)
    assert_response_is_200(response)
    return response.get("uri"), response.get("type")


def delete_rest_api_integration(apigateway_client, **kwargs):
    response = apigateway_client.delete_integration(**kwargs)
    assert_response_is_200(response)


def get_rest_api_integration(apigateway_client, **kwargs):
    response = apigateway_client.get_integration(**kwargs)
    assert_response_is_200(response)


def create_rest_api_method_response(apigateway_client, **kwargs):
    response = apigateway_client.put_method_response(**kwargs)
    assert_response_is_200(response)
    return response.get("statusCode")


def create_rest_api_integration_response(apigateway_client, **kwargs):
    response = apigateway_client.put_integration_response(**kwargs)
    assert_response_is_200(response)
    return response.get("statusCode")


def create_domain_name(apigateway_client, **kwargs):
    response = apigateway_client.create_domain_name(**kwargs)
    assert_response_is_200(response)


def create_base_path_mapping(apigateway_client, **kwargs):
    response = apigateway_client.create_base_path_mapping(**kwargs)
    assert_response_is_200(response)
    return response.get("basePath"), response.get("stage")


def create_rest_api_deployment(apigateway_client, **kwargs):
    response = apigateway_client.create_deployment(**kwargs)
    assert_response_is_200(response)


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
    if url_type == UrlType.HOST_BASED:
        return host_based_url(api_id, stage_name=stage, path=path)
    else:
        return path_based_url(api_id, stage_name=stage, path=path)

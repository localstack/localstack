from localstack.aws.api import RequestContext
from localstack.aws.api.apigateway import (
    ApigatewayApi,
    ApiKeySourceType,
    Authorizer,
    AuthorizerType,
    Boolean,
    EndpointConfiguration,
    ListOfARNs,
    ListOfString,
    MapOfStringToString,
    NullableInteger,
    RestApi,
    String,
)


class ApigatewayProvider(ApigatewayApi):
    def create_authorizer(
        self,
        context: RequestContext,
        rest_api_id: String,
        name: String,
        type: AuthorizerType,
        provider_arns: ListOfARNs = None,
        auth_type: String = None,
        authorizer_uri: String = None,
        authorizer_credentials: String = None,
        identity_source: String = None,
        identity_validation_expression: String = None,
        authorizer_result_ttl_in_seconds: NullableInteger = None,
    ) -> Authorizer:
        pass

    def create_rest_api(
        self,
        context: RequestContext,
        name: String,
        description: String = None,
        version: String = None,
        clone_from: String = None,
        binary_media_types: ListOfString = None,
        minimum_compression_size: NullableInteger = None,
        api_key_source: ApiKeySourceType = None,
        endpoint_configuration: EndpointConfiguration = None,
        policy: String = None,
        tags: MapOfStringToString = None,
        disable_execute_api_endpoint: Boolean = None,
    ) -> RestApi:
        pass

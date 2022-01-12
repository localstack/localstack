from localstack.aws.api import RequestContext
from localstack.aws.api.apigateway import (
    ApigatewayApi,
    Authorizer,
    AuthorizerType,
    ListOfARNs,
    NullableInteger,
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

from abc import ABC

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.apigateway import ApigatewayApi, Authorizer, CreateAuthorizerRequest


class ApigatewayProvider(ApigatewayApi, ABC):
    @handler("CreateAuthorizer", expand=False)
    def create_authorizer(
        self, context: RequestContext, request: CreateAuthorizerRequest
    ) -> Authorizer:
        raise NotImplementedError

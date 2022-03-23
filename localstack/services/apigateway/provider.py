from abc import ABC

from localstack.aws.api import handler, RequestContext

from localstack.aws.api.apigateway import ApigatewayApi, CreateAuthorizerRequest, Authorizer


class ApigatewayProvider(ApigatewayApi, ABC):

    @handler("CreateAuthorizer", expand=False)
    def create_authorizer(
        self, context: RequestContext, request: CreateAuthorizerRequest
    ) -> Authorizer:
        raise NotImplementedError

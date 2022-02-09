import logging
from typing import Any

from localstack.aws.api import RequestContext
from localstack.aws.api.awslambda import (
    Blob,
    InvocationResponse,
    InvocationType,
    LambdaApi,
    LogType,
    NamespacedFunctionName,
    Qualifier,
    String,
)
from localstack.services.awslambda.invocation.lambda_service import LambdaService
from localstack.services.generic_proxy import ProxyListener

LOG = logging.getLogger(__name__)


class NoopListener(ProxyListener):
    def forward_request(self, *args: Any, **kwargs: Any) -> bool:
        return True

    def return_response(self, *args: Any, **kwargs: Any) -> bool:
        return True


class LambdaProvider(LambdaApi):
    lambda_service: LambdaService

    def __init__(self) -> None:
        self.lambda_service = LambdaService()

    def invoke(
        self,
        context: RequestContext,
        function_name: NamespacedFunctionName,
        invocation_type: InvocationType = None,
        log_type: LogType = None,
        client_context: String = None,
        payload: Blob = None,
        qualifier: Qualifier = None,
    ) -> InvocationResponse:
        LOG.debug("Lambda function got invoked! Params: %s", dict(locals()))
        # TODO discuss where function data is stored - might need to be passed here
        result = self.lambda_service.invoke(
            function_name=function_name,
            account=context.account_id,
            region=context.region,
            invocation_type=invocation_type,
            log_type=log_type,
            client_context=client_context,
            payload=payload,
            qualifier=qualifier,
        )
        result = result.result()
        LOG.debug("Result: %s", result)
        return {}

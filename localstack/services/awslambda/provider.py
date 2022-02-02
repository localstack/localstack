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
from localstack.services.generic_proxy import ProxyListener

LOG = logging.getLogger(__name__)


class NoopListener(ProxyListener):
    def forward_request(self, *args: Any, **kwargs: Any) -> bool:
        return True

    def return_response(self, *args: Any, **kwargs: Any) -> bool:
        return True


class LambdaProvider(LambdaApi):
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
        LOG.debug("Lambda got invoked!")
        return {}

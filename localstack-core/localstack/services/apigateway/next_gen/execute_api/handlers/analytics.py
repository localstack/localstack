import logging

from localstack.http import Response
from localstack.utils.analytics.metrics import Counter, _LabeledCounterMetric

from ..api import RestApiGatewayHandler, RestApiGatewayHandlerChain
from ..context import RestApiInvocationContext

LOG = logging.getLogger(__name__)


class IntegrationUsageCounter(RestApiGatewayHandler):
    counter: _LabeledCounterMetric

    def __init__(self, counter: _LabeledCounterMetric = None):
        self.counter = counter or Counter(
            namespace="apigateway", name="rest_api_execute", labels=["invocation_type"]
        )

    def __call__(
        self,
        chain: RestApiGatewayHandlerChain,
        context: RestApiInvocationContext,
        response: Response,
    ):
        if context.integration:
            invocation_type = context.integration["type"]
            if invocation_type == "AWS":
                service_name = self._get_aws_integration_service(context.integration.get("uri"))
                invocation_type = f"{invocation_type}:{service_name}"
        else:
            # if the invocation does not have an integration attached, it probably failed before routing the request,
            # hence we should count it as a NOT_FOUND invocation
            invocation_type = "NOT_FOUND"

        self.counter.labels(invocation_type=invocation_type).increment()

    @staticmethod
    def _get_aws_integration_service(integration_uri: str) -> str:
        if not integration_uri:
            return "null"

        if len(split_arn := integration_uri.split(":", maxsplit=5)) < 4:
            return "null"

        return split_arn[4]

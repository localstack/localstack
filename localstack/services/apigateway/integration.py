import json
import logging

from localstack import config
from localstack.services.apigateway.apigateway_listener import apply_template
from localstack.services.apigateway.context import ApiInvocationContext
from localstack.utils.aws import aws_stack
from localstack.utils.common import make_http_request, to_str

LOG = logging.getLogger(__name__)


class BackendIntegration:
    """
    Backend integration
    """


class SnsIntegration(BackendIntegration):
    __slots__ = ["invocation_context"]

    def __init__(self, invocation_context: ApiInvocationContext):
        self.invocation_context = invocation_context

    def invoke(self):
        try:
            data = self.invocation_context.data
            data = json.dumps(data) if isinstance(data, (dict, list)) else to_str(data)
            payload = apply_template(
                self.invocation_context.integration,
                "request",
                data,
                path_params=self.invocation_context.path_params,
                query_params=self.invocation_context.query_params(),
                headers=self.invocation_context.headers,
            )
        except Exception as e:
            LOG.warning("Failed to apply template for SNS integration", e)
            raise
        uri = (
            self.invocation_context.integration.get("uri")
            or self.invocation_context.integration.get("integrationUri")
            or ""
        )
        region_name = uri.split(":")[3]
        headers = aws_stack.mock_aws_request_headers(service="sns", region_name=region_name)
        return make_http_request(
            config.service_url("sns"), method="POST", headers=headers, data=payload
        )

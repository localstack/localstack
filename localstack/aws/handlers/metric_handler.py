import copy
import logging
from typing import List, Optional

from localstack import config
from localstack.aws.api import RequestContext, ServiceRequest
from localstack.aws.chain import HandlerChain
from localstack.http import Response
from localstack.utils.aws.aws_stack import is_internal_call_context

LOG = logging.getLogger(__name__)


class MetricHandlerItem:
    """
    MetricHandlerItem to reference and update requests by the MetricHandler
    """

    request_id: str
    request_context: RequestContext
    request_after_parse: Optional[ServiceRequest]

    def __init__(self, request_contex: RequestContext) -> None:
        super().__init__()
        self.request_id = str(hash(request_contex))
        self.request_context = request_contex
        self.request_after_parse = None


class Metric:
    """
    Data object to store relevant information for a metric entry in the raw-data collection (csv)
    """

    service: str
    operation: str
    headers: str
    parameters: str
    status_code: int
    response_code: Optional[str]
    exception: str
    origin: str
    xfail: bool
    aws_validated: bool
    snapshot: bool
    node_id: str

    RAW_DATA_HEADER = [
        "service",
        "operation",
        "request_headers",
        "parameters",
        "response_code",
        "response_data",
        "exception",
        "origin",
        "test_node_id",
        "xfail",
        "aws_validated",
        "snapshot",
    ]

    def __init__(
        self,
        service: str,
        operation: str,
        headers: str,
        parameters: str,
        response_code: int,
        response_data: str,
        exception: str,
        origin: str,
        node_id: str = "",
        xfail: bool = False,
        aws_validated: bool = False,
        snapshot: bool = False,
    ) -> None:
        self.service = service
        self.operation = operation
        self.headers = headers
        self.parameters = parameters
        self.response_code = response_code
        self.response_data = response_data
        self.exception = exception
        self.origin = origin
        self.node_id = node_id
        self.xfail = xfail
        self.aws_validated = aws_validated
        self.snapshot = snapshot

    def __iter__(self):
        return iter(
            [
                self.service,
                self.operation,
                self.headers,
                self.parameters,
                self.response_code,
                self.response_data,
                self.exception,
                self.origin,
                self.node_id,
                self.xfail,
                self.aws_validated,
                self.snapshot,
            ]
        )


class MetricHandler:
    metric_data: List[Metric] = []

    def __init__(self) -> None:
        self.metrics_handler_items = {}

    def create_metric_handler_item(
        self, chain: HandlerChain, context: RequestContext, response: Response
    ):
        if not config.is_collect_metrics_mode():
            return
        item = MetricHandlerItem(context)
        self.metrics_handler_items[context] = item

    def _get_metric_handler_item_for_context(self, context: RequestContext) -> MetricHandlerItem:
        return self.metrics_handler_items[context]

    def record_parsed_request(
        self, chain: HandlerChain, context: RequestContext, response: Response
    ):
        if not config.is_collect_metrics_mode():
            return
        item = self._get_metric_handler_item_for_context(context)
        item.request_after_parse = copy.deepcopy(context.service_request)

    def record_exception(
        self, chain: HandlerChain, exception: Exception, context: RequestContext, response: Response
    ):
        if not config.is_collect_metrics_mode():
            return
        item = self._get_metric_handler_item_for_context(context)
        item.caught_exception_name = exception.__class__.__name__

    def update_metric_collection(
        self, chain: HandlerChain, context: RequestContext, response: Response
    ):
        if not config.is_collect_metrics_mode() or not context.service_operation:
            return

        is_internal = is_internal_call_context(context.request.headers)
        item = self._get_metric_handler_item_for_context(context)

        # parameters might get changed when dispatched to the service - we use the params stored in request_after_parse
        parameters = ",".join(item.request_after_parse or "")

        response_data = response.data.decode("utf-8") if response.status_code >= 300 else ""

        MetricHandler.metric_data.append(
            Metric(
                service=context.service_operation.service,
                operation=context.service_operation.operation,
                headers=context.request.headers,
                parameters=parameters,
                response_code=response.status_code,
                response_data=response_data,
                exception=context.service_exception.__class__.__name__
                if context.service_exception
                else "",
                origin="internal" if is_internal else "external",
            )
        )

        # cleanup
        del self.metrics_handler_items[context]

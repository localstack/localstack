import copy
import logging
from typing import Dict, Optional

from botocore.parsers import create_parser as create_response_parser

from localstack import config
from localstack.aws.api import RequestContext, ServiceRequest, ServiceResponse
from localstack.aws.chain import HandlerChain
from localstack.http import Response
from localstack.services.plugins import SERVICE_PLUGINS

LOG = logging.getLogger(__name__)


class Metric:
    request_id: str
    request_context: RequestContext
    request_after_parse: Optional[ServiceRequest]
    request_after_dispatch: Optional[ServiceRequest]
    caught_exception: Optional[Exception]
    http_response: Optional[Response]
    parsed_response: Optional[ServiceResponse]

    def __init__(self, request_contex: RequestContext) -> None:
        super().__init__()
        self.request_id = str(hash(request_contex))
        self.request_context = request_contex
        self.request_after_parse = None
        self.request_after_dispatch = None
        self.caught_exception = None
        self.http_response = None
        self.parsed_response = None


def _init_service_metric_counter() -> Dict:

    if not config.is_collect_metrics_mode():
        return {}

    metric_recorder = {}
    from localstack.aws.spec import load_service

    for s in SERVICE_PLUGINS.list_available():
        try:
            service = load_service(s)
            ops = {}
            for op in service.operation_names:
                params = {}
                if hasattr(service.operation_model(op).input_shape, "members"):
                    for n in service.operation_model(op).input_shape.members:
                        params[n] = 0
                if hasattr(service.operation_model(op), "error_shapes"):
                    exceptions = {}
                    for e in service.operation_model(op).error_shapes:
                        exceptions[e.name] = 0
                    params["errors"] = exceptions
                ops[op] = params

            metric_recorder[s] = ops
        except Exception:
            LOG.debug(f"cannot load service '{s}'")
    return metric_recorder


class MetricCollector:
    metric_recorder = _init_service_metric_counter()
    node_id = None
    xfail = False

    def __init__(self) -> None:
        self.metrics = {}

    def create_metric(self, chain: HandlerChain, context: RequestContext, response: Response):
        metric = Metric(context)
        self.metrics[context] = metric

    def _get_metric_for_context(self, context: RequestContext):
        return self.metrics[context]

    def record_parsed_request(
        self, chain: HandlerChain, context: RequestContext, response: Response
    ):
        metric = self._get_metric_for_context(context)
        metric.request_after_parse = copy.deepcopy(context.service_request)

    def record_dispatched_request(
        self, chain: HandlerChain, context: RequestContext, response: Response
    ):
        metric = self._get_metric_for_context(context)
        metric.request_after_dispatch = copy.deepcopy(context.service_request)

    def record_exception(
        self, chain: HandlerChain, exception: Exception, context: RequestContext, response: Response
    ):
        metric = self._get_metric_for_context(context)
        metric.caught_exception = exception

    def record_response(self, chain: HandlerChain, context: RequestContext, response: Response):
        metric = self._get_metric_for_context(context)

        # check if response is set
        if not response.response:
            return

        metric.http_response = response
        try:
            metric.parsed_response = self._parse_response(context, response)
        except Exception:
            LOG.exception("Error parsing response")

    def _parse_response(self, context: RequestContext, response: Response) -> ServiceResponse:
        operation_model = context.operation
        response_dict = {  # this is what botocore.endpoint.convert_to_response_dict normally does
            "headers": dict(response.headers.items()),  # boto doesn't like werkzeug headers
            "status_code": response.status_code,
            "body": response.data,
            "context": {
                "operation_name": operation_model.name if operation_model else "",
            },
        }

        parser = create_response_parser(context.service.protocol)
        return parser.parse(response_dict, operation_model.output_shape)

    def update_metric_collection(
        self, chain: HandlerChain, context: RequestContext, response: Response
    ):
        if (
            not config.is_collect_metrics_mode()
            or MetricCollector.xfail
            or not context.service_operation
        ):
            return
        metric = self._get_metric_for_context(context)
        if metric.caught_exception:
            ops = MetricCollector.metric_recorder[context.service_operation.service][
                context.service_operation.operation
            ]
            errors = ops.setdefault("errors", {})
            if metric.caught_exception.__class__.__name__ not in errors:
                # some errors are not explicitly in the shape, but are wrapped in a "CommonServiceException"
                errors = ops.setdefault("errors_not_in_shape", {})
            errors[metric.caught_exception.__class__.__name__] = (
                ops.get(metric.caught_exception.__class__.__name__, 0) + 1
            )

        if metric.request_after_parse and metric.http_response:
            if not str(metric.http_response.status_code).startswith("5"):
                ops = MetricCollector.metric_recorder[context.service_operation.service][
                    context.service_operation.operation
                ]
                if not context.service_request:
                    ops["none"] = ops.get("none", 0) + 1
                else:
                    for p in context.service_request:
                        # some params seem to be set implicitly but have 'None' value
                        if context.service_request[p] is not None:
                            ops[p] += 1

                test_list = ops.setdefault("tests", [])
                if MetricCollector.node_id not in test_list:
                    test_list.append(MetricCollector.node_id)

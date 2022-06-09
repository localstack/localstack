import copy
import logging
from typing import Dict, Optional

from botocore.parsers import create_parser as create_response_parser

from localstack import config
from localstack.aws.api import RequestContext, ServiceRequest, ServiceResponse
from localstack.aws.chain import HandlerChain
from localstack.http import Response
from localstack.services.plugins import SERVICE_PLUGINS
from localstack.utils.aws.aws_stack import is_internal_call_context

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

    for s, provider in SERVICE_PLUGINS.api_provider_specs.items():
        try:
            service = load_service(s)
            ops = {}
            service_attributes = {"pro": "pro" in provider, "community": "default" in provider}
            ops["service_attributes"] = service_attributes
            for op in service.operation_names:
                attributes = {}
                attributes["invoked"] = 0
                if hasattr(service.operation_model(op).input_shape, "members"):
                    params = {}
                    for n in service.operation_model(op).input_shape.members:
                        params[n] = 0
                    attributes["parameters"] = params
                if hasattr(service.operation_model(op), "error_shapes"):
                    exceptions = {}
                    for e in service.operation_model(op).error_shapes:
                        exceptions[e.name] = 0
                    attributes["errors"] = exceptions
                ops[op] = attributes

            metric_recorder[s] = ops
        except Exception:
            LOG.debug(f"cannot load service '{s}'")
    return metric_recorder


class MetricCollector:
    metric_recorder_internal = _init_service_metric_counter()
    metric_recorder_external = _init_service_metric_counter()
    node_id = None
    xfail = False
    data = []

    def __init__(self) -> None:
        self.metrics = {}

    def create_metric(self, chain: HandlerChain, context: RequestContext, response: Response):
        if not config.is_collect_metrics_mode():
            return
        metric = Metric(context)
        self.metrics[context] = metric

    def _get_metric_for_context(self, context: RequestContext):
        return self.metrics[context]

    def record_parsed_request(
        self, chain: HandlerChain, context: RequestContext, response: Response
    ):
        if not config.is_collect_metrics_mode():
            return
        metric = self._get_metric_for_context(context)
        metric.request_after_parse = copy.deepcopy(context.service_request)

    def record_dispatched_request(
        self, chain: HandlerChain, context: RequestContext, response: Response
    ):
        if not config.is_collect_metrics_mode():
            return
        metric = self._get_metric_for_context(context)
        metric.request_after_dispatch = copy.deepcopy(context.service_request)

    def record_exception(
        self, chain: HandlerChain, exception: Exception, context: RequestContext, response: Response
    ):
        if not config.is_collect_metrics_mode():
            return
        metric = self._get_metric_for_context(context)
        metric.caught_exception = exception

    def record_response(self, chain: HandlerChain, context: RequestContext, response: Response):
        if not config.is_collect_metrics_mode():
            return
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
            "body": "",  # TODO removed body to test problem with kinesis data streams response.data,
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

        is_internal = is_internal_call_context(context.request.headers)
        recorder = (
            MetricCollector.metric_recorder_internal
            if is_internal
            else MetricCollector.metric_recorder_external
        )

        metric = self._get_metric_for_context(context)

        service = recorder[context.service_operation.service]
        ops = service[context.service_operation.operation]

        if metric.caught_exception:
            errors = ops.setdefault("errors", {})
            if metric.caught_exception.__class__.__name__ not in errors:
                # some errors are not explicitly in the shape, but are wrapped in a "CommonServiceException"
                errors = ops.setdefault("errors_not_in_shape", {})
            errors[metric.caught_exception.__class__.__name__] = (
                ops.get(metric.caught_exception.__class__.__name__, 0) + 1
            )

        req = metric.request_after_parse
        ops["invoked"] += 1
        if not req:
            ops["parameters"]["_none_"] = ops["parameters"].get("_none_", 0) + 1
        else:
            for p in req:
                # some params seem to be set implicitly but have 'None' value
                if req[p] is not None:
                    ops["parameters"][p] += 1

        test_list = ops.setdefault("tests", [])
        if MetricCollector.node_id not in test_list:
            test_list.append(MetricCollector.node_id)

        parameters = ",".join(metric.request_after_parse or "")
        MetricCollector.data.append(
            [
                context.service_operation.service,
                context.service_operation.operation,
                parameters,
                response.status_code,
                response.data.decode("utf-8")
                if not str(response.status_code).startswith("2")
                else "",
                metric.caught_exception.__class__.__name__ if metric.caught_exception else "",
                MetricCollector.node_id,
                MetricCollector.xfail,
                "internal" if is_internal else "external",
            ]
        )

        # cleanup
        del self.metrics[context]

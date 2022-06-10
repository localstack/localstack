import logging
from typing import Dict

from localstack import config
from localstack.services.plugins import SERVICE_PLUGINS

LOG = logging.getLogger(__name__)


def _patch_skeleton_on_service_exception():
    def patch_on_service_exception(target, self, context, exception):
        if context.service_operation:
            ops = MetricRecorder.metric_recorder[context.service_operation.service][
                context.service_operation.operation
            ]
            errors = ops.setdefault("errors", {})
            if exception.__class__.__name__ not in errors:
                # some errors are not explicitly in the shape, but are wrapped in a "CommonServiceException"
                errors = ops.setdefault("errors_not_in_shape", {})
            errors[exception.__class__.__name__] = ops.get(exception.__class__.__name__, 0) + 1
        return target(self, context, exception)

    def patch_dispatch_request(target, self, context, instance):
        if context.service_operation:
            ops = MetricRecorder.metric_recorder[context.service_operation.service][
                context.service_operation.operation
            ]
            if not context.service_request:
                ops["none"] = ops.get("none", 0) + 1
            else:
                for p in context.service_request:
                    # some params seem to be set implicitly but have 'None' value
                    if context.service_request[p] is not None:
                        # TODO stackid in 'CreateChangeSet' caused error -> request modified?
                        ops[p] += 1

            test_list = ops.setdefault("tests", [])
            if MetricRecorder.node_id not in test_list:
                test_list.append(MetricRecorder.node_id)

        # TODO collect error responses here? Already collect service exceptions

        return target(self, context, instance)

    from localstack.aws.skeleton import Skeleton
    from localstack.utils.patch import Patch

    patches = [
        Patch.function(
            Skeleton.on_service_exception,
            patch_on_service_exception,
            pass_target=True,
        ),
        Patch.function(
            Skeleton.dispatch_request,
            patch_dispatch_request,
            pass_target=True,
        ),
    ]
    for p in patches:
        p.apply()


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

    # apply a patch so that we can count the service exceptions
    _patch_skeleton_on_service_exception()
    return metric_recorder


class MetricRecorder:
    metric_recorder = _init_service_metric_counter()
    node_id = None

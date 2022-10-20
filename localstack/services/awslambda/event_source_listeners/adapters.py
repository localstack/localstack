import json
import logging
from abc import ABC
from concurrent.futures import Future

from localstack.aws.api.lambda_ import InvocationType
from localstack.services.awslambda import api_utils
from localstack.services.awslambda.invocation.lambda_models import InvocationError, InvocationResult
from localstack.services.awslambda.invocation.lambda_service import LambdaService
from localstack.services.awslambda.invocation.models import lambda_stores
from localstack.services.awslambda.lambda_executors import (
    InvocationResult as LegacyInvocationResult,  # TODO: extract
)
from localstack.services.awslambda.lambda_utils import event_source_arn_matches
from localstack.utils.strings import to_bytes, to_str

LOG = logging.getLogger(__name__)


class EventSourceAdapter(ABC):
    """Adapter for the communication between event source mapping and lambda service"""

    def invoke(self, function_arn, context, payload, invocation_type, callback) -> None:
        pass

    def get_event_sources(self, source_arn: str):
        pass


class EventSourceLegacyAdapter(EventSourceAdapter):
    def __init__(self):
        pass

    def invoke(self, function_arn, context, payload, invocation_type, callback):
        from localstack.services.awslambda.lambda_api import run_lambda

        run_lambda(
            func_arn=function_arn,
            event=payload,
            context=context,
            asynchronous=(invocation_type == InvocationType.Event),
            callback=callback,
        )

    def get_event_sources(self, source_arn: str) -> list:
        from localstack.services.awslambda.lambda_api import get_event_sources

        return get_event_sources(source_arn=source_arn)


class EventSourceAsfAdapter(EventSourceAdapter):
    """
    Used to bridge run_lambda instances to the new provider
    """

    lambda_service: LambdaService

    def __init__(self, lambda_service: LambdaService):
        self.lambda_service = lambda_service

    def invoke(self, function_arn, context, payload, invocation_type, callback):

        # split ARN ( a bit unnecessary since we build an ARN again in the service)
        fn_parts = api_utils.FULL_FN_ARN_PATTERN.search(function_arn).groupdict()

        ft = self.lambda_service.invoke(
            # basically function ARN
            function_name=fn_parts["function_name"],
            qualifier=fn_parts["qualifier"],
            region=fn_parts["region_name"],
            account_id=fn_parts["account_id"],
            invocation_type=invocation_type,
            client_context=json.dumps(context or {}),
            payload=to_bytes(json.dumps(payload or {})),
        )

        def new_callback(ft_result: Future[InvocationResult]) -> None:
            try:
                result = ft_result.result(timeout=10)
                error = None
                if isinstance(result, InvocationError):
                    error = "?"
                callback(
                    result=LegacyInvocationResult(
                        result=to_str(json.loads(result.payload)),
                        log_output=result.logs,
                    ),
                    func_arn="doesntmatter",
                    event="doesntmatter",
                    error=error,
                )

            except Exception as e:
                # TODO: map exception to old error format?
                LOG.error(e)
                callback(
                    result=None,
                    func_arn="doesntmatter",
                    event="doesntmatter",
                    error=e,
                )

        ft.add_done_callback(new_callback)

    def get_event_sources(self, source_arn: str):
        # assuming the region/account from function_arn
        results = []
        for account_id in lambda_stores:
            for region in lambda_stores[account_id]:
                state = lambda_stores[account_id][region]
                for esm in state.event_source_mappings.values():
                    if event_source_arn_matches(
                        mapped=esm.get("EventSourceArn"), searched=source_arn
                    ):
                        results.append(esm)
        return results

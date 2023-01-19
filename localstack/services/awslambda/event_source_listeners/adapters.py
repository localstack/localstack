import json
import logging
import threading
from abc import ABC
from concurrent.futures import Future
from typing import Callable, Optional

from localstack import config
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
    """
    Adapter for the communication between event source mapping and lambda service
    Generally just a temporary construct to bridge the old and new provider and re-use the existing event source listeners.

    Remove this file when sunsetting the legacy provider or when replacing the event source listeners.
    """

    def invoke(
        self,
        function_arn: str,
        context: dict,
        payload: dict,
        invocation_type: InvocationType,
        callback: Optional[Callable] = None,
    ) -> None:
        pass

    def invoke_with_statuscode(
        self,
        function_arn,
        context,
        payload,
        invocation_type,
        callback=None,
        *,
        lock_discriminator,
        parallelization_factor
    ) -> int:
        pass

    def get_event_sources(self, source_arn: str):
        pass


class EventSourceLegacyAdapter(EventSourceAdapter):
    def __init__(self):
        pass

    def invoke(self, function_arn, context, payload, invocation_type, callback=None):
        from localstack.services.awslambda.lambda_api import run_lambda

        run_lambda(
            func_arn=function_arn,
            event=payload,
            context=context,
            asynchronous=(invocation_type == InvocationType.Event),
            callback=callback,
        )

    def invoke_with_statuscode(
        self,
        function_arn,
        context,
        payload,
        invocation_type,
        callback=None,
        *,
        lock_discriminator,
        parallelization_factor
    ) -> int:
        from localstack.services.awslambda import lambda_executors
        from localstack.services.awslambda.lambda_api import run_lambda

        if not config.SYNCHRONOUS_KINESIS_EVENTS:
            lambda_executors.LAMBDA_ASYNC_LOCKS.assure_lock_present(
                lock_discriminator, threading.BoundedSemaphore(parallelization_factor)
            )
        else:
            lock_discriminator = None

        result = run_lambda(
            func_arn=function_arn,
            event=payload,
            context=context,
            asynchronous=(invocation_type == InvocationType.Event),
            callback=callback,
            lock_discriminator=lock_discriminator,
        )
        status_code = getattr(result.result, "status_code", 0)
        return status_code

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

    def invoke(self, function_arn, context, payload, invocation_type, callback=None):

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

        if callback:

            def mapped_callback(ft_result: Future[InvocationResult]) -> None:
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
                    LOG.debug("Encountered an exception while handling callback", exc_info=True)
                    callback(
                        result=None,
                        func_arn="doesntmatter",
                        event="doesntmatter",
                        error=e,
                    )

            ft.add_done_callback(mapped_callback)

    def invoke_with_statuscode(
        self,
        function_arn,
        context,
        payload,
        invocation_type,
        callback=None,
        *,
        lock_discriminator,
        parallelization_factor
    ) -> int:
        # split ARN ( a bit unnecessary since we build an ARN again in the service)
        fn_parts = api_utils.FULL_FN_ARN_PATTERN.search(function_arn).groupdict()

        try:
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

            if callback:

                def mapped_callback(ft_result: Future[InvocationResult]) -> None:
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
                        LOG.debug("Encountered an exception while handling callback", exc_info=True)
                        callback(
                            result=None,
                            func_arn="doesntmatter",
                            event="doesntmatter",
                            error=e,
                        )

                ft.add_done_callback(mapped_callback)

            # they're always synchronous in the ASF provider
            result = ft.result(timeout=900)
            if isinstance(result, InvocationError):
                return 500
            else:
                return 200
        except Exception:
            LOG.debug("Encountered an exception while handling lambda invoke", exc_info=True)
            return 500

    def get_event_sources(self, source_arn: str):
        # assuming the region/account from function_arn
        results = []
        for account_id in lambda_stores:
            for region in lambda_stores[account_id]:
                state = lambda_stores[account_id][region]
                for esm in state.event_source_mappings.values():
                    if (
                        event_source_arn_matches(
                            mapped=esm.get("EventSourceArn"), searched=source_arn
                        )
                        and esm.get("State", "") == "Enabled"
                    ):
                        results.append(esm.copy())
        return results

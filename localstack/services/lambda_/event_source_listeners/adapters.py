import abc
import json
import logging
import threading
from abc import ABC
from functools import lru_cache
from typing import Callable, Optional

from localstack import config
from localstack.aws.api.lambda_ import InvocationType
from localstack.aws.connect import ServiceLevelClientFactory, connect_to
from localstack.aws.protocol.serializer import gen_amzn_requestid
from localstack.services.lambda_ import api_utils
from localstack.services.lambda_.api_utils import function_locators_from_arn, qualifier_is_version
from localstack.services.lambda_.invocation.lambda_models import InvocationResult
from localstack.services.lambda_.invocation.lambda_service import LambdaService
from localstack.services.lambda_.invocation.models import lambda_stores
from localstack.services.lambda_.legacy.lambda_executors import (
    InvocationResult as LegacyInvocationResult,  # TODO: extract
)
from localstack.services.lambda_.legacy.lambda_utils import event_source_arn_matches
from localstack.utils.aws.client_types import ServicePrincipal
from localstack.utils.json import BytesEncoder
from localstack.utils.strings import to_bytes, to_str
from localstack.utils.threads import FuncThread

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

    @abc.abstractmethod
    def get_client_factory(self, function_arn: str, region_name: str) -> ServiceLevelClientFactory:
        pass


class EventSourceLegacyAdapter(EventSourceAdapter):
    def __init__(self):
        pass

    def invoke(self, function_arn, context, payload, invocation_type, callback=None):
        from localstack.services.lambda_.legacy.lambda_api import run_lambda

        try:
            json.dumps(payload)
        except TypeError:
            payload = json.loads(json.dumps(payload or {}, cls=BytesEncoder))

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
        from localstack.services.lambda_.legacy import lambda_executors
        from localstack.services.lambda_.legacy.lambda_api import run_lambda

        if not config.SYNCHRONOUS_KINESIS_EVENTS:
            lambda_executors.LAMBDA_ASYNC_LOCKS.assure_lock_present(
                lock_discriminator, threading.BoundedSemaphore(parallelization_factor)
            )
        else:
            lock_discriminator = None

        try:
            json.dumps(payload)
        except TypeError:
            payload = json.loads(json.dumps(payload or {}, cls=BytesEncoder))

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
        from localstack.services.lambda_.legacy.lambda_api import get_event_sources

        return get_event_sources(source_arn=source_arn)

    def get_client_factory(self, function_arn: str, region_name: str) -> ServiceLevelClientFactory:
        return connect_to(region_name=region_name)


class EventSourceAsfAdapter(EventSourceAdapter):
    """
    Used to bridge run_lambda instances to the new provider
    """

    lambda_service: LambdaService

    def __init__(self, lambda_service: LambdaService):
        self.lambda_service = lambda_service

    def invoke(self, function_arn, context, payload, invocation_type, callback=None):
        def _invoke(*args, **kwargs):
            # split ARN ( a bit unnecessary since we build an ARN again in the service)
            fn_parts = api_utils.FULL_FN_ARN_PATTERN.search(function_arn).groupdict()

            result = self.lambda_service.invoke(
                # basically function ARN
                function_name=fn_parts["function_name"],
                qualifier=fn_parts["qualifier"],
                region=fn_parts["region_name"],
                account_id=fn_parts["account_id"],
                invocation_type=invocation_type,
                client_context=json.dumps(context or {}),
                payload=to_bytes(json.dumps(payload or {}, cls=BytesEncoder)),
                request_id=gen_amzn_requestid(),
            )

            if callback:
                try:
                    error = None
                    if result.is_error:
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

        thread = FuncThread(_invoke)
        thread.start()

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
            result = self.lambda_service.invoke(
                # basically function ARN
                function_name=fn_parts["function_name"],
                qualifier=fn_parts["qualifier"],
                region=fn_parts["region_name"],
                account_id=fn_parts["account_id"],
                invocation_type=invocation_type,
                client_context=json.dumps(context or {}),
                payload=to_bytes(json.dumps(payload or {}, cls=BytesEncoder)),
                request_id=gen_amzn_requestid(),
            )

            if callback:

                def mapped_callback(result: InvocationResult) -> None:
                    try:
                        error = None
                        if result.is_error:
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

                mapped_callback(result)

            # they're always synchronous in the ASF provider
            if result.is_error:
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

    @lru_cache(maxsize=64)
    def _cached_client_factory(self, region_name: str, role_arn: str) -> ServiceLevelClientFactory:
        return connect_to.with_assumed_role(
            role_arn=role_arn, region_name=region_name, service_principal=ServicePrincipal.lambda_
        )

    def _get_role_for_function(self, function_arn: str) -> str:
        function_name, qualifier, account, region = function_locators_from_arn(function_arn)
        store = lambda_stores[account][region]
        function = store.functions.get(function_name)
        if qualifier and qualifier != "$LATEST":
            if qualifier_is_version(qualifier):
                version_number = qualifier
            else:
                # the role of the routing config version and the regular configured version has to be identical
                version_number = function.aliases.get(qualifier).function_version
            version = function.versions.get(version_number)
        else:
            version = function.latest()
        return version.config.role

    def get_client_factory(self, function_arn: str, region_name: str) -> ServiceLevelClientFactory:
        role_arn = self._get_role_for_function(function_arn)

        return self._cached_client_factory(region_name=region_name, role_arn=role_arn)

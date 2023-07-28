import contextlib
import logging
from collections import defaultdict
from threading import RLock

from localstack import config
from localstack.aws.api.lambda_ import TooManyRequestsException
from localstack.services.lambda_.invocation.lambda_models import (
    Function,
    FunctionVersion,
    InitializationType,
)
from localstack.services.lambda_.invocation.models import lambda_stores
from localstack.utils.objects import singleton_factory

LOG = logging.getLogger(__name__)


class ConcurrencyTracker:
    """Keeps track of the number of running invocations per function"""

    lock: RLock

    # Concurrency tracker for provisioned concurrency can have a lock per function-version, rather than per function
    # function ARN (unqualified or qualified) => number of currently running invocations
    function_concurrency: dict[str, int]

    def __init__(self):
        self.function_concurrency = defaultdict(int)
        self.lock = RLock()


# class CountingServiceView:
#
#     counting_service: "CountingService"
#     account: str
#     region: str
#
#     def __init__(self, counting_service: "CountingService", account: str, region: str):
#         self.counting_service = counting_service
#         self.account = account
#         self.region = region
#
#     @contextlib.contextmanager
#     def get_invocation_lease(self) -> InitializationType:
#
#         # self.counting_service.get_invocation_lease()


class CountingService:
    """
    scope: per region and account
    enforcement of quota limits
    called on *each* invoke
    count invocations, keep track of concurrent invocations, ....
    """

    # Concurrency limits are per region and account
    # * https://repost.aws/knowledge-center/lambda-concurrency-limit-increase
    # * https://docs.aws.amazon.com/lambda/latest/dg/lambda-concurrency.htm
    # (account, region) => ConcurrencyTracker
    on_demand_concurrency_trackers: dict[(str, str), ConcurrencyTracker]
    # (account, region) => ConcurrencyTracker
    provisioned_concurrency_trackers: dict[(str, str), ConcurrencyTracker]
    # Lock for creating concurrency tracker
    lock: RLock

    def __init__(self):
        self.on_demand_concurrency_trackers = {}
        self.provisioned_concurrency_trackers = {}
        self.lock = RLock()

    @contextlib.contextmanager
    def get_invocation_lease(
        self, function: Function, function_version: FunctionVersion
    ) -> InitializationType:
        account = function_version.id.account
        region = function_version.id.region
        scope_tuple = (account, region)
        scoped_tracker = self.on_demand_concurrency_trackers.get(scope_tuple)
        if not scoped_tracker:
            with self.lock:
                scoped_tracker = self.on_demand_concurrency_trackers.get(scope_tuple)
                if not scoped_tracker:
                    scoped_tracker = self.on_demand_concurrency_trackers[
                        scope_tuple
                    ] = ConcurrencyTracker()
        unqualified_function_arn = function_version.id.unqualified_arn()

        qualified_arn = function_version.id.qualified_arn()
        provisioned_scoped_tracker = self.provisioned_concurrency_trackers.get(scope_tuple)
        if not provisioned_scoped_tracker:
            # MAYBE: could create separate lock for provisioned concurrency tracker (i.e., optimization)
            with self.lock:
                provisioned_scoped_tracker = self.provisioned_concurrency_trackers.get(scope_tuple)
                if not provisioned_scoped_tracker:
                    provisioned_scoped_tracker = self.provisioned_concurrency_trackers[
                        scope_tuple
                    ] = ConcurrencyTracker()

        # Daniel: async event handling. How do we know whether we can re-schedule the event?
        # Events can stay in the queue for hours.
        # TODO: write a test with reserved concurrency=0 (or unavailble) and an async invoke
        # TODO: write a test for reserved concurrency scheduling preference

        # TODO: fix locking => currently locks during yield !!!
        # with scoped_tracker.lock:
        # Tracker:
        # * per function version for provisioned concurrency
        # * per function for on-demand
        # => we can derive unreserved_concurrent_executions but could also consider a dedicated (redundant) counter

        # 1) Check for free provisioned concurrency
        # NOTE: potential challenge if an update happens in between reserving the lease here and actually assigning
        # * Increase provisioned: It could happen that we give a lease for provisioned-concurrency although
        # brand new provisioned environments are not yet initialized.
        # * Decrease provisioned: It could happen that we have running invocations that should still be counted
        # against the limit but they are not because we already updated the concurrency config to fewer envs.
        available_provisioned_concurrency = (
            function.provisioned_concurrency_configs.get(function_version.id.qualifier, 0)
            - provisioned_scoped_tracker.function_concurrency[qualified_arn]
        )
        if available_provisioned_concurrency > 0:
            provisioned_scoped_tracker.function_concurrency[qualified_arn] += 1
            yield "provisioned-concurrency"
            provisioned_scoped_tracker.function_concurrency[qualified_arn] -= 1

        # 2) reserved concurrency set => reserved concurrent executions only limited by local function limit
        if function.reserved_concurrent_executions is not None:
            on_demand_running_invocation_count = scoped_tracker.function_concurrency[
                unqualified_function_arn
            ]
            available_reserved_concurrency = (
                function.reserved_concurrent_executions
                - CountingService._calculate_provisioned_concurrency_sum(function)
                - on_demand_running_invocation_count
            )
            if available_reserved_concurrency:
                scoped_tracker.function_concurrency[unqualified_function_arn] += 1
                try:
                    yield "on-demand"
                finally:
                    scoped_tracker.function_concurrency[unqualified_function_arn] -= 1
                return
            else:
                raise TooManyRequestsException(
                    "Rate Exceeded.",
                    Reason="ReservedFunctionConcurrentInvocationLimitExceeded",
                    Type="User",
                )
        # 3) no reserved concurrency set. => consider account/region-global state instead
        else:
            # TODO: find better name (maybe check AWS docs ;) => unavailable_concurrency
            total_used_concurrency = 0
            store = lambda_stores[account][region]
            for fn in store.functions.values():
                if fn.reserved_concurrent_executions is not None:
                    total_used_concurrency += fn.reserved_concurrent_executions
                else:
                    fn_provisioned_concurrency = (
                        CountingService._calculate_provisioned_concurrency_sum(fn)
                    )
                    total_used_concurrency += fn_provisioned_concurrency
                    fn_on_demand_running_invocations = scoped_tracker.function_concurrency[
                        fn.latest().id.unqualified_arn()
                    ]
                    total_used_concurrency += fn_on_demand_running_invocations

            available_unreserved_concurrency = (
                config.LAMBDA_LIMITS_CONCURRENT_EXECUTIONS - total_used_concurrency
            )
            if available_unreserved_concurrency > 0:
                scoped_tracker.function_concurrency[unqualified_function_arn] += 1
                try:
                    yield "on-demand"
                finally:
                    scoped_tracker.function_concurrency[unqualified_function_arn] -= 1
                return
            elif available_unreserved_concurrency == 0:
                raise TooManyRequestsException(
                    "Rate Exceeded.",
                    Reason="ReservedFunctionConcurrentInvocationLimitExceeded",
                    Type="User",
                )
            else:  # sanity check for available_unreserved_concurrency < 0
                LOG.warning(
                    "Invalid function concurrency state detected for function: %s | available unreserved concurrency: %d",
                    unqualified_function_arn,
                    available_unreserved_concurrency,
                )

    # TODO: refactor into module
    @staticmethod
    def _calculate_provisioned_concurrency_sum(function: Function) -> int:
        provisioned_concurrency_sum_for_fn = sum(
            [
                provisioned_configs.provisioned_concurrent_executions
                for provisioned_configs in function.provisioned_concurrency_configs.values()
            ]
        )
        return provisioned_concurrency_sum_for_fn

    # Alternative: create in service
    @staticmethod
    @singleton_factory
    def get() -> "CountingService":
        return CountingService()

    # @classmethod
    # def get_view(cls, account, region) -> CountingServiceView:
    #     return CountingServiceView(cls.get(), account, region)

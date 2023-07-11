import contextlib
import logging
from collections import defaultdict
from threading import RLock

from localstack import config
from localstack.aws.api.lambda_ import TooManyRequestsException
from localstack.services.lambda_.invocation.lambda_models import Function, InitializationType
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
    * https://repost.aws/knowledge-center/lambda-concurrency-limit-increase
    * https://docs.aws.amazon.com/lambda/latest/dg/lambda-concurrency.htm
    enforcement of quota limits
    called on *each* invoke
    count invocations, keep track of concurrent invocations, ....
    """

    # TODO: lock when creating trackers
    # Concurrency limits are per region and account
    # (account, region) => ConcurrencyTracker
    concurrency_trackers: dict[(str, str), ConcurrencyTracker]
    lock: RLock

    def __init__(self):
        self.concurrency_trackers = {}
        self.lock = RLock()

    @contextlib.contextmanager
    def get_invocation_lease(self, function: Function) -> InitializationType:
        account = function.latest().id.account
        region = function.latest().id.region
        scope_tuple = (account, region)
        scoped_tracker = self.concurrency_trackers.get(scope_tuple)
        if not scoped_tracker:
            with self.lock:
                scoped_tracker = self.concurrency_trackers.get(scope_tuple)
                if not scoped_tracker:
                    scoped_tracker = self.concurrency_trackers[scope_tuple] = ConcurrencyTracker()
        unqualified_function_arn = function.latest().id.unqualified_arn()

        # Daniel: async event handling. How do we know whether we can re-schedule the event?
        # Events can stay in the queue for hours.
        # TODO: write a test with reserved concurrency=0 (or unavailble) and an async invoke

        # TODO: fix locking => currently locks during yield !!!
        with scoped_tracker.lock:
            # Tracker:
            # * per function version for provisioned concurrency
            # * per function for on-demand
            # => we can derive unreserved_concurrent_executions but could also consider a dedicated (redundant) counter

            # 1) TODO: Check for free provisioned concurrency
            # if available_provisioned_concurrency:
            #     yield "provisioned-concurrency"

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

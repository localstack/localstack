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
from localstack.utils.lambda_debug_mode.lambda_debug_mode import (
    is_lambda_debug_enabled_for,
)

LOG = logging.getLogger(__name__)


class ConcurrencyTracker:
    """Keeps track of the number of concurrent executions per lock scope (e.g., per function or function version).
    The lock scope depends on the provisioning type (i.e., on-demand or provisioned):
    * on-demand concurrency per function: unqualified arn ending with my-function
    * provisioned concurrency per function version: qualified arn ending with my-function:1
    """

    # Lock scope => concurrent executions counter
    concurrent_executions: dict[str, int]
    # Lock for safely updating the concurrent executions counter
    lock: RLock

    def __init__(self):
        self.concurrent_executions = defaultdict(int)
        self.lock = RLock()

    def increment(self, scope: str) -> None:
        self.concurrent_executions[scope] += 1

    def atomic_decrement(self, scope: str):
        with self.lock:
            self.decrement(scope)

    def decrement(self, scope: str) -> None:
        self.concurrent_executions[scope] -= 1


def calculate_provisioned_concurrency_sum(function: Function) -> int:
    """Returns the total provisioned concurrency for a given function, including all versions."""
    provisioned_concurrency_sum_for_fn = sum(
        [
            provisioned_configs.provisioned_concurrent_executions
            for provisioned_configs in function.provisioned_concurrency_configs.values()
        ]
    )
    return provisioned_concurrency_sum_for_fn


class CountingService:
    """
    The CountingService enforces quota limits per region and account in get_invocation_lease()
    for every Lambda invocation. It uses separate ConcurrencyTrackers for on-demand and provisioned concurrency
    to keep track of the number of concurrent invocations.

    Concurrency limits are per region and account:
    https://repost.aws/knowledge-center/lambda-concurrency-limit-increase
    https://docs.aws.amazon.com/lambda/latest/dg/lambda-concurrency.htm
    https://docs.aws.amazon.com/lambda/latest/dg/monitoring-concurrency.html
    """

    # (account, region) => ConcurrencyTracker (unqualified arn) => concurrent executions
    on_demand_concurrency_trackers: dict[(str, str), ConcurrencyTracker]
    # Lock for safely initializing new on-demand concurrency trackers
    on_demand_init_lock: RLock

    # (account, region) => ConcurrencyTracker (qualified arn) => concurrent executions
    provisioned_concurrency_trackers: dict[(str, str), ConcurrencyTracker]
    # Lock for safely initializing new provisioned concurrency trackers
    provisioned_concurrency_init_lock: RLock

    def __init__(self):
        self.on_demand_concurrency_trackers = {}
        self.on_demand_init_lock = RLock()
        self.provisioned_concurrency_trackers = {}
        self.provisioned_concurrency_init_lock = RLock()

    @contextlib.contextmanager
    def get_invocation_lease(
        self, function: Function | None, function_version: FunctionVersion
    ) -> InitializationType:
        """An invocation lease reserves the right to schedule an invocation.
        The returned lease type can either be on-demand or provisioned.
        Scheduling preference:
        1) Check for free provisioned concurrency => provisioned
        2) Check for reserved concurrency => on-demand
        3) Check for unreserved concurrency => on-demand

        HACK: We allow the function to be None for Lambda@Edge to skip provisioned and reserved concurrency.
        """
        account = function_version.id.account
        region = function_version.id.region
        scope_tuple = (account, region)
        on_demand_tracker = self.on_demand_concurrency_trackers.get(scope_tuple)
        # Double-checked locking pattern to initialize an on-demand concurrency tracker if it does not exist
        if not on_demand_tracker:
            with self.on_demand_init_lock:
                on_demand_tracker = self.on_demand_concurrency_trackers.get(scope_tuple)
                if not on_demand_tracker:
                    on_demand_tracker = self.on_demand_concurrency_trackers[scope_tuple] = (
                        ConcurrencyTracker()
                    )

        provisioned_tracker = self.provisioned_concurrency_trackers.get(scope_tuple)
        # Double-checked locking pattern to initialize a provisioned concurrency tracker if it does not exist
        if not provisioned_tracker:
            with self.provisioned_concurrency_init_lock:
                provisioned_tracker = self.provisioned_concurrency_trackers.get(scope_tuple)
                if not provisioned_tracker:
                    provisioned_tracker = self.provisioned_concurrency_trackers[scope_tuple] = (
                        ConcurrencyTracker()
                    )

        # TODO: check that we don't give a lease while updating provisioned concurrency
        # Potential challenge if an update happens in between reserving the lease here and actually assigning
        # * Increase provisioned: It could happen that we give a lease for provisioned-concurrency although
        # brand new provisioned environments are not yet initialized.
        # * Decrease provisioned: It could happen that we have running invocations that should still be counted
        # against the limit but they are not because we already updated the concurrency config to fewer envs.

        unqualified_function_arn = function_version.id.unqualified_arn()
        qualified_arn = function_version.id.qualified_arn()

        # Enforce one lease per ARN if the global flag is set
        if is_lambda_debug_enabled_for(qualified_arn):
            with provisioned_tracker.lock, on_demand_tracker.lock:
                on_demand_executions: int = on_demand_tracker.concurrent_executions[
                    unqualified_function_arn
                ]
                provisioned_executions = provisioned_tracker.concurrent_executions[qualified_arn]
                if on_demand_executions or provisioned_executions:
                    LOG.warning(
                        "Concurrent lambda invocations disabled for '%s' by Lambda Debug Mode",
                        qualified_arn,
                    )
                    raise TooManyRequestsException(
                        "Rate Exceeded.",
                        Reason="SingleLeaseEnforcement",
                        Type="User",
                    )

        lease_type = None
        # HACK: skip reserved and provisioned concurrency if function not available (e.g., in Lambda@Edge)
        if function is not None:
            with provisioned_tracker.lock:
                # 1) Check for free provisioned concurrency
                provisioned_concurrency_config = function.provisioned_concurrency_configs.get(
                    function_version.id.qualifier
                )
                if not provisioned_concurrency_config:
                    # check if any aliases point to the current version, and check the provisioned concurrency config
                    # for them. There can be only one config for a version, not matter if defined on the alias or version itself.
                    for alias in function.aliases.values():
                        if alias.function_version == function_version.id.qualifier:
                            provisioned_concurrency_config = (
                                function.provisioned_concurrency_configs.get(alias.name)
                            )
                            break
                if provisioned_concurrency_config:
                    available_provisioned_concurrency = (
                        provisioned_concurrency_config.provisioned_concurrent_executions
                        - provisioned_tracker.concurrent_executions[qualified_arn]
                    )
                    if available_provisioned_concurrency > 0:
                        provisioned_tracker.increment(qualified_arn)
                        lease_type = "provisioned-concurrency"

        if not lease_type:
            with on_demand_tracker.lock:
                # 2) If reserved concurrency is set AND no provisioned concurrency available:
                # => Check if enough reserved concurrency is available for the specific function.
                # HACK: skip reserved if function not available (e.g., in Lambda@Edge)
                if function and function.reserved_concurrent_executions is not None:
                    on_demand_running_invocation_count = on_demand_tracker.concurrent_executions[
                        unqualified_function_arn
                    ]
                    available_reserved_concurrency = (
                        function.reserved_concurrent_executions
                        - calculate_provisioned_concurrency_sum(function)
                        - on_demand_running_invocation_count
                    )
                    if available_reserved_concurrency > 0:
                        on_demand_tracker.increment(unqualified_function_arn)
                        lease_type = "on-demand"
                    else:
                        extras = {
                            "available_reserved_concurrency": available_reserved_concurrency,
                            "reserved_concurrent_executions": function.reserved_concurrent_executions,
                            "provisioned_concurrency_sum": calculate_provisioned_concurrency_sum(
                                function
                            ),
                            "on_demand_running_invocation_count": on_demand_running_invocation_count,
                        }
                        LOG.debug("Insufficient reserved concurrency available: %s", extras)
                        raise TooManyRequestsException(
                            "Rate Exceeded.",
                            Reason="ReservedFunctionConcurrentInvocationLimitExceeded",
                            Type="User",
                        )
                # 3) If no reserved concurrency is set AND no provisioned concurrency available.
                # => Check the entire state within the scope of account and region.
                else:
                    # TODO: Consider a dedicated counter for unavailable concurrency with locks for updates on
                    #  reserved and provisioned concurrency if this is too slow
                    # The total concurrency allocated or used (i.e., unavailable concurrency) per account and region
                    total_used_concurrency = 0
                    store = lambda_stores[account][region]
                    for fn in store.functions.values():
                        if fn.reserved_concurrent_executions is not None:
                            total_used_concurrency += fn.reserved_concurrent_executions
                        else:
                            fn_provisioned_concurrency = calculate_provisioned_concurrency_sum(fn)
                            total_used_concurrency += fn_provisioned_concurrency
                            fn_on_demand_concurrent_executions = (
                                on_demand_tracker.concurrent_executions[
                                    fn.latest().id.unqualified_arn()
                                ]
                            )
                            total_used_concurrency += fn_on_demand_concurrent_executions

                    available_unreserved_concurrency = (
                        config.LAMBDA_LIMITS_CONCURRENT_EXECUTIONS - total_used_concurrency
                    )
                    if available_unreserved_concurrency > 0:
                        on_demand_tracker.increment(unqualified_function_arn)
                        lease_type = "on-demand"
                    else:
                        if available_unreserved_concurrency < 0:
                            LOG.error(
                                "Invalid function concurrency state detected for function: %s | available unreserved concurrency: %d",
                                unqualified_function_arn,
                                available_unreserved_concurrency,
                            )
                        extras = {
                            "available_unreserved_concurrency": available_unreserved_concurrency,
                            "lambda_limits_concurrent_executions": config.LAMBDA_LIMITS_CONCURRENT_EXECUTIONS,
                            "total_used_concurrency": total_used_concurrency,
                        }
                        LOG.debug("Insufficient unreserved concurrency available: %s", extras)
                        raise TooManyRequestsException(
                            "Rate Exceeded.",
                            Reason="ReservedFunctionConcurrentInvocationLimitExceeded",
                            Type="User",
                        )
        try:
            yield lease_type
        finally:
            if lease_type == "provisioned-concurrency":
                provisioned_tracker.atomic_decrement(qualified_arn)
            elif lease_type == "on-demand":
                on_demand_tracker.atomic_decrement(unqualified_function_arn)
            else:
                LOG.error(
                    "Invalid lease type detected for function: %s: %s",
                    unqualified_function_arn,
                    lease_type,
                )

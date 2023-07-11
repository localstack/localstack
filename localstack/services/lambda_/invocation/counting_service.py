import contextlib
from collections import defaultdict
from threading import RLock

from localstack.services.lambda_.invocation.lambda_models import InitializationType

class ConcurrencyTracker:
    """account-scoped concurrency tracker that keeps track of the number of running invocations per function"""

    lock: RLock

    # function unqualified ARN => number of currently running invocations
    function_concurrency: dict[str, int]

    def __init__(self):
        self.function_concurrency = defaultdict(int)
        self.lock = RLock()


class CountingService:
    """
    scope: per region and account
    enforcement of quota limits
    called on *each* invoke
    count invocations, keep track of concurrent invocations, ....
    """

    ...

    @contextlib.contextmanager
    def get_invocation_lease(self) -> InitializationType:
        # TODO: impl.
        # check and get lease
        yield "on-demand"
        # release lease

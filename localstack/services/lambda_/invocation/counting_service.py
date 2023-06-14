import contextlib

from localstack.services.lambda_.invocation.lambda_models import InitializationType


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

import logging

from localstack import config, constants
from localstack.runtime import hooks

LOG = logging.getLogger(__name__)


def enable_debugger():
    from localstack.packages.debugpy import debugpy_package

    debugpy_package.install()
    import debugpy  # noqa: T100

    LOG.info("Starting debug server at: %s:%s", constants.BIND_HOST, config.DEVELOP_PORT)
    debugpy.listen((constants.BIND_HOST, config.DEVELOP_PORT))  # noqa: T100

    if config.WAIT_FOR_DEBUGGER:
        debugpy.wait_for_client()  # noqa: T100


@hooks.on_infra_start()
def conditionally_enable_debugger():
    if config.DEVELOP:
        enable_debugger()

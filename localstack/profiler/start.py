import logging
import os

from localstack import config
from localstack.packages.functiontrace import (
    functiontrace_package,
    functiontrace_server_package,
)

LOG = logging.getLogger(__name__)


def start_profiling():
    functiontrace_server_package.install()

    # functiontrace-server must be on the PATH
    os.environ["PATH"] += os.pathsep + functiontrace_server_package.get_installed_dir()
    LOG.debug("Setting new path to %s", os.environ["PATH"])

    functiontrace_package.install()

    import functiontrace
    import _functiontrace

    output_dir = os.path.join(config.dirs.cache, "profiles")
    LOG.debug("storing profiles to %s", output_dir)
    os.makedirs(output_dir, exist_ok=True)

    functiontrace.setup_dependencies()
    _functiontrace.begin_tracing(output_dir)

"""Adapter code for the legacy runtime to make sure the new runtime is compatible with the old one,
and at the same time doesn't need ``localstack.services.infra``, which imports AWS-specific modules."""

import logging
import os
import signal
import threading

from localstack.runtime import events
from localstack.utils import objects

LOG = logging.getLogger(__name__)

# event flag indicating the infrastructure has been started and that the ready marker has been printed
# TODO: deprecated, use events.infra_ready
INFRA_READY = events.infra_ready

# event flag indicating that the infrastructure has been shut down
SHUTDOWN_INFRA = threading.Event()

# can be set
EXIT_CODE: objects.Value[int] = objects.Value(0)


def signal_supervisor_restart():
    if pid := os.environ.get("SUPERVISOR_PID"):
        os.kill(int(pid), signal.SIGUSR1)
    else:
        LOG.warning("could not signal supervisor to restart localstack")


def exit_infra(code: int):
    """
    Triggers an orderly shutdown of the localstack infrastructure and sets the code the main process should
    exit with to a specific value.

    :param code: the exit code the main process should return with
    """
    EXIT_CODE.set(code)
    SHUTDOWN_INFRA.set()

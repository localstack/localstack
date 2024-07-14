"""Adapter code for the legacy runtime to make sure the new runtime is compatible with the old one,
and at the same time doesn't need ``localstack.services.infra``, which imports AWS-specific modules."""

import logging
import os
import signal

from localstack.runtime import events

LOG = logging.getLogger(__name__)

# event flag indicating the infrastructure has been started and that the ready marker has been printed
# TODO: deprecated, use events.infra_ready
INFRA_READY = events.infra_ready


def signal_supervisor_restart():
    if pid := os.environ.get("SUPERVISOR_PID"):
        os.kill(int(pid), signal.SIGUSR1)
    else:
        LOG.warning("could not signal supervisor to restart localstack")

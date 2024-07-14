"""Adapter code for the legacy runtime to make sure the new runtime is compatible with the old one,
and at the same time doesn't need ``localstack.services.infra``, which imports AWS-specific modules."""

import logging
import os
import signal

LOG = logging.getLogger(__name__)


def signal_supervisor_restart():
    if pid := os.environ.get("SUPERVISOR_PID"):
        os.kill(int(pid), signal.SIGUSR1)
    else:
        LOG.warning("could not signal supervisor to restart localstack")

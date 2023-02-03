import logging

from localstack import config

# set up logger
LOG = logging.getLogger(__name__)


def is_persistence_enabled() -> bool:
    return config.PERSISTENCE and config.dirs.data


def is_persistence_restored():
    return not is_persistence_enabled()

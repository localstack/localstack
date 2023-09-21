import logging

from localstack.aws.api.ram import RamApi

LOG = logging.getLogger(__name__)


class RamProvider(RamApi):
    pass

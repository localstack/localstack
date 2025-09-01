import logging

from localstack.aws.api.sns import SnsApi

# set up logger
LOG = logging.getLogger(__name__)


class SnsProvider(SnsApi): ...

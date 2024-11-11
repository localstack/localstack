import logging

from localstack import config
from localstack.http import Response

from ..api import RequestContext
from ..chain import Handler, HandlerChain

LOG = logging.getLogger(__name__)


class AccountRegionTracker:
    tracked = set()

    @staticmethod
    def track(account_id: str, region_name: str):
        AccountRegionTracker.tracked.add((account_id, region_name))


class AccountRegionCollector(Handler):
    """
    A handler that updates AccountRegionTracker with account and region of the request in RequestContext.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if context.account_id == config.INTERNAL_RESOURCE_ACCOUNT:
            return

        if (
            context.service
            and context.service.service_name == "cloudwatch"
            and context.operation is None
        ):
            return

        AccountRegionTracker.track(context.account_id, context.region)

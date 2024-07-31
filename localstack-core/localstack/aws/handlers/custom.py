import logging

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
    A handler that sets the AWS account of the request in the RequestContext.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        AccountRegionTracker.track(context.account_id, context.region)

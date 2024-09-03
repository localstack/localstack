import abc
import logging
import re
from functools import cached_property

from boto3.session import Session

from localstack.http import Request, Response
from localstack.utils.aws.arns import get_partition

from ..api import RequestContext
from ..chain import Handler, HandlerChain

LOG = logging.getLogger(__name__)


class RegionContextEnricher(Handler):
    """
    A handler that sets the AWS region of the request in the RequestContext.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        context.region = self.get_region(context.request)
        context.partition = get_partition(context.region)

    @staticmethod
    def get_region(request: Request) -> str:
        from localstack.utils.aws.request_context import extract_region_from_headers

        return extract_region_from_headers(request.headers)


class RegionRewriterStrategy(abc.ABC):
    @abc.abstractmethod
    def apply(self, context: RequestContext):
        """
        Apply the region rewriter to the request context
        :param context: Request Context
        """
        pass


class DefaultRegionRewriterStrategy(RegionRewriterStrategy):
    """
    If a region is not known, override it to "us-east-1"
    """

    default_region = "us-east-1"

    def apply(self, context: RequestContext):
        if not context.region:
            return

        if context.region not in self.available_regions:
            LOG.warning(
                "Region '%s' is not available. Resetting the region to 'us-east-1'. "
                "Please consider using a region in the 'aws' partition to avoid any unexpected behavior. "
                "Available regions: %s",
                context.region,
                self.available_regions,
            )
            context.region = self.default_region
            context.partition = "aws"
            self.rewrite_auth_header(context, self.default_region)

    def rewrite_auth_header(self, context: RequestContext, region: str):
        """
        Rewrites the `Authorization` header to reflect the specified region.
        :param context: Request context
        :param region: Region to rewrite the `Authorization` header to.
        """
        auth_header = context.request.headers.get("Authorization")

        if auth_header:
            regex = r"Credential=([^/]+)/([^/]+)/([^/]+)/"
            auth_header = re.sub(regex, rf"Credential=\1/\2/{region}/", auth_header)
            context.request.headers["Authorization"] = auth_header

    @cached_property
    def available_regions(self) -> list[str]:
        """
        Returns a list of supported regions.
        :return: List of regions in the `aws` partition.
        """
        # We cannot cache the session here, as it is not thread safe. As the entire method is cached, this should not
        # have a significant impact.
        # using s3 as "everywhere available" service, as it usually is supported in all regions
        # the S3 image also deletes other botocore specifications, so it is the easiest possibility
        return Session().get_available_regions("s3", "aws")


class RegionRewriter(Handler):
    """
    A handler that ensures the region being in a list of allowed regions
    """

    region_rewriter_strategy: RegionRewriterStrategy

    def __init__(self):
        self.region_rewriter_strategy = DefaultRegionRewriterStrategy()

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        self.region_rewriter_strategy.apply(context)

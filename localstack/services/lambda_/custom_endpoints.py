import urllib.parse
from typing import List, TypedDict

from rolo import Request, route

from localstack.aws.api.lambda_ import Runtime
from localstack.services.lambda_.runtimes import (
    ALL_RUNTIMES,
    DEPRECATED_RUNTIMES,
    SUPPORTED_RUNTIMES,
)


class LambdaRuntimesResponse(TypedDict, total=False):
    Runtimes: List[Runtime]


class LambdaCustomEndpoints:
    @route("/_aws/lambda/runtimes")
    def runtimes(self, request: Request) -> LambdaRuntimesResponse:
        """This metadata endpoint needs to be loaded before the Lambda provider.
        It can be used by the Webapp to query supported Lambda runtimes of an unknown LocalStack version."""
        query_params = urllib.parse.parse_qs(request.environ["QUERY_STRING"])
        # Query parameter values are all lists. Example: { "filter": ["all"] }
        filter_params = query_params.get("filter", [])
        runtimes = set()
        if "all" in filter_params:
            runtimes.update(ALL_RUNTIMES)
        if "deprecated" in filter_params:
            runtimes.update(DEPRECATED_RUNTIMES)
        # By default (i.e., without any filter param), we return the supported runtimes because that is most useful.
        if "supported" in filter_params or len(runtimes) == 0:
            runtimes.update(SUPPORTED_RUNTIMES)

        return LambdaRuntimesResponse(Runtimes=list(runtimes))

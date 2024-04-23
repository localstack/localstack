import urllib.parse
from typing import List, TypedDict

from rolo import Request, route

from localstack.aws.api.lambda_ import Runtime
from localstack.constants import TRUE_STRINGS
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
        # Query parameter values are all lists. Example: { "all": ["true"] }
        query_params = urllib.parse.parse_qs(request.environ["QUERY_STRING"])
        if query_params.get("all", ["false"])[0] in TRUE_STRINGS:
            return LambdaRuntimesResponse(Runtimes=ALL_RUNTIMES)
        elif query_params.get("deprecated", ["false"])[0] in TRUE_STRINGS:
            return LambdaRuntimesResponse(Runtimes=DEPRECATED_RUNTIMES)
        else:
            return LambdaRuntimesResponse(Runtimes=SUPPORTED_RUNTIMES)

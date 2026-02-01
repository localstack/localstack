import json
import logging
import urllib.parse
from typing import TypedDict

from rolo import Request, route

from localstack.aws.api.lambda_ import Runtime
from localstack.http import Response
from localstack.services.lambda_ import invocation_log
from localstack.services.lambda_.packages import get_runtime_client_path
from localstack.services.lambda_.runtimes import (
    ALL_RUNTIMES,
    DEPRECATED_RUNTIMES,
    SUPPORTED_RUNTIMES,
)

LOG = logging.getLogger(__name__)


class LambdaRuntimesResponse(TypedDict, total=False):
    Runtimes: list[Runtime]


class LambdaCustomEndpoints:
    @route("/_aws/lambda/runtimes", methods=["GET"])
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

    @route("/_aws/lambda/init", methods=["GET"])
    def init(self, request: Request) -> Response:
        """
        This internal endpoint exposes the init binary over an http API
        :param request: The HTTP request object.
        :return: Response containing the init binary.
        """
        runtime_client_path = get_runtime_client_path() / "var" / "rapid" / "init"
        runtime_init_binary = runtime_client_path.read_bytes()

        return Response(runtime_init_binary, mimetype="application/octet-stream")

    @route("/_aws/lambda/invocations", methods=["GET"])
    def list_invocations(self, request: Request):
        invocations = invocation_log.get_invocations()

        if request.args.get("arn"):
            invocations = [i for i in invocations if i.function_arn == request.args.get("arn")]

        # serialize
        doc = [i.to_dict() for i in invocations]

        if request.args.get("formatted") in ["true", "1"]:
            for invocation in doc:
                # split logs into a more readable format
                invocation["result"]["logs"] = invocation["result"]["logs"].splitlines()

                # parse payloads for nicer displaying
                if invocation["payload"].startswith("{"):
                    invocation["payload"] = json.loads(invocation["payload"])
                if invocation["result"]["payload"].startswith("{"):
                    invocation["result"]["payload"] = json.loads(invocation["result"]["payload"])

        return Response.for_json({"invocations": doc})

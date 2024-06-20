from collections import defaultdict
from typing import Any, Dict, List, Mapping, NamedTuple, Optional, Tuple
from urllib.parse import parse_qs, unquote

from botocore.model import OperationModel, ServiceModel, StructureShape
from werkzeug.datastructures import Headers, MultiDict
from werkzeug.exceptions import MethodNotAllowed, NotFound
from werkzeug.routing import Map, MapAdapter

from localstack.aws.protocol.routing import (
    GreedyPathConverter,
    StrictMethodRule,
    path_param_regex,
    post_process_arg_name,
    transform_path_params_to_rule_vars,
)
from localstack.http import Request
from localstack.http.request import get_raw_path


class _HttpOperation(NamedTuple):
    """Useful intermediary representation of the 'http' block of an operation to make code cleaner"""

    operation: OperationModel
    path: str
    method: str
    query_args: Mapping[str, List[str]]
    header_args: List[str]
    deprecated: bool

    @staticmethod
    def from_operation(op: OperationModel) -> "_HttpOperation":
        # botocore >= 1.28 might modify the internal model (specifically for S3).
        # It will modify the request URI to strip the bucket name from the path and set the original value at
        # "authPath".
        # Since botocore 1.31.2, botocore will strip the query from the `authPart`
        # We need to add it back from `requestUri` field
        # Use authPath if set, otherwise use the regular requestUri.
        if auth_path := op.http.get("authPath"):
            path, sep, query = op.http.get("requestUri", "").partition("?")
            uri = f"{auth_path.rstrip('/')}{sep}{query}"
        else:
            uri = op.http.get("requestUri")

        method = op.http.get("method")
        deprecated = op.deprecated

        # requestUris can contain mandatory query args (f.e. /apikeys?mode=import)
        path_query = uri.split("?")
        path = path_query[0]
        header_args = []
        query_args: Dict[str, List[str]] = {}

        if len(path_query) > 1:
            # parse the query args of the request URI (they are mandatory)
            query_args: Dict[str, List[str]] = parse_qs(path_query[1], keep_blank_values=True)
            # for mandatory keys without values, keep an empty list (instead of [''] - the result of parse_qs)
            query_args = {k: filter(None, v) for k, v in query_args.items()}

        # find the required header and query parameters of the input shape
        input_shape = op.input_shape
        if isinstance(input_shape, StructureShape):
            for required_member in input_shape.required_members:
                member_shape = input_shape.members[required_member]
                location = member_shape.serialization.get("location")
                if location is not None:
                    if location == "header":
                        header_name = member_shape.serialization.get("name")
                        header_args.append(header_name)
                    elif location == "querystring":
                        query_name = member_shape.serialization.get("name")
                        # do not overwrite potentially already existing query params with specific values
                        if query_name not in query_args:
                            # an empty list defines a required query param only needs to be present
                            # (no specific value will be enforced when matching)
                            query_args[query_name] = []

        return _HttpOperation(op, path, method, query_args, header_args, deprecated)


class _RequiredArgsRule:
    """
    Specific Rule implementation which checks if a set of certain required header and query parameters are matched by
    a specific request.
    """

    endpoint: Any
    required_query_args: Optional[Mapping[str, List[Any]]]
    required_header_args: List[str]
    match_score: int

    def __init__(self, operation: _HttpOperation) -> None:
        super().__init__()
        self.endpoint = operation.operation
        self.required_query_args = operation.query_args or {}
        self.required_header_args = operation.header_args or []
        self.match_score = (
            10 + 10 * len(self.required_query_args) + 10 * len(self.required_header_args)
        )
        # If this operation is deprecated, the score is a bit less high (bot not as much as a matching required arg)
        if operation.deprecated:
            self.match_score -= 5

    def matches(self, query_args: MultiDict, headers: Headers) -> bool:
        """
        Returns true if the given query args and the given headers of a request match the required query args and
        headers of this rule.
        :param query_args: query arguments of the incoming request
        :param headers: headers of the incoming request
        :return: True if the query args and headers match the required args of this rule
        """
        if self.required_query_args:
            for key, values in self.required_query_args.items():
                if key not in query_args:
                    return False
                # if a required query arg also has a list of required values set, the values need to match as well
                if values:
                    query_arg_values = query_args.getlist(key)
                    for value in values:
                        if value not in query_arg_values:
                            return False

        if self.required_header_args:
            for key in self.required_header_args:
                if key not in headers:
                    return False

        return True


class _RequestMatchingRule(StrictMethodRule):
    """
    A Werkzeug Rule extension which initially acts as a normal rule (i.e. matches a path and method).

    This rule matches if one of its sub-rules _might_ match.
    It cannot be assumed that one of the fine-grained rules matches, just because this rule initially matches.
    If this rule matches, the caller _must_ call `match_request` in order to find the actual fine-grained matching rule.
    The result of `match_request` is only meaningful if this wrapping rule also matches.
    """

    def __init__(
        self, string: str, operations: List[_HttpOperation], method: str, **kwargs
    ) -> None:
        super().__init__(string=string, method=method, **kwargs)
        # Create a rule which checks all required arguments (not only the path and method)
        rules = [_RequiredArgsRule(op) for op in operations]
        # Sort the rules descending based on their rule score
        # (i.e. the first matching rule will have the highest score)=
        self.rules = sorted(rules, key=lambda rule: rule.match_score, reverse=True)

    def match_request(self, request: Request) -> _RequiredArgsRule:
        """
        Function which needs to be called by a caller if the _RequestMatchingRule already matched using Werkzeug's
        default matching mechanism.

        :param request: to perform the fine-grained matching on
        :return: matching fine-grained rule
        :raises: NotFound if none of the fine-grained rules matches
        """
        for rule in self.rules:
            if rule.matches(request.args, request.headers):
                return rule
        raise NotFound()


def _create_service_map(service: ServiceModel) -> Map:
    """
    Creates a Werkzeug Map object with all rules necessary for the specific service.
    :param service: botocore service model to create the rules for
    :return: a Map instance which is used to perform the in-service operation routing
    """
    ops = [service.operation_model(op_name) for op_name in service.operation_names]

    rules = []

    # group all operations by their path and method
    path_index: Dict[(str, str), List[_HttpOperation]] = defaultdict(list)
    for op in ops:
        http_op = _HttpOperation.from_operation(op)
        path_index[(http_op.path, http_op.method)].append(http_op)

    # create a matching rule for each (path, method) combination
    for (path, method), ops in path_index.items():
        # translate the requestUri to a Werkzeug rule string
        rule_string = path_param_regex.sub(transform_path_params_to_rule_vars, path)

        if len(ops) == 1:
            # if there is only a single operation for a (path, method) combination,
            # the default Werkzeug rule can be used directly (this is the case for most rules)
            op = ops[0]
            rules.append(StrictMethodRule(string=rule_string, method=method, endpoint=op.operation))  # type: ignore
        else:
            # if there is an ambiguity with only the (path, method) combination,
            # a custom rule - which can use additional request metadata - needs to be used
            rules.append(_RequestMatchingRule(string=rule_string, method=method, operations=ops))

    return Map(
        rules=rules,
        # don't be strict about trailing slashes when matching
        strict_slashes=False,
        # we can't really use werkzeug's merge-slashes since it uses HTTP redirects to solve it
        merge_slashes=False,
        # get service-specific converters
        converters={"path": GreedyPathConverter},
    )


class RestServiceOperationRouter:
    """
    A router implementation which abstracts the (quite complex) routing of incoming HTTP requests to a specific
    operation within a "REST" service (rest-xml, rest-json).
    """

    _map: Map

    def __init__(self, service: ServiceModel):
        self._map = _create_service_map(service)

    def match(self, request: Request) -> Tuple[OperationModel, Mapping[str, Any]]:
        """
        Matches the given request to the operation it targets (or raises an exception if no operation matches).

        :param request: The request of which the targeting operation needs to be found
        :return: A tuple with the matched operation and the (already parsed) path params
        :raises: Werkzeug's NotFound exception in case the given request does not match any operation
        """

        # bind the map to get the actual matcher
        matcher: MapAdapter = self._map.bind(request.host)

        # perform the matching
        try:
            # some services (at least S3) allow OPTIONS request (f.e. for CORS preflight requests) without them being
            # specified. the specs do _not_ contain any operations on OPTIONS methods at all.
            # avoid matching issues for preflight requests by matching against a similar GET request instead.
            method = request.method if request.method != "OPTIONS" else "GET"

            path = get_raw_path(request)
            # trailing slashes are ignored in smithy matching,
            # see https://smithy.io/1.0/spec/core/http-traits.html#literal-character-sequences and this
            # makes sure that, e.g., in s3, `GET /mybucket/` is not matched to `GetBucket` and not to
            # `GetObject` and the associated rule.
            path = path.rstrip("/")

            rule, args = matcher.match(path, method=method, return_rule=True)
        except MethodNotAllowed as e:
            # MethodNotAllowed (405) exception is raised if a path is matching, but the method does not.
            # Our router handles this as a 404.
            raise NotFound() from e

        # if the found rule is a _RequestMatchingRule, the multi rule matching needs to be invoked to perform the
        # fine-grained matching based on the whole request
        if isinstance(rule, _RequestMatchingRule):
            rule = rule.match_request(request)

        # post process the arg keys and values
        # - the path param keys need to be "un-sanitized", i.e. sanitized rule variable names need to be reverted
        # - the path param values might still be url-encoded
        args = {post_process_arg_name(k): unquote(v) for k, v in args.items()}

        # extract the operation model from the rule
        operation: OperationModel = rule.endpoint

        return operation, args

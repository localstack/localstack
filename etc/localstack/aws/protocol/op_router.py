import re
from collections import defaultdict
from typing import Any, AnyStr, Dict, List, Mapping, Match, NamedTuple, Optional, Tuple
from urllib.parse import parse_qs, unquote

from botocore.model import OperationModel, ServiceModel, StructureShape
from werkzeug.datastructures import Headers, MultiDict
from werkzeug.exceptions import MethodNotAllowed, NotFound
from werkzeug.routing import Map, MapAdapter, PathConverter, Rule

from localstack.http import Request
from localstack.http.request import get_raw_path


class GreedyPathConverter(PathConverter):
    regex = ".*?"


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


class _StrictMethodRule(Rule):
    """
    Small extension to Werkzeug's Rule class which reverts unwanted assumptions made by Werkzeug.
    Reverted assumptions:
    - Werkzeug automatically matches HEAD requests to the corresponding GET request (i.e. Werkzeug's rule automatically
      adds the HEAD HTTP method to a rule which should only match GET requests). This is implemented to simplify
      implementing an app compliant with HTTP (where a HEAD request needs to return the headers of a corresponding GET
      request), but it is unwanted for our strict rule matching in here.
    """

    def __init__(self, string: str, method: str, **kwargs) -> None:
        super().__init__(string=string, methods=[method], **kwargs)

        # Make sure Werkzeug's Rule does not add any other methods
        # (f.e. the HEAD method even though the rule should only match GET)
        self.methods = {method.upper()}


class _RequestMatchingRule(_StrictMethodRule):
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


# Regex to find path parameters in requestUris of AWS service specs (f.e. /{param1}/{param2+})
_path_param_regex = re.compile(r"({.+?})")
# Translation table which replaces characters forbidden in Werkzeug rule names with temporary replacements
# Note: The temporary replacements must not occur in any requestUri of any operation in any service!
_rule_replacements = {"-": "_0_"}
# String translation table for #_rule_replacements for str#translate
_rule_replacement_table = str.maketrans(_rule_replacements)


def _transform_path_params_to_rule_vars(match: Match[AnyStr]) -> str:
    """
    Transforms a request URI path param to a valid Werkzeug Rule string variable placeholder.
    This transformation function should be used in combination with _path_param_regex on the request URIs (without any
    query params).

    :param match: Regex match which contains a single group. The match group is a request URI path param, including the
                    surrounding curly braces.
    :return: Werkzeug rule string variable placeholder which is semantically equal to the given request URI path param

    """
    # get the group match and strip the curly braces
    request_uri_variable: str = match.group(0)[1:-1]

    # if the request URI param is greedy (f.e. /foo/{Bar+}), add Werkzeug's "path" prefix (/foo/{path:Bar})
    greedy_prefix = ""
    if request_uri_variable.endswith("+"):
        greedy_prefix = "path:"
        request_uri_variable = request_uri_variable.strip("+")

    # replace forbidden chars (not allowed in Werkzeug rule variable names) with their placeholder
    escaped_request_uri_variable = request_uri_variable.translate(_rule_replacement_table)

    return f"<{greedy_prefix}{escaped_request_uri_variable}>"


def _post_process_arg_name(arg_key: str) -> str:
    """
    Reverses previous manipulations to the path parameters names (like replacing forbidden characters with
    placeholders).
    :param arg_key: Path param key name extracted using Werkzeug rules
    :return: Post-processed ("un-sanitized") path param key
    """
    result = arg_key
    for original, substitution in _rule_replacements.items():
        result = result.replace(substitution, original)
    return result


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
        rule_string = _path_param_regex.sub(_transform_path_params_to_rule_vars, path)

        if len(ops) == 1:
            # if there is only a single operation for a (path, method) combination,
            # the default Werkzeug rule can be used directly (this is the case for most rules)
            op = ops[0]
            rules.append(_StrictMethodRule(string=rule_string, method=method, endpoint=op.operation))  # type: ignore
        else:
            # if there is an ambiguity with only the (path, method) combination,
            # a custom rule - which can use additional request metadata - needs to be used
            rules.append(_RequestMatchingRule(string=rule_string, method=method, operations=ops))

    return Map(
        rules=rules,
        strict_slashes=False,
        merge_slashes=False,
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
            rule, args = matcher.match(get_raw_path(request), method=method, return_rule=True)
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
        args = {_post_process_arg_name(k): unquote(v) for k, v in args.items()}

        # extract the operation model from the rule
        operation: OperationModel = rule.endpoint

        return operation, args

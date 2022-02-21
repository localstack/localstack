"""
Request parsers for the different AWS service protocols.

The module contains classes that take an HTTP request to a service, and
given an operation model, parse the HTTP request according to the
specified input shape.

It can be seen as the counterpart to the ``serialize`` module in
``botocore`` (which serializes the request before sending it to this
parser). It has a lot of similarities with the ``parse`` module in
``botocore``, but serves a different purpose (parsing requests
instead of responses).

The different protocols have many similarities. The class hierarchy is
designed such that the parsers share as much logic as possible.
The class hierarchy looks as follows:
::
                          ┌─────────────┐
                          │RequestParser│
                          └─────────────┘
                             ▲   ▲   ▲
           ┌─────────────────┘   │   └────────────────────┐
  ┌────────┴─────────┐ ┌─────────┴───────────┐ ┌──────────┴──────────┐
  │QueryRequestParser│ │BaseRestRequestParser│ │BaseJSONRequestParser│
  └──────────────────┘ └─────────────────────┘ └─────────────────────┘
          ▲                    ▲            ▲   ▲           ▲
  ┌───────┴────────┐ ┌─────────┴──────────┐ │   │           │
  │EC2RequestParser│ │RestXMLRequestParser│ │   │           │
  └────────────────┘ └────────────────────┘ │   │           │
                           ┌────────────────┴───┴┐ ┌────────┴────────┐
                           │RestJSONRequestParser│ │JSONRequestParser│
                           └─────────────────────┘ └─────────────────┘
::

The ``RequestParser`` contains the logic that is used among all the
different protocols (``query``, ``json``, ``rest-json``, ``rest-xml``,
and ``ec2``).
The relation between the different protocols is described in the
``serializer``.

The classes are structured as follows:

* The ``RequestParser`` contains all the basic logic for the parsing
  which is shared among all different protocols.
* The ``BaseRestRequestParser`` contains the logic for the REST
  protocol specifics (i.e. specific HTTP metadata parsing).
* The ``BaseJSONRequestParser`` contains the logic for the JSON body
  parsing.
* The ``RestJSONRequestParser`` inherits the ReST specific logic from
  the ``BaseRestRequestParser`` and the JSON body parsing from the
  ``BaseJSONRequestParser``.
* The ``QueryRequestParser``, ``RestXMLRequestParser``, and the
  ``JSONRequestParser`` have a conventional inheritance structure.

The services and their protocols are defined by using AWS's Smithy
(a language to define services in a - somewhat - protocol-agnostic
way). The "peculiarities" in this parser code usually correspond
to certain so-called "traits" in Smithy.

The result of the parser methods are the operation model of the
service's action which the request was aiming for, as well as the
parsed parameters for the service's function invocation.

**Experimental:** The parsers in this module are still experimental.
When implementing services with these parsers, some edge cases might
not work out-of-the-box.
"""
import abc
import base64
import datetime
import re
from abc import ABC
from collections import OrderedDict, defaultdict
from email.utils import parsedate_to_datetime
from functools import partial
from typing import Any, DefaultDict, Dict, List, Optional, Pattern, Tuple, Union
from urllib.parse import parse_qs, unquote, urlsplit
from xml.etree import ElementTree as ETree

import cbor2
import dateutil.parser
from botocore.model import (
    ListShape,
    MapShape,
    OperationModel,
    OperationNotFoundError,
    ServiceModel,
    Shape,
    StructureShape,
)

from localstack.aws.api import HttpRequest
from localstack.utils.common import to_str


def _text_content(func):
    """
    This decorator hides the difference between an XML node with text or a plain string.
    It's used to ensure that scalar processing operates only on text strings, which
    allows the same scalar handlers to be used for XML nodes from the body, HTTP headers,
    and across different protocols.

    :param func: function which should be wrapped
    :return: wrapper function which can be called with a node or a string, where the
             wrapped function is always called with a string
    """

    def _get_text_content(
        self,
        request: HttpRequest,
        shape: Shape,
        node_or_string: Union[ETree.Element, str],
        path_regex: Pattern[str] = None,
    ):
        if hasattr(node_or_string, "text"):
            text = node_or_string.text
            if text is None:
                # If an XML node is empty <foo></foo>, we want to parse that as an empty string,
                # not as a null/None value.
                text = ""
        else:
            text = node_or_string
        return func(self, request, shape, text, path_regex)

    return _get_text_content


class RequestParserError(Exception):
    """Error which is thrown if the request parsing fails."""

    pass


class RequestParser(abc.ABC):
    """
    The request parser is responsible for parsing an incoming HTTP request.
    It determines which operation the request was aiming for and parses the incoming request such that the resulting
    dictionary can be used to invoke the service's function implementation.
    It is the base class for all parsers and therefore contains the basic logic which is used among all of them.
    """

    service: ServiceModel
    DEFAULT_ENCODING = "utf-8"
    # The default timestamp format is ISO8601, but this can be overwritten by subclasses.
    TIMESTAMP_FORMAT = "iso8601"
    # The default timestamp format for header fields
    HEADER_TIMESTAMP_FORMAT = "rfc822"

    def __init__(self, service: ServiceModel) -> None:
        super().__init__()
        self.service = service

    def parse(self, request: HttpRequest) -> Tuple[OperationModel, Any]:
        """
        Determines which operation the request was aiming for and parses the incoming request such that the resulting
        dictionary can be used to invoke the service's function implementation.

        :param request: to parse
        :return: a tuple with the operation model (defining the action / operation which the request aims for),
                 and the parsed service parameters
        """
        raise NotImplementedError

    def _parse_shape(
        self, request: HttpRequest, shape: Shape, node: any, path_regex: Pattern[str] = None
    ) -> any:
        """
        Main parsing method which dynamically calls the parsing function for the specific shape.

        :param request: the complete HttpRequest
        :param shape: of the node
        :param node: the single part of the HTTP request to parse
        :param path_regex: regex of the path. This is necessary to extract members located in the URI. Defaults to None.
        :return: result of the parsing operation, the type depends on the shape
        """
        location = shape.serialization.get("location")
        if location is not None:
            if location == "header":
                header_name = shape.serialization.get("name")
                payload = request.headers.get(header_name)
            elif location == "headers":
                payload = self._parse_header_map(shape, request.headers)
                # shapes with the location trait "headers" only contain strings and are not further processed
                return payload
            elif location == "querystring":
                query_name = shape.serialization.get("name")
                parsed_query = request.args
                if shape.type_name == "list":
                    payload = parsed_query.getlist(query_name)
                else:
                    payload = parsed_query.get(query_name)
            elif location == "uri":
                # Use the path and the query string for the matching
                url = request.full_path if request.query_string else request.path
                regex_group_name = shape.serialization.get("name")
                match = path_regex.match(url)
                payload = unquote(match.group(regex_group_name)) if match is not None else None
            else:
                raise RequestParserError("Unknown shape location '%s'." % location)
        else:
            # If we don't have to use a specific location, we use the node
            payload = node

        fn_name = "_parse_%s" % shape.type_name
        handler = getattr(self, fn_name, self._noop_parser)
        return handler(request, shape, payload, path_regex) if payload is not None else None

    # The parsing functions for primitive types, lists, and timestamps are shared among subclasses.

    def _parse_list(
        self, request: HttpRequest, shape: ListShape, node: list, path_regex: Pattern[str] = None
    ):
        parsed = []
        member_shape = shape.member
        for item in node:
            parsed.append(self._parse_shape(request, member_shape, item, path_regex))
        return parsed

    @_text_content
    def _parse_integer(self, _, __, node: str, ___) -> int:
        return int(node)

    @_text_content
    def _parse_float(self, _, __, node: str, ___) -> float:
        return float(node)

    @_text_content
    def _parse_blob(self, _, __, node: str, ___) -> bytes:
        return base64.b64decode(node)

    @_text_content
    def _parse_timestamp(self, _, shape: Shape, node: str, ___) -> datetime.datetime:
        timestamp_format = shape.serialization.get("timestampFormat")
        if not timestamp_format and shape.serialization.get("location") == "header":
            timestamp_format = self.HEADER_TIMESTAMP_FORMAT
        return self._convert_str_to_timestamp(node, timestamp_format)

    @_text_content
    def _parse_boolean(self, _, __, node: str, ___) -> bool:
        value = node.lower()
        if value == "true":
            return True
        if value == "false":
            return False
        raise ValueError("cannot parse boolean value %s" % node)

    @_text_content
    def _noop_parser(self, _, __, node: any, ___):
        return node

    _parse_character = _parse_string = _noop_parser
    _parse_double = _parse_float
    _parse_long = _parse_integer

    def _convert_str_to_timestamp(self, value: str, timestamp_format=None):
        if timestamp_format is None:
            timestamp_format = self.TIMESTAMP_FORMAT
        timestamp_format = timestamp_format.lower()
        converter = getattr(self, "_timestamp_%s" % timestamp_format)
        final_value = converter(value)
        return final_value

    @staticmethod
    def _timestamp_iso8601(date_string: str) -> datetime.datetime:
        return dateutil.parser.isoparse(date_string)

    @staticmethod
    def _timestamp_unixtimestamp(timestamp_string: str) -> datetime.datetime:
        return datetime.datetime.utcfromtimestamp(int(timestamp_string))

    @staticmethod
    def _timestamp_rfc822(datetime_string: str) -> datetime.datetime:
        return parsedate_to_datetime(datetime_string)

    @staticmethod
    def _get_request_uri_regex(operation: OperationModel) -> Optional[Pattern[str]]:
        """
        Tries to extract the request URI from a given operation.
        If a request URI can be found, it is transformed to a regular expression which can be used to try to match
        incoming requests (i.e. their paths).

        :param operation: to extract the requestUri and convert to a regex of
        :return: extracted requestUri, converted to a regular expression
        """
        if operation is None:
            return None
        request_uri_regex = None
        http = operation.http
        if len(http) > 0:
            request_uri = http.get("requestUri")
            request_uri_regex = RequestParser._convert_request_uri_to_regex(request_uri)
        return request_uri_regex

    @staticmethod
    def _convert_request_uri_to_regex(request_uri: str) -> Optional[Pattern[str]]:
        """
        Converts the given request_uri to a regular expression.
        It adds fences (line start and line end operators) and replaces the path param placeholders (f.e. "{VarName}")
        with named capture groups (where the capture group name is the variable placeholder name).

        :param request_uri: to convert to a regex
        :return: regex
        """
        if request_uri is None:
            return None
        # Escape characters within the request_uri for the usage in a regex
        escaped_request_uri = re.escape(request_uri)
        # Replace the variable placeholder (f.e. {ConnectionId} in "/fuu/{ConnectionId}/bar/") with a
        # named regex group. Note: allowing slashes in param values, as required, e.g., for ARNs in paths.
        # The curly braces have been escaped previously and need to be captured here. Hence the "\\\\" in the pattern.
        # The request URL may contain the first query parameter (starting with a ?). Hence the exclusion of ? and &.
        # A group will have the following regex: /fuu/(?P<\g<VariableName>>[^?&]+))/bar
        request_uri_regex = re.sub(
            "\\\\{(?P<VariableName>[^}]+)\\\\}",
            r"(?P<\g<VariableName>>[^?&]+)",
            escaped_request_uri,
        )
        # The variable name (now regex group name) can also contain trailing "+" signs (f.e. S3).
        # This means that the key should be greedy (there can only be one greedy param).
        # This is implemented by making groups which do not contain a "+" and are not at the end of the URI non-greedy
        # (with a trailing ?).
        if "\\+>[^?&]+)" in request_uri_regex:
            request_uri_regex = request_uri_regex.replace("\\+>[^?&]+)", ">[^?&]_greedy_+)")
            request_uri_regex = request_uri_regex.replace(">[^?&]+)", ">[^?&]+?)")
            request_uri_regex = request_uri_regex.replace(">[^?&]_greedy_+)", ">[^?&]+)")
        # Make sure the URL starts with our regex, do not add a fence to the end (there might be optional query params).
        request_uri_regex = f"^{request_uri_regex}"
        # The result is a regex itself.
        return re.compile(request_uri_regex)

    @staticmethod
    def _parse_header_map(shape: Shape, headers: dict) -> dict:
        # Note that headers are case insensitive, so we .lower() all header names and header prefixes.
        parsed = {}
        prefix = shape.serialization.get("name", "").lower()
        for header_name, header_value in headers.items():
            if header_name.lower().startswith(prefix):
                # The key name inserted into the parsed hash strips off the prefix.
                name = header_name[len(prefix) :]
                parsed[name] = header_value
        return parsed


class QueryRequestParser(RequestParser):
    """
    The ``QueryRequestParser`` is responsible for parsing incoming requests for services which use the ``query``
    protocol. The requests for these services encode the majority of their parameters in the URL query string.

    **Experimental:** This parser is still experimental.
    When implementing services with this parser, some edge cases might not work out-of-the-box.
    """

    # Prefix for non-flattened lists
    NON_FLATTENED_LIST_PREFIX = "member."

    def parse(self, request: HttpRequest) -> Tuple[OperationModel, Any]:
        body = request.get_data(as_text=True)
        instance = parse_qs(body, keep_blank_values=True)
        if not instance:
            # if the body does not contain any information, fallback to the actual query parameters
            instance = request.args
        # The query parsing returns a list for each entry in the dict (this is how HTTP handles lists in query params).
        # However, the AWS Query format does not have any duplicates.
        # Therefore we take the first element of each entry in the dict.
        instance = {k: self._get_first(v) for k, v in instance.items()}
        if "Action" not in instance:
            raise RequestParserError(
                f"Operation detection failed. "
                f"Missing Action in request for query-protocol service {self.service}."
            )
        action = instance["Action"]
        try:
            operation: OperationModel = self.service.operation_model(action)
        except OperationNotFoundError as e:
            raise RequestParserError(
                f"Operation detection failed."
                f"Operation {action} could not be found for service {self.service}."
            ) from e
        # Extract the URI for the operation and convert it to a regex
        request_uri_regex = self._get_request_uri_regex(operation)
        input_shape: StructureShape = operation.input_shape
        return operation, self._parse_shape(request, input_shape, instance, request_uri_regex)

    def _process_member(
        self,
        request: HttpRequest,
        member_name: str,
        member_shape: Shape,
        node: dict,
        path_regex: Pattern[str] = None,
    ):
        if isinstance(member_shape, (MapShape, ListShape, StructureShape)):
            # If we have a complex type, we filter the node and change it's keys to craft a new "context" for the
            # new hierarchy level
            sub_node = self._filter_node(member_name, node)
        else:
            # If it is a primitive type we just get the value from the dict
            sub_node = node.get(member_name)
        # The filtered node is processed and returned (or None if the sub_node is None)
        return (
            self._parse_shape(request, member_shape, sub_node, path_regex)
            if sub_node is not None
            else None
        )

    def _parse_structure(
        self,
        request: HttpRequest,
        shape: StructureShape,
        node: dict,
        path_regex: Pattern[str] = None,
    ) -> dict:
        result = {}

        for member, member_shape in shape.members.items():
            # The key in the node is either the serialization config "name" of the shape, or the name of the member
            member_name = self._get_serialized_name(member_shape, member)
            # BUT, if it's flattened and a list, the name is defined by the list's member's name
            if member_shape.serialization.get("flattened"):
                if isinstance(member_shape, ListShape):
                    member_name = self._get_serialized_name(member_shape.member, member)
            value = self._process_member(request, member_name, member_shape, node, path_regex)
            if value is not None or member in shape.required_members:
                # If the member is required, but not existing, we explicitly set None
                result[member] = value

        return result if len(result) > 0 else None

    def _parse_map(
        self, request: HttpRequest, shape: MapShape, node: dict, path_regex: Pattern[str]
    ) -> dict:
        """
        This is what the node looks like for a flattened map::
        ::
          {
              "Attribute.1.Name": "MyKey",
              "Attribute.1.Value": "MyValue",
              "Attribute.2.Name": ...,
              ...
          }
        ::
        This function expects an already filtered / pre-processed node. The node dict would therefore look like:
        ::
          {
              "1.Name": "MyKey",
              "1.Value": "MyValue",
              "2.Name": ...
          }
        ::
        """
        key_prefix = ""
        # Non-flattened maps have an additional hierarchy level named "entry"
        # https://awslabs.github.io/smithy/1.0/spec/core/xml-traits.html#xmlflattened-trait
        if not shape.serialization.get("flattened"):
            key_prefix += "entry."
        result = {}

        i = 0
        while True:
            i += 1
            # The key and value can be renamed (with their serialization config's "name").
            # By default they are called "key" and "value".
            key_name = f"{key_prefix}{i}.{self._get_serialized_name(shape.key, 'key')}"
            value_name = f"{key_prefix}{i}.{self._get_serialized_name(shape.value, 'value')}"

            # We process the key and value individually
            k = self._process_member(request, key_name, shape.key, node)
            v = self._process_member(request, value_name, shape.value, node)
            if k is None or v is None:
                # technically, if one exists but not the other, then that would be an invalid request
                break
            result[k] = v

        return result if len(result) > 0 else None

    def _parse_list(
        self, request: HttpRequest, shape: ListShape, node: dict, path_regex: Pattern[str] = None
    ) -> list:
        """
        Some actions take lists of parameters. These lists are specified using the param.[member.]n notation.
        The "member" is used if the list is not flattened.
        Values of n are integers starting from 1.
        For example, a list with two elements looks like this:
        - Flattened: &AttributeName.1=first&AttributeName.2=second
        - Non-flattened: &AttributeName.member.1=first&AttributeName.member.2=second
        This function expects an already filtered / processed node. The node dict would therefore look like:
        ::
          {
              "1": "first",
              "2": "second",
              "3": ...
          }
        ::
        """
        key_prefix = ""
        # Non-flattened lists have an additional hierarchy level named "member"
        # https://awslabs.github.io/smithy/1.0/spec/core/xml-traits.html#xmlflattened-trait
        if not shape.serialization.get("flattened"):
            key_prefix += self.NON_FLATTENED_LIST_PREFIX

        # We collect the list value as well as the integer indicating the list position so we can
        # later sort the list by the position, in case they attribute values are unordered
        result: List[Tuple[int, Any]] = []

        i = 0
        while True:
            i += 1
            key_name = f"{key_prefix}{i}"
            value = self._process_member(request, key_name, shape.member, node)
            if value is None:
                break
            result.append((i, value))

        return [r[1] for r in sorted(result)] if len(result) > 0 else None

    @staticmethod
    def _get_first(node: any) -> any:
        if isinstance(node, (list, tuple)):
            return node[0]
        return node

    @staticmethod
    def _filter_node(name: str, node: dict) -> dict:
        """Filters the node dict for entries where the key starts with the given name."""
        filtered = {k[len(name) + 1 :]: v for k, v in node.items() if k.startswith(name)}
        return filtered if len(filtered) > 0 else None

    def _get_serialized_name(self, shape: Shape, default_name: str) -> str:
        """
        Returns the serialized name for the shape if it exists.
        Otherwise it will return the given default_name.
        """
        return shape.serialization.get("name", default_name)


class BaseRestRequestParser(RequestParser):
    """
    The ``BaseRestRequestParser`` is the base class for all "resty" AWS service protocols.
    The operation which should be invoked is determined based on the HTTP method and the path suffix.
    The body encoding is done in the respective subclasses.
    """

    def __init__(self, service: ServiceModel) -> None:
        super().__init__(service)
        # When parsing a request, we need to lookup the operation based on the HTTP method and URI.
        # We create a mapping when the parser is initialized.
        # Since the path can contain URI path parameters, the key of the dict is a regex.
        self.operation_lookup: DefaultDict[
            str, OrderedDict[Pattern[str], List[OperationModel]]
        ] = defaultdict(lambda: OrderedDict())
        # Extract all operation models from the service spec
        operation_models = [
            service.operation_model(operation) for operation in service.operation_names
        ]
        # Sort the operation models descending based on their normalized request URIs.
        # This is necessary, to ensure that greedy regex matches do not cause wrong method lookups.
        # f.e. /fuu/{bar}/baz should have precedence over /fuu/{bar}.
        sorted_operation_models = sorted(
            operation_models, key=self._get_normalized_request_uri_length, reverse=True
        )
        for operation_model in sorted_operation_models:
            http = operation_model.http
            method = http.get("method")
            request_uri_regex = self._get_request_uri_regex(operation_model)
            # there are certain edge cases where specifications can contain overloading request URIs
            if request_uri_regex not in self.operation_lookup[method]:
                self.operation_lookup[method][request_uri_regex] = [operation_model]
            else:
                self.operation_lookup[method][request_uri_regex].append(operation_model)

    def _get_normalized_request_uri_length(self, operation_model: OperationModel) -> int:
        """
        Fings the length of the normalized request URI for the given operation model.
        See #_get_normalized_request_uri for a description of the normalization.
        """
        return len(self._get_normalized_request_uri(operation_model))

    def _get_normalized_request_uri(self, operation_model: OperationModel) -> str:
        """
        Fings the normalized request URI for the given operation model.
        A normalized request URI has a static, common replacement for path parameter placeholders, starting with a
        space character (which is the lowest non-control character in ASCII and is not expected to be present in a
        service specification's request URI pattern).
        This allows the resulting normalized request URIs to be sorted.
        :param operation_model: to get the normalized request URI for.
            This function expects that the given operation model has HTTP metadata!
        :return: normalized request URI for the given operation model
        """
        request_uri: str = operation_model.http.get("requestUri")
        # Make sure that all path parameter placeholders have the same name and length
        return re.sub(r"{(.*?)}", " param", request_uri)

    def parse(self, request: HttpRequest) -> Tuple[OperationModel, Any]:
        operation, path_regex = self._detect_operation(request)
        shape: StructureShape = operation.input_shape
        final_parsed = {}
        if shape is not None:
            self._parse_payload(request, shape, shape.members, path_regex, final_parsed)
        return operation, final_parsed

    def _detect_operation(self, request: HttpRequest) -> Tuple[OperationModel, Pattern[str]]:
        """
        Detects the operation this request is aiming for and returns the detected operation as well as the request URI
        pattern.

        :param request: to detect the operation for
        :return: Tuple containing the detected operation the request is targeting and the URI
                    pattern it was detected with
        :raises: RequestParserError if the operation could not be detected
        """
        # Use the path and the query string for the matching
        url = request.full_path if request.query_string else request.path
        # Find the regex which matches the given path (as well as its operation)
        try:
            path_regex, operations = next(
                filter(
                    lambda item: item[0].match(url),
                    self.operation_lookup[request.method].items(),
                )
            )
            if len(operations) > 1:
                raise RequestParserError(
                    f"Unable to find operation for request to service "
                    f"{self.service.service_name}: {request.method} {request.path} "
                    f"(ambiguous results)"
                )
            return operations[0], path_regex
        except StopIteration:
            raise RequestParserError(
                f"Unable to find operation for request to service "
                f"{self.service.service_name}: {request.method} {request.path}"
            )

    def _parse_payload(
        self,
        request: HttpRequest,
        shape: Shape,
        member_shapes: Dict[str, Shape],
        path_regex: Pattern[str],
        final_parsed: dict,
    ) -> None:
        """Parses all attributes which are located in the payload / body of the incoming request."""
        payload_parsed = {}
        non_payload_parsed = {}
        if "payload" in shape.serialization:
            # If a payload is specified in the output shape, then only that shape is used for the body payload.
            payload_member_name = shape.serialization["payload"]
            body_shape = member_shapes[payload_member_name]
            if body_shape.serialization.get("eventstream"):
                body = self._create_event_stream(request, body_shape)
                payload_parsed[payload_member_name] = body
            elif body_shape.type_name == "string":
                # Only set the value if it's not empty (the request's data is an empty binary by default)
                if request.data:
                    body = request.data
                    if isinstance(body, bytes):
                        body = body.decode(self.DEFAULT_ENCODING)
                    payload_parsed[payload_member_name] = body
            elif body_shape.type_name == "blob":
                # Only set the value if it's not empty (the request's data is an empty binary by default)
                if request.data:
                    payload_parsed[payload_member_name] = request.data
            else:
                original_parsed = self._initial_body_parse(request)
                payload_parsed[payload_member_name] = self._parse_shape(
                    request, body_shape, original_parsed, path_regex
                )
        else:
            # The payload covers the whole body. We only parse the body if it hasn't been handled by the payload logic.
            non_payload_parsed = self._initial_body_parse(request)
        # even if the payload has been parsed, the rest of the shape needs to be processed as well
        # (for members which are located outside of the body, like uri or header)
        non_payload_parsed = self._parse_shape(request, shape, non_payload_parsed, path_regex)
        # update the final result with the parsed body and the parsed payload (where the payload has precedence)
        final_parsed.update(non_payload_parsed)
        final_parsed.update(payload_parsed)

    def _initial_body_parse(self, request: HttpRequest) -> any:
        """
        This method executes the initial parsing of the body (XML, JSON, or CBOR).
        The parsed body will afterwards still be walked through and the nodes will be converted to the appropriate
        types, but this method does the first round of parsing.

        :param request: of which the body should be parsed
        :return: depending on the actual implementation
        """
        raise NotImplementedError("_initial_body_parse")

    def _create_event_stream(self, request: HttpRequest, shape: Shape) -> any:
        # TODO handle event streams
        raise NotImplementedError("_create_event_stream")


class RestXMLRequestParser(BaseRestRequestParser):
    """
    The ``RestXMLRequestParser`` is responsible for parsing incoming requests for services which use the ``rest-xml``
    protocol. The requests for these services encode the majority of their parameters as XML in the request body.

    **Experimental:** This parser is still experimental.
    When implementing services with this parser, some edge cases might not work out-of-the-box.
    """

    def __init__(self, service_model: ServiceModel):
        super(RestXMLRequestParser, self).__init__(service_model)
        self._namespace_re = re.compile("{.*}")

    def _initial_body_parse(self, request: HttpRequest) -> ETree.Element:
        body = request.data
        if not body:
            return ETree.Element("")
        return self._parse_xml_string_to_dom(body)

    def _parse_structure(
        self,
        request: HttpRequest,
        shape: StructureShape,
        node: ETree.Element,
        path_regex: Pattern[str] = None,
    ) -> dict:
        parsed = {}
        xml_dict = self._build_name_to_xml_node(node)
        for member_name, member_shape in shape.members.items():
            xml_name = self._member_key_name(member_shape, member_name)
            member_node = xml_dict.get(xml_name)
            # If a shape defines a location trait, the node might be None (since these are extracted from the request's
            # metadata like headers or the URI)
            if (
                member_node is not None
                or "location" in member_shape.serialization
                or member_shape.serialization.get("eventheader")
            ):
                parsed[member_name] = self._parse_shape(
                    request, member_shape, member_node, path_regex
                )
            elif member_shape.serialization.get("xmlAttribute"):
                attributes = {}
                location_name = member_shape.serialization["name"]
                for key, value in node.attrib.items():
                    new_key = self._namespace_re.sub(location_name.split(":")[0] + ":", key)
                    attributes[new_key] = value
                if location_name in attributes:
                    parsed[member_name] = attributes[location_name]
            elif member_name in shape.required_members:
                # If the member is required, but not existing, we explicitly set None
                parsed[member_name] = None
        return parsed

    def _parse_map(
        self, request: HttpRequest, shape: MapShape, node: dict, path_regex: Pattern[str] = None
    ) -> dict:
        parsed = {}
        key_shape = shape.key
        value_shape = shape.value
        key_location_name = key_shape.serialization.get("name", "key")
        value_location_name = value_shape.serialization.get("name", "value")
        if shape.serialization.get("flattened") and not isinstance(node, list):
            node = [node]
        for keyval_node in node:
            key_name = val_name = None
            for single_pair in keyval_node:
                # Within each <entry> there's a <key> and a <value>
                tag_name = self._node_tag(single_pair)
                if tag_name == key_location_name:
                    key_name = self._parse_shape(request, key_shape, single_pair, path_regex)
                elif tag_name == value_location_name:
                    val_name = self._parse_shape(request, value_shape, single_pair, path_regex)
                else:
                    raise RequestParserError("Unknown tag: %s" % tag_name)
            parsed[key_name] = val_name
        return parsed

    def _parse_list(
        self, request: HttpRequest, shape: ListShape, node: dict, path_regex: Pattern[str] = None
    ) -> list:
        # When we use _build_name_to_xml_node, repeated elements are aggregated
        # into a list. However, we can't tell the difference between a scalar
        # value and a single element flattened list. So before calling the
        # real _handle_list, we know that "node" should actually be a list if
        # it's flattened, and if it's not, then we make it a one element list.
        if shape.serialization.get("flattened") and not isinstance(node, list):
            node = [node]
        return super(RestXMLRequestParser, self)._parse_list(request, shape, node, path_regex)

    def _node_tag(self, node: ETree.Element) -> str:
        return self._namespace_re.sub("", node.tag)

    @staticmethod
    def _member_key_name(shape: Shape, member_name: str) -> str:
        # This method is needed because we have to special case flattened list
        # with a serialization name.  If this is the case we use the
        # locationName from the list's member shape as the key name for the
        # surrounding structure.
        if isinstance(shape, ListShape) and shape.serialization.get("flattened"):
            list_member_serialized_name = shape.member.serialization.get("name")
            if list_member_serialized_name is not None:
                return list_member_serialized_name
        serialized_name = shape.serialization.get("name")
        if serialized_name is not None:
            return serialized_name
        return member_name

    def _parse_xml_string_to_dom(self, xml_string: bytes) -> ETree.Element:
        try:
            parser = ETree.XMLParser(target=ETree.TreeBuilder(), encoding=self.DEFAULT_ENCODING)
            parser.feed(xml_string)
            root = parser.close()
        except ETree.ParseError as e:
            raise RequestParserError(
                "Unable to parse request (%s), invalid XML received:\n%s" % (e, xml_string)
            ) from e
        return root

    def _build_name_to_xml_node(self, parent_node: Union[list, ETree.Element]) -> dict:
        # If the parent node is actually a list. We should not be trying
        # to serialize it to a dictionary. Instead, return the first element
        # in the list.
        if isinstance(parent_node, list):
            return self._build_name_to_xml_node(parent_node[0])
        xml_dict = {}
        for item in parent_node:
            key = self._node_tag(item)
            if key in xml_dict:
                # If the key already exists, the most natural
                # way to handle this is to aggregate repeated
                # keys into a single list.
                # <foo>1</foo><foo>2</foo> -> {'foo': [Node(1), Node(2)]}
                if isinstance(xml_dict[key], list):
                    xml_dict[key].append(item)
                else:
                    # Convert from a scalar to a list.
                    xml_dict[key] = [xml_dict[key], item]
            else:
                xml_dict[key] = item
        return xml_dict

    def _create_event_stream(self, request: HttpRequest, shape: Shape) -> any:
        # TODO handle event streams
        raise NotImplementedError("_create_event_stream")


class BaseJSONRequestParser(RequestParser, ABC):
    """
    The ``BaseJSONRequestParser`` is the base class for all JSON-based AWS service protocols.
    This base-class handles parsing the payload / body as JSON.
    """

    TIMESTAMP_FORMAT = "unixtimestamp"

    def _parse_structure(
        self,
        request: HttpRequest,
        shape: StructureShape,
        value: Optional[dict],
        path_regex: Pattern[str] = None,
    ) -> Optional[dict]:
        if shape.is_document_type:
            final_parsed = value
        else:
            if value is None:
                # If the comes across the wire as "null" (None in python),
                # we should be returning this unchanged, instead of as an
                # empty dict.
                return None
            final_parsed = {}
            for member_name, member_shape in shape.members.items():
                json_name = member_shape.serialization.get("name", member_name)
                raw_value = value.get(json_name)
                parsed = self._parse_shape(request, member_shape, raw_value, path_regex)
                if parsed is not None or member_name in shape.required_members:
                    # If the member is required, but not existing, we set it to None anyways
                    final_parsed[member_name] = parsed
        return final_parsed

    def _parse_map(
        self,
        request: HttpRequest,
        shape: MapShape,
        value: Optional[dict],
        path_regex: Pattern[str] = None,
    ) -> Optional[dict]:
        if value is None:
            return None
        parsed = {}
        key_shape = shape.key
        value_shape = shape.value
        for key, value in value.items():
            actual_key = self._parse_shape(request, key_shape, key, path_regex)
            actual_value = self._parse_shape(request, value_shape, value, path_regex)
            parsed[actual_key] = actual_value
        return parsed

    def _parse_body_as_json(self, request: HttpRequest) -> dict:
        body_contents = request.data
        if not body_contents:
            return {}
        if request.mimetype.startswith("application/x-amz-cbor"):
            try:
                return cbor2.loads(body_contents)
            except ValueError as e:
                raise RequestParserError("HTTP body could not be parsed as CBOR.") from e
        else:
            try:
                return request.get_json(force=True)
            except ValueError as e:
                raise RequestParserError("HTTP body could not be parsed as JSON.") from e

    def _parse_boolean(
        self, request: HttpRequest, shape: Shape, node: bool, path_regex: Pattern[str] = None
    ) -> bool:
        return super()._noop_parser(request, shape, node, path_regex)


class JSONRequestParser(BaseJSONRequestParser):
    """
    The ``JSONRequestParser`` is responsible for parsing incoming requests for services which use the ``json``
    protocol.
    The requests for these services encode the majority of their parameters as JSON in the request body.
    The operation is defined in an HTTP header field.

    **Experimental:** This parser is still experimental.
    When implementing services with this parser, some edge cases might not work out-of-the-box.
    """

    def parse(self, request: HttpRequest) -> Tuple[OperationModel, Any]:
        target = request.headers["X-Amz-Target"]
        # assuming that the last part of the target string (e.g., "x.y.z.MyAction") contains the operation name
        operation_name = target.rpartition(".")[2]
        operation = self.service.operation_model(operation_name)
        shape = operation.input_shape
        path_regex = self._get_request_uri_regex(operation)
        final_parsed = self._do_parse(request, shape, path_regex)
        return operation, final_parsed

    def _do_parse(
        self, request: HttpRequest, shape: Shape, path_regex: Pattern[str] = None
    ) -> dict:
        parsed = {}
        if shape is not None:
            event_name = shape.event_stream_name
            if event_name:
                parsed = self._handle_event_stream(request, shape, event_name)
            else:
                parsed = self._handle_json_body(request, shape, path_regex)
        return parsed

    def _handle_event_stream(self, request: HttpRequest, shape: Shape, event_name: str):
        # TODO handle event streams
        raise NotImplementedError

    def _handle_json_body(
        self, request: HttpRequest, shape: Shape, path_regex: Pattern[str] = None
    ) -> any:
        # The json.loads() gives us the primitive JSON types, but we need to traverse the parsed JSON data to convert
        # to richer types (blobs, timestamps, etc.)
        parsed_json = self._parse_body_as_json(request)
        return self._parse_shape(request, shape, parsed_json, path_regex)


class RestJSONRequestParser(BaseRestRequestParser, BaseJSONRequestParser):
    """
    The ``RestJSONRequestParser`` is responsible for parsing incoming requests for services which use the ``rest-json``
    protocol.
    The requests for these services encode the majority of their parameters as JSON in the request body.
    The operation is defined by the HTTP method and the path suffix.

    **Experimental:** This parser is still experimental.
    When implementing services with this parser, some edge cases might not work out-of-the-box.
    """

    def _initial_body_parse(self, request: HttpRequest) -> dict:
        return self._parse_body_as_json(request)

    def _create_event_stream(self, request: HttpRequest, shape: Shape) -> any:
        raise NotImplementedError


class EC2RequestParser(QueryRequestParser):
    """
    The ``EC2RequestParser`` is responsible for parsing incoming requests for services which use the ``ec2``
    protocol (which only is EC2). Protocol is quite similar to the ``query`` protocol with some small differences.

    **Experimental:** This parser is still experimental.
    When implementing services with this parser, some edge cases might not work out-of-the-box.
    """

    # The EC2 protocol does not use a prefix notation for flattened lists
    NON_FLATTENED_LIST_PREFIX = ""

    def _get_serialized_name(self, shape: Shape, default_name: str) -> str:
        # Returns the serialized name for the shape if it exists.
        # Otherwise it will return the passed in default_name.
        if "queryName" in shape.serialization:
            return shape.serialization["queryName"]
        elif "name" in shape.serialization:
            # A locationName is always capitalized on input for the ec2 protocol.
            name = shape.serialization["name"]
            return name[0].upper() + name[1:]
        else:
            return default_name


class S3RequestParser(RestXMLRequestParser):
    def parse(self, request: HttpRequest) -> Tuple[OperationModel, Any]:
        """Handle virtual-host-addressing for S3."""
        if (
            # TODO implement a more sophisticated determination if the host contains S3 virtual host addressing
            not request.host.startswith("s3.")
            and not request.host.startswith("localhost.")
            and not request.host.startswith("127.0.0.1")
        ):
            self._revert_virtual_host_style(request)
        return super().parse(request)

    def _revert_virtual_host_style(self, request: HttpRequest):
        # extract the bucket name from the host part of the request
        bucket_name = request.host.split(".")[0]
        # split the url and put the bucket name at the front
        parts = urlsplit(request.url)
        path_parts = parts.path.split("/")
        path_parts = [bucket_name] + path_parts
        path_parts = [part for part in path_parts if part]
        path = "/" + "/".join(path_parts) or "/"
        # set the path with the bucket name in the front at the request
        # TODO directly modifying the request can cause issues with our handler chain, instead clone the HTTP request
        request.path = path

    def _detect_operation(self, request: HttpRequest) -> Tuple[OperationModel, Pattern[str]]:
        """
        Performs a specific operation detection to resolve conflicts with request URIs which are only contained in the
        service specification of S3.
        """
        # Use the path and the query string for the matching
        url = request.path
        if request.query_string:
            url += f"?{to_str(request.query_string)}"
        # Find the regexes which match the given path (as well as its operations)
        regex_operation_list_tuples = list(
            filter(
                lambda item: item[0].match(url),
                self.operation_lookup[request.method].items(),
            )
        )
        if not regex_operation_list_tuples:
            # couldn't find a single operation
            raise RequestParserError(
                f"Unable to find operation for request to service "
                f"{self.service.service_name}: {request.method} {request.path}"
            )
        # flatten the list, such that each entry is a tuple of a single regex to a single operation
        regex_operation_tuples = [
            (regex, operation)
            for regex, operations in regex_operation_list_tuples
            for operation in operations
        ]
        if len(regex_operation_tuples) == 1:
            # exactly found one operation, no ambiguity
            path_regex, operation_models = regex_operation_tuples[0]
            return operation_models, path_regex
        else:
            # otherwise, we score the results and pick the lowest score
            scoring_function = partial(self._score_regex_operation_tuple, request)
            sorted_operations = sorted(regex_operation_tuples, key=scoring_function)
            # take the operation with the highest score
            path_regex, operation_model = sorted_operations[0]
            return operation_model, path_regex

    def _score_regex_operation_tuple(
        self, request: HttpRequest, regex_operation_tuple: Tuple[Pattern[str], OperationModel]
    ) -> int:
        """
        Calculates a score how much the request is likely to target the given operation.
        :param request: to calculate the score for the operation of
        :param regex_operation_tuple: Tuple containing the request URI pattern regex and the operation model.
        :return: score which indicates how well the request fits the operation. The lower the better.
        """
        score = 0
        path_regex, operation_model = regex_operation_tuple
        if operation_model.deprecated:
            # The best match is required members, but if there's an equal score, the non-deprecated should win
            score += 1

        input_shape = operation_model.input_shape
        if input_shape:
            # check if the request contains all required non-body members
            for required_member in input_shape.required_members:
                member_shape = input_shape.members[required_member]
                # parsing the whole body is expensive and unnecessary, we only consider required members which are
                # located in the request's metadata (uri, query, headers)
                if member_shape.serialization.get("location"):
                    try:
                        parsed_member_shape = self._parse_shape(
                            request, member_shape, None, path_regex
                        )
                        if parsed_member_shape is None:
                            # the required member is not present, this operation most likely isn't the right one
                            score += 10
                        else:
                            # add a reward for matched required members:
                            # methods which define required members which are matched by the request should win
                            # over methods without any required members
                            score -= 10
                    except RequestParserError:
                        # the required member is not present, this operation most likely isn't the right one
                        score += 10
        return score


def create_parser(service: ServiceModel) -> RequestParser:
    """
    Creates the right parser for the given service model.

    **Experimental:** The parsers in this module are still experimental.
    When implementing services with these parsers, some edge cases might
    not work out-of-the-box.

    :param service: to create the parser for
    :return: RequestParser which can handle the protocol of the service
    """
    # Unfortunately, some services show subtle differences in their parsing or operation detection behavior, even though
    # their specification states they implement the same protocol.
    # In order to avoid bundling the whole complexity in the specific protocols, or even have service-distinctions
    # within the parser implementations, the service-specific parser implementations (basically the implicit /
    # informally more specific protocol implementation) has precedence over the more general protocol-specific parsers.
    service_specific_parsers = {
        "s3": S3RequestParser,
    }
    protocol_specific_parsers = {
        "query": QueryRequestParser,
        "json": JSONRequestParser,
        "rest-json": RestJSONRequestParser,
        "rest-xml": RestXMLRequestParser,
        "ec2": EC2RequestParser,
    }

    # Try to select a service-specific parser implementation
    if service.service_name in service_specific_parsers:
        return service_specific_parsers[service.service_name](service)
    else:
        # Otherwise, pick the protocol-specific parser for the protocol of the service
        return protocol_specific_parsers[service.protocol](service)

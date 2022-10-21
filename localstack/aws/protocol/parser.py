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
"""
import abc
import base64
import datetime
import functools
import re
from abc import ABC
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union
from typing.io import IO
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
from werkzeug.exceptions import BadRequest, NotFound

from localstack.aws.api import HttpRequest
from localstack.aws.protocol.op_router import RestServiceOperationRouter
from localstack.config import LEGACY_S3_PROVIDER


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
        uri_params: Mapping[str, Any] = None,
    ):
        if hasattr(node_or_string, "text"):
            text = node_or_string.text
            if text is None:
                # If an XML node is empty <foo></foo>, we want to parse that as an empty string,
                # not as a null/None value.
                text = ""
        else:
            text = node_or_string
        return func(self, request, shape, text, uri_params)

    return _get_text_content


class RequestParserError(Exception):
    """
    Error which is thrown if the request parsing fails.
    Super class of all exceptions raised by the parser.
    """

    pass


class UnknownParserError(RequestParserError):
    """
    Error which indicates that the raised exception of the parser could be caused by invalid data or by any other
    (unknown) issue. Errors like this should be reported and indicate an issue in the parser itself.
    """

    pass


class ProtocolParserError(RequestParserError):
    """
    Error which indicates that the given data is not compliant with the service's specification and cannot be parsed.
    This usually results in a response with an HTTP 4xx status code (client error).
    """

    pass


class OperationNotFoundParserError(ProtocolParserError):
    """
    Error which indicates that the given data cannot be matched to a specific operation.
    The request is likely _not_ meant to be handled by the ASF service provider itself.
    """

    pass


def _handle_exceptions(func):
    """
    Decorator which handles the exceptions raised by the parser. It ensures that all exceptions raised by the public
    methods of the parser are instances of RequestParserError.
    :param func: to wrap in order to add the exception handling
    :return: wrapped function
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except RequestParserError:
            raise
        except Exception as e:
            raise UnknownParserError(
                "An unknown error occurred when trying to parse the request."
            ) from e

    return wrapper


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

    @_handle_exceptions
    def parse(self, request: HttpRequest) -> Tuple[OperationModel, Any]:
        """
        Determines which operation the request was aiming for and parses the incoming request such that the resulting
        dictionary can be used to invoke the service's function implementation.

        :param request: to parse
        :return: a tuple with the operation model (defining the action / operation which the request aims for),
                 and the parsed service parameters
        :raises: RequestParserError (either a ProtocolParserError or an UnknownParserError)
        """
        raise NotImplementedError

    def _parse_shape(
        self, request: HttpRequest, shape: Shape, node: Any, uri_params: Mapping[str, Any] = None
    ) -> Any:
        """
        Main parsing method which dynamically calls the parsing function for the specific shape.

        :param request: the complete HttpRequest
        :param shape: of the node
        :param node: the single part of the HTTP request to parse
        :param uri_params: the extracted URI path params
        :return: result of the parsing operation, the type depends on the shape
        """
        if shape is None:
            return None
        location = shape.serialization.get("location")
        if location is not None:
            if location == "header":
                header_name = shape.serialization.get("name")
                payload = request.headers.get(header_name)
                if shape.type_name == "list":
                    # headers may contain a comma separated list of values (e.g., the ObjectAttributes member in
                    # s3.GetObjectAttributes), so we prepare it here for the handler, which will be `_parse_list`.
                    payload = payload.split(",")
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
                uri_param_name = shape.serialization.get("name")
                if uri_param_name in uri_params:
                    payload = uri_params[uri_param_name]
            else:
                raise UnknownParserError("Unknown shape location '%s'." % location)
        else:
            # If we don't have to use a specific location, we use the node
            payload = node

        fn_name = "_parse_%s" % shape.type_name
        handler = getattr(self, fn_name, self._noop_parser)
        try:
            return handler(request, shape, payload, uri_params) if payload is not None else None
        except (TypeError, ValueError, AttributeError) as e:
            raise ProtocolParserError(
                f"Invalid type when parsing {shape.name}: '{payload}' cannot be parsed to {shape.type_name}."
            ) from e

    # The parsing functions for primitive types, lists, and timestamps are shared among subclasses.

    def _parse_list(
        self,
        request: HttpRequest,
        shape: ListShape,
        node: list,
        uri_params: Mapping[str, Any] = None,
    ):
        parsed = []
        member_shape = shape.member
        for item in node:
            parsed.append(self._parse_shape(request, member_shape, item, uri_params))
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
    def _noop_parser(self, _, __, node: Any, ___):
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
    """

    @_handle_exceptions
    def parse(self, request: HttpRequest) -> Tuple[OperationModel, Any]:
        instance = request.values
        if "Action" not in instance:
            raise ProtocolParserError(
                f"Operation detection failed. "
                f"Missing Action in request for query-protocol service {self.service}."
            )
        action = instance["Action"]
        try:
            operation: OperationModel = self.service.operation_model(action)
        except OperationNotFoundError as e:
            raise OperationNotFoundParserError(
                f"Operation detection failed."
                f"Operation {action} could not be found for service {self.service}."
            ) from e
        # There are no uri params in the query protocol (all ops are POST on "/")
        uri_params = {}
        input_shape: StructureShape = operation.input_shape
        parsed = self._parse_shape(request, input_shape, instance, uri_params)
        if parsed is None:
            return operation, {}
        return operation, parsed

    def _process_member(
        self,
        request: HttpRequest,
        member_name: str,
        member_shape: Shape,
        node: dict,
        uri_params: Mapping[str, Any] = None,
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
            self._parse_shape(request, member_shape, sub_node, uri_params)
            if sub_node is not None
            else None
        )

    def _parse_structure(
        self,
        request: HttpRequest,
        shape: StructureShape,
        node: dict,
        uri_params: Mapping[str, Any] = None,
    ) -> dict:
        result = {}

        for member, member_shape in shape.members.items():
            # The key in the node is either the serialization config "name" of the shape, or the name of the member
            member_name = self._get_serialized_name(member_shape, member, node)
            # BUT, if it's flattened and a list, the name is defined by the list's member's name
            if member_shape.serialization.get("flattened"):
                if isinstance(member_shape, ListShape):
                    member_name = self._get_serialized_name(member_shape.member, member, node)
            value = self._process_member(request, member_name, member_shape, node, uri_params)
            if value is not None or member in shape.required_members:
                # If the member is required, but not existing, we explicitly set None
                result[member] = value

        return result if len(result) > 0 else None

    def _parse_map(
        self, request: HttpRequest, shape: MapShape, node: dict, uri_params: Mapping[str, Any]
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
            key_name = f"{key_prefix}{i}.{self._get_serialized_name(shape.key, 'key', node)}"
            value_name = f"{key_prefix}{i}.{self._get_serialized_name(shape.value, 'value', node)}"

            # We process the key and value individually
            k = self._process_member(request, key_name, shape.key, node)
            v = self._process_member(request, value_name, shape.value, node)
            if k is None or v is None:
                # technically, if one exists but not the other, then that would be an invalid request
                break
            result[k] = v

        return result if len(result) > 0 else None

    def _parse_list(
        self,
        request: HttpRequest,
        shape: ListShape,
        node: dict,
        uri_params: Mapping[str, Any] = None,
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
        # The keys might be prefixed (f.e. for flattened lists)
        key_prefix = self._get_list_key_prefix(shape, node)

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
    def _filter_node(name: str, node: dict) -> dict:
        """Filters the node dict for entries where the key starts with the given name."""
        filtered = {k[len(name) + 1 :]: v for k, v in node.items() if k.startswith(name)}
        return filtered if len(filtered) > 0 else None

    def _get_serialized_name(self, shape: Shape, default_name: str, node: dict) -> str:
        """
        Returns the serialized name for the shape if it exists.
        Otherwise, it will return the given default_name.
        """
        return shape.serialization.get("name", default_name)

    def _get_list_key_prefix(self, shape: ListShape, node: dict):
        key_prefix = ""
        # Non-flattened lists have an additional hierarchy level:
        # https://awslabs.github.io/smithy/1.0/spec/core/xml-traits.html#xmlflattened-trait
        # The hierarchy level's name is the serialization name of its member or (by default) "member".
        if not shape.serialization.get("flattened"):
            key_prefix += f"{self._get_serialized_name(shape.member, 'member', node)}."
        return key_prefix


class BaseRestRequestParser(RequestParser):
    """
    The ``BaseRestRequestParser`` is the base class for all "resty" AWS service protocols.
    The operation which should be invoked is determined based on the HTTP method and the path suffix.
    The body encoding is done in the respective subclasses.
    """

    def __init__(self, service: ServiceModel) -> None:
        super().__init__(service)
        self.ignore_get_body_errors = False
        self._operation_router = RestServiceOperationRouter(service)

    @_handle_exceptions
    def parse(self, request: HttpRequest) -> Tuple[OperationModel, Any]:
        try:
            operation, uri_params = self._operation_router.match(request)
        except NotFound as e:
            raise OperationNotFoundParserError(
                f"Unable to find operation for request to service "
                f"{self.service.service_name}: {request.method} {request.path}"
            ) from e

        shape: StructureShape = operation.input_shape
        final_parsed = {}
        if shape is not None:
            self._parse_payload(request, shape, shape.members, uri_params, final_parsed)
        return operation, final_parsed

    def _parse_payload(
        self,
        request: HttpRequest,
        shape: Shape,
        member_shapes: Dict[str, Shape],
        uri_params: Mapping[str, Any],
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
                # This control path is equivalent to operation.has_streaming_input (shape has a payload which is a blob)
                # in which case we assume essentially an IO[bytes] to be passed. Since the payload can be optional, we
                # only set the parameter if content_length=0, which indicates an empty request. If the content length is
                # not set, it could be a streaming response.
                if request.content_length != 0:
                    payload_parsed[payload_member_name] = self.create_input_stream(request)
            else:
                original_parsed = self._initial_body_parse(request)
                payload_parsed[payload_member_name] = self._parse_shape(
                    request, body_shape, original_parsed, uri_params
                )
        else:
            # The payload covers the whole body. We only parse the body if it hasn't been handled by the payload logic.
            try:
                non_payload_parsed = self._initial_body_parse(request)
            except ProtocolParserError:
                # GET requests should ignore the body, so we just let them pass
                if not (request.method in ["GET", "HEAD"] and self.ignore_get_body_errors):
                    raise

        # even if the payload has been parsed, the rest of the shape needs to be processed as well
        # (for members which are located outside of the body, like uri or header)
        non_payload_parsed = self._parse_shape(request, shape, non_payload_parsed, uri_params)
        # update the final result with the parsed body and the parsed payload (where the payload has precedence)
        final_parsed.update(non_payload_parsed)
        final_parsed.update(payload_parsed)

    def _initial_body_parse(self, request: HttpRequest) -> Any:
        """
        This method executes the initial parsing of the body (XML, JSON, or CBOR).
        The parsed body will afterwards still be walked through and the nodes will be converted to the appropriate
        types, but this method does the first round of parsing.

        :param request: of which the body should be parsed
        :return: depending on the actual implementation
        """
        raise NotImplementedError("_initial_body_parse")

    def _create_event_stream(self, request: HttpRequest, shape: Shape) -> Any:
        # TODO handle event streams
        raise NotImplementedError("_create_event_stream")

    def create_input_stream(self, request: HttpRequest) -> IO[bytes]:
        """
        Returns an IO object that makes the payload of the HttpRequest available for streaming.

        :param request: the http request
        :return: the input stream that allows services to consume the request payload
        """
        # for now _get_stream_for_parsing seems to be a good compromise. it can be used even after `request.data` was
        # previously called. however the reverse doesn't work. once the stream has been consumed, `request.data` will
        # return b''
        return request._get_stream_for_parsing()


class RestXMLRequestParser(BaseRestRequestParser):
    """
    The ``RestXMLRequestParser`` is responsible for parsing incoming requests for services which use the ``rest-xml``
    protocol. The requests for these services encode the majority of their parameters as XML in the request body.
    """

    def __init__(self, service_model: ServiceModel):
        super(RestXMLRequestParser, self).__init__(service_model)
        self.ignore_get_body_errors = True
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
        uri_params: Mapping[str, Any] = None,
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
                    request, member_shape, member_node, uri_params
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
        self,
        request: HttpRequest,
        shape: MapShape,
        node: dict,
        uri_params: Mapping[str, Any] = None,
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
                    key_name = self._parse_shape(request, key_shape, single_pair, uri_params)
                elif tag_name == value_location_name:
                    val_name = self._parse_shape(request, value_shape, single_pair, uri_params)
                else:
                    raise ProtocolParserError("Unknown tag: %s" % tag_name)
            parsed[key_name] = val_name
        return parsed

    def _parse_list(
        self,
        request: HttpRequest,
        shape: ListShape,
        node: dict,
        uri_params: Mapping[str, Any] = None,
    ) -> list:
        # When we use _build_name_to_xml_node, repeated elements are aggregated
        # into a list. However, we can't tell the difference between a scalar
        # value and a single element flattened list. So before calling the
        # real _handle_list, we know that "node" should actually be a list if
        # it's flattened, and if it's not, then we make it a one element list.
        if shape.serialization.get("flattened") and not isinstance(node, list):
            node = [node]
        return super(RestXMLRequestParser, self)._parse_list(request, shape, node, uri_params)

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

    @staticmethod
    def _parse_xml_string_to_dom(xml_string: str) -> ETree.Element:
        try:
            parser = ETree.XMLParser(target=ETree.TreeBuilder())
            parser.feed(xml_string)
            root = parser.close()
        except ETree.ParseError as e:
            raise ProtocolParserError(
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

    def _create_event_stream(self, request: HttpRequest, shape: Shape) -> Any:
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
        uri_params: Mapping[str, Any] = None,
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
                parsed = self._parse_shape(request, member_shape, raw_value, uri_params)
                if parsed is not None or member_name in shape.required_members:
                    # If the member is required, but not existing, we set it to None anyways
                    final_parsed[member_name] = parsed
        return final_parsed

    def _parse_map(
        self,
        request: HttpRequest,
        shape: MapShape,
        value: Optional[dict],
        uri_params: Mapping[str, Any] = None,
    ) -> Optional[dict]:
        if value is None:
            return None
        parsed = {}
        key_shape = shape.key
        value_shape = shape.value
        for key, value in value.items():
            actual_key = self._parse_shape(request, key_shape, key, uri_params)
            actual_value = self._parse_shape(request, value_shape, value, uri_params)
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
                raise ProtocolParserError("HTTP body could not be parsed as CBOR.") from e
        else:
            try:
                return request.get_json(force=True)
            except BadRequest as e:
                raise ProtocolParserError("HTTP body could not be parsed as JSON.") from e

    def _parse_boolean(
        self, request: HttpRequest, shape: Shape, node: bool, uri_params: Mapping[str, Any] = None
    ) -> bool:
        return super()._noop_parser(request, shape, node, uri_params)

    def _parse_blob(
        self, request: HttpRequest, shape: Shape, node: bool, uri_params: Mapping[str, Any] = None
    ) -> bytes:
        if isinstance(node, bytes) and request.mimetype.startswith("application/x-amz-cbor"):
            # CBOR does not base64 encode binary data
            return bytes(node)
        else:
            return super()._parse_blob(request, shape, node, uri_params)


class JSONRequestParser(BaseJSONRequestParser):
    """
    The ``JSONRequestParser`` is responsible for parsing incoming requests for services which use the ``json``
    protocol.
    The requests for these services encode the majority of their parameters as JSON in the request body.
    The operation is defined in an HTTP header field.
    """

    @_handle_exceptions
    def parse(self, request: HttpRequest) -> Tuple[OperationModel, Any]:
        target = request.headers["X-Amz-Target"]
        # assuming that the last part of the target string (e.g., "x.y.z.MyAction") contains the operation name
        operation_name = target.rpartition(".")[2]
        operation = self.service.operation_model(operation_name)
        shape = operation.input_shape
        # There are no uri params in the query protocol
        uri_params = {}
        final_parsed = self._do_parse(request, shape, uri_params)
        return operation, final_parsed

    def _do_parse(
        self, request: HttpRequest, shape: Shape, uri_params: Mapping[str, Any] = None
    ) -> dict:
        parsed = {}
        if shape is not None:
            event_name = shape.event_stream_name
            if event_name:
                parsed = self._handle_event_stream(request, shape, event_name)
            else:
                parsed = self._handle_json_body(request, shape, uri_params)
        return parsed

    def _handle_event_stream(self, request: HttpRequest, shape: Shape, event_name: str):
        # TODO handle event streams
        raise NotImplementedError

    def _handle_json_body(
        self, request: HttpRequest, shape: Shape, uri_params: Mapping[str, Any] = None
    ) -> Any:
        # The json.loads() gives us the primitive JSON types, but we need to traverse the parsed JSON data to convert
        # to richer types (blobs, timestamps, etc.)
        parsed_json = self._parse_body_as_json(request)
        return self._parse_shape(request, shape, parsed_json, uri_params)


class RestJSONRequestParser(BaseRestRequestParser, BaseJSONRequestParser):
    """
    The ``RestJSONRequestParser`` is responsible for parsing incoming requests for services which use the ``rest-json``
    protocol.
    The requests for these services encode the majority of their parameters as JSON in the request body.
    The operation is defined by the HTTP method and the path suffix.
    """

    def _initial_body_parse(self, request: HttpRequest) -> dict:
        return self._parse_body_as_json(request)

    def _create_event_stream(self, request: HttpRequest, shape: Shape) -> Any:
        raise NotImplementedError


class EC2RequestParser(QueryRequestParser):
    """
    The ``EC2RequestParser`` is responsible for parsing incoming requests for services which use the ``ec2``
    protocol (which only is EC2). Protocol is quite similar to the ``query`` protocol with some small differences.
    """

    def _get_serialized_name(self, shape: Shape, default_name: str, node: dict) -> str:
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

    def _get_list_key_prefix(self, shape: ListShape, node: dict):
        # The EC2 protocol does not use a prefix notation for flattened lists
        return ""


class S3RequestParser(RestXMLRequestParser):
    class VirtualHostRewriter:
        """
        Context Manager which rewrites the request object parameters such that - within the context - it looks like a
        normal S3 request.
        """

        def __init__(self, request: HttpRequest):
            self.request = request
            self.old_host = None
            self.old_path = None

        def __enter__(self):
            # only modify the request if it uses the virtual host addressing
            if self._is_vhost_address(self.request):
                # save the original path and host for restoring on context exit
                self.old_path = self.request.path
                self.old_host = self.request.host
                self.old_raw_uri = self.request.environ.get("RAW_URI")

                # extract the bucket name from the host part of the request
                bucket_name, new_host = self.old_host.split(".", maxsplit=1)

                # split the url and put the bucket name at the front
                path_parts = self.old_path.split("/")
                path_parts = [bucket_name] + path_parts
                path_parts = [part for part in path_parts if part]
                new_path = "/" + "/".join(path_parts) or "/"

                # create a new RAW_URI for the WSGI environment, this is necessary because of our `get_raw_path` utility
                if self.old_raw_uri:
                    path_parts = self.old_raw_uri.split("/")
                    path_parts = [bucket_name] + path_parts
                    path_parts = [part for part in path_parts if part]
                    new_raw_uri = "/" + "/".join(path_parts) or "/"
                    if qs := self.request.query_string:
                        new_raw_uri += "?" + qs.decode("utf-8")
                else:
                    new_raw_uri = None

                # set the new path and host
                self._set_request_props(self.request, new_path, new_host, new_raw_uri)
            return self.request

        def __exit__(self, exc_type, exc_value, exc_traceback):
            # reset the original request properties on exit of the context
            if self.old_host or self.old_path:
                self._set_request_props(
                    self.request, self.old_path, self.old_host, self.old_raw_uri
                )

        @staticmethod
        def _set_request_props(
            request: HttpRequest, path: str, host: str, raw_uri: Optional[str] = None
        ):
            """Sets the HTTP request's path and host and clears the cache in the request object."""
            request.path = path
            request.headers["Host"] = host
            if raw_uri:
                request.environ["RAW_URI"] = raw_uri

            try:
                # delete the werkzeug request property cache that depends on path, but make sure all of them are
                # initialized first, otherwise `del` will raise a key error
                request.host = None  # noqa
                request.url = None  # noqa
                request.base_url = None  # noqa
                request.full_path = None  # noqa
                request.host_url = None  # noqa
                request.root_url = None  # noqa
                del request.host  # noqa
                del request.url  # noqa
                del request.base_url  # noqa
                del request.full_path  # noqa
                del request.host_url  # noqa
                del request.root_url  # noqa
            except AttributeError:
                pass

        @staticmethod
        def _is_vhost_address(request: HttpRequest) -> bool:
            from localstack.services.s3.s3_utils import uses_host_addressing

            return uses_host_addressing(request.headers)

    @_handle_exceptions
    def parse(self, request: HttpRequest) -> Tuple[OperationModel, Any]:
        if LEGACY_S3_PROVIDER:
            """Handle virtual-host-addressing for S3."""
            with self.VirtualHostRewriter(request):
                return super().parse(request)
        else:
            return super().parse(request)

    def _parse_shape(
        self, request: HttpRequest, shape: Shape, node: Any, uri_params: Mapping[str, Any] = None
    ) -> Any:
        """
        Special handling of parsing the shape for s3 object-names (=key):
        trailing '/' are valid and need to be preserved, however, the url-matcher removes it from the key
        we check the request.url to verify the name
        """
        if (
            shape is not None
            and uri_params is not None
            and shape.serialization.get("location") == "uri"
            and shape.serialization.get("name") == "Key"
            and request.base_url.endswith(f"{uri_params['Key']}/")
        ):
            uri_params = dict(uri_params)
            uri_params["Key"] = uri_params["Key"] + "/"
        return super()._parse_shape(request, shape, node, uri_params)


class SQSRequestParser(QueryRequestParser):
    def _get_serialized_name(self, shape: Shape, default_name: str, node: dict) -> str:
        """
        SQS allows using both - the proper serialized name of a map as well as the member name - as name for maps.
        For example, both works for the TagQueue operation:
        - Using the proper serialized name "Tag": Tag.1.Key=key&Tag.1.Value=value
        - Using the member name "Tag" in the parent structure: Tags.1.Key=key&Tags.1.Value=value
        The Java SDK implements the second variant: https://github.com/aws/aws-sdk-java-v2/issues/2524
        This has been approved to be a bug and against the spec, but since the client has a lot of users, and AWS SQS
        supports both, we need to handle it here.
        """
        # ask the super implementation for the proper serialized name
        primary_name = super()._get_serialized_name(shape, default_name, node)

        # determine a potential suffix for the name of the member in the node
        suffix = ""
        if shape.type_name == "map":
            if not shape.serialization.get("flattened"):
                suffix = ".entry.1.Key"
            else:
                suffix = ".1.Key"
        if shape.type_name == "list":
            if not shape.serialization.get("flattened"):
                suffix = ".member.1"
            else:
                suffix = ".1"

        # if the primary name is _not_ available in the node, but the default name is, we use the default name
        if f"{primary_name}{suffix}" not in node and f"{default_name}{suffix}" in node:
            return default_name
        # otherwise we use the primary name
        return primary_name


def create_parser(service: ServiceModel) -> RequestParser:
    """
    Creates the right parser for the given service model.

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
        "sqs": SQSRequestParser,
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

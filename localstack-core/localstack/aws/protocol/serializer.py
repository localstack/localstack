"""
Response serializers for the different AWS service protocols.

The module contains classes that take a service's response dict, and
given an operation model, serialize the HTTP response according to the
specified output shape.

It can be seen as the counterpart to the ``parse`` module in ``botocore``
(which parses the result of these serializer). It has a lot of
similarities with the ``serialize`` module in ``botocore``, but
serves a different purpose (serializing responses instead of requests).

The different protocols have many similarities. The class hierarchy is
designed such that the serializers share as much logic as possible.
The class hierarchy looks as follows:
::
                                      ┌───────────────────┐
                                      │ResponseSerializer │
                                      └───────────────────┘
                                          ▲    ▲      ▲
                   ┌──────────────────────┘    │      └──────────────────┐
      ┌────────────┴────────────┐ ┌────────────┴─────────────┐ ┌─────────┴────────────┐
      │BaseXMLResponseSerializer│ │BaseRestResponseSerializer│ │JSONResponseSerializer│
      └─────────────────────────┘ └──────────────────────────┘ └──────────────────────┘
                         ▲    ▲             ▲             ▲              ▲
  ┌──────────────────────┴─┐ ┌┴─────────────┴──────────┐ ┌┴──────────────┴──────────┐
  │QueryResponseSerializer │ │RestXMLResponseSerializer│ │RestJSONResponseSerializer│
  └────────────────────────┘ └─────────────────────────┘ └──────────────────────────┘
              ▲
   ┌──────────┴──────────┐
   │EC2ResponseSerializer│
   └─────────────────────┘
::

The ``ResponseSerializer`` contains the logic that is used among all the
different protocols (``query``, ``json``, ``rest-json``, ``rest-xml``, and
``ec2``).
The protocols relate to each other in the following ways:

* The ``query`` and the ``rest-xml`` protocols both have XML bodies in their
  responses which are serialized quite similarly (with some specifics for each
  type).
* The ``json`` and the ``rest-json`` protocols both have JSON bodies in their
  responses which are serialized the same way.
* The ``rest-json`` and ``rest-xml`` protocols serialize some metadata in
  the HTTP response's header fields
* The ``ec2`` protocol is basically similar to the ``query`` protocol with a
  specific error response formatting.

The serializer classes in this module correspond directly to the different
protocols. ``#create_serializer`` shows the explicit mapping between the
classes and the protocols.
The classes are structured as follows:

* The ``ResponseSerializer`` contains all the basic logic for the
  serialization which is shared among all different protocols.
* The ``BaseXMLResponseSerializer`` and the ``JSONResponseSerializer``
  contain the logic for the XML and the JSON serialization respectively.
* The ``BaseRestResponseSerializer`` contains the logic for the REST
  protocol specifics (i.e. specific HTTP header serializations).
* The ``RestXMLResponseSerializer`` and the ``RestJSONResponseSerializer``
  inherit the ReST specific logic from the ``BaseRestResponseSerializer``
  and the XML / JSON body serialization from their second super class.

The services and their protocols are defined by using AWS's Smithy
(a language to define services in a - somewhat - protocol-agnostic
way). The "peculiarities" in this serializer code usually correspond
to certain so-called "traits" in Smithy.

The result of the serialization methods is the HTTP response which can
be sent back to the calling client.
"""

import abc
import base64
import functools
import json
import logging
import string
from abc import ABC
from binascii import crc32
from datetime import datetime
from email.utils import formatdate
from struct import pack
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple, Union
from xml.etree import ElementTree as ETree

import cbor2
import xmltodict
from botocore.model import ListShape, MapShape, OperationModel, ServiceModel, Shape, StructureShape
from botocore.serialize import ISO8601, ISO8601_MICRO
from botocore.utils import calculate_md5, is_json_value_header, parse_to_aware_datetime
from werkzeug import Request as WerkzeugRequest
from werkzeug import Response as WerkzeugResponse
from werkzeug.datastructures import Headers, MIMEAccept
from werkzeug.http import parse_accept_header

from localstack.aws.api import CommonServiceException, ServiceException
from localstack.aws.spec import ProtocolName, load_service
from localstack.constants import (
    APPLICATION_AMZ_CBOR_1_1,
    APPLICATION_AMZ_JSON_1_0,
    APPLICATION_AMZ_JSON_1_1,
    APPLICATION_CBOR,
    APPLICATION_JSON,
    APPLICATION_XML,
    TEXT_XML,
)
from localstack.http import Response
from localstack.utils.common import to_bytes, to_str
from localstack.utils.strings import long_uid
from localstack.utils.xml import strip_xmlns

LOG = logging.getLogger(__name__)

REQUEST_ID_CHARACTERS = string.digits + string.ascii_uppercase


class ResponseSerializerError(Exception):
    """
    Error which is thrown if the request serialization fails.
    Super class of all exceptions raised by the serializer.
    """

    pass


class UnknownSerializerError(ResponseSerializerError):
    """
    Error which indicates that the exception raised by the serializer could be caused by invalid data or by any other
    (unknown) issue. Errors like this should be reported and indicate an issue in the serializer itself.
    """

    pass


class ProtocolSerializerError(ResponseSerializerError):
    """
    Error which indicates that the given data is not compliant with the service's specification and cannot be
    serialized. This usually results in a response to the client with an HTTP 5xx status code (internal server error).
    """

    pass


def _handle_exceptions(func):
    """
    Decorator which handles the exceptions raised by the serializer. It ensures that all exceptions raised by the public
    methods of the parser are instances of ResponseSerializerError.
    :param func: to wrap in order to add the exception handling
    :return: wrapped function
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ResponseSerializerError:
            raise
        except Exception as e:
            raise UnknownSerializerError(
                "An unknown error occurred when trying to serialize the response."
            ) from e

    return wrapper


class ResponseSerializer(abc.ABC):
    """
    The response serializer is responsible for the serialization of a service implementation's result to an actual
    HTTP response (which will be sent to the calling client).
    It is the base class of all serializers and therefore contains the basic logic which is used among all of them.
    """

    DEFAULT_ENCODING = "utf-8"
    # The default timestamp format is ISO8601, but this can be overwritten by subclasses.
    TIMESTAMP_FORMAT = "iso8601"
    # Event streaming binary data type mapping for type "string"
    AWS_BINARY_DATA_TYPE_STRING = 7
    # Defines the supported mime types of the specific serializer. Sorted by priority (preferred / default first).
    # Needs to be specified by subclasses.
    SUPPORTED_MIME_TYPES: List[str] = []

    @_handle_exceptions
    def serialize_to_response(
        self,
        response: dict,
        operation_model: OperationModel,
        headers: Optional[Dict | Headers],
        request_id: str,
    ) -> Response:
        """
        Takes a response dict and serializes it to an actual HttpResponse.

        :param response: to serialize
        :param operation_model: specification of the service & operation containing information about the shape of the
                                service's output / response
        :param headers: the headers of the incoming request this response should be serialized for. This is necessary
                        for features like Content-Negotiation (define response content type based on request headers).
        :param request_id: autogenerated AWS request ID identifying the original request
        :return: Response which can be sent to the calling client
        :raises: ResponseSerializerError (either a ProtocolSerializerError or an UnknownSerializerError)
        """

        # determine the preferred mime type (based on the serializer's supported mime types and the Accept header)
        mime_type = self._get_mime_type(headers)

        # if the operation has a streaming output, handle the serialization differently
        if operation_model.has_event_stream_output:
            return self._serialize_event_stream(response, operation_model, mime_type, request_id)

        serialized_response = self._create_default_response(operation_model, mime_type)
        shape = operation_model.output_shape
        # The shape can also be none (for empty responses), but it still needs to be serialized (to add some metadata)
        shape_members = shape.members if shape is not None else None
        self._serialize_response(
            response,
            serialized_response,
            shape,
            shape_members,
            operation_model,
            mime_type,
            request_id,
        )
        serialized_response = self._prepare_additional_traits_in_response(
            serialized_response, operation_model, request_id
        )
        return serialized_response

    @_handle_exceptions
    def serialize_error_to_response(
        self,
        error: ServiceException,
        operation_model: OperationModel,
        headers: Optional[Dict | Headers],
        request_id: str,
    ) -> Response:
        """
        Takes an error instance and serializes it to an actual HttpResponse.
        Therefore, this method is used for errors which should be serialized and transmitted to the calling client.

        :param error: to serialize
        :param operation_model: specification of the service & operation containing information about the shape of the
                                service's output / response
        :param headers: the headers of the incoming request this response should be serialized for. This is necessary
                        for features like Content-Negotiation (define response content type based on request headers).
        :param request_id: autogenerated AWS request ID identifying the original request
        :return: HttpResponse which can be sent to the calling client
        :raises: ResponseSerializerError (either a ProtocolSerializerError or an UnknownSerializerError)
        """
        # determine the preferred mime type (based on the serializer's supported mime types and the Accept header)
        mime_type = self._get_mime_type(headers)

        # TODO implement streaming error serialization
        serialized_response = self._create_default_response(operation_model, mime_type)
        if not error or not isinstance(error, ServiceException):
            raise ProtocolSerializerError(
                f"Error to serialize ({error.__class__.__name__ if error else None}) is not a ServiceException."
            )
        shape = operation_model.service_model.shape_for_error_code(error.code)
        serialized_response.status_code = error.status_code

        self._serialize_error(
            error, serialized_response, shape, operation_model, mime_type, request_id
        )
        serialized_response = self._prepare_additional_traits_in_response(
            serialized_response, operation_model, request_id
        )
        return serialized_response

    def _serialize_response(
        self,
        parameters: dict,
        response: Response,
        shape: Optional[Shape],
        shape_members: dict,
        operation_model: OperationModel,
        mime_type: str,
        request_id: str,
    ) -> None:
        raise NotImplementedError

    def _serialize_body_params(
        self,
        params: dict,
        shape: Shape,
        operation_model: OperationModel,
        mime_type: str,
        request_id: str,
    ) -> Optional[str]:
        """
        Actually serializes the given params for the given shape to a string for the transmission in the body of the
        response.
        :param params: to serialize
        :param shape: to know how to serialize the params
        :param operation_model: for additional metadata
        :param mime_type: Mime type which should be used to encode the payload
        :param request_id: autogenerated AWS request ID identifying the original request
        :return: string containing the serialized body
        """
        raise NotImplementedError

    def _serialize_error(
        self,
        error: ServiceException,
        response: Response,
        shape: StructureShape,
        operation_model: OperationModel,
        mime_type: str,
        request_id: str,
    ) -> None:
        raise NotImplementedError

    def _serialize_event_stream(
        self,
        response: dict,
        operation_model: OperationModel,
        mime_type: str,
        request_id: str,
    ) -> Response:
        """
        Serializes a given response dict (the return payload of a service implementation) to an _event stream_ using the
        given operation model.

        :param response: dictionary containing the payload for the response
        :param operation_model: describing the operation the response dict is being returned by
        :param mime_type: Mime type which should be used to encode the payload
        :param request_id: autogenerated AWS request ID identifying the original request
        :return: Response which can directly be sent to the client (in chunks)
        """
        event_stream_shape = operation_model.get_event_stream_output()
        event_stream_member_name = operation_model.output_shape.event_stream_name

        # wrap the generator in operation specific serialization
        def event_stream_serializer() -> Iterable[bytes]:
            yield self._encode_event_payload("initial-response")

            # create a default response
            serialized_event_response = self._create_default_response(operation_model, mime_type)
            # get the members of the event stream shape
            event_stream_shape_members = (
                event_stream_shape.members if event_stream_shape is not None else None
            )
            # extract the generator from the given response data
            event_generator = response.get(event_stream_member_name)
            if not isinstance(event_generator, Iterator):
                raise ProtocolSerializerError(
                    "Expected iterator for streaming event serialization."
                )

            # yield one event per generated event
            for event in event_generator:
                # find the actual event payload (the member with event=true)
                event_member_shape = None
                event_member_name = None
                for member_name, member_shape in event_stream_shape_members.items():
                    if member_shape.serialization.get("event") and member_name in event:
                        event_member_shape = member_shape
                        event_member_name = member_name
                        break
                if event_member_shape is None:
                    raise UnknownSerializerError("Couldn't find event shape for serialization.")

                # serialize the part of the response for the event
                self._serialize_response(
                    event.get(event_member_name),
                    serialized_event_response,
                    event_member_shape,
                    event_member_shape.members if event_member_shape is not None else None,
                    operation_model,
                    mime_type,
                    request_id,
                )
                # execute additional response traits (might be modifying the response)
                serialized_event_response = self._prepare_additional_traits_in_response(
                    serialized_event_response, operation_model, request_id
                )
                # encode the event and yield it
                yield self._encode_event_payload(
                    event_type=event_member_name, content=serialized_event_response.data
                )

        return Response(
            response=event_stream_serializer(),
            status=operation_model.http.get("responseCode", 200),
        )

    def _encode_event_payload(
        self,
        event_type: str,
        content: Union[str, bytes] = "",
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> bytes:
        """
        Encodes the given event payload according to AWS specific binary event encoding.
        A specification of the format can be found in the AWS docs:
        https://docs.aws.amazon.com/AmazonS3/latest/API/RESTSelectObjectAppendix.html

        :param content: string or bytes of the event payload
        :param event_type: type of the event. Usually the name of the event shape or specific event types like
                            "initial-response".
        :param error_code: Optional. Error code if the payload represents an error.
        :param error_message: Optional. Error message if the payload represents an error.
        :return: bytes with the AWS-specific encoded event payload
        """

        # determine the event type (error if an error message or an error code is set)
        if error_message or error_code:
            message_type = "error"
        else:
            message_type = "event"

        # set the headers
        headers = {":event-type": event_type, ":message-type": message_type}
        if error_message:
            headers[":error-message"] = error_message
        if error_code:
            headers[":error-code"] = error_code

        # construct headers
        header_section = b""
        for key, value in headers.items():
            header_name = key.encode(self.DEFAULT_ENCODING)
            header_value = to_bytes(value)
            header_section += pack("!B", len(header_name))
            header_section += header_name
            header_section += pack("!B", self.AWS_BINARY_DATA_TYPE_STRING)
            header_section += pack("!H", len(header_value))
            header_section += header_value

        # construct body
        if isinstance(content, str):
            payload = bytes(content, self.DEFAULT_ENCODING)
        else:
            payload = content

        # calculate lengths
        headers_length = len(header_section)
        payload_length = len(payload)

        # construct message
        # - prelude
        result = pack("!I", payload_length + headers_length + 16)
        result += pack("!I", headers_length)
        # - prelude crc
        prelude_crc = crc32(result)
        result += pack("!I", prelude_crc)
        # - headers
        result += header_section
        # - payload
        result += payload
        # - message crc
        payload_crc = crc32(result)
        result += pack("!I", payload_crc)

        return result

    def _create_default_response(self, operation_model: OperationModel, mime_type: str) -> Response:
        """
        Creates a boilerplate default response to be used by subclasses as starting points.
        Uses the default HTTP response status code defined in the operation model (if defined), otherwise 200.

        :param operation_model: to extract the default HTTP status code
        :param mime_type: Mime type which should be used to encode the payload
        :return: boilerplate HTTP response
        """
        return Response(status=operation_model.http.get("responseCode", 200))

    def _get_mime_type(self, headers: Optional[Dict | Headers]) -> str:
        """
        Extracts the accepted mime type from the request headers and returns a matching, supported mime type for the
        serializer or the default mime type of the service if there is no match.
        :param headers: to extract the "Accept" header from
        :return: preferred mime type to be used by the serializer (if it is not accepted by the client,
                 an error is logged)
        """
        accept_header = None
        if headers and "Accept" in headers and not headers.get("Accept") == "*/*":
            accept_header = headers.get("Accept")
        elif headers and headers.get("Content-Type"):
            # If there is no specific Accept header given, we use the given Content-Type as a fallback.
            # i.e. if the request content was JSON encoded and the client doesn't send a specific an Accept header, the
            # serializer should prefer JSON encoding.
            content_type = headers.get("Content-Type")
            LOG.debug(
                "No accept header given. Using request's Content-Type (%s) as preferred response Content-Type.",
                content_type,
            )
            accept_header = content_type + ", */*"
        mime_accept: MIMEAccept = parse_accept_header(accept_header, MIMEAccept)
        mime_type = mime_accept.best_match(self.SUPPORTED_MIME_TYPES)
        if not mime_type:
            # There is no match between the supported mime types and the requested one(s)
            mime_type = self.SUPPORTED_MIME_TYPES[0]
            LOG.debug(
                "Determined accept type (%s) is not supported by this serializer. Using default of this serializer: %s",
                accept_header,
                mime_type,
            )
        return mime_type

    # Some extra utility methods subclasses can use.

    @staticmethod
    def _timestamp_iso8601(value: datetime) -> str:
        if value.microsecond > 0:
            timestamp_format = ISO8601_MICRO
        else:
            timestamp_format = ISO8601
        return value.strftime(timestamp_format)

    @staticmethod
    def _timestamp_unixtimestamp(value: datetime) -> float:
        return value.timestamp()

    @staticmethod
    def _timestamp_unixtimestampmillis(value: datetime) -> int:
        return int(value.timestamp() * 1000)

    def _timestamp_rfc822(self, value: datetime) -> str:
        if isinstance(value, datetime):
            value = self._timestamp_unixtimestamp(value)
        return formatdate(value, usegmt=True)

    def _convert_timestamp_to_str(
        self, value: Union[int, str, datetime], timestamp_format=None
    ) -> str:
        if timestamp_format is None:
            timestamp_format = self.TIMESTAMP_FORMAT
        timestamp_format = timestamp_format.lower()
        datetime_obj = parse_to_aware_datetime(value)
        converter = getattr(self, "_timestamp_%s" % timestamp_format)
        final_value = converter(datetime_obj)
        return final_value

    @staticmethod
    def _get_serialized_name(shape: Shape, default_name: str) -> str:
        """
        Returns the serialized name for the shape if it exists.
        Otherwise, it will return the passed in default_name.
        """
        return shape.serialization.get("name", default_name)

    def _get_base64(self, value: Union[str, bytes]):
        """
        Returns the base64-encoded version of value, handling
        both strings and bytes. The returned value is a string
        via the default encoding.
        """
        if isinstance(value, str):
            value = value.encode(self.DEFAULT_ENCODING)
        return base64.b64encode(value).strip().decode(self.DEFAULT_ENCODING)

    def _encode_payload(self, body: Union[bytes, str]) -> bytes:
        if isinstance(body, str):
            return body.encode(self.DEFAULT_ENCODING)
        return body

    def _prepare_additional_traits_in_response(
        self, response: Response, operation_model: OperationModel, request_id: str
    ):
        """Applies additional traits on the raw response for a given model or protocol."""
        if operation_model.http_checksum_required:
            self._add_md5_header(response)
        return response

    def _has_header(self, header_name: str, headers: dict):
        """Case-insensitive check for header key."""
        if header_name is None:
            return False
        else:
            return header_name.lower() in [key.lower() for key in headers.keys()]

    def _add_md5_header(self, response: Response):
        """Add a Content-MD5 header if not yet there. Adapted from botocore.utils"""
        headers = response.headers
        body = response.data
        if body is not None and "Content-MD5" not in headers:
            md5_digest = calculate_md5(body)
            headers["Content-MD5"] = md5_digest

    def _get_error_message(self, error: Exception) -> Optional[str]:
        return str(error) if error is not None and str(error) != "None" else None


class BaseXMLResponseSerializer(ResponseSerializer):
    """
    The BaseXMLResponseSerializer performs the basic logic for the XML response serialization.
    It is slightly adapted by the QueryResponseSerializer.
    While the botocore's RestXMLSerializer is quite similar, there are some subtle differences (since botocore's
    implementation handles the serialization of the requests from the client to the service, not the responses from the
    service to the client).
    """

    SUPPORTED_MIME_TYPES = [TEXT_XML, APPLICATION_XML, APPLICATION_JSON]

    def _serialize_error(
        self,
        error: ServiceException,
        response: Response,
        shape: StructureShape,
        operation_model: OperationModel,
        mime_type: str,
        request_id: str,
    ) -> None:
        # Check if we need to add a namespace
        attr = (
            {"xmlns": operation_model.metadata.get("xmlNamespace")}
            if "xmlNamespace" in operation_model.metadata
            else {}
        )
        root = ETree.Element("ErrorResponse", attr)

        error_tag = ETree.SubElement(root, "Error")
        self._add_error_tags(error, error_tag, mime_type)
        request_id_element = ETree.SubElement(root, "RequestId")
        request_id_element.text = request_id

        self._add_additional_error_tags(vars(error), root, shape, mime_type)

        response.set_response(self._encode_payload(self._node_to_string(root, mime_type)))

    def _add_error_tags(
        self, error: ServiceException, error_tag: ETree.Element, mime_type: str
    ) -> None:
        code_tag = ETree.SubElement(error_tag, "Code")
        code_tag.text = error.code
        message = self._get_error_message(error)
        if message:
            self._default_serialize(error_tag, message, None, "Message", mime_type)
        if error.sender_fault:
            # The sender fault is either not set or "Sender"
            self._default_serialize(error_tag, "Sender", None, "Type", mime_type)

    def _add_additional_error_tags(
        self, parameters: dict, node: ETree, shape: StructureShape, mime_type: str
    ):
        if shape:
            params = {}
            # TODO add a possibility to serialize simple non-modelled errors (like S3 NoSuchBucket#BucketName)
            for member in shape.members:
                # XML protocols do not add modeled default fields to the root node
                # (tested for cloudfront, route53, cloudwatch, iam)
                if member.lower() not in ["code", "message"] and member in parameters:
                    params[member] = parameters[member]

            # If there is an error shape with members which should be set, they need to be added to the node
            if params:
                # Serialize the remaining params
                root_name = shape.serialization.get("name", shape.name)
                pseudo_root = ETree.Element("")
                self._serialize(shape, params, pseudo_root, root_name, mime_type)
                real_root = list(pseudo_root)[0]
                # Add the child elements to the already created root error element
                for child in list(real_root):
                    node.append(child)

    def _serialize_body_params(
        self,
        params: dict,
        shape: Shape,
        operation_model: OperationModel,
        mime_type: str,
        request_id: str,
    ) -> Optional[str]:
        root = self._serialize_body_params_to_xml(params, shape, operation_model, mime_type)
        self._prepare_additional_traits_in_xml(root, request_id)
        return self._node_to_string(root, mime_type)

    def _serialize_body_params_to_xml(
        self, params: dict, shape: Shape, operation_model: OperationModel, mime_type: str
    ) -> Optional[ETree.Element]:
        if shape is None:
            return
        # The botocore serializer expects `shape.serialization["name"]`, but this isn't always present for responses
        root_name = shape.serialization.get("name", shape.name)
        pseudo_root = ETree.Element("")
        self._serialize(shape, params, pseudo_root, root_name, mime_type)
        real_root = list(pseudo_root)[0]
        return real_root

    def _serialize(
        self, shape: Shape, params: Any, xmlnode: ETree.Element, name: str, mime_type: str
    ) -> None:
        """This method dynamically invokes the correct `_serialize_type_*` method for each shape type."""
        if shape is None:
            return
        # Some output shapes define a `resultWrapper` in their serialization spec.
        # While the name would imply that the result is _wrapped_, it is actually renamed.
        if shape.serialization.get("resultWrapper"):
            name = shape.serialization.get("resultWrapper")

        try:
            method = getattr(self, "_serialize_type_%s" % shape.type_name, self._default_serialize)
            method(xmlnode, params, shape, name, mime_type)
        except (TypeError, ValueError, AttributeError) as e:
            raise ProtocolSerializerError(
                f"Invalid type when serializing {shape.name}: '{xmlnode}' cannot be parsed to {shape.type_name}."
            ) from e

    def _serialize_type_structure(
        self, xmlnode: ETree.Element, params: dict, shape: StructureShape, name: str, mime_type
    ) -> None:
        structure_node = ETree.SubElement(xmlnode, name)

        if "xmlNamespace" in shape.serialization:
            namespace_metadata = shape.serialization["xmlNamespace"]
            attribute_name = "xmlns"
            if namespace_metadata.get("prefix"):
                attribute_name += ":%s" % namespace_metadata["prefix"]
            structure_node.attrib[attribute_name] = namespace_metadata["uri"]
        for key, value in params.items():
            if value is None:
                # Don't serialize any param whose value is None.
                continue
            try:
                member_shape = shape.members[key]
            except KeyError:
                LOG.warning(
                    "Response object %s contains a member which is not specified: %s",
                    shape.name,
                    key,
                )
                continue
            member_name = member_shape.serialization.get("name", key)
            # We need to special case member shapes that are marked as an xmlAttribute.
            # Rather than serializing into an XML child node, we instead serialize the shape to
            # an XML attribute of the *current* node.
            if member_shape.serialization.get("xmlAttribute"):
                # xmlAttributes must have a serialization name.
                xml_attribute_name = member_shape.serialization["name"]
                structure_node.attrib[xml_attribute_name] = value
                continue
            self._serialize(member_shape, value, structure_node, member_name, mime_type)

    def _serialize_type_list(
        self, xmlnode: ETree.Element, params: list, shape: ListShape, name: str, mime_type: str
    ) -> None:
        if params is None:
            # Don't serialize any param whose value is None.
            return
        member_shape = shape.member
        if shape.serialization.get("flattened"):
            # If the list is flattened, either take the member's "name" or the name of the usual name for the parent
            # element for the children.
            element_name = self._get_serialized_name(member_shape, name)
            list_node = xmlnode
        else:
            element_name = self._get_serialized_name(member_shape, "member")
            list_node = ETree.SubElement(xmlnode, name)
        for item in params:
            # Don't serialize any item which is None
            if item is not None:
                self._serialize(member_shape, item, list_node, element_name, mime_type)

    def _serialize_type_map(
        self, xmlnode: ETree.Element, params: dict, shape: MapShape, name: str, mime_type: str
    ) -> None:
        """
        Given the ``name`` of MyMap, an input of {"key1": "val1", "key2": "val2"}, and the ``flattened: False``
        we serialize this as:
          <MyMap>
            <entry>
              <key>key1</key>
              <value>val1</value>
            </entry>
            <entry>
              <key>key2</key>
              <value>val2</value>
            </entry>
          </MyMap>
        If it is flattened, it is serialized as follows:
          <MyMap>
            <key>key1</key>
            <value>val1</value>
          </MyMap>
          <MyMap>
            <key>key2</key>
            <value>val2</value>
          </MyMap>
        """
        if params is None:
            # Don't serialize a non-existing map
            return
        if shape.serialization.get("flattened"):
            entries_node = xmlnode
            entry_node_name = name
        else:
            entries_node = ETree.SubElement(xmlnode, name)
            entry_node_name = "entry"

        for key, value in params.items():
            if value is None:
                # Don't serialize any param whose value is None.
                continue
            entry_node = ETree.SubElement(entries_node, entry_node_name)
            key_name = self._get_serialized_name(shape.key, default_name="key")
            val_name = self._get_serialized_name(shape.value, default_name="value")
            self._serialize(shape.key, key, entry_node, key_name, mime_type)
            self._serialize(shape.value, value, entry_node, val_name, mime_type)

    @staticmethod
    def _serialize_type_boolean(xmlnode: ETree.Element, params: bool, _, name: str, __) -> None:
        """
        For scalar types, the 'params' attr is actually just a scalar value representing the data
        we need to serialize as a boolean. It will either be 'true' or 'false'
        """
        node = ETree.SubElement(xmlnode, name)
        if params:
            str_value = "true"
        else:
            str_value = "false"
        node.text = str_value

    def _serialize_type_blob(
        self, xmlnode: ETree.Element, params: Union[str, bytes], _, name: str, __
    ) -> None:
        node = ETree.SubElement(xmlnode, name)
        node.text = self._get_base64(params)

    def _serialize_type_timestamp(
        self, xmlnode: ETree.Element, params: str, shape: Shape, name: str, mime_type: str
    ) -> None:
        node = ETree.SubElement(xmlnode, name)
        if mime_type != APPLICATION_JSON:
            # Default XML timestamp serialization
            node.text = self._convert_timestamp_to_str(
                params, shape.serialization.get("timestampFormat")
            )
        else:
            # For services with XML protocols, where the Accept header is JSON, timestamps are formatted like for JSON
            # protocols, but using the int representation instead of the float representation (f.e. requesting JSON
            # responses in STS).
            node.text = str(
                int(self._convert_timestamp_to_str(params, JSONResponseSerializer.TIMESTAMP_FORMAT))
            )

    def _default_serialize(self, xmlnode: ETree.Element, params: str, _, name: str, __) -> None:
        node = ETree.SubElement(xmlnode, name)
        node.text = str(params)

    def _prepare_additional_traits_in_xml(self, root: Optional[ETree.Element], request_id: str):
        """
        Prepares the XML root node before being serialized with additional traits (like the Response ID in the Query
        protocol).
        For some protocols (like rest-xml), the root can be None.
        """
        pass

    def _create_default_response(self, operation_model: OperationModel, mime_type: str) -> Response:
        response = super()._create_default_response(operation_model, mime_type)
        response.headers["Content-Type"] = mime_type
        return response

    def _node_to_string(self, root: Optional[ETree.Element], mime_type: str) -> Optional[str]:
        """Generates the string representation of the given XML element."""
        if root is not None:
            content = ETree.tostring(
                element=root, encoding=self.DEFAULT_ENCODING, xml_declaration=True
            )
            if mime_type == APPLICATION_JSON:
                # FIXME try to directly convert the ElementTree node to JSON
                xml_dict = xmltodict.parse(content)
                xml_dict = strip_xmlns(xml_dict)
                content = json.dumps(xml_dict)
            return content


class BaseRestResponseSerializer(ResponseSerializer, ABC):
    """
    The BaseRestResponseSerializer performs the basic logic for the ReST response serialization.
    In our case it basically only adds the request metadata to the HTTP header.
    """

    HEADER_TIMESTAMP_FORMAT = "rfc822"

    def _serialize_response(
        self,
        parameters: dict,
        response: Response,
        shape: Optional[Shape],
        shape_members: dict,
        operation_model: OperationModel,
        mime_type: str,
        request_id: str,
    ) -> None:
        header_params, payload_params = self._partition_members(parameters, shape)
        self._process_header_members(header_params, response, shape)
        # "HEAD" responses are basically "GET" responses without the actual body.
        # Do not process the body payload in this case (setting a body could also manipulate the headers)
        if operation_model.http.get("method") != "HEAD":
            self._serialize_payload(
                payload_params,
                response,
                shape,
                shape_members,
                operation_model,
                mime_type,
                request_id,
            )
        self._serialize_content_type(response, shape, shape_members, mime_type)
        self._prepare_additional_traits_in_response(response, operation_model, request_id)

    def _serialize_payload(
        self,
        parameters: dict,
        response: Response,
        shape: Optional[Shape],
        shape_members: dict,
        operation_model: OperationModel,
        mime_type: str,
        request_id: str,
    ) -> None:
        """
        Serializes the given payload.

        :param parameters: The user input params
        :param response: The final serialized Response
        :param shape: Describes the expected output shape (can be None in case of an "empty" response)
        :param shape_members: The members of the output struct shape
        :param operation_model: The specification of the operation of which the response is serialized here
        :param mime_type: Mime type which should be used to encode the payload
        :param request_id: autogenerated AWS request ID identifying the original request
        :return: None - the given `serialized` dict is modified
        """
        if shape is None:
            return

        payload_member = shape.serialization.get("payload")
        # If this shape is defined as being an event, we need to search for the payload member
        if not payload_member and shape.serialization.get("event"):
            for member_name, member_shape in shape_members.items():
                # Try to find the first shape which is marked as "eventpayload" and is given in the params dict
                if member_shape.serialization.get("eventpayload") and parameters.get(member_name):
                    payload_member = member_name
                    break
        if payload_member is not None and shape_members[payload_member].type_name in [
            "blob",
            "string",
        ]:
            # If it's streaming, then the body is just the value of the payload.
            body_payload = parameters.get(payload_member, b"")
            body_payload = self._encode_payload(body_payload)
            response.set_response(body_payload)
        elif payload_member is not None:
            # If there's a payload member, we serialized that member to the body.
            body_params = parameters.get(payload_member)
            if body_params is not None:
                response.set_response(
                    self._encode_payload(
                        self._serialize_body_params(
                            body_params,
                            shape_members[payload_member],
                            operation_model,
                            mime_type,
                            request_id,
                        )
                    )
                )
        else:
            # Otherwise, we use the "traditional" way of serializing the whole parameters dict recursively.
            response.set_response(
                self._encode_payload(
                    self._serialize_body_params(
                        parameters, shape, operation_model, mime_type, request_id
                    )
                )
            )

    def _serialize_content_type(
        self, serialized: Response, shape: Shape, shape_members: dict, mime_type: str
    ):
        """
        Some protocols require varied Content-Type headers depending on user input.
        This allows subclasses to apply this conditionally.
        """
        pass

    def _has_streaming_payload(self, payload: Optional[str], shape_members):
        """Determine if payload is streaming (a blob or string)."""
        return payload is not None and shape_members[payload].type_name in ["blob", "string"]

    def _prepare_additional_traits_in_response(
        self, response: Response, operation_model: OperationModel, request_id: str
    ):
        """Adds the request ID to the headers (in contrast to the body - as in the Query protocol)."""
        response = super()._prepare_additional_traits_in_response(
            response, operation_model, request_id
        )
        response.headers["x-amz-request-id"] = request_id
        return response

    def _process_header_members(self, parameters: dict, response: Response, shape: Shape):
        shape_members = shape.members if isinstance(shape, StructureShape) else []
        for name in shape_members:
            member_shape = shape_members[name]
            location = member_shape.serialization.get("location")
            if not location:
                continue
            if name not in parameters:
                # ignores optional keys
                continue
            key = member_shape.serialization.get("name", name)
            value = parameters[name]
            if value is None:
                continue
            if location == "header":
                response.headers[key] = self._serialize_header_value(member_shape, value)
            elif location == "headers":
                header_prefix = key
                self._serialize_header_map(header_prefix, response, value)
            elif location == "statusCode":
                response.status_code = int(value)

    def _serialize_header_map(self, prefix: str, response: Response, params: dict) -> None:
        """Serializes the header map for the location trait "headers"."""
        for key, val in params.items():
            actual_key = prefix + key
            response.headers[actual_key] = val

    def _serialize_header_value(self, shape: Shape, value: Any):
        """Serializes a value for the location trait "header"."""
        if shape.type_name == "timestamp":
            datetime_obj = parse_to_aware_datetime(value)
            timestamp_format = shape.serialization.get(
                "timestampFormat", self.HEADER_TIMESTAMP_FORMAT
            )
            return self._convert_timestamp_to_str(datetime_obj, timestamp_format)
        elif shape.type_name == "list":
            converted_value = [
                self._serialize_header_value(shape.member, v) for v in value if v is not None
            ]
            return ",".join(converted_value)
        elif shape.type_name == "boolean":
            # Set the header value to "true" if the given value is truthy, otherwise set the header value to "false".
            return "true" if value else "false"
        elif is_json_value_header(shape):
            # Serialize with no spaces after separators to save space in
            # the header.
            return self._get_base64(json.dumps(value, separators=(",", ":")))
        else:
            return value

    def _partition_members(self, parameters: dict, shape: Optional[Shape]) -> Tuple[dict, dict]:
        """Separates the top-level keys in the given parameters dict into header- and payload-located params."""
        if not isinstance(shape, StructureShape):
            # If the shape isn't a structure, we default to the whole response being parsed in the body.
            # Non-payload members are only loaded in the top-level hierarchy and those are always structures.
            return {}, parameters
        header_params = {}
        payload_params = {}
        shape_members = shape.members
        for name in shape_members:
            member_shape = shape_members[name]
            if name not in parameters:
                continue
            location = member_shape.serialization.get("location")
            if location:
                header_params[name] = parameters[name]
            else:
                payload_params[name] = parameters[name]
        return header_params, payload_params


class RestXMLResponseSerializer(BaseRestResponseSerializer, BaseXMLResponseSerializer):
    """
    The ``RestXMLResponseSerializer`` is responsible for the serialization of responses from services with the
    ``rest-xml`` protocol.
    It combines the ``BaseRestResponseSerializer`` (for the ReST specific logic) with the ``BaseXMLResponseSerializer``
    (for the XML body response serialization).
    """

    pass


class QueryResponseSerializer(BaseXMLResponseSerializer):
    """
    The ``QueryResponseSerializer`` is responsible for the serialization of responses from services which use the
    ``query`` protocol. The responses of these services also use XML. It is basically a subset of the features, since it
    does not allow any payload or location traits.
    """

    def _serialize_response(
        self,
        parameters: dict,
        response: Response,
        shape: Optional[Shape],
        shape_members: dict,
        operation_model: OperationModel,
        mime_type: str,
        request_id: str,
    ) -> None:
        """
        Serializes the given parameters as XML for the query protocol.

        :param parameters: The user input params
        :param response: The final serialized Response
        :param shape: Describes the expected output shape (can be None in case of an "empty" response)
        :param shape_members: The members of the output struct shape
        :param operation_model: The specification of the operation of which the response is serialized here
        :param mime_type: Mime type which should be used to encode the payload
        :param request_id: autogenerated AWS request ID identifying the original request
        :return: None - the given `serialized` dict is modified
        """
        response.set_response(
            self._encode_payload(
                self._serialize_body_params(
                    parameters, shape, operation_model, mime_type, request_id
                )
            )
        )

    def _serialize_body_params_to_xml(
        self, params: dict, shape: Shape, operation_model: OperationModel, mime_type: str
    ) -> ETree.Element:
        # The Query protocol responses have a root element which is not contained in the specification file.
        # Therefore, we first call the super function to perform the normal XML serialization, and afterwards wrap the
        # result in a root element based on the operation name.
        node = super()._serialize_body_params_to_xml(params, shape, operation_model, mime_type)

        # Check if we need to add a namespace
        attr = (
            {"xmlns": operation_model.metadata.get("xmlNamespace")}
            if "xmlNamespace" in operation_model.metadata
            else None
        )

        # Create the root element and add the result of the XML serializer as a child node
        root = ETree.Element(f"{operation_model.name}Response", attr)
        if node is not None:
            root.append(node)
        return root

    def _prepare_additional_traits_in_xml(self, root: Optional[ETree.Element], request_id: str):
        # Add the response metadata here (it's not defined in the specs)
        # For the ec2 and the query protocol, the root cannot be None at this time.
        response_metadata = ETree.SubElement(root, "ResponseMetadata")
        request_id_element = ETree.SubElement(response_metadata, "RequestId")
        request_id_element.text = request_id


class EC2ResponseSerializer(QueryResponseSerializer):
    """
    The ``EC2ResponseSerializer`` is responsible for the serialization of responses from services which use the
    ``ec2`` protocol (basically the EC2 service). This protocol is basically equal to the ``query`` protocol with only
    a few subtle differences.
    """

    def _serialize_error(
        self,
        error: ServiceException,
        response: Response,
        shape: StructureShape,
        operation_model: OperationModel,
        mime_type: str,
        request_id: str,
    ) -> None:
        # EC2 errors look like:
        # <Response>
        #   <Errors>
        #     <Error>
        #       <Code>InvalidInstanceID.Malformed</Code>
        #       <Message>Invalid id: "1343124"</Message>
        #     </Error>
        #   </Errors>
        #   <RequestID>12345</RequestID>
        # </Response>
        # This is different from QueryParser in that it's RequestID, not RequestId
        # and that the Error tag is in an enclosing Errors tag.
        attr = (
            {"xmlns": operation_model.metadata.get("xmlNamespace")}
            if "xmlNamespace" in operation_model.metadata
            else None
        )
        root = ETree.Element("Response", attr)
        errors_tag = ETree.SubElement(root, "Errors")
        error_tag = ETree.SubElement(errors_tag, "Error")
        self._add_error_tags(error, error_tag, mime_type)
        request_id_element = ETree.SubElement(root, "RequestID")
        request_id_element.text = request_id
        response.set_response(self._encode_payload(self._node_to_string(root, mime_type)))

    def _prepare_additional_traits_in_xml(self, root: Optional[ETree.Element], request_id: str):
        # The EC2 protocol does not use the root output shape, therefore we need to remove the hierarchy level
        # below the root level
        if len(root) > 0:
            output_node = root[0]
            for child in output_node:
                root.append(child)
            root.remove(output_node)

        # Add the requestId here (it's not defined in the specs)
        # For the ec2 and the query protocol, the root cannot be None at this time.
        request_id_element = ETree.SubElement(root, "requestId")
        request_id_element.text = request_id


class JSONResponseSerializer(ResponseSerializer):
    """
    The ``JSONResponseSerializer`` is responsible for the serialization of responses from services with the ``json``
    protocol. It implements the JSON response body serialization, which is also used by the
    ``RestJSONResponseSerializer``.
    """

    JSON_TYPES = [APPLICATION_JSON, APPLICATION_AMZ_JSON_1_0, APPLICATION_AMZ_JSON_1_1]
    CBOR_TYPES = [APPLICATION_CBOR, APPLICATION_AMZ_CBOR_1_1]
    SUPPORTED_MIME_TYPES = JSON_TYPES + CBOR_TYPES

    TIMESTAMP_FORMAT = "unixtimestamp"

    def _serialize_error(
        self,
        error: ServiceException,
        response: Response,
        shape: StructureShape,
        operation_model: OperationModel,
        mime_type: str,
        request_id: str,
    ) -> None:
        body = dict()

        # TODO implement different service-specific serializer configurations
        #   - currently we set both, the `__type` member as well as the `X-Amzn-Errortype` header
        #   - the specification defines that it's either the __type field OR the header
        response.headers["X-Amzn-Errortype"] = error.code
        body["__type"] = error.code

        if shape:
            remaining_params = {}
            # TODO add a possibility to serialize simple non-modelled errors (like S3 NoSuchBucket#BucketName)
            for member in shape.members:
                if hasattr(error, member):
                    remaining_params[member] = getattr(error, member)
                # Default error message fields can sometimes have different casing in the specs
                elif member.lower() in ["code", "message"] and hasattr(error, member.lower()):
                    remaining_params[member] = getattr(error, member.lower())
            self._serialize(body, remaining_params, shape, None, mime_type)

        # Only set the message if it has not been set with the shape members
        if "message" not in body and "Message" not in body:
            message = self._get_error_message(error)
            if message is not None:
                body["message"] = message

        if mime_type in self.CBOR_TYPES:
            response.set_response(cbor2.dumps(body))
            response.content_type = mime_type
        else:
            response.set_json(body)

    def _serialize_response(
        self,
        parameters: dict,
        response: Response,
        shape: Optional[Shape],
        shape_members: dict,
        operation_model: OperationModel,
        mime_type: str,
        request_id: str,
    ) -> None:
        if mime_type in self.CBOR_TYPES:
            response.content_type = mime_type
        else:
            json_version = operation_model.metadata.get("jsonVersion")
            if json_version is not None:
                response.headers["Content-Type"] = "application/x-amz-json-%s" % json_version
        response.set_response(
            self._serialize_body_params(parameters, shape, operation_model, mime_type, request_id)
        )

    def _serialize_body_params(
        self,
        params: dict,
        shape: Shape,
        operation_model: OperationModel,
        mime_type: str,
        request_id: str,
    ) -> Optional[str]:
        body = {}
        if shape is not None:
            self._serialize(body, params, shape, None, mime_type)

        if mime_type in self.CBOR_TYPES:
            return cbor2.dumps(body)
        else:
            return json.dumps(body)

    def _serialize(self, body: dict, value: Any, shape, key: Optional[str], mime_type: str):
        """This method dynamically invokes the correct `_serialize_type_*` method for each shape type."""
        try:
            method = getattr(self, "_serialize_type_%s" % shape.type_name, self._default_serialize)
            method(body, value, shape, key, mime_type)
        except (TypeError, ValueError, AttributeError) as e:
            raise ProtocolSerializerError(
                f"Invalid type when serializing {shape.name}: '{value}' cannot be parsed to {shape.type_name}."
            ) from e

    def _serialize_type_structure(
        self, body: dict, value: dict, shape: StructureShape, key: Optional[str], mime_type: str
    ):
        if value is None:
            return
        if shape.is_document_type:
            body[key] = value
        else:
            if key is not None:
                # If a key is provided, this is a result of a recursive
                # call, so we need to add a new child dict as the value
                # of the passed in serialized dict.  We'll then add
                # all the structure members as key/vals in the new serialized
                # dictionary we just created.
                new_serialized = {}
                body[key] = new_serialized
                body = new_serialized
            members = shape.members
            for member_key, member_value in value.items():
                if member_value is None:
                    continue
                try:
                    member_shape = members[member_key]
                except KeyError:
                    LOG.warning(
                        "Response object %s contains a member which is not specified: %s",
                        shape.name,
                        member_key,
                    )
                    continue
                if "name" in member_shape.serialization:
                    member_key = member_shape.serialization["name"]
                self._serialize(body, member_value, member_shape, member_key, mime_type)

    def _serialize_type_map(
        self, body: dict, value: dict, shape: MapShape, key: str, mime_type: str
    ):
        if value is None:
            return
        map_obj = {}
        body[key] = map_obj
        for sub_key, sub_value in value.items():
            if sub_value is not None:
                self._serialize(map_obj, sub_value, shape.value, sub_key, mime_type)

    def _serialize_type_list(
        self, body: dict, value: list, shape: ListShape, key: str, mime_type: str
    ):
        if value is None:
            return
        list_obj = []
        body[key] = list_obj
        for list_item in value:
            if list_item is not None:
                wrapper = {}
                # The JSON list serialization is the only case where we aren't
                # setting a key on a dict.  We handle this by using
                # a __current__ key on a wrapper dict to serialize each
                # list item before appending it to the serialized list.
                self._serialize(wrapper, list_item, shape.member, "__current__", mime_type)
                list_obj.append(wrapper["__current__"])

    def _default_serialize(self, body: dict, value: Any, _, key: str, __):
        body[key] = value

    def _serialize_type_timestamp(
        self, body: dict, value: Any, shape: Shape, key: str, mime_type: str
    ):
        timestamp_format = (
            shape.serialization.get("timestampFormat")
            # CBOR always uses unix timestamp milliseconds
            if mime_type not in self.CBOR_TYPES
            else "unixtimestampmillis"
        )
        body[key] = self._convert_timestamp_to_str(value, timestamp_format)

    def _serialize_type_blob(
        self, body: dict, value: Union[str, bytes], _, key: str, mime_type: str
    ):
        if mime_type in self.CBOR_TYPES:
            body[key] = value
        else:
            body[key] = self._get_base64(value)

    def _prepare_additional_traits_in_response(
        self, response: Response, operation_model: OperationModel, request_id: str
    ):
        response.headers["x-amzn-requestid"] = request_id
        response = super()._prepare_additional_traits_in_response(
            response, operation_model, request_id
        )
        return response


class RestJSONResponseSerializer(BaseRestResponseSerializer, JSONResponseSerializer):
    """
    The ``RestJSONResponseSerializer`` is responsible for the serialization of responses from services with the
    ``rest-json`` protocol.
    It combines the ``BaseRestResponseSerializer`` (for the ReST specific logic) with the ``JSONResponseSerializer``
    (for the JSOn body response serialization).
    """

    def _serialize_content_type(
        self, serialized: Response, shape: Shape, shape_members: dict, mime_type: str
    ):
        """Set Content-Type to application/json for all structured bodies."""
        payload = shape.serialization.get("payload") if shape is not None else None
        if self._has_streaming_payload(payload, shape_members):
            # Don't apply content-type to streaming bodies
            return

        has_body = serialized.data != b""
        has_content_type = self._has_header("Content-Type", serialized.headers)
        if has_body and not has_content_type:
            serialized.headers["Content-Type"] = mime_type


class S3ResponseSerializer(RestXMLResponseSerializer):
    """
    The ``S3ResponseSerializer`` adds some minor logic to handle S3 specific peculiarities with the error response
    serialization and the root node tag.
    """

    SUPPORTED_MIME_TYPES = [APPLICATION_XML, TEXT_XML]
    _RESPONSE_ROOT_TAGS = {
        "CompleteMultipartUploadOutput": "CompleteMultipartUploadResult",
        "CopyObjectOutput": "CopyObjectResult",
        "CreateMultipartUploadOutput": "InitiateMultipartUploadResult",
        "DeleteObjectsOutput": "DeleteResult",
        "GetBucketAccelerateConfigurationOutput": "AccelerateConfiguration",
        "GetBucketAclOutput": "AccessControlPolicy",
        "GetBucketAnalyticsConfigurationOutput": "AnalyticsConfiguration",
        "GetBucketCorsOutput": "CORSConfiguration",
        "GetBucketEncryptionOutput": "ServerSideEncryptionConfiguration",
        "GetBucketIntelligentTieringConfigurationOutput": "IntelligentTieringConfiguration",
        "GetBucketInventoryConfigurationOutput": "InventoryConfiguration",
        "GetBucketLifecycleOutput": "LifecycleConfiguration",
        "GetBucketLifecycleConfigurationOutput": "LifecycleConfiguration",
        "GetBucketLoggingOutput": "BucketLoggingStatus",
        "GetBucketMetricsConfigurationOutput": "MetricsConfiguration",
        "NotificationConfigurationDeprecated": "NotificationConfiguration",
        "GetBucketOwnershipControlsOutput": "OwnershipControls",
        "GetBucketPolicyStatusOutput": "PolicyStatus",
        "GetBucketReplicationOutput": "ReplicationConfiguration",
        "GetBucketRequestPaymentOutput": "RequestPaymentConfiguration",
        "GetBucketTaggingOutput": "Tagging",
        "GetBucketVersioningOutput": "VersioningConfiguration",
        "GetBucketWebsiteOutput": "WebsiteConfiguration",
        "GetObjectAclOutput": "AccessControlPolicy",
        "GetObjectLegalHoldOutput": "LegalHold",
        "GetObjectLockConfigurationOutput": "ObjectLockConfiguration",
        "GetObjectRetentionOutput": "Retention",
        "GetObjectTaggingOutput": "Tagging",
        "GetObjectAttributesOutput": "GetObjectAttributesResponse",
        "GetPublicAccessBlockOutput": "PublicAccessBlockConfiguration",
        "ListBucketAnalyticsConfigurationsOutput": "ListBucketAnalyticsConfigurationResult",
        "ListBucketInventoryConfigurationsOutput": "ListInventoryConfigurationsResult",
        "ListBucketMetricsConfigurationsOutput": "ListMetricsConfigurationsResult",
        "ListBucketsOutput": "ListAllMyBucketsResult",
        "ListMultipartUploadsOutput": "ListMultipartUploadsResult",
        "ListObjectsOutput": "ListBucketResult",
        "ListObjectsV2Output": "ListBucketResult",
        "ListObjectVersionsOutput": "ListVersionsResult",
        "ListPartsOutput": "ListPartsResult",
        "UploadPartCopyOutput": "CopyPartResult",
    }

    XML_NAMESPACE = "http://s3.amazonaws.com/doc/2006-03-01/"

    def _serialize_response(
        self,
        parameters: dict,
        response: Response,
        shape: Optional[Shape],
        shape_members: dict,
        operation_model: OperationModel,
        mime_type: str,
        request_id: str,
    ) -> None:
        header_params, payload_params = self._partition_members(parameters, shape)
        self._process_header_members(header_params, response, shape)
        # "HEAD" responses are basically "GET" responses without the actual body.
        # Do not process the body payload in this case (setting a body could also manipulate the headers)
        # - If the response is a redirection, the body should be empty as well
        # - If the response is from a "PUT" request, the body should be empty except if there's a specific "payload"
        #   field in the serialization (CopyObject and CopyObjectPart)
        http_method = operation_model.http.get("method")
        if (
            http_method != "HEAD"
            and not 300 <= response.status_code < 400
            and not (http_method == "PUT" and shape and not shape.serialization.get("payload"))
        ):
            self._serialize_payload(
                payload_params,
                response,
                shape,
                shape_members,
                operation_model,
                mime_type,
                request_id,
            )
        self._serialize_content_type(response, shape, shape_members, mime_type)

    def _serialize_error(
        self,
        error: ServiceException,
        response: Response,
        shape: StructureShape,
        operation_model: OperationModel,
        mime_type: str,
        request_id: str,
    ) -> None:
        attr = (
            {"xmlns": operation_model.metadata.get("xmlNamespace")}
            if "xmlNamespace" in operation_model.metadata
            else {}
        )
        root = ETree.Element("Error", attr)
        self._add_error_tags(error, root, mime_type)
        request_id_element = ETree.SubElement(root, "RequestId")
        request_id_element.text = request_id

        header_params, payload_params = self._partition_members(vars(error), shape)
        self._add_additional_error_tags(payload_params, root, shape, mime_type)
        self._process_header_members(header_params, response, shape)

        response.set_response(self._encode_payload(self._node_to_string(root, mime_type)))

    def _serialize_body_params(
        self,
        params: dict,
        shape: Shape,
        operation_model: OperationModel,
        mime_type: str,
        request_id: str,
    ) -> Optional[str]:
        root = self._serialize_body_params_to_xml(params, shape, operation_model, mime_type)
        # S3 does not follow the specs on the root tag name for 41 of 44 operations
        root.tag = self._RESPONSE_ROOT_TAGS.get(root.tag, root.tag)
        self._prepare_additional_traits_in_xml(root, request_id)
        return self._node_to_string(root, mime_type)

    def _prepare_additional_traits_in_response(
        self, response: Response, operation_model: OperationModel, request_id: str
    ):
        """Adds the request ID to the headers (in contrast to the body - as in the Query protocol)."""
        response = super()._prepare_additional_traits_in_response(
            response, operation_model, request_id
        )
        # s3 extended Request ID
        # mostly used internally on AWS and corresponds to a HostId
        response.headers["x-amz-id-2"] = (
            "s9lzHYrFp76ZVxRcpX9+5cjAnEH2ROuNkd2BHfIa6UkFVdtjf5mKR3/eTPFvsiP/XV/VLi31234="
        )
        return response

    def _add_error_tags(
        self, error: ServiceException, error_tag: ETree.Element, mime_type: str
    ) -> None:
        code_tag = ETree.SubElement(error_tag, "Code")
        code_tag.text = error.code
        message = self._get_error_message(error)
        if message:
            self._default_serialize(error_tag, message, None, "Message", mime_type)
        else:
            # In S3, if there's no message, create an empty node
            self._create_empty_node(error_tag, "Message")
        if error.sender_fault:
            # The sender fault is either not set or "Sender"
            self._default_serialize(error_tag, "Sender", None, "Type", mime_type)

    @staticmethod
    def _create_empty_node(xmlnode: ETree.Element, name: str) -> None:
        ETree.SubElement(xmlnode, name)

    def _prepare_additional_traits_in_xml(self, root: Optional[ETree.Element], request_id: str):
        # some tools (Serverless) require a newline after the "<?xml ...>\n" preamble line, e.g., for LocationConstraint
        if root and not root.tail:
            root.tail = "\n"

        root.attrib["xmlns"] = self.XML_NAMESPACE

    @staticmethod
    def _timestamp_iso8601(value: datetime) -> str:
        """
        This is very specific to S3, S3 returns an ISO8601 timestamp but with milliseconds always set to 000
        Some SDKs are very picky about the length
        """
        return value.strftime("%Y-%m-%dT%H:%M:%S.000Z")


class SqsQueryResponseSerializer(QueryResponseSerializer):
    """
    Unfortunately, SQS uses a rare interpretation of the XML protocol: It uses HTML entities within XML tag text nodes.
    For example:
    - Normal XML serializers: <Message>No need to escape quotes (like this: ") with HTML entities in XML.</Message>
    - SQS XML serializer: <Message>No need to escape quotes (like this: &quot;) with HTML entities in XML.</Message>

    None of the prominent XML frameworks for python allow HTML entity escapes when serializing XML.
    This serializer implements the following workaround:
    - Escape quotes and \r with their HTML entities (&quot; and &#xD;).
    - Since & is (correctly) escaped in XML, the serialized string contains &amp;quot; and &amp;#xD;
    - These double-escapes are corrected by replacing such strings with their original.
    """

    # those are deleted from the JSON specs, but need to be kept for legacy reason (sent in 'x-amzn-query-error')
    QUERY_PREFIXED_ERRORS = {
        "BatchEntryIdsNotDistinct",
        "BatchRequestTooLong",
        "EmptyBatchRequest",
        "InvalidBatchEntryId",
        "MessageNotInflight",
        "PurgeQueueInProgress",
        "QueueDeletedRecently",
        "TooManyEntriesInBatchRequest",
        "UnsupportedOperation",
    }

    # Some error code changed between JSON and query, and we need to have a way to map it for legacy reason
    JSON_TO_QUERY_ERROR_CODES = {
        "InvalidParameterValueException": "InvalidParameterValue",
        "MissingRequiredParameterException": "MissingParameter",
        "AccessDeniedException": "AccessDenied",
        "QueueDoesNotExist": "AWS.SimpleQueueService.NonExistentQueue",
        "QueueNameExists": "QueueAlreadyExists",
    }

    SENDER_FAULT_ERRORS = (
        QUERY_PREFIXED_ERRORS
        | JSON_TO_QUERY_ERROR_CODES.keys()
        | {"OverLimit", "ResourceNotFoundException"}
    )

    def _default_serialize(self, xmlnode: ETree.Element, params: str, _, name: str, __) -> None:
        """
        Ensures that we "mark" characters in the node's text which need to be specifically encoded.
        This is necessary to easily identify these specific characters later, after the standard XML serialization is
        done, while not replacing any other occurrences of these characters which might appear in the serialized string.
        """
        node = ETree.SubElement(xmlnode, name)
        node.text = (
            str(params)
            .replace('"', '__marker__"__marker__')
            .replace("\r", "__marker__-r__marker__")
        )

    def _node_to_string(self, root: Optional[ETree.ElementTree], mime_type: str) -> Optional[str]:
        """Replaces the previously "marked" characters with their encoded value."""
        generated_string = super()._node_to_string(root, mime_type)
        if generated_string is None:
            return None
        generated_string = to_str(generated_string)
        # Undo the second escaping of the &
        # Undo the second escaping of the carriage return (\r)
        if mime_type == APPLICATION_JSON:
            # At this point the json was already dumped and escaped, so we replace directly.
            generated_string = generated_string.replace(r"__marker__\"__marker__", r"\"").replace(
                "__marker__-r__marker__", r"\r"
            )
        else:
            generated_string = generated_string.replace('__marker__"__marker__', "&quot;").replace(
                "__marker__-r__marker__", "&#xD;"
            )

        return to_bytes(generated_string)

    def _add_error_tags(
        self, error: ServiceException, error_tag: ETree.Element, mime_type: str
    ) -> None:
        """The SQS API stubs is now generated from JSON specs, and some fields have been modified"""
        code_tag = ETree.SubElement(error_tag, "Code")

        if error.code in self.JSON_TO_QUERY_ERROR_CODES:
            error_code = self.JSON_TO_QUERY_ERROR_CODES[error.code]
        elif error.code in self.QUERY_PREFIXED_ERRORS:
            error_code = f"AWS.SimpleQueueService.{error.code}"
        else:
            error_code = error.code
        code_tag.text = error_code
        message = self._get_error_message(error)
        if message:
            self._default_serialize(error_tag, message, None, "Message", mime_type)
        if error.code in self.SENDER_FAULT_ERRORS or error.sender_fault:
            # The sender fault is either not set or "Sender"
            self._default_serialize(error_tag, "Sender", None, "Type", mime_type)


class SqsJsonResponseSerializer(JSONResponseSerializer):
    # those are deleted from the JSON specs, but need to be kept for legacy reason (sent in 'x-amzn-query-error')
    QUERY_PREFIXED_ERRORS = {
        "BatchEntryIdsNotDistinct",
        "BatchRequestTooLong",
        "EmptyBatchRequest",
        "InvalidBatchEntryId",
        "MessageNotInflight",
        "PurgeQueueInProgress",
        "QueueDeletedRecently",
        "TooManyEntriesInBatchRequest",
        "UnsupportedOperation",
    }

    # Some error code changed between JSON and query, and we need to have a way to map it for legacy reason
    JSON_TO_QUERY_ERROR_CODES = {
        "InvalidParameterValueException": "InvalidParameterValue",
        "MissingRequiredParameterException": "MissingParameter",
        "AccessDeniedException": "AccessDenied",
        "QueueDoesNotExist": "AWS.SimpleQueueService.NonExistentQueue",
        "QueueNameExists": "QueueAlreadyExists",
    }

    def _serialize_error(
        self,
        error: ServiceException,
        response: Response,
        shape: StructureShape,
        operation_model: OperationModel,
        mime_type: str,
        request_id: str,
    ) -> None:
        """
        Overrides _serialize_error as SQS has a special header for query API legacy reason: 'x-amzn-query-error',
        which contained the exception code as well as a Sender field.
        Ex: 'x-amzn-query-error': 'InvalidParameterValue;Sender'
        """
        # TODO: for body["__type"] = error.code, it seems AWS differs from what we send for SQS
        # AWS: "com.amazon.coral.service#InvalidParameterValueException"
        # or AWS: "com.amazonaws.sqs#BatchRequestTooLong"
        # LocalStack: "InvalidParameterValue"
        super()._serialize_error(error, response, shape, operation_model, mime_type, request_id)
        # We need to add a prefix to certain errors, as they have been deleted in the specs. These will not change
        if error.code in self.JSON_TO_QUERY_ERROR_CODES:
            code = self.JSON_TO_QUERY_ERROR_CODES[error.code]
        elif error.code in self.QUERY_PREFIXED_ERRORS:
            code = f"AWS.SimpleQueueService.{error.code}"
        else:
            code = error.code

        response.headers["x-amzn-query-error"] = f"{code};Sender"


def gen_amzn_requestid():
    """
    Generate generic AWS request ID.

    3 uses a different format and set of request Ids.

    Examples:
    996d38a0-a4e9-45de-bad4-480cd962d208
    b9260553-df1b-4db6-ae41-97b89a5f85ea
    """
    return long_uid()


@functools.cache
def create_serializer(service: ServiceModel) -> ResponseSerializer:
    """
    Creates the right serializer for the given service model.

    :param service: to create the serializer for
    :return: ResponseSerializer which can handle the protocol of the service
    """

    # Unfortunately, some services show subtle differences in their serialized responses, even though their
    # specification states they implement the same protocol.
    # Since some clients might be stricter / less resilient than others, we need to mimic the serialization of the
    # specific services as close as possible.
    # Therefore, the service-specific serializer implementations (basically the implicit / informally more specific
    # protocol implementation) has precedence over the more general protocol-specific serializers.
    service_specific_serializers = {
        "sqs": {"json": SqsJsonResponseSerializer, "query": SqsQueryResponseSerializer},
        "s3": {"rest-xml": S3ResponseSerializer},
    }
    protocol_specific_serializers = {
        "query": QueryResponseSerializer,
        "json": JSONResponseSerializer,
        "rest-json": RestJSONResponseSerializer,
        "rest-xml": RestXMLResponseSerializer,
        "ec2": EC2ResponseSerializer,
    }

    # Try to select a service- and protocol-specific serializer implementation
    if (
        service.service_name in service_specific_serializers
        and service.protocol in service_specific_serializers[service.service_name]
    ):
        return service_specific_serializers[service.service_name][service.protocol]()
    else:
        # Otherwise, pick the protocol-specific serializer for the protocol of the service
        return protocol_specific_serializers[service.protocol]()


def aws_response_serializer(
    service_name: str, operation: str, protocol: Optional[ProtocolName] = None
):
    """
    A decorator for an HTTP route that can serialize return values or exceptions into AWS responses.
    This can be used to create AWS request handlers in a convenient way. Example usage::

        from localstack.http import route, Request
        from localstack.aws.api.sqs import ListQueuesResult

        @route("/_aws/sqs/queues")
        @aws_response_serializer("sqs", "ListQueues")
        def my_route(request: Request):
            if some_condition_on_request:
                raise CommonServiceError("...")  # <- will be serialized into an error response

            return ListQueuesResult(QueueUrls=...)  # <- object from the SQS API will be serialized

    :param service_name: the AWS service (e.g., "sqs", "lambda")
    :param protocol: the protocol of the AWS service to serialize to. If not set (by default) the default protocol
                    of the service in botocore is used.
    :param operation: the operation name (e.g., "ReceiveMessage", "ListFunctions")
    :returns: a decorator
    """

    def _decorate(fn):
        service_model = load_service(service_name, protocol=protocol)
        operation_model = service_model.operation_model(operation)
        serializer = create_serializer(service_model)

        def _proxy(*args, **kwargs) -> WerkzeugResponse:
            # extract request from function invocation (decorator can be used for methods as well as for functions).
            if len(args) > 0 and isinstance(args[0], WerkzeugRequest):
                # function
                request = args[0]
            elif len(args) > 1 and isinstance(args[1], WerkzeugRequest):
                # method (arg[0] == self)
                request = args[1]
            elif "request" in kwargs:
                request = kwargs["request"]
            else:
                raise ValueError(f"could not find Request in signature of function {fn}")

            # TODO: we have no context here
            # TODO: maybe try to get the request ID from the headers first before generating a new one
            request_id = gen_amzn_requestid()

            try:
                response = fn(*args, **kwargs)

                if isinstance(response, WerkzeugResponse):
                    return response

                return serializer.serialize_to_response(
                    response, operation_model, request.headers, request_id
                )

            except ServiceException as e:
                return serializer.serialize_error_to_response(
                    e, operation_model, request.headers, request_id
                )
            except Exception as e:
                return serializer.serialize_error_to_response(
                    CommonServiceException(
                        "InternalError", f"An internal error occurred: {e}", status_code=500
                    ),
                    operation_model,
                    request.headers,
                    request_id,
                )

        return _proxy

    return _decorate

"""Utils to process AWS requests as a client."""

import io
import logging
from datetime import datetime, timezone
from typing import Dict, Iterable, Optional
from urllib.parse import urlsplit

from botocore import awsrequest
from botocore.endpoint import Endpoint
from botocore.model import OperationModel
from botocore.parsers import ResponseParser, ResponseParserFactory
from werkzeug.datastructures import Headers

from localstack import config
from localstack.http import Request, Response
from localstack.runtime import hooks
from localstack.utils.patch import Patch, patch
from localstack.utils.strings import to_str

from .api import CommonServiceException, RequestContext, ServiceException, ServiceResponse
from .connect import get_service_endpoint
from .gateway import Gateway

LOG = logging.getLogger(__name__)


def create_http_request(aws_request: awsrequest.AWSPreparedRequest) -> Request:
    """
    Create an ASF HTTP Request from a botocore AWSPreparedRequest.

    :param aws_request: the botocore prepared request
    :return: a new Request
    """
    split_url = urlsplit(aws_request.url)
    host = split_url.netloc.split(":")
    if len(host) == 1:
        server = (to_str(host[0]), None)
    elif len(host) == 2:
        server = (to_str(host[0]), int(host[1]))
    else:
        raise ValueError

    # prepare the RequestContext
    headers = Headers()
    for k, v in aws_request.headers.items():
        headers[k] = to_str(v)

    return Request(
        method=aws_request.method,
        path=split_url.path,
        query_string=split_url.query,
        headers=headers,
        body=aws_request.body,
        server=server,
    )


class _ResponseStream(io.RawIOBase):
    """
    Wraps a Response and makes it available as a readable IO stream. If the response stream is used as an iterable, it
    will use the underlying response object directly.

    Adapted from https://stackoverflow.com/a/20260030/804840
    """

    def __init__(self, response: Response):
        self.response = response
        self.iterator = response.iter_encoded()
        self._buf = None

    def stream(self) -> Iterable[bytes]:
        # adds compatibility for botocore's client-side AWSResponse.raw attribute.
        return self.iterator

    def readable(self):
        return True

    def readinto(self, buffer):
        try:
            upto = len(buffer)  # We're supposed to return at most this much
            chunk = self._buf or next(self.iterator)
            # FIXME: this is very slow as it copies the entire chunk
            output, self._buf = chunk[:upto], chunk[upto:]
            buffer[: len(output)] = output
            return len(output)
        except StopIteration:
            return 0  # indicate EOF

    def read(self, amt=None) -> bytes | None:
        # see https://github.com/python/cpython/blob/main/Lib/_pyio.py
        # adds compatibility for botocore's client-side AWSResponse.raw attribute.
        # it seems the default implementation of RawIOBase.read to not handle well some cases
        if amt is None:
            amt = -1
        return super().read(amt)

    def close(self) -> None:
        return self.response.close()

    def __iter__(self):
        return self.iterator

    def __next__(self):
        return next(self.iterator)

    def __str__(self):
        length = self.response.content_length
        if length is None:
            length = "unknown"

        return f"StreamedBytes({length})"

    def __repr__(self):
        return self.__str__()


class _RawStream:
    """This is a compatibility adapter for the raw_stream attribute passed to botocore's EventStream."""

    def __init__(self, response: Response):
        self.response = response
        self.iterator = response.iter_encoded()

    def stream(self) -> Iterable[bytes]:
        return self.iterator

    def close(self):
        pass


def _add_modeled_error_fields(
    response_dict: Dict,
    parsed_response: Dict,
    operation_model: OperationModel,
    parser: ResponseParser,
):
    """
    This function adds additional error shape members (other than message, code, and type) to an already parsed error
    response dict.
    Port of botocore's Endpoint#_add_modeled_error_fields.
    """
    error_code = parsed_response.get("Error", {}).get("Code")
    if error_code is None:
        return
    service_model = operation_model.service_model
    error_shape = service_model.shape_for_error_code(error_code)
    if error_shape is None:
        return
    modeled_parse = parser.parse(response_dict, error_shape)
    parsed_response.update(modeled_parse)


def _cbor_timestamp_parser(value):
    return datetime.fromtimestamp(value / 1000)


def _cbor_blob_parser(value):
    return bytes(value)


@hooks.on_infra_start()
def _patch_botocore_json_parser():
    from botocore.parsers import BaseJSONParser

    @patch(BaseJSONParser._parse_body_as_json)
    def _parse_body_as_json(fn, self, body_contents):
        """
        botocore does not support CBOR encoded response parsing. Since we use the botocore parsers
        to parse responses from external backends (like kinesis-mock), we need to patch botocore to
        try CBOR decoding in case the JSON decoding fails.
        """
        try:
            return fn(self, body_contents)
        except UnicodeDecodeError as json_exception:
            # cbor2: explicitly load from private _decoder module to avoid using the (non-patched) C-version
            from cbor2._decoder import loads

            try:
                LOG.debug("botocore failed decoding JSON. Trying to decode as CBOR.")
                return loads(body_contents)
            except Exception as cbor_exception:
                LOG.debug("CBOR fallback decoding failed.")
                raise cbor_exception from json_exception


@hooks.on_infra_start()
def _patch_cbor2():
    """
    Patch fixing the AWS CBOR en-/decoding of datetime fields.

    Unfortunately, Kinesis (the only known service using CBOR) does not use the number of seconds (with floating-point
    milliseconds - according to RFC8949), but uses milliseconds.
    Python cbor2 is highly optimized by using a C-implementation by default, which cannot be patched.
    Instead of `from cbor2 import loads`, directly import the python-native loads implementation to avoid loading the
    unpatched C implementation:
    ```
    from cbor2._decoder import loads
    from cbor2._decoder import dumps
    ```

    See https://github.com/aws/aws-sdk-java-v2/issues/4661
    """
    from cbor2._decoder import CBORDecodeValueError, semantic_decoders
    from cbor2._encoder import CBOREncodeValueError, default_encoders
    from cbor2._types import CBORTag

    def _patched_decode_epoch_datetime(self) -> datetime:
        """
        Replaces `cbor2._decoder.CBORDecoder.decode_epoch_datetime` as default datetime semantic_decoder.
        """
        # Semantic tag 1
        value = self._decode()

        try:
            # The next line is the only change in this patch compared to the original function.
            # AWS breaks the CBOR spec by using the millis (instead of seconds with floating point support for millis)
            # https://github.com/aws/aws-sdk-java-v2/issues/4661
            value = value / 1000
            tmp = datetime.fromtimestamp(value, timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise CBORDecodeValueError("error decoding datetime from epoch") from exc

        return self.set_shareable(tmp)

    def _patched_encode_datetime(self, value: datetime) -> None:
        """
        Replaces `cbor2._encoder.CBOREncoder.encode_datetime` as default datetime default_encoder.
        """
        if not value.tzinfo:
            if self._timezone:
                value = value.replace(tzinfo=self._timezone)
            else:
                raise CBOREncodeValueError(
                    f"naive datetime {value!r} encountered and no default timezone has been set"
                )

        if self.datetime_as_timestamp:
            from calendar import timegm

            if not value.microsecond:
                timestamp: float = timegm(value.utctimetuple())
            else:
                timestamp = timegm(value.utctimetuple()) + value.microsecond / 1000000
            # The next line is the only change in this patch compared to the original function.
            # - AWS breaks the CBOR spec by using the millis (instead of seconds with floating point support for millis)
            #   https://github.com/aws/aws-sdk-java-v2/issues/4661
            # - AWS SDKs in addition have very tight assumptions on the type.
            #   This needs to be an integer, and must not be a floating point number (CBOR is typed)!
            timestamp = int(timestamp * 1000)
            self.encode_semantic(CBORTag(1, timestamp))
        else:
            datestring = value.isoformat().replace("+00:00", "Z")
            self.encode_semantic(CBORTag(0, datestring))

    # overwrite the default epoch datetime en-/decoder with patched versions
    default_encoders[datetime] = _patched_encode_datetime
    semantic_decoders[1] = _patched_decode_epoch_datetime


def _create_and_enrich_aws_request(
    fn, self: Endpoint, params: dict, operation_model: OperationModel = None
):
    """
    Patch that adds the botocore operation model and request parameters to a newly created AWSPreparedRequest,
    which normally only holds low-level HTTP request information.
    """
    request: awsrequest.AWSPreparedRequest = fn(self, params, operation_model)

    request.params = params
    request.operation_model = operation_model

    return request


botocore_in_memory_endpoint_patch = Patch.function(
    Endpoint.create_request, _create_and_enrich_aws_request
)


@hooks.on_infra_start(should_load=config.IN_MEMORY_CLIENT)
def _patch_botocore_endpoint_in_memory():
    botocore_in_memory_endpoint_patch.apply()


def parse_response(
    operation: OperationModel, response: Response, include_response_metadata: bool = True
) -> ServiceResponse:
    """
    Parses an HTTP Response object into an AWS response object using botocore. It does this by adapting the
    procedure of ``botocore.endpoint.convert_to_response_dict`` to work with Werkzeug's server-side response object.

    :param operation: the operation of the original request
    :param response: the HTTP response object containing the response of the operation
    :param include_response_metadata: True if the ResponseMetadata (typical for boto response dicts) should be included
    :return: a parsed dictionary as it is returned by botocore
    """
    # this is what botocore.endpoint.convert_to_response_dict normally does
    response_dict = {
        "headers": dict(response.headers.items()),  # boto doesn't like werkzeug headers
        "status_code": response.status_code,
        "context": {
            "operation_name": operation.name,
        },
    }

    if response_dict["status_code"] >= 301:
        response_dict["body"] = response.data
    elif operation.has_event_stream_output:
        # TODO test this
        response_dict["body"] = _RawStream(response)
    elif operation.has_streaming_output:
        # for s3.GetObject for example, the Body attribute is actually a stream, not the raw bytes value
        response_dict["body"] = _ResponseStream(response)
    else:
        response_dict["body"] = response.data

    factory = ResponseParserFactory()
    if response.content_type and response.content_type.startswith("application/x-amz-cbor"):
        # botocore cannot handle CBOR encoded responses (because it never sends them), we need to modify the parser
        factory.set_parser_defaults(
            timestamp_parser=_cbor_timestamp_parser, blob_parser=_cbor_blob_parser
        )

    parser = factory.create_parser(operation.service_model.protocol)
    parsed_response = parser.parse(response_dict, operation.output_shape)

    if response.status_code >= 301:
        # Add possible additional error shape members
        _add_modeled_error_fields(response_dict, parsed_response, operation, parser)

    if not include_response_metadata:
        parsed_response.pop("ResponseMetadata", None)

    return parsed_response


def parse_service_exception(
    response: Response, parsed_response: Dict
) -> Optional[ServiceException]:
    """
    Creates a ServiceException (one ASF can handle) from a parsed response (one that botocore would return).
    It does not automatically raise the exception (see #raise_service_exception).
    :param response: Un-parsed response
    :param parsed_response: Parsed response
    :return: ServiceException or None (if it's not an error response)
    """
    if response.status_code < 301 or "Error" not in parsed_response:
        return None
    error = parsed_response["Error"]
    service_exception = CommonServiceException(
        code=error.get("Code", f"'{response.status_code}'"),
        status_code=response.status_code,
        message=error.get("Message", ""),
        sender_fault=error.get("Type") == "Sender",
    )
    # Add all additional fields in the parsed response as members of the exception
    for key, value in parsed_response.items():
        if key.lower() not in ["code", "message", "type", "error"] and not hasattr(
            service_exception, key
        ):
            setattr(service_exception, key, value)
    return service_exception


def raise_service_exception(response: Response, parsed_response: Dict) -> None:
    """
    Creates and raises a ServiceException from a parsed response (one that botocore would return).
    :param response: Un-parsed response
    :param parsed_response: Parsed response
    :raise ServiceException: If the response is an error response
    :return: None if the response is not an error response
    """
    if service_exception := parse_service_exception(response, parsed_response):
        raise service_exception


class GatewayShortCircuit:
    gateway: Gateway

    def __init__(self, gateway: Gateway):
        self.gateway = gateway
        self._internal_url = get_service_endpoint()

    def __call__(
        self, event_name: str, request: awsrequest.AWSPreparedRequest, **kwargs
    ) -> awsrequest.AWSResponse | None:
        # TODO: we sometimes overrides the endpoint_url to direct it to DynamoDBLocal directly
        # if the default endpoint_url is not in the request, just skips the in-memory forwarding
        if self._internal_url not in request.url:
            return

        # extract extra data from enriched AWSPreparedRequest
        params = request.params
        operation: OperationModel = request.operation_model

        # create request
        context = RequestContext()
        context.request = create_http_request(request)

        # TODO: just a hacky thing to unblock the service model being set to `sqs-query` blocking for now
        # this is using the same services as `localstack.aws.protocol.service_router.resolve_conflicts`, maybe
        # consolidate. `docdb` and `neptune` uses the RDS API and service.
        if operation.service_model.service_name not in {
            "sqs-query",
            "docdb",
            "neptune",
            "timestream-write",
        }:
            context.service = operation.service_model

        context.operation = operation
        context.service_request = params["body"]

        # perform request
        response = Response()
        self.gateway.handle(context, response)

        # transform Werkzeug response to client-side botocore response
        aws_response = awsrequest.AWSResponse(
            url=context.request.url,
            status_code=response.status_code,
            headers=response.headers,
            raw=_ResponseStream(response),
        )

        return aws_response

    @staticmethod
    def modify_client(client, gateway):
        client.meta.events.register_first("before-send.*.*", GatewayShortCircuit(gateway))

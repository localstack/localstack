"""Utils to process AWS requests as a client."""
import dataclasses
import io
import json
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Iterable, Optional

from boto3 import Session
from botocore.awsrequest import AWSPreparedRequest
from botocore.client import BaseClient
from botocore.config import Config as BotoConfig
from botocore.model import OperationModel
from botocore.parsers import ResponseParser, ResponseParserFactory
from werkzeug import Response

from localstack.aws.api import CommonServiceException, ServiceException, ServiceResponse
from localstack.constants import INTERNAL_AWS_ACCESS_KEY_ID, INTERNAL_AWS_SECRET_ACCESS_KEY
from localstack.runtime import hooks
from localstack.utils.aws.aws_stack import extract_region_from_arn
from localstack.utils.patch import patch

if TYPE_CHECKING:
    from mypy_boto3_sqs import SQSClient

LOG = logging.getLogger(__name__)


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
        to parse responses from external backends (like kinesalite), we need to patch botocore to
        try CBOR decoding in case the JSON decoding fails.
        """
        try:
            return fn(self, body_contents)
        except UnicodeDecodeError as json_exception:
            import cbor2

            try:
                LOG.debug("botocore failed decoding JSON. Trying to decode as CBOR.")
                return cbor2.loads(body_contents)
            except Exception as cbor_exception:
                LOG.debug("CBOR fallback decoding failed.")
                raise cbor_exception from json_exception


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


#
# Internal AWS client
#

"""
The internal AWS client API provides the means to perform cross-service communication within LocalStack.
Any additional information LocalStack might need for the purpose of policy enforcement is sent as a
data transfer object. This is a serialised dict object sent in the request header.
"""

LOCALSTACK_DATA_HEADER = "x-localstack-data"
"""Request header which contains the data transfer object."""


def LocalStackData(TypedDict):
    source_arn: str
    source_service: str  # eg. 'ec2.amazonaws.com'


def Credentials(TypedDict):
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_session_token: str


@dataclasses.dataclass(frozen=True)
class ClientOptions:
    """This object holds configuration options for the internal AWS client."""

    aws_region: Optional[str] = None
    endpoint_url: Optional[str] = None  # TODO@viren should the default endpoint be used here?
    verify_ssl: bool = True
    use_ssl: bool = True
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_session_token: Optional[str] = None
    boto_config: Optional[BotoConfig] = dataclasses.field(default_factory=BotoConfig)
    localstack_data: dict[str, Any] = dataclasses.field(default_factory=LocalStackData)


class ClientFactory:
    """Factory to build the internal AWS client."""

    # TODO migrate to immutable clientfactory instances
    client_options: ClientOptions
    session: Session

    def __init__(self, client_options: ClientOptions = None):
        self.client_options = client_options or ClientOptions()
        self.session = Session()

    def with_endpoint(self, endpoint: str) -> "ClientFactory":
        """Override the API endpoint."""
        return ClientFactory(
            client_options=dataclasses.replace(self.client_options, endpoint_url=endpoint)
        )

    def with_source_arn(self, arn: str) -> "ClientFactory":
        """TODO"""
        return ClientFactory(
            client_options=dataclasses.replace(
                self.client_options,
                localstack_data=self.client_options.localstack_data
                | LocalStackData(source_arn=arn),
            )
        )

    def with_target_arn(self, arn: str) -> "ClientFactory":
        """TODO"""
        region = extract_region_from_arn(arn)
        return ClientFactory(
            client_options=dataclasses.replace(self.client_options, aws_region=region)
        )

    def with_source_service_principal(self, source_service: str) -> "ClientFactory":
        """TODO"""
        return ClientFactory(
            client_options=dataclasses.replace(
                self.client_options,
                localstack_data=self.client_options.localstack_data
                | LocalStackData(source_service=f"{source_service}.amazonaws.com"),
            )
        )

    def with_credentials(
        self, aws_access_key_id: str, aws_secret_access_key: str
    ) -> "ClientFactory":
        """TODO"""
        return ClientFactory(
            client_options=dataclasses.replace(
                self.client_options,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
            )
        )

    def with_default_credentials(self) -> "ClientFactory":
        """TODO"""
        return self.credentials(
            aws_access_key_id=INTERNAL_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=INTERNAL_AWS_SECRET_ACCESS_KEY,
        )

    def with_env_credentials(self) -> "ClientFactory":
        """TODO"""
        # TODO wrong output format of session.get_credentials()
        return self.credentials(self.session.get_credentials())

    def with_boto_config(self, config: BotoConfig) -> "ClientFactory":
        """TODO"""
        return ClientFactory(
            client_options=dataclasses.replace(
                self.client_options, boto_config=self.client_options.boto_config.merge(config)
            )
        )

    def build(self, service: str) -> BaseClient:
        """TODO"""
        assert self.client_options.aws_access_key_id
        assert self.client_options.aws_secret_access_key

        # TODO: creating a boto client is very intensive. In old aws_stack, we cache clients based on
        # [service_name, client, env, region, endpoint_url, config, internal, kwargs]
        # Come up with an appropriate solution here
        client = self.session.client(
            service_name=service,
            config=self.client_options.boto_config,
            aws_access_key_id=self.client_options.aws_access_key_id,
        )

        def event_handler(request: AWSPreparedRequest, **_):
            # Send a compact JSON representation as DTO
            request.headers[LOCALSTACK_DATA_HEADER] = json.dumps(
                self.client_options.localstack_data, separators=(",", ":")
            )

        client.meta.events.register("before-send.*.*", handler=event_handler)

        return client

    #
    # Convenience helpers
    #

    def sqs(self) -> "SQSClient":
        return self.build("sqs")


def aws_client():
    return ClientFactory()

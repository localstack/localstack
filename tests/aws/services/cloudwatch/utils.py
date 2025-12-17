import abc
import json
from typing import Any

import xmltodict
from botocore.auth import SigV4Auth
from botocore.serialize import create_serializer

# import the unpatched cbor2 on purpose to avoid being polluted by Kinesis-only patches
from cbor2 import loads as cbor2_loads
from requests import Response

from localstack import constants
from localstack.aws.spec import get_service_catalog
from localstack.config import LOCALSTACK_HOST
from localstack.testing.aws.util import is_aws_cloud


class BaseCloudWatchHttpClient(abc.ABC):
    """
    Simple HTTP client for making CloudWatch requests manually using different protocols.

    This serialization type is not yet available via boto3 client, and we have more control over raw responses.
    """

    protocol: str = ""

    def __init__(
        self,
        region_name: str,
        client_factory,
    ):
        self.region_name = region_name
        # CloudWatch uses the signing name `monitoring`
        self._client = client_factory(
            "monitoring", region=self.region_name, signer_factory=SigV4Auth
        )
        self.service_model = get_service_catalog().get("cloudwatch")
        self.target_prefix = self.service_model.metadata.get("targetPrefix") or ""

    @abc.abstractmethod
    def _deserialize_response(self, response: Response) -> Any: ...

    @abc.abstractmethod
    def _build_headers(self, operation: str, query_mode: bool = False) -> dict: ...

    def _serialize_body(self, body: dict, operation: str) -> str | bytes:
        # here we use the Botocore serializer directly, since it has some complex behavior,
        # and we know CloudWatch supports it by default
        protocol_serializer = create_serializer(self.protocol)
        operation_model = self.service_model.operation_model(operation)
        request = protocol_serializer.serialize_to_request(body, operation_model)
        return request["body"]

    @property
    def host(self) -> str:
        return (
            f"monitoring.{self.region_name}.amazonaws.com"
            if is_aws_cloud()
            else LOCALSTACK_HOST.host_and_port()
        )

    def _build_endpoint(self, operation: str) -> str:
        return f"https://{self.host}"

    def post_raw(
        self, operation: str, payload: dict, query_mode: bool = False, **kwargs
    ) -> Response:
        """
        Perform a CloudWatch operation, encoding the request payload based on the `_serialize_body` and returning
        the raw response without any processing or checks.
        """
        response = self._client.post(
            self._build_endpoint(operation),
            data=self._serialize_body(payload, operation),
            headers=self._build_headers(operation, query_mode),
            **kwargs,
        )
        return response

    def post(
        self, operation: str, payload: dict, status_code: int = 200, query_mode: bool = False
    ) -> Any:
        """
        Perform a CloudWatch operation and decode it based on the `_deserialize_response` implementation
        """
        response = self.post_raw(operation, payload, query_mode=query_mode)
        response_body = self._deserialize_response(response)
        if response.status_code != status_code:
            raise ValueError(f"Bad status: {response.status_code}, response body: {response_body}")
        return response_body


class CloudWatchCBORHTTPClient(BaseCloudWatchHttpClient):
    protocol = "smithy-rpc-v2-cbor"

    def _deserialize_response(self, response: Response) -> Any:
        if response.content:
            return cbor2_loads(response.content)
        return {}

    def _build_headers(self, operation: str, query_mode: bool = False) -> dict:
        headers = {
            "content-type": constants.APPLICATION_CBOR,
            "accept": constants.APPLICATION_CBOR,
            "host": self.host,
            "Smithy-Protocol": "rpc-v2-cbor",
        }
        if query_mode:
            headers["x-amzn-query-mode"] = "true"

        return headers

    def _build_endpoint(self, operation: str) -> str:
        return f"https://{self.host}/service/{self.target_prefix}/operation/{operation}"


class CloudWatchJSONHTTPClient(BaseCloudWatchHttpClient):
    protocol = "json"

    def _deserialize_response(self, response: Response) -> Any:
        if response.content:
            return json.loads(response.content)
        return {}

    def _build_headers(self, operation: str, query_mode: bool = False) -> dict:
        headers = {
            "Content-Type": constants.APPLICATION_AMZ_JSON_1_0,
            "X-Amz-Target": f"{self.target_prefix}.{operation}",
            "Host": self.host,
            "x-amzn-query-mode": "true" if query_mode else "false",
        }
        if query_mode:
            headers["x-amzn-query-mode"] = "true"

        return headers


class CloudWatchQueryHTTPClient(BaseCloudWatchHttpClient):
    protocol = "query"

    def _deserialize_response(self, response: Response) -> Any:
        if not response.content:
            return {}
        content_type = response.headers.get("Content-Type", "")
        if content_type.startswith(constants.APPLICATION_XML) or content_type.startswith(
            constants.TEXT_XML
        ):
            # FIXME: the snapshot library doesn't deal well with ResponseMetadata in raw responses, will be fixed when
            #  we release a new version
            #  https://github.com/localstack/localstack-snapshot/pull/13
            response = xmltodict.parse(response.content)
            container = response[next(iter(response.keys()))]
            if isinstance(container, dict):
                container.pop("ResponseMetadata", None)
            return response
        elif content_type.startswith(constants.APPLICATION_JSON):
            return json.loads(response.content)
        else:
            return response.content

    def _build_headers(self, operation: str, query_mode: bool = False) -> dict:
        return {
            "content-type": constants.APPLICATION_X_WWW_FORM_URLENCODED,
            "host": self.host,
        }


def get_cloudwatch_client(client_factory, region: str, protocol: str) -> BaseCloudWatchHttpClient:
    match protocol:
        case "smithy-rpc-v2-cbor":
            return CloudWatchCBORHTTPClient(
                region_name=region,
                client_factory=client_factory,
            )
        case "json":
            return CloudWatchJSONHTTPClient(
                region_name=region,
                client_factory=client_factory,
            )
        case "query":
            return CloudWatchQueryHTTPClient(
                region_name=region,
                client_factory=client_factory,
            )
        case _:
            raise ValueError("protocol must be in ['smithy-rpc-v2-cbor', 'json', 'query']")

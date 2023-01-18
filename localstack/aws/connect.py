"""
LocalStack client stack.

This module provides the interface to perform cross-service communication between
LocalStack providers.
"""
import json
from functools import cache
from typing import Mapping, Optional, TypedDict, Union

from boto3.session import Session
from botocore.awsrequest import AWSPreparedRequest
from botocore.client import BaseClient
from botocore.config import Config
from werkzeug.datastructures import Headers

from localstack import config
from localstack.constants import (
    INTERNAL_AWS_ACCESS_KEY_ID,
    INTERNAL_AWS_SECRET_ACCESS_KEY,
    MAX_POOL_CONNECTIONS,
)
from localstack.utils.aws.arns import extract_region_from_arn
from localstack.utils.aws.aws_stack import get_local_service_url
from localstack.utils.aws.request_context import get_region_from_request_context

#
# Data transfer object
#

LOCALSTACK_DATA_HEADER = "x-localstack-data"
"""Request header which contains the data transfer object."""


class LocalStackData(TypedDict):
    """
    LocalStack Data Transfer Object.

    This is sent with every internal request and contains any additional information
    LocalStack might need for the purpose of policy enforcement. It is serialised
    into text and sent in the request header.

    Attributes can be added as needed. The keys should roughly correspond to:
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
    """

    source_arn: str
    """ARN of resource which is triggering the call"""

    source_service: str
    """Service principal where the call originates, eg. `ec2`"""

    target_arn: str
    """ARN of the resource being targeted."""


def dump_dto(data: LocalStackData) -> str:
    # TODO@viren: Improve minification using custom JSONEncoder that use shortened keys

    # To produce a compact JSON representation of DTO, remove spaces from separators
    return json.dumps(data, separators=(",", ":"))


def load_dto(data: str) -> LocalStackData:
    return json.loads(data)


#
# Client
#


class ConnectFactory:
    """
    Factory to build the AWS client.

    Boto client creation is resource intensive. This class caches all Boto
    clients it creates and must be used instead of directly using boto lib.
    """

    def __init__(
        self,
        use_ssl: bool = False,
        verify: bool = False,
    ):
        """
        :param use_ssl: Whether to use SSL
        :param verify: Whether to verify SSL certificates
        """
        self._use_ssl = use_ssl
        self._verify = verify
        self._session = Session()
        self._config = Config(max_pool_connections=MAX_POOL_CONNECTIONS)

    def __call__(self, *args, **kwargs) -> BaseClient:
        """
        Every `ConnectFactory` instance is a proxy for creating the internal client.
        """
        return self.get_internal_client(*args, **kwargs)

    def get_external_client(
        self,
        service_name: str,
        region_name: Optional[str],
        aws_access_key_id: Optional[str],
        aws_secret_access_key: Optional[str],
        endpoint_url: str = None,
        config: Config = None,
    ):
        """
        Build and return client for connections originating outside LocalStack.

        If either of the access keys or region are set to None, they are loaded from following
        locations:
        - AWS environment variables
        - Credentials file `~/.aws/credentials`
        - Config file `~/.aws/config`

        :param service_name: Service to build the client for, eg. `s3`
        :param region_name: Name of the AWS region to be associated with the client
            If set to None, loads from botocore session.
        :param aws_access_key_id: Access key to use for the client.
            If set to None, loads from botocore session.
        :param aws_secret_access_key: Secret key to use for the client.
            If set to None, loads from botocore session.
        :param endpoint_url: Full endpoint URL to be used by the client.
            Defaults to appropriate LocalStack endpoint.
        :param config: Boto config for advanced use.
        """
        client = self.get_client(
            service_name=service_name,
            region_name=region_name or self.get_region_name(),
            use_ssl=self._use_ssl,
            verify=self._verify,
            endpoint_url=endpoint_url or get_local_service_url(service_name),
            aws_access_key_id=aws_access_key_id or self.get_session_access_key(),
            aws_secret_access_key=aws_secret_access_key or self.get_session_secret_key(),
            aws_session_token=None,
            config=config or self._config,
            dto=None,
        )
        return client

    def get_internal_client(
        self,
        target_service: str,
        region_name: str = None,
        endpoint_url: str = None,
        aws_access_key_id: str = INTERNAL_AWS_ACCESS_KEY_ID,
        aws_secret_access_key: str = INTERNAL_AWS_SECRET_ACCESS_KEY,
        config: Config = None,
        source_arn: str = None,
        source_service: str = None,
        target_arn: str = None,
    ) -> BaseClient:
        """
        Build and return client for connections originating within LocalStack.

        :param target_service: Service to build the client for, eg. `s3`
        :param region_name: Region name
        :param endpoint_url: Full endpoint URL to be used by the client.
            Defaults to appropriate LocalStack endpoint.
        :param aws_access_key_id: Access key to use for the client.
            Defaults to LocalStack internal credentials.
        :param aws_secret_access_key: Secret key to use for the client.
            Defaults to LocalStack internal credentials.
        :param config: Boto config for advanced use.
        :param source_arn: ARN of resource which triggers the call.
        :param source_service: Service name where call originates.
        :param target_arn: ARN of targeted resource. When set, the region from ARN
            takes precedence over the `region` argument.
        """
        localstack_data = LocalStackData()

        if source_arn:
            localstack_data["source_arn"] = source_arn

        if source_service:
            localstack_data["source_service"] = source_service

        if target_arn:
            # Attention: region is overriden here
            region_name = extract_region_from_arn(target_arn)
            localstack_data["target_arn"] = target_arn

        assert region_name, "Region not set for internal client"

        dto = dump_dto(localstack_data)

        client = self.get_client(
            service_name=target_service,
            region_name=region_name,
            use_ssl=self._use_ssl,
            verify=self._verify,
            endpoint_url=endpoint_url or get_local_service_url(target_service),
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=None,
            config=config or self._config,
            dto=dto,
        )

        if len(localstack_data):

            def _handler(request: AWSPreparedRequest, **_):
                request.headers[LOCALSTACK_DATA_HEADER] = dto

            client.meta.events.register("before-send.*.*", handler=_handler)

        return client

    @cache
    def get_client(
        self,
        service_name: str,
        region_name: str,
        use_ssl: bool,
        verify: bool,
        endpoint_url: str,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        aws_session_token: str,
        config: Config,
        dto: Optional[str],  # noqa
    ) -> BaseClient:
        return self._session.client(
            service_name=service_name,
            region_name=region_name,
            use_ssl=use_ssl,
            verify=verify,
            endpoint_url=endpoint_url,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            config=config,
        )

    #
    # Boto session utilities
    #

    def get_partition_for_region(self, region_name: str) -> str:
        """
        Return the AWS partition name for a given region, eg. `aws`, `aws-cn`, etc.
        """
        return self._session.get_partition_for_region(region_name)

    def get_session_region_name(self) -> str:
        """
        Return AWS region as set in the Boto session.
        """
        return self._session.region_name

    def get_region_name(self) -> str:
        """
        Return the AWS region name from following sources, in order of availability.
        - LocalStack request context
        - LocalStack default region
        - Boto session
        """
        return (
            get_region_from_request_context()
            or config.DEFAULT_REGION
            or self.get_session_region_name()
        )

    def get_session_access_key(self) -> str:
        """
        Return AWS access key from the Boto session.
        """
        credentials = self._session.get_credentials()
        return credentials.access_key

    def get_session_secret_key(self) -> str:
        """
        Return AWS secret key from the Boto session.
        """
        credentials = self._session.get_credentials()
        return credentials.secret_key


connector = ConnectFactory()
connect_to = connector.get_internal_client
connect_externally_to = connector.get_external_client

#
# Utilities
#


def is_internal_call(headers: Union[Mapping, Headers]) -> bool:
    """
    Whether given request headers are for an internal LocalStack cross-service call.
    """
    return LOCALSTACK_DATA_HEADER in headers

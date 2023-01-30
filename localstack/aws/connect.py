"""
LocalStack client stack.

This module provides the interface to perform cross-service communication between
LocalStack providers.
"""
import json
import logging
from functools import cache
from typing import Mapping, Optional, TypedDict, Union

from boto3.session import Session
from botocore.client import BaseClient
from botocore.config import Config
from werkzeug.datastructures import Headers

from localstack import config
from localstack.constants import (
    INTERNAL_AWS_ACCESS_KEY_ID,
    INTERNAL_AWS_SECRET_ACCESS_KEY,
    MAX_POOL_CONNECTIONS,
)
from localstack.utils.aws.aws_stack import get_local_service_url
from localstack.utils.aws.request_context import get_region_from_request_context

LOG = logging.getLogger(__name__)

#
# Data transfer object
#

LOCALSTACK_REQUEST_PARAM_HEADER = "x-localstack-data"
"""Request header which contains the data transfer object."""


class LocalstackRequestParameters(TypedDict):
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


def dump_dto(data: LocalstackRequestParameters) -> str:
    # TODO@viren: Improve minification using custom JSONEncoder that use shortened keys

    # To produce a compact JSON representation of DTO, remove spaces from separators
    return json.dumps(data, separators=(",", ":"))


def load_dto(data: str) -> LocalstackRequestParameters:
    return json.loads(data)


#
# Client
#

# Names of arguments that can be passed to Boto API operation functions.
# These have appropriate entries on the data transfer object.
ARG_SOURCE_SERVICE = "_SourceService"
ARG_SOURCE_ARN = "_SourceArn"
ARG_TARGET_ARN = "_TargetArn"


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

    def get_internal_client(
        self,
        service_name: str,
        region_name: str,
        endpoint_url: str = None,
        aws_access_key_id: str = INTERNAL_AWS_ACCESS_KEY_ID,
        aws_secret_access_key: str = INTERNAL_AWS_SECRET_ACCESS_KEY,
        config: Config = None,
    ) -> BaseClient:
        """
        Build and return client for connections originating within LocalStack.

        Region in `_TargetArn` takes precedence when specified.

        :param service_name: Service to build the client for, eg. `s3`
        :param region_name: Region name. See note above.
        :param endpoint_url: Full endpoint URL to be used by the client.
            Defaults to appropriate LocalStack endpoint.
        :param aws_access_key_id: Access key to use for the client.
            Defaults to LocalStack internal credentials.
        :param aws_secret_access_key: Secret key to use for the client.
            Defaults to LocalStack internal credentials.
        :param config: Boto config for advanced use.
        """

        return self._get_client(
            service_name=service_name,
            region_name=region_name,
            use_ssl=self._use_ssl,
            verify=self._verify,
            endpoint_url=endpoint_url or get_local_service_url(service_name),
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=None,
            config=config or self._config,
        )

    def get_external_client(
        self,
        service_name: str,
        region_name: Optional[str],
        aws_access_key_id: Optional[str],
        aws_secret_access_key: Optional[str],
        endpoint_url: str = None,
        config: Config = None,
    ) -> BaseClient:
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

        return self._get_client(
            service_name=service_name,
            region_name=region_name or self.get_region_name(),
            use_ssl=self._use_ssl,
            verify=self._verify,
            endpoint_url=endpoint_url or get_local_service_url(service_name),
            aws_access_key_id=aws_access_key_id or self.get_session_access_key(),
            aws_secret_access_key=aws_secret_access_key or self.get_session_secret_key(),
            aws_session_token=None,
            config=config or self._config,
        )

    @cache
    def _get_client(
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
    ) -> BaseClient:
        client = self._session.client(
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

        def _handler_piggyback_dto(params, model, context, **kwargs):
            """
            Construct the data transfer object at the time of parsing the client
            parameters and proxy it over the Boto context dict.
            """

            dto = LocalstackRequestParameters()
            if ARG_SOURCE_SERVICE in params:
                dto["source_service"] = params.pop(ARG_SOURCE_SERVICE)
            if ARG_SOURCE_ARN in params:
                dto["source_arn"] = params.pop(ARG_SOURCE_ARN)
            if ARG_TARGET_ARN in params:
                target_arn = params.pop(ARG_TARGET_ARN)

                if target_arn.startswith("arn:"):
                    dto["target_arn"] = params.pop(ARG_TARGET_ARN)
                else:
                    try:
                        dto["target_arn"] = params[target_arn]
                    except KeyError:
                        LOG.warning(
                            "TargetArn '%s' not an ARN or a valid ref to another parameter."
                            % target_arn
                        )

            if dto:
                context["_localstack"] = dto

        def _handler_inject_dto_header(model, params, request_signer, context, **kwargs):
            """
            Retrieve the data transfer object and make it part of the request
            headers.
            """
            if dto := context.pop("_localstack", None):
                params["headers"][LOCALSTACK_REQUEST_PARAM_HEADER] = dump_dto(dto)

        client.meta.events.register("provide-client-params.*.*", handler=_handler_piggyback_dto)
        client.meta.events.register("before-call.*.*", handler=_handler_inject_dto_header)

        return client

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
    return LOCALSTACK_REQUEST_PARAM_HEADER in headers

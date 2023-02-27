"""
LocalStack client stack.

This module provides the interface to perform cross-service communication between
LocalStack providers.
"""
import json
import logging
import threading
from abc import ABC, abstractmethod
from functools import cache
from typing import Optional, TypedDict

from boto3.session import Session
from botocore.client import BaseClient
from botocore.config import Config

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

INTERNAL_REQUEST_PARAMS_HEADER = "x-localstack-data"
"""Request header which contains the data transfer object."""


class InternalRequestParameters(TypedDict):
    """
    LocalStack Data Transfer Object.

    This is sent with every internal request and contains any additional information
    LocalStack might need for the purpose of policy enforcement. It is serialised
    into text and sent in the request header.

    Attributes can be added as needed. The keys should roughly correspond to:
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
    """

    source_arn: str | None
    """ARN of resource which is triggering the call"""

    target_arn: str | None
    """ARN of the resource being accessed."""

    service_principal: str | None
    """Service principal making this call"""


def dump_dto(data: InternalRequestParameters) -> str:
    # TODO@viren: Minification can be improved using custom JSONEncoder that uses shortened keys

    # To produce a compact JSON representation of DTO, remove spaces from separators
    return json.dumps(data, separators=(",", ":"))


def load_dto(data: str) -> InternalRequestParameters:
    return json.loads(data)


#
# Factory
#


class ClientFactory(ABC):
    """
    Factory to build the AWS client.

    Boto client creation is resource intensive. This class caches all Boto
    clients it creates and must be used instead of directly using boto lib.
    """

    def __init__(
        self,
        use_ssl: bool = False,
        verify: bool = False,
        session: Session = None,
        config: Config = None,
    ):
        """
        :param use_ssl: Whether to use SSL
        :param verify: Whether to verify SSL certificates
        :param session: Session to be used for client creation. Will create a new session if not provided.
            Please note that sessions are not generally thread safe.
            Either create a new session for each factory or make sure the session is not shared with another thread.
            The factory itself has a lock for the session, so as long as you only use the session in one factory,
            it should be fine using the factory in a multithreaded context.
        :param config: Config used as default for client creation.
        """
        self._use_ssl = use_ssl
        self._verify = verify
        self._config: Config = config or Config(max_pool_connections=MAX_POOL_CONNECTIONS)
        self._session: Session = session or Session()
        self._create_client_lock = threading.RLock()

    def __call__(self, *args, **kwargs) -> BaseClient:
        return self.get_client(*args, **kwargs)

    @abstractmethod
    def get_client(
        self,
        service_name: str,
        region_name: Optional[str],
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        aws_session_token: Optional[str] = None,
        endpoint_url: str = None,
        config: Config = None,
    ):
        raise NotImplementedError()

    def _get_client_post_hook(self, client: BaseClient) -> BaseClient:
        """
        This is called after the client is created by Boto.

        Any modifications to the client can be implemented here in subclasses
        without affecting the caching mechanism.
        """
        return client

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
        """
        Returns a boto3 client with the given configuration, and the hooks added by `_get_client_post_hook`.
        This is a cached call, so modifications to the used client will affect others.
        Please use another instance of the factory, should you want to modify clients.
        Client creation is behind a lock as it is not generally thread safe.

        :param service_name: Service to build the client for, eg. `s3`
        :param region_name: Name of the AWS region to be associated with the client
            If set to None, loads from botocore session.
        :param aws_access_key_id: Access key to use for the client.
            If set to None, loads from botocore session.
        :param aws_secret_access_key: Secret key to use for the client.
            If set to None, loads from botocore session.
        :param aws_session_token: Session token to use for the client.
            Not being used if not set.
        :param endpoint_url: Full endpoint URL to be used by the client.
            Defaults to appropriate LocalStack endpoint.
        :param config: Boto config for advanced use.
        :return: Boto3 client.
        """
        with self._create_client_lock:
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

        return self._get_client_post_hook(client)

    #
    # Boto session utilities
    #
    def _get_session_region(self) -> str:
        """
        Return AWS region as set in the Boto session.
        """
        return self._session.region_name

    def _get_region(self) -> str:
        """
        Return the AWS region name from following sources, in order of availability.
        - LocalStack request context
        - LocalStack default region
        - Boto session
        """
        return (
            get_region_from_request_context()
            or config.DEFAULT_REGION
            or self._get_session_region()  # TODO this will never be called, as DEFAULT_REGION defaults to 'us-east-1'
        )


class InternalClientFactory(ClientFactory):
    def _get_client_post_hook(self, client: BaseClient) -> BaseClient:
        """
        Register handlers that enable internal data object transfer mechanism
        for internal clients.
        """
        client.meta.events.register(
            "provide-client-params.*.*", handler=_handler_create_request_parameters
        )
        client.meta.events.register("before-call.*.*", handler=_handler_inject_dto_header)

        return client

    def get_client(
        self,
        service_name: str,
        region_name: Optional[str],
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        aws_session_token: Optional[str] = None,
        endpoint_url: str = None,
        config: Config = None,
    ) -> BaseClient:
        """
        Build and return client for connections originating within LocalStack.

        All API operation methods (such as `.list_buckets()` or `.run_instances()`
        take additional args that start with `_` prefix. These are used to pass
        additional information to LocalStack server during internal calls.

        :param service_name: Service to build the client for, eg. `s3`
        :param region_name: Region name. See note above.
            If set to None, loads from botocore session.
        :param aws_access_key_id: Access key to use for the client.
            Defaults to LocalStack internal credentials.
        :param aws_secret_access_key: Secret key to use for the client.
            Defaults to LocalStack internal credentials.
        :param aws_session_token: Session token to use for the client.
            Not being used if not set.
        :param endpoint_url: Full endpoint URL to be used by the client.
            Defaults to appropriate LocalStack endpoint.
        :param config: Boto config for advanced use.
        """

        return self._get_client(
            service_name=service_name,
            region_name=region_name or self._get_region(),
            use_ssl=self._use_ssl,
            verify=self._verify,
            endpoint_url=endpoint_url or get_local_service_url(service_name),
            aws_access_key_id=aws_access_key_id or INTERNAL_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=aws_secret_access_key or INTERNAL_AWS_SECRET_ACCESS_KEY,
            aws_session_token=aws_session_token,
            config=config or self._config,
        )


class ExternalClientFactory(ClientFactory):
    def get_client(
        self,
        service_name: str,
        region_name: Optional[str],
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        aws_session_token: Optional[str] = None,
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
        :param aws_session_token: Session token to use for the client.
            Not being used if not set.
        :param endpoint_url: Full endpoint URL to be used by the client.
            Defaults to appropriate LocalStack endpoint.
        :param config: Boto config for advanced use.
        """

        return self._get_client(
            service_name=service_name,
            region_name=region_name or self._get_region(),
            use_ssl=self._use_ssl,
            verify=self._verify,
            endpoint_url=endpoint_url or get_local_service_url(service_name),
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            config=config or self._config,
        )


connect_to = InternalClientFactory()
connect_externally_to = ExternalClientFactory()

#
# Handlers
#


def _handler_create_request_parameters(params, model, context, **kwargs):
    """
    Construct the data transfer object at the time of parsing the client
    parameters and proxy it via the Boto context dict.

    This handler enables the use of additional keyword parameters in Boto API
    operation functions.
    """

    # Names of arguments that can be passed to Boto API operation functions.
    # These must correspond to entries on the data transfer object.
    dto = InternalRequestParameters()
    for member in InternalRequestParameters.__annotations__.keys():
        parameter = f"_{''.join([part.title() for part in member.split('_')])}"
        if parameter in params:
            dto[member] = params.pop(parameter)

    if dto:
        context["_localstack"] = dto


def _handler_inject_dto_header(model, params, request_signer, context, **kwargs):
    """
    Retrieve the data transfer object from the Boto context dict and serialise
    it as part of the request headers.
    """
    if dto := context.pop("_localstack", None):
        params["headers"][INTERNAL_REQUEST_PARAMS_HEADER] = dump_dto(dto)

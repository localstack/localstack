import base64
import json
import logging
import re

import requests

from localstack.aws.api.events import (
    ApiDestinationDescription,
    ApiDestinationHttpMethod,
    ApiDestinationInvocationRateLimitPerSecond,
    ApiDestinationName,
    ApiDestinationState,
    Arn,
    ConnectionArn,
    ConnectionAuthorizationType,
    ConnectionState,
    HttpsEndpoint,
    Timestamp,
)
from localstack.aws.connect import connect_to
from localstack.services.events.models import ApiDestination, Connection, ValidationException
from localstack.utils.aws.arns import (
    extract_account_id_from_arn,
    extract_region_from_arn,
    parse_arn,
)
from localstack.utils.aws.message_forwarding import (
    list_of_parameters_to_object,
)
from localstack.utils.http import add_query_params_to_url
from localstack.utils.strings import to_str

VALID_AUTH_TYPES = [t.value for t in ConnectionAuthorizationType]
LOG = logging.getLogger(__name__)


class APIDestinationService:
    def __init__(
        self,
        name: ApiDestinationName,
        region: str,
        account_id: str,
        connection_arn: ConnectionArn,
        connection: Connection,
        invocation_endpoint: HttpsEndpoint,
        http_method: ApiDestinationHttpMethod,
        invocation_rate_limit_per_second: ApiDestinationInvocationRateLimitPerSecond | None,
        description: ApiDestinationDescription | None = None,
    ):
        self.validate_input(name, connection_arn, http_method, invocation_endpoint)
        self.connection = connection
        state = self._get_state()

        self.api_destination = ApiDestination(
            name,
            region,
            account_id,
            connection_arn,
            invocation_endpoint,
            http_method,
            state,
            invocation_rate_limit_per_second,
            description,
        )

    @classmethod
    def restore_from_api_destination_and_connection(
        cls, api_destination: ApiDestination, connection: Connection
    ):
        api_destination_service = cls(
            name=api_destination.name,
            region=api_destination.region,
            account_id=api_destination.account_id,
            connection_arn=api_destination.connection_arn,
            connection=connection,
            invocation_endpoint=api_destination.invocation_endpoint,
            http_method=api_destination.http_method,
            invocation_rate_limit_per_second=api_destination.invocation_rate_limit_per_second,
        )
        api_destination_service.api_destination = api_destination
        return api_destination_service

    @property
    def arn(self) -> Arn:
        return self.api_destination.arn

    @property
    def state(self) -> ApiDestinationState:
        return self.api_destination.state

    @property
    def creation_time(self) -> Timestamp:
        return self.api_destination.creation_time

    @property
    def last_modified_time(self) -> Timestamp:
        return self.api_destination.last_modified_time

    def set_state(self, state: ApiDestinationState) -> None:
        if hasattr(self, "api_destination"):
            if state == ApiDestinationState.ACTIVE:
                state = self._get_state()
            self.api_destination.state = state

    def update(
        self,
        connection,
        invocation_endpoint,
        http_method,
        invocation_rate_limit_per_second,
        description,
    ):
        self.set_state(ApiDestinationState.INACTIVE)
        self.connection = connection
        self.api_destination.connection_arn = connection.arn
        if invocation_endpoint:
            self.api_destination.invocation_endpoint = invocation_endpoint
        if http_method:
            self.api_destination.http_method = http_method
        if invocation_rate_limit_per_second:
            self.api_destination.invocation_rate_limit_per_second = invocation_rate_limit_per_second
        if description:
            self.api_destination.description = description
        self.api_destination.last_modified_time = Timestamp.now()
        self.set_state(ApiDestinationState.ACTIVE)

    def _get_state(self) -> ApiDestinationState:
        """Determine ApiDestinationState based on ConnectionState."""
        return (
            ApiDestinationState.ACTIVE
            if self.connection.state == ConnectionState.AUTHORIZED
            else ApiDestinationState.INACTIVE
        )

    @classmethod
    def validate_input(
        cls,
        name: ApiDestinationName,
        connection_arn: ConnectionArn,
        http_method: ApiDestinationHttpMethod,
        invocation_endpoint: HttpsEndpoint,
    ) -> None:
        errors = []
        errors.extend(cls._validate_api_destination_name(name))
        errors.extend(cls._validate_connection_arn(connection_arn))
        errors.extend(cls._validate_http_method(http_method))
        errors.extend(cls._validate_invocation_endpoint(invocation_endpoint))

        if errors:
            error_message = (
                f"{len(errors)} validation error{'s' if len(errors) > 1 else ''} detected: "
            )
            error_message += "; ".join(errors)
            raise ValidationException(error_message)

    @staticmethod
    def _validate_api_destination_name(name: str) -> list[str]:
        """Validate the API destination name according to AWS rules. Returns a list of validation errors."""
        errors = []
        if not re.match(r"^[\.\-_A-Za-z0-9]+$", name):
            errors.append(
                f"Value '{name}' at 'name' failed to satisfy constraint: "
                "Member must satisfy regular expression pattern: [\\.\\-_A-Za-z0-9]+"
            )
        if not (1 <= len(name) <= 64):
            errors.append(
                f"Value '{name}' at 'name' failed to satisfy constraint: "
                "Member must have length less than or equal to 64"
            )
        return errors

    @staticmethod
    def _validate_connection_arn(connection_arn: ConnectionArn) -> list[str]:
        errors = []
        if not re.match(
            r"^arn:aws([a-z]|\-)*:events:[a-z0-9\-]+:\d{12}:connection/[\.\-_A-Za-z0-9]+/[\-A-Za-z0-9]+$",
            connection_arn,
        ):
            errors.append(
                f"Value '{connection_arn}' at 'connectionArn' failed to satisfy constraint: "
                "Member must satisfy regular expression pattern: "
                "^arn:aws([a-z]|\\-)*:events:([a-z]|\\d|\\-)*:([0-9]{12})?:connection\\/[\\.\\-_A-Za-z0-9]+\\/[\\-A-Za-z0-9]+$"
            )
        return errors

    @staticmethod
    def _validate_http_method(http_method: ApiDestinationHttpMethod) -> list[str]:
        errors = []
        allowed_methods = ["HEAD", "POST", "PATCH", "DELETE", "PUT", "GET", "OPTIONS"]
        if http_method not in allowed_methods:
            errors.append(
                f"Value '{http_method}' at 'httpMethod' failed to satisfy constraint: "
                f"Member must satisfy enum value set: [{', '.join(allowed_methods)}]"
            )
        return errors

    @staticmethod
    def _validate_invocation_endpoint(invocation_endpoint: HttpsEndpoint) -> list[str]:
        errors = []
        endpoint_pattern = r"^((%[0-9A-Fa-f]{2}|[-()_.!~*';/?:@&=+$,A-Za-z0-9])+)([).!';/?:,])?$"
        if not re.match(endpoint_pattern, invocation_endpoint):
            errors.append(
                f"Value '{invocation_endpoint}' at 'invocationEndpoint' failed to satisfy constraint: "
                "Member must satisfy regular expression pattern: "
                "^((%[0-9A-Fa-f]{2}|[-()_.!~*';/?:@&=+$,A-Za-z0-9])+)([).!';/?:,])?$"
            )
        return errors


ApiDestinationServiceDict = dict[Arn, APIDestinationService]


def add_api_destination_authorization(destination, headers, event):
    connection_arn = destination.get("ConnectionArn", "")
    connection_name = re.search(r"connection\/([a-zA-Z0-9-_]+)\/", connection_arn).group(1)

    account_id = extract_account_id_from_arn(connection_arn)
    region = extract_region_from_arn(connection_arn)

    events_client = connect_to(aws_access_key_id=account_id, region_name=region).events
    connection_details = events_client.describe_connection(Name=connection_name)
    secret_arn = connection_details["SecretArn"]
    parsed_arn = parse_arn(secret_arn)
    secretsmanager_client = connect_to(
        aws_access_key_id=parsed_arn["account"], region_name=parsed_arn["region"]
    ).secretsmanager
    auth_secret = json.loads(
        secretsmanager_client.get_secret_value(SecretId=secret_arn)["SecretString"]
    )

    headers.update(_auth_keys_from_connection(connection_details, auth_secret))

    auth_parameters = connection_details.get("AuthParameters", {})
    invocation_parameters = auth_parameters.get("InvocationHttpParameters")

    endpoint = destination.get("InvocationEndpoint")
    if invocation_parameters:
        header_parameters = list_of_parameters_to_object(
            invocation_parameters.get("HeaderParameters", [])
        )
        headers.update(header_parameters)

        body_parameters = list_of_parameters_to_object(
            invocation_parameters.get("BodyParameters", [])
        )
        event.update(body_parameters)

        query_parameters = invocation_parameters.get("QueryStringParameters", [])
        query_object = list_of_parameters_to_object(query_parameters)
        endpoint = add_query_params_to_url(endpoint, query_object)

    return endpoint


def _auth_keys_from_connection(connection_details, auth_secret):
    headers = {}

    auth_type = connection_details.get("AuthorizationType").upper()
    auth_parameters = connection_details.get("AuthParameters")
    match auth_type:
        case ConnectionAuthorizationType.BASIC:
            username = auth_secret.get("username", "")
            password = auth_secret.get("password", "")
            auth = "Basic " + to_str(base64.b64encode(f"{username}:{password}".encode("ascii")))
            headers.update({"authorization": auth})

        case ConnectionAuthorizationType.API_KEY:
            api_key_name = auth_secret.get("api_key_name", "")
            api_key_value = auth_secret.get("api_key_value", "")
            headers.update({api_key_name: api_key_value})

        case ConnectionAuthorizationType.OAUTH_CLIENT_CREDENTIALS:
            oauth_parameters = auth_parameters.get("OAuthParameters", {})
            oauth_method = auth_secret.get("http_method")

            oauth_http_parameters = oauth_parameters.get("OAuthHttpParameters", {})
            oauth_endpoint = auth_secret.get("authorization_endpoint", "")
            query_object = list_of_parameters_to_object(
                oauth_http_parameters.get("QueryStringParameters", [])
            )
            oauth_endpoint = add_query_params_to_url(oauth_endpoint, query_object)

            client_id = auth_secret.get("client_id", "")
            client_secret = auth_secret.get("client_secret", "")

            oauth_body = list_of_parameters_to_object(
                oauth_http_parameters.get("BodyParameters", [])
            )
            oauth_body.update({"client_id": client_id, "client_secret": client_secret})

            oauth_header = list_of_parameters_to_object(
                oauth_http_parameters.get("HeaderParameters", [])
            )
            oauth_result = requests.request(
                method=oauth_method,
                url=oauth_endpoint,
                data=json.dumps(oauth_body),
                headers=oauth_header,
            )
            oauth_data = json.loads(oauth_result.text)

            token_type = oauth_data.get("token_type", "")
            access_token = oauth_data.get("access_token", "")
            auth_header = f"{token_type} {access_token}"
            headers.update({"authorization": auth_header})

    return headers

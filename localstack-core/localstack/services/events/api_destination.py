# TODO Target Helper

import logging
import re

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
from localstack.services.events.models import ApiDestination, Connection, ValidationException

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

# ##########
#     # Helper Methods for connections and api destinations
#     ##########

#

#     def _get_public_parameters(self, auth_type: str, auth_parameters: dict) -> dict:
#         """Extract public parameters (without secrets) based on auth type."""
#         public_params = {}

#         if auth_type == "BASIC" and "BasicAuthParameters" in auth_parameters:
#             public_params["BasicAuthParameters"] = {
#                 "Username": auth_parameters["BasicAuthParameters"]["Username"]
#             }

#         elif auth_type == "API_KEY" and "ApiKeyAuthParameters" in auth_parameters:
#             public_params["ApiKeyAuthParameters"] = {
#                 "ApiKeyName": auth_parameters["ApiKeyAuthParameters"]["ApiKeyName"]
#             }

#         elif auth_type == "OAUTH_CLIENT_CREDENTIALS" and "OAuthParameters" in auth_parameters:
#             oauth_params = auth_parameters["OAuthParameters"]
#             public_params["OAuthParameters"] = {
#                 "AuthorizationEndpoint": oauth_params["AuthorizationEndpoint"],
#                 "HttpMethod": oauth_params["HttpMethod"],
#                 "ClientParameters": {"ClientID": oauth_params["ClientParameters"]["ClientID"]},
#             }
#             if "OAuthHttpParameters" in oauth_params:
#                 public_params["OAuthParameters"]["OAuthHttpParameters"] = oauth_params.get(
#                     "OAuthHttpParameters"
#                 )

#         if "InvocationHttpParameters" in auth_parameters:
#             public_params["InvocationHttpParameters"] = auth_parameters["InvocationHttpParameters"]

#         return public_params

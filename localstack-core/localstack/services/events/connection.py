import json
import logging
import re
import uuid
from datetime import datetime, timezone

from localstack.aws.api.events import (
    Arn,
    ConnectionAuthorizationType,
    ConnectionDescription,
    ConnectionName,
    ConnectionState,
    CreateConnectionAuthRequestParameters,
    Timestamp,
    UpdateConnectionAuthRequestParameters,
)
from localstack.aws.connect import connect_to
from localstack.services.events.models import Connection, ValidationException

VALID_AUTH_TYPES = [t.value for t in ConnectionAuthorizationType]
LOG = logging.getLogger(__name__)


class ConnectionService:
    def __init__(
        self,
        name: ConnectionName,
        region: str,
        account_id: str,
        authorization_type: ConnectionAuthorizationType,
        auth_parameters: CreateConnectionAuthRequestParameters,
        description: ConnectionDescription | None = None,
    ):
        self._validate_input(name, authorization_type)
        state = self._get_initial_state(authorization_type)
        secret_arn = self.create_connection_secret(
            region, account_id, name, authorization_type, auth_parameters
        )

        self.connection = Connection(
            name,
            region,
            account_id,
            authorization_type,
            auth_parameters,
            state,
            secret_arn,
            description,
        )

    @property
    def arn(self) -> Arn:
        return self.connection.arn

    @property
    def state(self) -> ConnectionState:
        return self.connection.state

    @property
    def creation_time(self) -> Timestamp:
        return self.connection.creation_time

    @property
    def last_modified_time(self) -> Timestamp:
        return self.connection.last_modified_time

    @property
    def last_authorized_time(self) -> Timestamp:
        return self.connection.last_authorized_time

    @property
    def secret_arn(self) -> Arn:
        return self.connection.secret_arn

    @property
    def auth_parameters(self) -> CreateConnectionAuthRequestParameters:
        return self.connection.auth_parameters

    def set_state(self, state: ConnectionState) -> None:
        if hasattr(self, "connection"):
            self.connection.state = state

    def update(
        self,
        description: ConnectionDescription,
        authorization_type: ConnectionAuthorizationType,
        auth_parameters: UpdateConnectionAuthRequestParameters,
    ) -> None:
        self.set_state(ConnectionState.UPDATING)
        if description:
            self.connection.description = description
        # Use existing values if not provided in update
        if authorization_type:
            auth_type = (
                authorization_type.value
                if hasattr(authorization_type, "value")
                else authorization_type
            )
            self._validate_auth_type(auth_type)
        else:
            auth_type = self.connection.authorization_type
        auth_params = auth_parameters if auth_parameters else self.connection.auth_parameters

        try:
            if self.connection.secret_arn:
                self.update_connection_secret(self.connection.secret_arn, auth_type, auth_params)
            else:
                secret_arn = self.create_connection_secret(
                    self.connection.region,
                    self.connection.account_id,
                    self.connection.name,
                    auth_type,
                    auth_params,
                )
                self.connection.secret_arn = secret_arn
                self.connection.last_authorized_time = datetime.now(timezone.utc)

            # Set new values
            self.connection.authorization_type = auth_type
            self.connection.auth_parameters = auth_params
            self.set_state(ConnectionState.AUTHORIZED)
            self.connection.last_modified_time = datetime.now(timezone.utc)

        except Exception as error:
            LOG.warning(
                "Connection with name %s updating failed with errors: %s.",
                self.connection.name,
                error,
            )

    def delete(self) -> None:
        self.set_state(ConnectionState.DELETING)
        self.delete_connection_secret(self.connection.secret_arn)
        self.set_state(ConnectionState.DELETING)  # required for AWS parity
        self.connection.last_modified_time = datetime.now(timezone.utc)

    def create_connection_secret(
        self,
        region: str,
        account_id: str,
        name: str,
        authorization_type: ConnectionAuthorizationType,
        auth_parameters: CreateConnectionAuthRequestParameters
        | UpdateConnectionAuthRequestParameters,
    ) -> Arn | None:
        self.set_state(ConnectionState.AUTHORIZING)
        secretsmanager_client = connect_to(
            aws_access_key_id=account_id, region_name=region
        ).secretsmanager
        secret_value = self._get_secret_value(authorization_type, auth_parameters)
        secret_name = f"events!connection/{name}/{str(uuid.uuid4())}"
        try:
            secret_arn = secretsmanager_client.create_secret(
                Name=secret_name,
                SecretString=secret_value,
                Tags=[{"Key": "BYPASS_SECRET_ID_VALIDATION", "Value": "1"}],
            )["ARN"]
            self.set_state(ConnectionState.AUTHORIZED)
            return secret_arn
        except Exception as error:
            LOG.warning("Secret with name %s creation failed with errors: %s.", secret_name, error)

    def update_connection_secret(
        self,
        secret_arn: str,
        authorization_type: ConnectionAuthorizationType,
        auth_parameters: UpdateConnectionAuthRequestParameters,
    ) -> None:
        self.set_state(ConnectionState.AUTHORIZING)
        secretsmanager_client = connect_to(
            aws_access_key_id=self.connection.account_id, region_name=self.connection.region
        ).secretsmanager
        secret_value = self._get_secret_value(authorization_type, auth_parameters)
        try:
            secretsmanager_client.update_secret(SecretId=secret_arn, SecretString=secret_value)
            self.set_state(ConnectionState.AUTHORIZED)
            self.connection.last_authorized_time = datetime.now(timezone.utc)
        except Exception as error:
            LOG.warning("Secret with id %s updating failed with errors: %s.", secret_arn, error)

    def delete_connection_secret(self, secret_arn: str) -> None:
        self.set_state(ConnectionState.DEAUTHORIZING)
        secretsmanager_client = connect_to(
            aws_access_key_id=self.connection.account_id, region_name=self.connection.region
        ).secretsmanager
        try:
            secretsmanager_client.delete_secret(
                SecretId=secret_arn, ForceDeleteWithoutRecovery=True
            )
            self.set_state(ConnectionState.DEAUTHORIZED)
        except Exception as error:
            LOG.warning("Secret with id %s deleting failed with errors: %s.", secret_arn, error)

    def _get_secret_value(
        self,
        authorization_type: ConnectionAuthorizationType,
        auth_parameters: CreateConnectionAuthRequestParameters
        | UpdateConnectionAuthRequestParameters,
    ) -> str:
        result = {}
        match authorization_type:
            case ConnectionAuthorizationType.BASIC:
                params = auth_parameters.get("BasicAuthParameters", {})
                result = {"username": params.get("Username"), "password": params.get("Password")}
            case ConnectionAuthorizationType.API_KEY:
                params = auth_parameters.get("ApiKeyAuthParameters", {})
                result = {
                    "api_key_name": params.get("ApiKeyName"),
                    "api_key_value": params.get("ApiKeyValue"),
                }
            case ConnectionAuthorizationType.OAUTH_CLIENT_CREDENTIALS:
                params = auth_parameters.get("OAuthParameters", {})
                client_params = params.get("ClientParameters", {})
                result = {
                    "client_id": client_params.get("ClientID"),
                    "client_secret": client_params.get("ClientSecret"),
                    "authorization_endpoint": params.get("AuthorizationEndpoint"),
                    "http_method": params.get("HttpMethod"),
                }

        if "InvocationHttpParameters" in auth_parameters:
            result["invocation_http_parameters"] = auth_parameters["InvocationHttpParameters"]

        return json.dumps(result)

    def _get_initial_state(self, auth_type: str) -> ConnectionState:
        if auth_type == "OAUTH_CLIENT_CREDENTIALS":
            return ConnectionState.AUTHORIZING
        return ConnectionState.AUTHORIZED

    def _validate_input(
        self,
        name: ConnectionName,
        authorization_type: ConnectionAuthorizationType,
    ) -> None:
        errors = []
        errors.extend(self._validate_connection_name(name))
        errors.extend(self._validate_auth_type(authorization_type))
        if errors:
            error_message = (
                f"{len(errors)} validation error{'s' if len(errors) > 1 else ''} detected: "
            )
            error_message += "; ".join(errors)
            raise ValidationException(error_message)

    def _validate_connection_name(self, name: str) -> list[str]:
        errors = []
        if not re.match("^[\\.\\-_A-Za-z0-9]+$", name):
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

    def _validate_auth_type(self, auth_type: str) -> list[str]:
        if auth_type not in VALID_AUTH_TYPES:
            return [
                f"Value '{auth_type}' at 'authorizationType' failed to satisfy constraint: "
                f"Member must satisfy enum value set: [{', '.join(VALID_AUTH_TYPES)}]"
            ]
        return []


ConnectionServiceDict = dict[Arn, ConnectionService]

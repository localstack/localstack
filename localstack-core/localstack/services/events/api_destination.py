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


#     def _get_connection_by_arn(self, connection_arn: str) -> Optional[Dict]:
#         """Retrieve a connection by its ARN."""
#         parsed_arn = parse_arn(connection_arn)
#         store = self.get_store(parsed_arn["region"], parsed_arn["account"])
#         connection_name = parsed_arn["resource"].split("/")[1]
#         return store.connections.get(connection_name)

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

#     def _get_initial_state(self, auth_type: str) -> ConnectionState:
#         """Get initial connection state based on auth type."""
#         if auth_type == "OAUTH_CLIENT_CREDENTIALS":
#             return ConnectionState.AUTHORIZING
#         return ConnectionState.AUTHORIZED

#     def _determine_api_destination_state(self, connection_state: str) -> str:
#         """Determine ApiDestinationState based on ConnectionState."""
#         return "ACTIVE" if connection_state == "AUTHORIZED" else "INACTIVE"

#     def _create_api_destination_object(
#         self,
#         context: RequestContext,
#         name: str,
#         connection_arn: str,
#         invocation_endpoint: str,
#         http_method: str,
#         description: Optional[str] = None,
#         invocation_rate_limit_per_second: Optional[int] = None,
#         api_destination_state: Optional[str] = "ACTIVE",
#     ) -> ApiDestination:
#         """Create a standardized API destination object."""
#         now = datetime.utcnow()
#         api_destination_arn = f"arn:{get_partition(context.region)}:events:{context.region}:{context.account_id}:api-destination/{name}/{short_uid()}"

#         api_destination: ApiDestination = {
#             "ApiDestinationArn": api_destination_arn,
#             "Name": name,
#             "ConnectionArn": connection_arn,
#             "InvocationEndpoint": invocation_endpoint,
#             "HttpMethod": http_method,
#             "Description": description,
#             "InvocationRateLimitPerSecond": invocation_rate_limit_per_second or 300,
#             "CreationTime": now,
#             "LastModifiedTime": now,
#             "ApiDestinationState": api_destination_state,
#         }
#         return api_destination

#     def _create_connection_arn(
#         self, context: RequestContext, name: str, connection_uuid: str
#     ) -> str:
#         """Create a standardized connection ARN."""
#         return f"arn:{get_partition(context.region)}:events:{context.region}:{context.account_id}:connection/{name}/{connection_uuid}"

#     def _get_secret_value(
#         self,
#         authorization_type: ConnectionAuthorizationType,
#         auth_parameters: CreateConnectionAuthRequestParameters,
#     ) -> str:
#         result = {}
#         match authorization_type:
#             case ConnectionAuthorizationType.BASIC:
#                 params = auth_parameters.get("BasicAuthParameters", {})
#                 result = {"username": params.get("Username"), "password": params.get("Password")}
#             case ConnectionAuthorizationType.API_KEY:
#                 params = auth_parameters.get("ApiKeyAuthParameters", {})
#                 result = {
#                     "api_key_name": params.get("ApiKeyName"),
#                     "api_key_value": params.get("ApiKeyValue"),
#                 }
#             case ConnectionAuthorizationType.OAUTH_CLIENT_CREDENTIALS:
#                 params = auth_parameters.get("OAuthParameters", {})
#                 client_params = params.get("ClientParameters", {})
#                 result = {
#                     "client_id": client_params.get("ClientID"),
#                     "client_secret": client_params.get("ClientSecret"),
#                     "authorization_endpoint": params.get("AuthorizationEndpoint"),
#                     "http_method": params.get("HttpMethod"),
#                 }

#         if "InvocationHttpParameters" in auth_parameters:
#             result["invocation_http_parameters"] = auth_parameters["InvocationHttpParameters"]

#         return json.dumps(result)

#     def _create_connection_secret(
#         self,
#         context: RequestContext,
#         name: str,
#         authorization_type: ConnectionAuthorizationType,
#         auth_parameters: CreateConnectionAuthRequestParameters,
#     ) -> str:
#         """Create a standardized secret ARN."""
#         # TODO use service role as described here: https://docs.aws.amazon.com/eventbridge/latest/userguide/using-service-linked-roles-service-action-1.html
#         # not too important as it is created automatically on AWS anyway, with the right permissions
#         secretsmanager_client = connect_to(
#             aws_access_key_id=context.account_id, region_name=context.region
#         ).secretsmanager
#         secret_value = self._get_secret_value(authorization_type, auth_parameters)

#         # create secret
#         secret_name = f"events!connection/{name}/{str(uuid.uuid4())}"
#         return secretsmanager_client.create_secret(
#             Name=secret_name,
#             SecretString=secret_value,
#             Tags=[{"Key": "BYPASS_SECRET_ID_VALIDATION", "Value": "1"}],
#         )["ARN"]

#     def _update_connection_secret(
#         self,
#         context: RequestContext,
#         secret_id: str,
#         authorization_type: ConnectionAuthorizationType,
#         auth_parameters: CreateConnectionAuthRequestParameters,
#     ) -> None:
#         secretsmanager_client = connect_to(
#             aws_access_key_id=context.account_id, region_name=context.region
#         ).secretsmanager
#         secret_value = self._get_secret_value(authorization_type, auth_parameters)
#         secretsmanager_client.update_secret(SecretId=secret_id, SecretString=secret_value)

#     def _delete_connection_secret(self, context: RequestContext, secret_id: str):
#         secretsmanager_client = connect_to(
#             aws_access_key_id=context.account_id, region_name=context.region
#         ).secretsmanager
#         secretsmanager_client.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)

#     def _create_connection_object(
#         self,
#         context: RequestContext,
#         name: str,
#         authorization_type: ConnectionAuthorizationType,
#         auth_parameters: dict,
#         description: Optional[str] = None,
#         connection_state: Optional[str] = None,
#         creation_time: Optional[datetime] = None,
#         connection_arn: Optional[str] = None,
#         secret_id: Optional[str] = None,
#     ) -> Dict[str, Any]:
#         """Create a standardized connection object."""
#         current_time = creation_time or datetime.utcnow()
#         connection_uuid = str(uuid.uuid4())

#         if secret_id:
#             self._update_connection_secret(context, secret_id, authorization_type, auth_parameters)
#         else:
#             secret_id = self._create_connection_secret(
#                 context, name, authorization_type, auth_parameters
#             )

#         connection: Dict[str, Any] = {
#             "ConnectionArn": connection_arn
#             or self._create_connection_arn(context, name, connection_uuid),
#             "Name": name,
#             "ConnectionState": connection_state or self._get_initial_state(authorization_type),
#             "AuthorizationType": authorization_type,
#             "AuthParameters": self._get_public_parameters(authorization_type, auth_parameters),
#             "SecretArn": secret_id,
#             "CreationTime": current_time,
#             "LastModifiedTime": current_time,
#             "LastAuthorizedTime": current_time,
#         }

#         if description:
#             connection["Description"] = description

#         return connection

#     def _handle_api_destination_operation(self, operation_name: str, func: Callable) -> Any:
#         """Generic error handler for API destination operations."""
#         try:
#             return func()
#         except (
#             ValidationException,
#             ResourceNotFoundException,
#             ResourceAlreadyExistsException,
#         ) as e:
#             raise e
#         except Exception as e:
#             raise ValidationException(f"Error {operation_name} API destination: {str(e)}")

#     def _handle_connection_operation(self, operation_name: str, func: Callable) -> Any:
#         """Generic error handler for connection operations."""
#         try:
#             return func()
#         except (
#             ValidationException,
#             ResourceNotFoundException,
#             ResourceAlreadyExistsException,
#         ) as e:
#             raise e
#         except Exception as e:
#             raise ValidationException(f"Error {operation_name} connection: {str(e)}")

#     def _create_connection_response(
#         self, connection: Dict[str, Any], override_state: Optional[str] = None
#     ) -> dict:
#         """Create a standardized response for connection operations."""
#         response = {
#             "ConnectionArn": connection["ConnectionArn"],
#             "ConnectionState": override_state or connection["ConnectionState"],
#             "CreationTime": connection["CreationTime"],
#             "LastModifiedTime": connection["LastModifiedTime"],
#             "LastAuthorizedTime": connection.get("LastAuthorizedTime"),
#         }
#         if "SecretArn" in connection:
#             response["SecretArn"] = connection["SecretArn"]
#         return response


##########
# Helper Methods for connections and api destinations
##########

# def _validate_api_destination_name(self, name: str) -> list[str]:
#     """Validate the API destination name according to AWS rules. Returns a list of validation errors."""
#     errors = []
#     if not re.match(r"^[\.\-_A-Za-z0-9]+$", name):
#         errors.append(
#             f"Value '{name}' at 'name' failed to satisfy constraint: "
#             "Member must satisfy regular expression pattern: [\\.\\-_A-Za-z0-9]+"
#         )
#     if not (1 <= len(name) <= 64):
#         errors.append(
#             f"Value '{name}' at 'name' failed to satisfy constraint: "
#             "Member must have length less than or equal to 64"
#         )
#     return errors

# def _validate_connection_name(self, name: str) -> list[str]:
#     """Validate the connection name according to AWS rules. Returns a list of validation errors."""
#     errors = []
#     if not re.match("^[\\.\\-_A-Za-z0-9]+$", name):
#         errors.append(
#             f"Value '{name}' at 'name' failed to satisfy constraint: "
#             "Member must satisfy regular expression pattern: [\\.\\-_A-Za-z0-9]+"
#         )
#     if not (1 <= len(name) <= 64):
#         errors.append(
#             f"Value '{name}' at 'name' failed to satisfy constraint: "
#             "Member must have length less than or equal to 64"
#         )
#     return errors

# def _validate_auth_type(self, auth_type: str) -> list[str]:
#     """Validate the authorization type. Returns a list of validation errors."""
#     errors = []
#     if auth_type not in VALID_AUTH_TYPES:
#         errors.append(
#             f"Value '{auth_type}' at 'authorizationType' failed to satisfy constraint: "
#             f"Member must satisfy enum value set: [{', '.join(VALID_AUTH_TYPES)}]"
#         )
#     return errors

# def _get_connection_by_arn(self, connection_arn: str) -> Optional[Dict]:
#     """Retrieve a connection by its ARN."""
#     parsed_arn = parse_arn(connection_arn)
#     store = self.get_store(parsed_arn["region"], parsed_arn["account"])
#     connection_name = parsed_arn["resource"].split("/")[1]
#     return store.connections.get(connection_name)

# def _get_public_parameters(self, auth_type: str, auth_parameters: dict) -> dict:
#     """Extract public parameters (without secrets) based on auth type."""
#     public_params = {}

#     if auth_type == "BASIC" and "BasicAuthParameters" in auth_parameters:
#         public_params["BasicAuthParameters"] = {
#             "Username": auth_parameters["BasicAuthParameters"]["Username"]
#         }

#     elif auth_type == "API_KEY" and "ApiKeyAuthParameters" in auth_parameters:
#         public_params["ApiKeyAuthParameters"] = {
#             "ApiKeyName": auth_parameters["ApiKeyAuthParameters"]["ApiKeyName"]
#         }

#     elif auth_type == "OAUTH_CLIENT_CREDENTIALS" and "OAuthParameters" in auth_parameters:
#         oauth_params = auth_parameters["OAuthParameters"]
#         public_params["OAuthParameters"] = {
#             "AuthorizationEndpoint": oauth_params["AuthorizationEndpoint"],
#             "HttpMethod": oauth_params["HttpMethod"],
#             "ClientParameters": {"ClientID": oauth_params["ClientParameters"]["ClientID"]},
#         }
#         if "OAuthHttpParameters" in oauth_params:
#             public_params["OAuthParameters"]["OAuthHttpParameters"] = oauth_params.get(
#                 "OAuthHttpParameters"
#             )

#     if "InvocationHttpParameters" in auth_parameters:
#         public_params["InvocationHttpParameters"] = auth_parameters["InvocationHttpParameters"]

#     return public_params

# def _get_initial_state(self, auth_type: str) -> ConnectionState:
#     """Get initial connection state based on auth type."""
#     if auth_type == "OAUTH_CLIENT_CREDENTIALS":
#         return ConnectionState.AUTHORIZING
#     return ConnectionState.AUTHORIZED

# def _determine_api_destination_state(self, connection_state: str) -> str:
#     """Determine ApiDestinationState based on ConnectionState."""
#     return "ACTIVE" if connection_state == "AUTHORIZED" else "INACTIVE"

# def _create_api_destination_object(
#     self,
#     context: RequestContext,
#     name: str,
#     connection_arn: str,
#     invocation_endpoint: str,
#     http_method: str,
#     description: Optional[str] = None,
#     invocation_rate_limit_per_second: Optional[int] = None,
#     api_destination_state: Optional[str] = "ACTIVE",
# ) -> ApiDestination:
#     """Create a standardized API destination object."""
#     now = datetime.utcnow()
#     api_destination_arn = f"arn:{get_partition(context.region)}:events:{context.region}:{context.account_id}:api-destination/{name}/{short_uid()}"

#     api_destination: ApiDestination = {
#         "ApiDestinationArn": api_destination_arn,
#         "Name": name,
#         "ConnectionArn": connection_arn,
#         "InvocationEndpoint": invocation_endpoint,
#         "HttpMethod": http_method,
#         "Description": description,
#         "InvocationRateLimitPerSecond": invocation_rate_limit_per_second or 300,
#         "CreationTime": now,
#         "LastModifiedTime": now,
#         "ApiDestinationState": api_destination_state,
#     }
#     return api_destination

# def _create_connection_arn(
#     self, context: RequestContext, name: str, connection_uuid: str
# ) -> str:
#     """Create a standardized connection ARN."""
#     return f"arn:{get_partition(context.region)}:events:{context.region}:{context.account_id}:connection/{name}/{connection_uuid}"

# def _get_secret_value(
#     self,
#     authorization_type: ConnectionAuthorizationType,
#     auth_parameters: CreateConnectionAuthRequestParameters,
# ) -> str:
#     result = {}
#     match authorization_type:
#         case ConnectionAuthorizationType.BASIC:
#             params = auth_parameters.get("BasicAuthParameters", {})
#             result = {"username": params.get("Username"), "password": params.get("Password")}
#         case ConnectionAuthorizationType.API_KEY:
#             params = auth_parameters.get("ApiKeyAuthParameters", {})
#             result = {
#                 "api_key_name": params.get("ApiKeyName"),
#                 "api_key_value": params.get("ApiKeyValue"),
#             }
#         case ConnectionAuthorizationType.OAUTH_CLIENT_CREDENTIALS:
#             params = auth_parameters.get("OAuthParameters", {})
#             client_params = params.get("ClientParameters", {})
#             result = {
#                 "client_id": client_params.get("ClientID"),
#                 "client_secret": client_params.get("ClientSecret"),
#                 "authorization_endpoint": params.get("AuthorizationEndpoint"),
#                 "http_method": params.get("HttpMethod"),
#             }

#     if "InvocationHttpParameters" in auth_parameters:
#         result["invocation_http_parameters"] = auth_parameters["InvocationHttpParameters"]

#     return json.dumps(result)

# def _create_connection_secret(
#     self,
#     context: RequestContext,
#     name: str,
#     authorization_type: ConnectionAuthorizationType,
#     auth_parameters: CreateConnectionAuthRequestParameters,
# ) -> str:
#     """Create a standardized secret ARN."""
#     # TODO use service role as described here: https://docs.aws.amazon.com/eventbridge/latest/userguide/using-service-linked-roles-service-action-1.html
#     # not too important as it is created automatically on AWS anyway, with the right permissions
#     secretsmanager_client = connect_to(
#         aws_access_key_id=context.account_id, region_name=context.region
#     ).secretsmanager
#     secret_value = self._get_secret_value(authorization_type, auth_parameters)

#     # create secret
#     secret_name = f"events!connection/{name}/{str(uuid.uuid4())}"
#     return secretsmanager_client.create_secret(
#         Name=secret_name,
#         SecretString=secret_value,
#         Tags=[{"Key": "BYPASS_SECRET_ID_VALIDATION", "Value": "1"}],
#     )["ARN"]

# def _update_connection_secret(
#     self,
#     context: RequestContext,
#     secret_id: str,
#     authorization_type: ConnectionAuthorizationType,
#     auth_parameters: CreateConnectionAuthRequestParameters,
# ) -> None:
#     secretsmanager_client = connect_to(
#         aws_access_key_id=context.account_id, region_name=context.region
#     ).secretsmanager
#     secret_value = self._get_secret_value(authorization_type, auth_parameters)
#     secretsmanager_client.update_secret(SecretId=secret_id, SecretString=secret_value)

# def _delete_connection_secret(self, context: RequestContext, secret_id: str):
#     secretsmanager_client = connect_to(
#         aws_access_key_id=context.account_id, region_name=context.region
#     ).secretsmanager
#     secretsmanager_client.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)

# def _create_connection_object(
#     self,
#     context: RequestContext,
#     name: str,
#     authorization_type: ConnectionAuthorizationType,
#     auth_parameters: dict,
#     description: Optional[str] = None,
#     connection_state: Optional[str] = None,
#     creation_time: Optional[datetime] = None,
#     connection_arn: Optional[str] = None,
#     secret_id: Optional[str] = None,
# ) -> Dict[str, Any]:
#     """Create a standardized connection object."""
#     current_time = creation_time or datetime.utcnow()
#     connection_uuid = str(uuid.uuid4())

#     if secret_id:
#         self._update_connection_secret(context, secret_id, authorization_type, auth_parameters)
#     else:
#         secret_id = self._create_connection_secret(
#             context, name, authorization_type, auth_parameters
#         )

#     connection: Dict[str, Any] = {
#         "ConnectionArn": connection_arn
#         or self._create_connection_arn(context, name, connection_uuid),
#         "Name": name,
#         "ConnectionState": connection_state or self._get_initial_state(authorization_type),
#         "AuthorizationType": authorization_type,
#         "AuthParameters": self._get_public_parameters(authorization_type, auth_parameters),
#         "SecretArn": secret_id,
#         "CreationTime": current_time,
#         "LastModifiedTime": current_time,
#         "LastAuthorizedTime": current_time,
#     }

#     if description:
#         connection["Description"] = description

#     return connection

# def _handle_api_destination_operation(self, operation_name: str, func: Callable) -> Any:
#     """Generic error handler for API destination operations."""
#     try:
#         return func()
#     except (
#         ValidationException,
#         ResourceNotFoundException,
#         ResourceAlreadyExistsException,
#     ) as e:
#         raise e
#     except Exception as e:
#         raise ValidationException(f"Error {operation_name} API destination: {str(e)}")

# def _handle_connection_operation(self, operation_name: str, func: Callable) -> Any:
#     """Generic error handler for connection operations."""
#     try:
#         return func()
#     except (
#         ValidationException,
#         ResourceNotFoundException,
#         ResourceAlreadyExistsException,
#     ) as e:
#         raise e
#     except Exception as e:
#         raise ValidationException(f"Error {operation_name} connection: {str(e)}")

# def _create_connection_response(
#     self, connection: Dict[str, Any], override_state: Optional[str] = None
# ) -> dict:
#     """Create a standardized response for connection operations."""
#     response = {
#         "ConnectionArn": connection["ConnectionArn"],
#         "ConnectionState": override_state or connection["ConnectionState"],
#         "CreationTime": connection["CreationTime"],
#         "LastModifiedTime": connection["LastModifiedTime"],
#         "LastAuthorizedTime": connection.get("LastAuthorizedTime"),
#     }
#     if "SecretArn" in connection:
#         response["SecretArn"] = connection["SecretArn"]
#     return response

# ##########
# # Connections
# ##########

# @handler("CreateConnection")
# def create_connection(
#     self,
#     context: RequestContext,
#     name: ConnectionName,
#     authorization_type: ConnectionAuthorizationType,
#     auth_parameters: CreateConnectionAuthRequestParameters,
#     description: ConnectionDescription = None,
#     invocation_connectivity_parameters: ConnectivityResourceParameters = None,
#     **kwargs,
# ) -> CreateConnectionResponse:
#     """Create a new connection."""
#     auth_type = authorization_type
#     if hasattr(authorization_type, "value"):
#         auth_type = authorization_type.value

#     errors = []
#     errors.extend(self._validate_connection_name(name))
#     errors.extend(self._validate_auth_type(auth_type))

#     if errors:
#         error_message = (
#             f"{len(errors)} validation error{'s' if len(errors) > 1 else ''} detected: "
#         )
#         error_message += "; ".join(errors)
#         raise ValidationException(error_message)

#     def create():
#         store = self.get_store(context.region, context.account_id)

#         if name in store.connections:
#             raise ResourceAlreadyExistsException(f"Connection {name} already exists.")

#         connection = self._create_connection_object(
#             context, name, auth_type, auth_parameters, description
#         )
#         store.connections[name] = connection

#         return CreateConnectionResponse(**self._create_connection_response(connection))

#     return self._handle_connection_operation("creating", create)

# @handler("DescribeConnection")
# def describe_connection(
#     self, context: RequestContext, name: ConnectionName, **kwargs
# ) -> DescribeConnectionResponse:
#     store = self.get_store(context.region, context.account_id)
#     try:
#         if name not in store.connections:
#             raise ResourceNotFoundException(
#                 f"Failed to describe the connection(s). Connection '{name}' does not exist."
#             )

#         return DescribeConnectionResponse(**store.connections[name])

#     except ResourceNotFoundException as e:
#         raise e
#     except Exception as e:
#         raise ValidationException(f"Error describing connection: {str(e)}")

# @handler("UpdateConnection")
# def update_connection(
#     self,
#     context: RequestContext,
#     name: ConnectionName,
#     description: ConnectionDescription = None,
#     authorization_type: ConnectionAuthorizationType = None,
#     auth_parameters: UpdateConnectionAuthRequestParameters = None,
#     invocation_connectivity_parameters: ConnectivityResourceParameters = None,
#     **kwargs,
# ) -> UpdateConnectionResponse:
#     store = self.get_store(context.region, context.account_id)

#     def update():
#         if name not in store.connections:
#             raise ResourceNotFoundException(
#                 f"Failed to describe the connection(s). Connection '{name}' does not exist."
#             )

#         existing_connection = store.connections[name]

#         # Use existing values if not provided in update
#         if authorization_type:
#             auth_type = (
#                 authorization_type.value
#                 if hasattr(authorization_type, "value")
#                 else authorization_type
#             )
#             self._validate_auth_type(auth_type)
#         else:
#             auth_type = existing_connection["AuthorizationType"]

#         auth_params = (
#             auth_parameters if auth_parameters else existing_connection["AuthParameters"]
#         )
#         desc = description if description else existing_connection.get("Description")

#         connection = self._create_connection_object(
#             context,
#             name,
#             auth_type,
#             auth_params,
#             desc,
#             ConnectionState.AUTHORIZED,
#             existing_connection["CreationTime"],
#             connection_arn=existing_connection["ConnectionArn"],
#             secret_id=existing_connection["SecretArn"],
#         )
#         store.connections[name] = connection

#         return UpdateConnectionResponse(**self._create_connection_response(connection))

#     return self._handle_connection_operation("updating", update)

# @handler("DeleteConnection")
# def delete_connection(
#     self, context: RequestContext, name: ConnectionName, **kwargs
# ) -> DeleteConnectionResponse:
#     store = self.get_store(context.region, context.account_id)

#     def delete():
#         if name not in store.connections:
#             raise ResourceNotFoundException(
#                 f"Failed to describe the connection(s). Connection '{name}' does not exist."
#             )

#         connection = store.connections.pop(name)
#         self._delete_connection_secret(context, connection["SecretArn"])

#         return DeleteConnectionResponse(
#             **self._create_connection_response(connection, ConnectionState.DELETING)
#         )

#     return self._handle_connection_operation("deleting", delete)

# @handler("ListConnections")
# def list_connections(
#     self,
#     context: RequestContext,
#     name_prefix: ConnectionName = None,
#     connection_state: ConnectionState = None,
#     next_token: NextToken = None,
#     limit: LimitMax100 = None,
#     **kwargs,
# ) -> ListConnectionsResponse:
#     store = self.get_store(context.region, context.account_id)
#     try:
#         connections = []

#         for conn in store.connections.values():
#             if name_prefix and not conn["Name"].startswith(name_prefix):
#                 continue

#             if connection_state and conn["ConnectionState"] != connection_state:
#                 continue

#             connection_summary = {
#                 "ConnectionArn": conn["ConnectionArn"],
#                 "ConnectionState": conn["ConnectionState"],
#                 "CreationTime": conn["CreationTime"],
#                 "LastAuthorizedTime": conn.get("LastAuthorizedTime"),
#                 "LastModifiedTime": conn["LastModifiedTime"],
#                 "Name": conn["Name"],
#                 "AuthorizationType": conn["AuthorizationType"],
#             }
#             connections.append(connection_summary)

#         connections.sort(key=lambda x: x["CreationTime"])

#         if limit:
#             connections = connections[:limit]

#         return ListConnectionsResponse(Connections=connections)

#     except Exception as e:
#         raise ValidationException(f"Error listing connections: {str(e)}")

# ##########

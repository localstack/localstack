import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.sync import poll_condition
from tests.aws.services.events.helper_functions import is_old_provider

API_DESTINATION_AUTHS = [
    {
        "type": "BASIC",
        "key": "BasicAuthParameters",
        "parameters": {"Username": "user", "Password": "pass"},
    },
    {
        "type": "API_KEY",
        "key": "ApiKeyAuthParameters",
        "parameters": {"ApiKeyName": "Api", "ApiKeyValue": "apikey_secret"},
    },
    {
        "type": "OAUTH_CLIENT_CREDENTIALS",
        "key": "OAuthParameters",
        "parameters": {
            "AuthorizationEndpoint": "replace_this",
            "ClientParameters": {"ClientID": "id", "ClientSecret": "password"},
            "HttpMethod": "put",
            "OAuthHttpParameters": {
                "BodyParameters": [{"Key": "oauthbody", "Value": "value1"}],
                "HeaderParameters": [{"Key": "oauthheader", "Value": "value2"}],
                "QueryStringParameters": [{"Key": "oauthquery", "Value": "value3"}],
            },
        },
    },
]

API_DESTINATION_AUTH_PARAMS = [
    {
        "AuthorizationType": "BASIC",
        "AuthParameters": {
            "BasicAuthParameters": {"Username": "user", "Password": "pass"},
        },
    },
    {
        "AuthorizationType": "API_KEY",
        "AuthParameters": {
            "ApiKeyAuthParameters": {"ApiKeyName": "ApiKey", "ApiKeyValue": "secret"},
        },
    },
    {
        "AuthorizationType": "OAUTH_CLIENT_CREDENTIALS",
        "AuthParameters": {
            "OAuthParameters": {
                "AuthorizationEndpoint": "https://example.com/oauth",
                "ClientParameters": {"ClientID": "client_id", "ClientSecret": "client_secret"},
                "HttpMethod": "POST",
            }
        },
    },
]


class TestEventBridgeApiDestinations:
    @markers.aws.validated
    @pytest.mark.parametrize("auth", API_DESTINATION_AUTHS)
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_api_destinations(
        self,
        aws_client,
        create_connection,
        create_api_destination,
        destination_name,
        auth,
        api_destination_snapshot,
    ):
        connection_response = create_connection(auth)
        connection_arn = connection_response["ConnectionArn"]

        response = create_api_destination(
            ConnectionArn=connection_arn,
            HttpMethod="POST",
            InvocationEndpoint="https://example.com/api",
            Description="Test API destination",
        )
        api_destination_snapshot.match("create-api-destination", response)

        describe_response = aws_client.events.describe_api_destination(Name=destination_name)
        api_destination_snapshot.match("describe-api-destination", describe_response)

        list_response = aws_client.events.list_api_destinations(NamePrefix=destination_name)
        api_destination_snapshot.match("list-api-destinations", list_response)

        update_response = aws_client.events.update_api_destination(
            Name=destination_name,
            ConnectionArn=connection_arn,
            HttpMethod="PUT",
            InvocationEndpoint="https://example.com/api/v2",
            Description="Updated API destination",
        )
        api_destination_snapshot.match("update-api-destination", update_response)

        describe_updated_response = aws_client.events.describe_api_destination(
            Name=destination_name
        )
        api_destination_snapshot.match(
            "describe-updated-api-destination", describe_updated_response
        )

        delete_response = aws_client.events.delete_api_destination(Name=destination_name)
        api_destination_snapshot.match("delete-api-destination", delete_response)

        with pytest.raises(aws_client.events.exceptions.ResourceNotFoundException) as exc_info:
            aws_client.events.describe_api_destination(Name=destination_name)
        api_destination_snapshot.match(
            "describe-api-destination-not-found-error", exc_info.value.response
        )

    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="V1 provider does not support this feature")
    def test_create_api_destination_invalid_parameters(
        self, aws_client, api_destination_snapshot, destination_name
    ):
        with pytest.raises(ClientError) as e:
            aws_client.events.create_api_destination(
                Name=destination_name,
                ConnectionArn="invalid-connection-arn",
                HttpMethod="INVALID_METHOD",
                InvocationEndpoint="invalid-endpoint",
            )
        api_destination_snapshot.match(
            "create-api-destination-invalid-parameters-error", e.value.response
        )

    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="V1 provider does not support this feature")
    def test_create_api_destination_name_validation(
        self, aws_client, api_destination_snapshot, create_connection
    ):
        invalid_name = "Invalid Name With Spaces!"

        connection_response = create_connection(API_DESTINATION_AUTHS[0])
        connection_arn = connection_response["ConnectionArn"]

        with pytest.raises(ClientError) as e:
            aws_client.events.create_api_destination(
                Name=invalid_name,
                ConnectionArn=connection_arn,
                HttpMethod="POST",
                InvocationEndpoint="https://example.com/api",
            )
        api_destination_snapshot.match(
            "create-api-destination-invalid-name-error", e.value.response
        )


class TestEventBridgeConnections:
    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_create_connection(
        self, aws_client, connection_snapshot, create_connection, connection_name
    ):
        response = create_connection(
            "API_KEY",
            {
                "ApiKeyAuthParameters": {"ApiKeyName": "ApiKey", "ApiKeyValue": "secret"},
                "InvocationHttpParameters": {},
            },
        )
        connection_snapshot.match("create-connection", response)

        describe_response = aws_client.events.describe_connection(Name=connection_name)
        connection_snapshot.match("describe-connection", describe_response)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    @pytest.mark.parametrize("auth_params", API_DESTINATION_AUTH_PARAMS)
    def test_create_connection_with_auth(
        self, aws_client, connection_snapshot, create_connection, auth_params, connection_name
    ):
        response = create_connection(
            auth_params["AuthorizationType"],
            auth_params["AuthParameters"],
        )
        connection_snapshot.match("create-connection-auth", response)

        describe_response = aws_client.events.describe_connection(Name=connection_name)
        connection_snapshot.match("describe-connection-auth", describe_response)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_list_connections(
        self, aws_client, connection_snapshot, create_connection, connection_name
    ):
        create_connection(
            "BASIC",
            {
                "BasicAuthParameters": {"Username": "user", "Password": "pass"},
                "InvocationHttpParameters": {},
            },
        )

        response = aws_client.events.list_connections(NamePrefix=connection_name)
        connection_snapshot.match("list-connections", response)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_delete_connection(
        self, aws_client, connection_snapshot, create_connection, connection_name
    ):
        response = create_connection(
            "API_KEY",
            {
                "ApiKeyAuthParameters": {"ApiKeyName": "ApiKey", "ApiKeyValue": "secret"},
                "InvocationHttpParameters": {},
            },
        )
        connection_snapshot.match("create-connection-response", response)

        secret_arn = aws_client.events.describe_connection(Name=connection_name)["SecretArn"]
        # check if secret exists
        aws_client.secretsmanager.describe_secret(SecretId=secret_arn)

        delete_response = aws_client.events.delete_connection(Name=connection_name)
        connection_snapshot.match("delete-connection", delete_response)

        # wait until connection is deleted
        def is_connection_deleted():
            try:
                aws_client.events.describe_connection(Name=connection_name)
                return False
            except Exception:
                return True

        poll_condition(is_connection_deleted)

        with pytest.raises(aws_client.events.exceptions.ResourceNotFoundException) as exc:
            aws_client.events.describe_connection(Name=connection_name)
        connection_snapshot.match("describe-deleted-connection", exc.value.response)

        def is_secret_deleted():
            try:
                aws_client.secretsmanager.describe_secret(SecretId=secret_arn)
                return False
            except Exception:
                return True

        poll_condition(is_secret_deleted)

        with pytest.raises(aws_client.secretsmanager.exceptions.ResourceNotFoundException):
            aws_client.secretsmanager.describe_secret(SecretId=secret_arn)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_create_connection_invalid_parameters(
        self, aws_client, connection_snapshot, connection_name
    ):
        with pytest.raises(ClientError) as e:
            aws_client.events.create_connection(
                Name=connection_name,
                AuthorizationType="INVALID_AUTH_TYPE",
                AuthParameters={},
            )
        connection_snapshot.match("create-connection-invalid-auth-error", e.value.response)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_update_connection(
        self, aws_client, snapshot, connection_snapshot, create_connection, connection_name
    ):
        create_response = create_connection(
            "BASIC",
            {
                "BasicAuthParameters": {"Username": "user", "Password": "pass"},
                "InvocationHttpParameters": {},
            },
        )
        connection_snapshot.match("create-connection", create_response)

        describe_response = aws_client.events.describe_connection(Name=connection_name)
        connection_snapshot.match("describe-created-connection", describe_response)

        # add secret id transformer
        secret_id = describe_response["SecretArn"]
        secret_uuid, _, secret_suffix = secret_id.rpartition("/")[2].rpartition("-")
        connection_snapshot.add_transformer(
            snapshot.transform.regex(secret_uuid, "<secret-uuid>"), priority=-1
        )
        connection_snapshot.add_transformer(
            snapshot.transform.regex(secret_suffix, "<secret-id-suffix>"), priority=-1
        )

        get_secret_response = aws_client.secretsmanager.get_secret_value(SecretId=secret_id)
        connection_snapshot.match("connection-secret-before-update", get_secret_response)

        update_response = aws_client.events.update_connection(
            Name=connection_name,
            AuthorizationType="BASIC",
            AuthParameters={
                "BasicAuthParameters": {"Username": "new_user", "Password": "new_pass"},
                "InvocationHttpParameters": {},
            },
        )
        connection_snapshot.match("update-connection", update_response)

        describe_response = aws_client.events.describe_connection(Name=connection_name)
        connection_snapshot.match("describe-updated-connection", describe_response)

        get_secret_response = aws_client.secretsmanager.get_secret_value(SecretId=secret_id)
        connection_snapshot.match("connection-secret-after-update", get_secret_response)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_create_connection_name_validation(self, aws_client, connection_snapshot):
        invalid_name = "Invalid Name With Spaces!"

        with pytest.raises(ClientError) as e:
            aws_client.events.create_connection(
                Name=invalid_name,
                AuthorizationType="API_KEY",
                AuthParameters={
                    "ApiKeyAuthParameters": {"ApiKeyName": "ApiKey", "ApiKeyValue": "secret"},
                    "InvocationHttpParameters": {},
                },
            )
        connection_snapshot.match("create-connection-invalid-name-error", e.value.response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "auth_params", API_DESTINATION_AUTH_PARAMS, ids=["basic", "api-key", "oauth"]
    )
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_connection_secrets(
        self,
        aws_client,
        snapshot,
        connection_snapshot,
        create_connection,
        connection_name,
        auth_params,
    ):
        response = create_connection(
            auth_params["AuthorizationType"],
            auth_params["AuthParameters"],
        )
        connection_snapshot.match("create-connection-auth", response)

        describe_response = aws_client.events.describe_connection(Name=connection_name)
        connection_snapshot.match("describe-connection-auth", describe_response)

        secret_id = describe_response["SecretArn"]
        secret_uuid, _, secret_suffix = secret_id.rpartition("/")[2].rpartition("-")
        connection_snapshot.add_transformer(
            snapshot.transform.regex(secret_uuid, "<secret-uuid>"), priority=-1
        )
        connection_snapshot.add_transformer(
            snapshot.transform.regex(secret_suffix, "<secret-id-suffix>"), priority=-1
        )
        get_secret_response = aws_client.secretsmanager.get_secret_value(SecretId=secret_id)
        connection_snapshot.match("connection-secret", get_secret_response)

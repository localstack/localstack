import base64
import json
import time
import uuid

import aws_cdk as cdk
import aws_cdk.aws_apigateway as apigateway
import aws_cdk.aws_iam as iam
import aws_cdk.aws_lambda as awslambda
import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from localstack.utils.testutil import get_lambda_log_events

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
            "HttpMethod": "POST",
            "OAuthHttpParameters": {
                "BodyParameters": [
                    {"Key": "grant_type", "Value": "client_credentials"},
                    {"Key": "client_id", "Value": "id"},
                    {"Key": "client_secret", "Value": "password"},
                    {"Key": "oauthbody", "Value": "value1"},
                ],
                "HeaderParameters": [
                    {"Key": "Content-Type", "Value": "application/x-www-form-urlencoded"},
                    {"Key": "oauthheader", "Value": "value2"},
                ],
                "QueryStringParameters": [{"Key": "oauthquery", "Value": "value3"}],
            },
        },
    },
]

LAMBDA_BACKEND_CODE = r"""
import json
def handler(event, context):
    print(json.dumps(event))
    return {
        "statusCode": 200,
        "headers": event.get("headers", {}),
        "body": json.dumps(event.get("body", {})),
        "queryStringParameters": event.get("queryStringParameters", {})
    }
"""

OAUTH_TOKEN_LAMBDA_CODE = r"""
import json
def handler(event, context):
    print(json.dumps(event))
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({
            "access_token": "my-oauth-token",
            "token_type": "bearer",
            "expires_in": 86400
        })
    }
"""


@markers.acceptance_test
@pytest.mark.parametrize("auth", API_DESTINATION_AUTHS)
class TestApiDestinationsCfn:
    @pytest.fixture(scope="function", autouse=True)
    def infrastructure(self, aws_client, infrastructure_setup):
        infra = infrastructure_setup(namespace="ApiDestCfnTest")

        stack = cdk.Stack(infra.cdk_app, "ApiDestCfnTestStack")

        backend = awslambda.Function(
            stack,
            "BackendFunction",
            runtime=awslambda.Runtime.PYTHON_3_10,
            code=awslambda.Code.from_inline(LAMBDA_BACKEND_CODE),
            handler="index.handler",
        )

        api = apigateway.RestApi(stack, "RestApi")
        resource = api.root.add_resource("test")
        resource.add_method("POST", apigateway.LambdaIntegration(backend, proxy=True))

        oauth_token_lambda = awslambda.Function(
            stack,
            "OAuthTokenFunction",
            runtime=awslambda.Runtime.PYTHON_3_10,
            code=awslambda.Code.from_inline(OAUTH_TOKEN_LAMBDA_CODE),
            handler="index.handler",
        )
        oauth_token_url = oauth_token_lambda.add_function_url(
            auth_type=awslambda.FunctionUrlAuthType.NONE
        ).url

        role = iam.Role(
            stack,
            "TargetRole",
            assumed_by=iam.ServicePrincipal("events.amazonaws.com"),
            inline_policies={
                "ApiDestinationPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["events:InvokeApiDestination"], resources=["*"]
                        )
                    ]
                )
            },
        )

        cdk.CfnOutput(stack, "BackendFunctionName", value=backend.function_name)
        cdk.CfnOutput(stack, "OAuthFunctionName", value=oauth_token_lambda.function_name)
        cdk.CfnOutput(stack, "ApiId", value=api.rest_api_id)
        cdk.CfnOutput(stack, "RoleArn", value=role.role_arn)
        cdk.CfnOutput(stack, "OAuthTokenUrl", value=oauth_token_url)

        infra.add_cdk_stack(stack)
        with infra.provisioner() as prov:
            time.sleep(30)

            yield prov

    @markers.aws.validated
    def test_api_destination_integration(self, aws_client, infrastructure, snapshot, auth):
        # Retrieve outputs
        outputs = infrastructure.get_stack_outputs(stack_name="ApiDestCfnTestStack")
        backend_function_name = outputs["BackendFunctionName"]
        oauth_function_name = outputs["OAuthFunctionName"]
        api_id = outputs["ApiId"]
        role_arn = outputs["RoleArn"]
        oauth_token_url = outputs["OAuthTokenUrl"]

        region = aws_client.events.meta.region_name
        invocation_endpoint = f"https://{api_id}.execute-api.{region}.amazonaws.com/prod/test"
        connection_name = f"c-{short_uid()}"
        auth_type = auth["type"]
        key = auth["key"]
        parameters = auth["parameters"].copy()

        if auth_type == "OAUTH_CLIENT_CREDENTIALS":
            parameters["AuthorizationEndpoint"] = oauth_token_url

        connection_resp = aws_client.events.create_connection(
            Name=connection_name,
            AuthorizationType=auth_type,
            AuthParameters={
                key: parameters,
                "InvocationHttpParameters": {
                    "BodyParameters": [
                        {"Key": "connection_body_param", "Value": "value", "IsValueSecret": False},
                        {"Key": "oauthbody", "Value": "value1", "IsValueSecret": False},
                    ],
                    "HeaderParameters": [
                        {
                            "Key": "connection-header-param",
                            "Value": "value",
                            "IsValueSecret": False,
                        },
                        {"Key": "overwritten-header", "Value": "original", "IsValueSecret": False},
                        {"Key": "oauthheader", "Value": "value2", "IsValueSecret": False},
                    ],
                    "QueryStringParameters": [
                        {"Key": "connection_query_param", "Value": "value", "IsValueSecret": False},
                        {"Key": "overwritten_query", "Value": "original", "IsValueSecret": False},
                        {"Key": "oauthquery", "Value": "value3", "IsValueSecret": False},
                    ],
                },
            },
        )

        # Wait for the connection to become AUTHORIZED if using OAuth
        if auth_type == "OAUTH_CLIENT_CREDENTIALS":

            def _wait_for_connection_auth():
                conn_desc = aws_client.events.describe_connection(Name=connection_name)
                state = conn_desc.get("ConnectionState")
                if state == "AUTHORIZED":
                    return conn_desc
                raise AssertionError(f"Connection not yet authorized. Current state: {state}")

            retry(_wait_for_connection_auth, retries=20, sleep=5)

        dest_name = f"d-{short_uid()}"
        dest_resp = aws_client.events.create_api_destination(
            Name=dest_name,
            ConnectionArn=connection_resp["ConnectionArn"],
            InvocationEndpoint=invocation_endpoint,
            HttpMethod="POST",
        )

        api_destination_arn = dest_resp["ApiDestinationArn"]

        # Additional delay to ensure API Destination setup
        time.sleep(10)

        rule_name = f"r-{short_uid()}"
        target_id = f"target-{short_uid()}"
        pattern = json.dumps({"source": ["source-123"], "detail-type": ["type-123"]})
        aws_client.events.put_rule(Name=rule_name, EventPattern=pattern)
        time.sleep(10)

        unique_marker = str(uuid.uuid4())
        detail = {"i": 0, "marker": unique_marker}

        aws_client.events.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    "Id": target_id,
                    "Arn": api_destination_arn,
                    "Input": json.dumps({"target_value": "value", "marker": unique_marker}),
                    "RoleArn": role_arn,
                    "HttpParameters": {
                        "HeaderParameters": {"target-header": "target_header_value"},
                        "QueryStringParameters": {"target_query": "t_query"},
                    },
                }
            ],
        )

        try:
            aws_client.logs.create_log_group(logGroupName=f"/aws/lambda/{backend_function_name}")
        except aws_client.logs.exceptions.ResourceAlreadyExistsException:
            print("Log group for backend lambda already exists.")

        try:
            aws_client.logs.create_log_group(logGroupName=f"/aws/lambda/{oauth_function_name}")
        except aws_client.logs.exceptions.ResourceAlreadyExistsException:
            print("Log group for OAuth token lambda already exists.")

        aws_client.events.put_events(
            Entries=[
                {"Source": "source-123", "DetailType": "type-123", "Detail": json.dumps(detail)}
            ]
        )

        def _check_backend_logs(retries=0):
            events = get_lambda_log_events(
                function_name=backend_function_name, logs_client=aws_client.logs
            )
            filtered = []
            for e in events:
                if isinstance(e, dict) and "body" in e:
                    try:
                        body = json.loads(e["body"])
                        if body.get("marker") == unique_marker:
                            filtered.append(e)
                    except Exception as ex:
                        print("Exception parsing event body:", ex)
            if len(filtered) == 1:
                return filtered[0]
            raise AssertionError(
                f"Expected exactly 1 invocation with marker {unique_marker}, found {len(filtered)}"
            )

        event_log = retry(_check_backend_logs, retries=30, sleep=5)

        headers = {k.lower(): v for k, v in event_log.get("headers", {}).items()}
        posted_body = json.loads(event_log.get("body", "{}"))
        qs_params = event_log.get("queryStringParameters", {}) or {}

        assert posted_body["target_value"] == "value"
        assert posted_body["marker"] == unique_marker

        # Validate target-level params
        assert headers.get("target-header", "").lower() == "target_header_value"
        assert qs_params.get("target_query") == "t_query"
        assert qs_params.get("overwritten_query") == "original"

        # Auth validation
        match auth_type:
            case "BASIC":
                user_pass = base64.b64encode(b"user:pass").decode("utf-8")
                assert headers.get("authorization") == f"Basic {user_pass}"
            case "API_KEY":
                assert headers.get("api") == "apikey_secret"
            case "OAUTH_CLIENT_CREDENTIALS":
                assert headers.get("authorization") == "Bearer my-oauth-token"

        aws_client.events.remove_targets(Rule=rule_name, Ids=[target_id])
        aws_client.events.delete_rule(Name=rule_name, Force=True)
        aws_client.events.delete_connection(Name=connection_name)
        aws_client.events.delete_api_destination(Name=dest_name)

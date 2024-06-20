import pytest
from botocore.config import Config

from localstack import config
from localstack.constants import APPLICATION_JSON
from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.strings import short_uid
from tests.aws.services.apigateway.apigateway_fixtures import (
    create_rest_api_deployment,
    create_rest_api_integration,
    create_rest_api_integration_response,
    create_rest_api_method_response,
    create_rest_api_stage,
    create_rest_resource,
    create_rest_resource_method,
    delete_rest_api,
    import_rest_api,
)
from tests.aws.services.lambda_.test_lambda import TEST_LAMBDA_PYTHON_ECHO_STATUS_CODE

# default name used for created REST API stages
DEFAULT_STAGE_NAME = "dev"

STEPFUNCTIONS_ASSUME_ROLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

APIGATEWAY_STEPFUNCTIONS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "states:*", "Resource": "*"}],
}

APIGATEWAY_KINESIS_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "kinesis:*", "Resource": "*"}],
}

APIGATEWAY_LAMBDA_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "lambda:*", "Resource": "*"}],
}

APIGATEWAY_S3_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
}

APIGATEWAY_DYNAMODB_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"}],
}

APIGATEWAY_ASSUME_ROLE_POLICY = {
    "Statement": {
        "Sid": "",
        "Effect": "Allow",
        "Principal": {"Service": "apigateway.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }
}


def is_next_gen_api():
    return config.APIGW_NEXT_GEN_PROVIDER and not is_aws_cloud()


@pytest.fixture
def create_rest_api_with_integration(
    create_rest_apigw, wait_for_stream_ready, create_iam_role_with_policy, aws_client
):
    def _factory(
        integration_uri,
        path_part="test",
        req_parameters=None,
        req_templates=None,
        res_templates=None,
        integration_type=None,
        stage=DEFAULT_STAGE_NAME,
    ):
        name = f"test-apigw-{short_uid()}"
        api_id, name, root_id = create_rest_apigw(
            name=name, endpointConfiguration={"types": ["REGIONAL"]}
        )

        resource_id, _ = create_rest_resource(
            aws_client.apigateway, restApiId=api_id, parentId=root_id, pathPart=path_part
        )

        if req_parameters is None:
            req_parameters = {}

        method, _ = create_rest_resource_method(
            aws_client.apigateway,
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            authorizationType="NONE",
            apiKeyRequired=False,
            requestParameters={value: True for value in req_parameters.values()},
        )

        # set AWS policy to give API GW access to backend resources
        if ":dynamodb:" in integration_uri:
            policy = APIGATEWAY_DYNAMODB_POLICY
        elif ":kinesis:" in integration_uri:
            policy = APIGATEWAY_KINESIS_POLICY
        elif integration_type in ("HTTP", "HTTP_PROXY"):
            policy = None
        else:
            raise Exception(f"Unexpected integration URI: {integration_uri}")
        assume_role_arn = ""
        if policy:
            assume_role_arn = create_iam_role_with_policy(
                RoleName=f"role-apigw-{short_uid()}",
                PolicyName=f"policy-apigw-{short_uid()}",
                RoleDefinition=APIGATEWAY_ASSUME_ROLE_POLICY,
                PolicyDefinition=policy,
            )

        create_rest_api_integration(
            aws_client.apigateway,
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod=method,
            integrationHttpMethod="POST",
            type=integration_type or "AWS",
            credentials=assume_role_arn,
            uri=integration_uri,
            requestTemplates=req_templates or {},
            requestParameters=req_parameters,
        )

        create_rest_api_method_response(
            aws_client.apigateway,
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            statusCode="200",
        )

        res_templates = res_templates or {APPLICATION_JSON: "$input.json('$')"}
        create_rest_api_integration_response(
            aws_client.apigateway,
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            statusCode="200",
            responseTemplates=res_templates,
        )

        deployment_id, _ = create_rest_api_deployment(aws_client.apigateway, restApiId=api_id)
        create_rest_api_stage(
            aws_client.apigateway, restApiId=api_id, stageName=stage, deploymentId=deployment_id
        )

        return api_id

    yield _factory


@pytest.fixture
def create_status_code_echo_server(aws_client, create_lambda_function):
    lambda_client = aws_client.lambda_

    def _create_status_code_echo_server():
        function_name = f"lambda_fn_echo_status_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO_STATUS_CODE,
        )
        create_url_response = lambda_client.create_function_url_config(
            FunctionName=function_name, AuthType="NONE", InvokeMode="BUFFERED"
        )
        aws_client.lambda_.add_permission(
            FunctionName=function_name,
            StatementId="urlPermission",
            Action="lambda:InvokeFunctionUrl",
            Principal="*",
            FunctionUrlAuthType="NONE",
        )
        return create_url_response["FunctionUrl"]

    return _create_status_code_echo_server


@pytest.fixture
def apigw_redeploy_api(aws_client):
    def _factory(rest_api_id: str, stage_name: str):
        deployment_id = aws_client.apigateway.create_deployment(restApiId=rest_api_id)["id"]

        aws_client.apigateway.update_stage(
            restApiId=rest_api_id,
            stageName=stage_name,
            patchOperations=[{"op": "replace", "path": "/deploymentId", "value": deployment_id}],
        )

    return _factory


@pytest.fixture
def import_apigw(aws_client, aws_client_factory):
    rest_api_ids = []

    if is_aws_cloud():
        client_config = (
            Config(
                # Api gateway can throttle requests pretty heavily. Leading to potentially undeleted apis
                retries={"max_attempts": 10, "mode": "adaptive"}
            )
            if is_aws_cloud()
            else None
        )

        apigateway_client = aws_client_factory(config=client_config).apigateway
    else:
        apigateway_client = aws_client.apigateway

    def _import_apigateway_function(*args, **kwargs):
        response, root_id = import_rest_api(apigateway_client, **kwargs)
        rest_api_ids.append(response.get("id"))
        return response, root_id

    yield _import_apigateway_function

    for rest_api_id in rest_api_ids:
        delete_rest_api(apigateway_client, restApiId=rest_api_id)


@pytest.fixture
def apigw_add_transformers(snapshot):
    snapshot.add_transformer(snapshot.transform.jsonpath("$..items..id", "id"))
    snapshot.add_transformer(snapshot.transform.key_value("deploymentId"))

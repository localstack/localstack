import pytest

from localstack.constants import APPLICATION_JSON
from localstack.utils.strings import short_uid
from tests.integration.apigateway_fixtures import (
    create_rest_api_deployment,
    create_rest_api_integration,
    create_rest_api_integration_response,
    create_rest_api_method_response,
    create_rest_api_stage,
    create_rest_resource,
    create_rest_resource_method,
)
from tests.integration.test_apigateway import (
    APIGATEWAY_ASSUME_ROLE_POLICY,
    APIGATEWAY_DYNAMODB_POLICY,
    APIGATEWAY_KINESIS_POLICY,
)

# default name used for created REST API stages
DEFAULT_STAGE_NAME = "dev"


@pytest.fixture
def create_rest_api_with_integration(
    create_rest_apigw,
    apigateway_client,
    wait_for_stream_ready,
    create_iam_role_with_policy,
):
    def _factory(
        integration_uri,
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
            apigateway_client, restApiId=api_id, parentId=root_id, pathPart="test"
        )

        method, _ = create_rest_resource_method(
            apigateway_client,
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            authorizationType="NONE",
        )

        # set AWS policy to give API GW access to backend resources
        if ":dynamodb:" in integration_uri:
            policy = APIGATEWAY_DYNAMODB_POLICY
        elif ":kinesis:" in integration_uri:
            policy = APIGATEWAY_KINESIS_POLICY
        else:
            raise Exception(f"Unexpected integration URI: {integration_uri}")
        assume_role_arn = create_iam_role_with_policy(
            RoleName=f"role-apigw-{short_uid()}",
            PolicyName=f"policy-apigw-{short_uid()}",
            RoleDefinition=APIGATEWAY_ASSUME_ROLE_POLICY,
            PolicyDefinition=policy,
        )

        create_rest_api_integration(
            apigateway_client,
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod=method,
            integrationHttpMethod="POST",
            type=integration_type or "AWS",
            credentials=assume_role_arn,
            uri=integration_uri,
            requestTemplates=req_templates or {},
        )

        create_rest_api_method_response(
            apigateway_client,
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            statusCode="200",
        )

        res_templates = res_templates or {APPLICATION_JSON: "$input.json('$')"}
        create_rest_api_integration_response(
            apigateway_client,
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="POST",
            statusCode="200",
            responseTemplates=res_templates,
        )

        deployment_id, _ = create_rest_api_deployment(apigateway_client, restApiId=api_id)
        create_rest_api_stage(
            apigateway_client, restApiId=api_id, stageName=stage, deploymentId=deployment_id
        )

        return api_id

    yield _factory

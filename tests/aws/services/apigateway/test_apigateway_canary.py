import json

import pytest
import requests
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.sync import retry
from tests.aws.services.apigateway.apigateway_fixtures import api_invoke_url


@pytest.fixture
def create_api_for_deployment(aws_client, create_rest_apigw):
    def _create(response_template=None):
        # create API, method, integration, deployment
        api_id, _, root_id = create_rest_apigw()

        aws_client.apigateway.put_method(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            authorizationType="NONE",
        )

        aws_client.apigateway.put_method_response(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            statusCode="200",
        )

        aws_client.apigateway.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            type="MOCK",
            requestTemplates={"application/json": '{"statusCode": 200}'},
        )

        response_template = response_template or {
            "statusCode": 200,
            "message": "default deployment",
        }
        aws_client.apigateway.put_integration_response(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            statusCode="200",
            selectionPattern="",
            responseTemplates={"application/json": json.dumps(response_template)},
        )

        return api_id, root_id

    return _create


class TestStageCrudCanary:
    @markers.aws.validated
    def test_create_update_stages(
        self, create_api_for_deployment, aws_client, create_rest_apigw, snapshot
    ):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("deploymentId"),
                snapshot.transform.key_value("id"),
            ]
        )
        api_id, resource_id = create_api_for_deployment()

        create_deployment_1 = aws_client.apigateway.create_deployment(restApiId=api_id)
        snapshot.match("create-deployment-1", create_deployment_1)
        deployment_id = create_deployment_1["id"]

        aws_client.apigateway.update_integration_response(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            statusCode="200",
            patchOperations=[
                {
                    "op": "replace",
                    "path": "/responseTemplates/application~1json",
                    "value": json.dumps({"statusCode": 200, "message": "second deployment"}),
                }
            ],
        )

        create_deployment_2 = aws_client.apigateway.create_deployment(restApiId=api_id)
        snapshot.match("create-deployment-2", create_deployment_2)
        deployment_id_2 = create_deployment_2["id"]

        stage_name = "dev"
        create_stage = aws_client.apigateway.create_stage(
            restApiId=api_id,
            stageName=stage_name,
            deploymentId=deployment_id,
            description="dev stage",
            variables={
                "testVar": "default",
            },
            canarySettings={
                "deploymentId": deployment_id_2,
                "percentTraffic": 50,
                "stageVariableOverrides": {
                    "testVar": "canary",
                },
            },
        )
        snapshot.match("create-stage", create_stage)

        get_stage = aws_client.apigateway.get_stage(
            restApiId=api_id,
            stageName=stage_name,
        )
        snapshot.match("get-stage", get_stage)

        update_stage = aws_client.apigateway.update_stage(
            restApiId=api_id,
            stageName=stage_name,
            patchOperations=[
                {
                    "op": "replace",
                    "path": "/canarySettings/stageVariableOverrides/testVar",
                    "value": "updated",
                },
            ],
        )
        snapshot.match("update-stage-canary-settings-overrides", update_stage)

        # remove canary settings
        update_stage = aws_client.apigateway.update_stage(
            restApiId=api_id,
            stageName=stage_name,
            patchOperations=[
                {"op": "remove", "path": "/canarySettings"},
            ],
        )
        snapshot.match("update-stage-remove-canary-settings", update_stage)

        get_stage = aws_client.apigateway.get_stage(
            restApiId=api_id,
            stageName=stage_name,
        )
        snapshot.match("get-stage-after-remove", get_stage)

    @markers.aws.validated
    def test_create_canary_deployment_with_stage(
        self, create_api_for_deployment, aws_client, create_rest_apigw, snapshot
    ):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("deploymentId"),
                snapshot.transform.key_value("id"),
            ]
        )
        api_id, resource_id = create_api_for_deployment()

        create_deployment = aws_client.apigateway.create_deployment(restApiId=api_id)
        snapshot.match("create-deployment", create_deployment)
        deployment_id = create_deployment["id"]

        stage_name = "dev"
        create_stage = aws_client.apigateway.create_stage(
            restApiId=api_id,
            stageName=stage_name,
            deploymentId=deployment_id,
            description="dev stage",
            variables={
                "testVar": "default",
            },
        )
        snapshot.match("create-stage", create_stage)

        create_canary_deployment = aws_client.apigateway.create_deployment(
            restApiId=api_id,
            stageName=stage_name,
            canarySettings={
                "percentTraffic": 50,
                "stageVariableOverrides": {
                    "testVar": "canary",
                },
            },
        )
        snapshot.match("create-canary-deployment", create_canary_deployment)

        get_stage = aws_client.apigateway.get_stage(
            restApiId=api_id,
            stageName=stage_name,
        )
        snapshot.match("get-stage", get_stage)

    @markers.aws.validated
    def test_create_canary_deployment(
        self, create_api_for_deployment, aws_client, create_rest_apigw, snapshot
    ):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("deploymentId"),
                snapshot.transform.key_value("id"),
            ]
        )
        api_id, resource_id = create_api_for_deployment()

        create_deployment = aws_client.apigateway.create_deployment(restApiId=api_id)
        snapshot.match("create-deployment", create_deployment)
        deployment_id = create_deployment["id"]

        stage_name_1 = "dev1"
        create_stage = aws_client.apigateway.create_stage(
            restApiId=api_id,
            stageName=stage_name_1,
            deploymentId=deployment_id,
            description="dev stage",
            variables={
                "testVar": "default",
            },
            canarySettings={
                "deploymentId": deployment_id,
                "percentTraffic": 40,
                "stageVariableOverrides": {
                    "testVar": "canary1",
                },
            },
        )
        snapshot.match("create-stage", create_stage)

        create_canary_deployment = aws_client.apigateway.create_deployment(
            restApiId=api_id,
            stageName=stage_name_1,
            canarySettings={
                "percentTraffic": 50,
                "stageVariableOverrides": {
                    "testVar": "canary2",
                },
            },
        )
        snapshot.match("create-canary-deployment", create_canary_deployment)
        canary_deployment_id = create_canary_deployment["id"]

        get_stage_1 = aws_client.apigateway.get_stage(
            restApiId=api_id,
            stageName=stage_name_1,
        )
        snapshot.match("get-stage-1", get_stage_1)

        stage_name_2 = "dev2"
        create_stage_2 = aws_client.apigateway.create_stage(
            restApiId=api_id,
            stageName=stage_name_2,
            deploymentId=deployment_id,
            description="dev stage",
            variables={
                "testVar": "default",
            },
            canarySettings={
                "deploymentId": canary_deployment_id,
                "percentTraffic": 60,
                "stageVariableOverrides": {
                    "testVar": "canary-overridden",
                },
            },
        )
        snapshot.match("create-stage-2", create_stage_2)

    @markers.aws.validated
    def test_create_canary_deployment_by_stage_update(
        self, create_api_for_deployment, aws_client, create_rest_apigw, snapshot
    ):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("deploymentId"),
                snapshot.transform.key_value("id"),
            ]
        )
        api_id, resource_id = create_api_for_deployment()

        create_deployment = aws_client.apigateway.create_deployment(restApiId=api_id)
        snapshot.match("create-deployment", create_deployment)
        deployment_id = create_deployment["id"]

        create_deployment_2 = aws_client.apigateway.create_deployment(restApiId=api_id)
        snapshot.match("create-deployment-2", create_deployment_2)
        deployment_id_2 = create_deployment_2["id"]

        stage_name = "dev"
        create_stage = aws_client.apigateway.create_stage(
            restApiId=api_id,
            stageName=stage_name,
            deploymentId=deployment_id,
            description="dev stage",
            variables={
                "testVar": "default",
            },
        )
        snapshot.match("create-stage", create_stage)

        update_stage = aws_client.apigateway.update_stage(
            restApiId=api_id,
            stageName=stage_name,
            patchOperations=[
                {
                    "op": "replace",
                    "path": "/canarySettings/deploymentId",
                    "value": deployment_id_2,
                },
            ],
        )
        snapshot.match("update-stage-with-deployment", update_stage)

        update_stage = aws_client.apigateway.update_stage(
            restApiId=api_id,
            stageName=stage_name,
            patchOperations=[
                {
                    "op": "remove",
                    "path": "/canarySettings",
                },
            ],
        )
        snapshot.match("remove-stage-canary", update_stage)

        update_stage = aws_client.apigateway.update_stage(
            restApiId=api_id,
            stageName=stage_name,
            patchOperations=[
                {"op": "replace", "path": "/canarySettings/percentTraffic", "value": "50"}
            ],
        )
        snapshot.match("update-stage-with-percent", update_stage)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_stage(
                restApiId=api_id,
                stageName=stage_name,
                patchOperations=[
                    {"op": "replace", "path": "/canarySettings/deploymentId", "value": "deploy"}
                ],
            )

        snapshot.match("wrong-deployment-id", e.value.response)

    @markers.aws.validated
    def test_create_canary_deployment_validation(
        self, create_api_for_deployment, aws_client, create_rest_apigw, snapshot
    ):
        api_id, resource_id = create_api_for_deployment()

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_deployment(
                restApiId=api_id,
                canarySettings={
                    "percentTraffic": 50,
                    "stageVariableOverrides": {
                        "testVar": "canary",
                    },
                },
            )
        snapshot.match("create-canary-deployment-no-stage", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_deployment(
                restApiId=api_id,
                stageName="",
                canarySettings={
                    "percentTraffic": 50,
                    "stageVariableOverrides": {
                        "testVar": "canary",
                    },
                },
            )
        snapshot.match("create-canary-deployment-empty-stage", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.create_deployment(
                restApiId=api_id,
                stageName="non-existing",
                canarySettings={
                    "percentTraffic": 50,
                    "stageVariableOverrides": {
                        "testVar": "canary",
                    },
                },
            )
        snapshot.match("create-canary-deployment-non-existing-stage", e.value.response)

    @markers.aws.validated
    def test_update_stage_canary_deployment_validation(
        self, create_api_for_deployment, aws_client, create_rest_apigw, snapshot
    ):
        api_id, resource_id = create_api_for_deployment()

        stage_name = "dev"
        aws_client.apigateway.create_deployment(restApiId=api_id, stageName=stage_name)

        aws_client.apigateway.create_deployment(
            restApiId=api_id,
            stageName=stage_name,
            canarySettings={
                "percentTraffic": 50,
                "stageVariableOverrides": {
                    "testVar": "canary",
                },
            },
        )

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_stage(
                restApiId=api_id,
                stageName=stage_name,
                patchOperations=[
                    {"op": "remove", "path": "/canarySettings/stageVariableOverrides"},
                ],
            )
        snapshot.match("update-stage-canary-settings-remove-overrides", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_stage(
                restApiId=api_id,
                stageName=stage_name,
                patchOperations=[
                    {"op": "remove", "path": "/canarySettings/badPath"},
                ],
            )
        snapshot.match("update-stage-canary-settings-bad-path", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_stage(
                restApiId=api_id,
                stageName=stage_name,
                patchOperations=[
                    {"op": "replace", "path": "/canarySettings/badPath", "value": "badPath"},
                ],
            )
        snapshot.match("update-stage-canary-settings-replace-bad-path", e.value.response)

        # create deployment and stage with no canary settings
        stage_no_canary = "dev2"
        deployment_2 = aws_client.apigateway.create_deployment(
            restApiId=api_id, stageName=stage_no_canary
        )
        deployment_2_id = deployment_2["id"]
        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_stage(
                restApiId=api_id,
                stageName=stage_no_canary,
                patchOperations=[
                    # you need to use replace for every canarySettings, `add` is not supported
                    {"op": "add", "path": "/canarySettings/deploymentId", "value": deployment_2_id},
                ],
            )
        snapshot.match("update-stage-add-deployment", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_stage(
                restApiId=api_id,
                stageName=stage_no_canary,
                patchOperations=[
                    {"op": "replace", "path": "/canarySettings/deploymentId", "value": "deploy"},
                ],
            )
        snapshot.match("update-stage-no-deployment", e.value.response)

    @markers.aws.validated
    def test_update_stage_with_copy_ops(
        self, create_api_for_deployment, aws_client, create_rest_apigw, snapshot
    ):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("deploymentId"),
                snapshot.transform.key_value("id"),
            ]
        )
        api_id, resource_id = create_api_for_deployment()

        stage_name = "dev"
        aws_client.apigateway.create_deployment(
            restApiId=api_id,
            stageName=stage_name,
            variables={
                "testVar": "test",
                "testVar2": "test2",
            },
        )

        with pytest.raises(ClientError) as e:
            aws_client.apigateway.update_stage(
                restApiId=api_id,
                stageName=stage_name,
                patchOperations=[
                    {
                        "op": "copy",
                        "from": "/canarySettings/stageVariableOverrides",
                        "path": "/variables",
                    },
                    {"op": "copy", "from": "/canarySettings/deploymentId", "path": "/deploymentId"},
                ],
            )
        snapshot.match("copy-with-no-replace", e.value.response)

        update_stage = aws_client.apigateway.update_stage(
            restApiId=api_id,
            stageName=stage_name,
            patchOperations=[
                {"op": "replace", "value": "0.0", "path": "/canarySettings/percentTraffic"},
                # copy is said to be unsupported, but it is partially. It actually doesn't copy, just apply the first
                # call above, create the canary with default params and ignore what's under
                # https://docs.aws.amazon.com/apigateway/latest/api/patch-operations.html#UpdateStage-Patch
                {"op": "copy", "from": "/canarySettings/deploymentId", "path": "/deploymentId"},
                {
                    "op": "copy",
                    "from": "/canarySettings/stageVariableOverrides",
                    "path": "/variables",
                },
            ],
        )
        snapshot.match("update-stage-with-copy", update_stage)


class TestCanaryDeployments:
    @markers.aws.validated
    def test_invoking_canary_deployment(self, aws_client, create_api_for_deployment, snapshot):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("deploymentId"),
                snapshot.transform.key_value("id"),
            ]
        )
        api_id, resource_id = create_api_for_deployment(
            response_template={
                "statusCode": 200,
                "message": "default deployment",
                "variable": "$stageVariables.testVar",
                "nonExistingDefault": "$stageVariables.noStageVar",
                "nonOverridden": "$stageVariables.defaultVar",
                "isCanary": "$context.isCanaryRequest",
            }
        )

        stage_name = "dev"
        create_deployment_1 = aws_client.apigateway.create_deployment(
            restApiId=api_id,
            stageName=stage_name,
            variables={
                "testVar": "default",
                "defaultVar": "default",
            },
        )
        snapshot.match("create-deployment-1", create_deployment_1)

        aws_client.apigateway.update_integration_response(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod="GET",
            statusCode="200",
            patchOperations=[
                {
                    "op": "replace",
                    "path": "/responseTemplates/application~1json",
                    "value": json.dumps(
                        {
                            "statusCode": 200,
                            "message": "canary deployment",
                            "variable": "$stageVariables.testVar",
                            "nonExistingDefault": "$stageVariables.noStageVar",
                            "nonOverridden": "$stageVariables.defaultVar",
                            "isCanary": "$context.isCanaryRequest",
                        }
                    ),
                }
            ],
        )

        create_deployment_2 = aws_client.apigateway.create_deployment(
            restApiId=api_id,
            stageName=stage_name,
            canarySettings={
                "percentTraffic": 0,
                "stageVariableOverrides": {
                    "testVar": "canary",
                    "noStageVar": "canary",
                },
            },
        )
        snapshot.match("create-deployment-2", create_deployment_2)

        invocation_url = api_invoke_url(api_id=api_id, stage=stage_name, path="/")

        def invoke_api(url: str, expected: str) -> dict:
            _response = requests.get(url, verify=False)
            assert _response.ok
            response_content = _response.json()
            assert expected in response_content["message"]
            return response_content

        response_data = retry(
            invoke_api, sleep=2, retries=10, url=invocation_url, expected="default"
        )
        snapshot.match("response-deployment-1", response_data)

        # update stage to always redirect to canary
        update_stage = aws_client.apigateway.update_stage(
            restApiId=api_id,
            stageName=stage_name,
            patchOperations=[
                {"op": "replace", "path": "/canarySettings/percentTraffic", "value": "100.0"},
            ],
        )
        snapshot.match("update-stage", update_stage)

        response_data = retry(
            invoke_api, sleep=2, retries=10, url=invocation_url, expected="canary"
        )
        snapshot.match("response-canary-deployment", response_data)

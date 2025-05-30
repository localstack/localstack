# TODO: also see .test_apigateway_common.TestStages
import json

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers

# TODO: think of a way to assert we are in a canary deployment? returning different MOCK response + stage variable over


@pytest.fixture
def create_api_for_deployment(aws_client, create_rest_apigw):
    def _create():
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

        aws_client.apigateway.put_integration_response(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            statusCode="200",
            selectionPattern="",
            responseTemplates={
                "application/json": json.dumps({"statusCode": 200, "message": "default deployment"})
            },
        )

        return api_id, root_id

    return _create


# TODO:
# You create a canary release deployment when deploying the API with canary settings as an additional input to the deployment creation operation.
#
# You can also create a canary release deployment from an existing non-canary deployment by making a stage:update request to add the canary settings on the stage.
#
# When creating a non-canary release deployment, you can specify a non-existing stage name. API Gateway creates one if the specified stage does not exist. However, you cannot specify any non-existing stage name when creating a canary release deployment. You will get an error and API Gateway will not create any canary release deployment.


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

        # TODO: this fails because no more overrides, add in validation test
        # update_stage = aws_client.apigateway.update_stage(
        #     restApiId=api_id,
        #     stageName=stage_name,
        #     patchOperations=[
        #         {"op": "remove", "path": "/canarySettings/stageVariableOverrides"},
        #     ],
        # )
        # snapshot.match("update-stage-canary-settings-remove-overrides", update_stage)

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
                    "op": "add",
                    "path": "/canarySettings/deploymentId",
                    "value": deployment_id,
                },
            ],
        )
        snapshot.match("update-stage", update_stage)

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
                stageName="non-existing",
                canarySettings={
                    "percentTraffic": 50,
                    "stageVariableOverrides": {
                        "testVar": "canary",
                    },
                },
            )
        snapshot.match("create-canary-deployment-non-existing-stage", e.value.response)

        # create_canary_deployment = aws_client.apigateway.create_deployment(restApiId=api_id)
        # snapshot.match("create-canary-deployment", create_deployment_1)
        # canary_deployment_id = create_deployment_1["id"]

        # with pytest.raises(ClientError) as e:
        #     aws_client.apigateway.update_stage(
        #         restApiId=api_id,
        #         stageName="s1",
        #         patchOperations=[
        #             {"op": "replace", "path": "/documentation_version", "value": "123"}
        #         ],
        #     )
        # snapshot.match("error-update-doc-version", e.value.response)
        #
        # with pytest.raises(ClientError) as ctx:
        #     client.update_stage(
        #         restApiId=api_id,
        #         stageName="s1",
        #         patchOperations=[
        #             {"op": "replace", "path": "/tags/tag1", "value": "value1"},
        #         ],
        #     )
        # snapshot.match("error-update-tags", ctx.value.response)
        #
        # # update & get stage
        # response = client.update_stage(
        #     restApiId=api_id,
        #     stageName="s1",
        #     patchOperations=[
        #         {"op": "replace", "path": "/description", "value": "stage new"},
        #         {"op": "replace", "path": "/variables/var1", "value": "test"},
        #         {"op": "replace", "path": "/variables/var2", "value": "test2"},
        #         {"op": "replace", "path": "/*/*/throttling/burstLimit", "value": "123"},
        #         {"op": "replace", "path": "/*/*/caching/enabled", "value": "true"},
        #         {"op": "replace", "path": "/tracingEnabled", "value": "true"},
        #         {"op": "replace", "path": "/test/GET/throttling/burstLimit", "value": "124"},
        #     ],
        # )
        # snapshot.match("update-stage", response)
        #
        # response = client.get_stage(restApiId=api_id, stageName="s1")
        # snapshot.match("get-stage", response)
        #
        # # show that updating */* does not override previously set values, only
        # # provides default values then like shown above
        # response = client.update_stage(
        #     restApiId=api_id,
        #     stageName="s1",
        #     patchOperations=[
        #         {"op": "replace", "path": "/*/*/throttling/burstLimit", "value": "100"},
        #     ],
        # )
        # snapshot.match("update-stage-override", response)

# TODO: also see .test_apigateway_common.TestStages
import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers

# @pytest.fixture
# def _create_api_with_stage(
#     self, aws_client, create_rest_apigw, apigw_add_transformers, snapshot
# ):
#     client = aws_client.apigateway
#     use that
#
#     def _create():
#         # create API, method, integration, deployment
#         api_id, api_name, root_id = create_rest_apigw()
#         client.put_method(
#             restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE"
#         )
#         client.put_integration(
#             restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK"
#         )
#         response = client.create_deployment(restApiId=api_id)
#         deployment_id = response["id"]
# TODO: think of a way to assert we are in a canary deployment? returning different MOCK response + stage variable over
#
#         # create stage
#         response = client.create_stage(
#             restApiId=api_id,
#             stageName="s1",
#             deploymentId=deployment_id,
#             description="my stage",
#         )
#         snapshot.match("create-stage", response)
#
#         return api_id
#
#     return _create


class TestStageCrudCanary:
    @markers.aws.validated
    def test_create_update_stages(
        self, _create_api_with_stage, aws_client, create_rest_apigw, snapshot
    ):
        client = aws_client.apigateway
        api_id = _create_api_with_stage()

        # negative tests for immutable/non-updateable attributes

        with pytest.raises(ClientError) as ctx:
            client.update_stage(
                restApiId=api_id,
                stageName="s1",
                patchOperations=[
                    {"op": "replace", "path": "/documentation_version", "value": "123"}
                ],
            )
        snapshot.match("error-update-doc-version", ctx.value.response)

        with pytest.raises(ClientError) as ctx:
            client.update_stage(
                restApiId=api_id,
                stageName="s1",
                patchOperations=[
                    {"op": "replace", "path": "/tags/tag1", "value": "value1"},
                ],
            )
        snapshot.match("error-update-tags", ctx.value.response)

        # update & get stage
        response = client.update_stage(
            restApiId=api_id,
            stageName="s1",
            patchOperations=[
                {"op": "replace", "path": "/description", "value": "stage new"},
                {"op": "replace", "path": "/variables/var1", "value": "test"},
                {"op": "replace", "path": "/variables/var2", "value": "test2"},
                {"op": "replace", "path": "/*/*/throttling/burstLimit", "value": "123"},
                {"op": "replace", "path": "/*/*/caching/enabled", "value": "true"},
                {"op": "replace", "path": "/tracingEnabled", "value": "true"},
                {"op": "replace", "path": "/test/GET/throttling/burstLimit", "value": "124"},
            ],
        )
        snapshot.match("update-stage", response)

        response = client.get_stage(restApiId=api_id, stageName="s1")
        snapshot.match("get-stage", response)

        # show that updating */* does not override previously set values, only
        # provides default values then like shown above
        response = client.update_stage(
            restApiId=api_id,
            stageName="s1",
            patchOperations=[
                {"op": "replace", "path": "/*/*/throttling/burstLimit", "value": "100"},
            ],
        )
        snapshot.match("update-stage-override", response)

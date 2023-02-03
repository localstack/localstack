import json

import pytest

from localstack.utils.http import safe_requests as requests
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.integration.apigateway_fixtures import (
    api_invoke_url,
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
    APIGATEWAY_KINESIS_POLICY,
)


# PutRecord does not return EncryptionType, but it's documented as such.
# xxx requires further investigation
@pytest.mark.skip_snapshot_verify(paths=["$..EncryptionType", "$..ChildShards"])
def test_apigateway_to_kinesis(
    create_rest_apigw,
    apigateway_client,
    sts_client,
    kinesis_create_stream,
    kinesis_client,
    create_lambda_function,
    lambda_client,
    lambda_su_role,
    cleanups,
    wait_for_stream_ready,
    create_iam_role_with_policy,
    snapshot,
):
    snapshot.add_transformer(snapshot.transform.apigateway_api())
    snapshot.add_transformer(snapshot.transform.kinesis_api())

    stream_name = f"kinesis-stream-{short_uid()}"
    region_name = apigateway_client.meta.region_name

    api_id, name, root_id = create_rest_apigw(
        name="test-apigateway-to-kinesis",
        description="test apigateway to kinesis",
        endpointConfiguration={"types": ["REGIONAL"]},
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

    assume_role_arn = create_iam_role_with_policy(
        RoleName=f"role-apigw-{short_uid()}",
        PolicyName=f"policy-apigw-{short_uid()}",
        RoleDefinition=APIGATEWAY_ASSUME_ROLE_POLICY,
        PolicyDefinition=APIGATEWAY_KINESIS_POLICY,
    )

    create_rest_api_integration(
        apigateway_client,
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod=method,
        integrationHttpMethod="POST",
        type="AWS",
        credentials=assume_role_arn,
        uri=f"arn:aws:apigateway:{region_name}:kinesis:action/PutRecord",
        requestTemplates={
            "application/json": json.dumps(
                {
                    "StreamName": stream_name,
                    "Data": "$util.base64Encode($input.body)",
                    "PartitionKey": "test",
                }
            )
        },
    )

    create_rest_api_method_response(
        apigateway_client,
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        statusCode="200",
    )

    create_rest_api_integration_response(
        apigateway_client,
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="POST",
        statusCode="200",
    )

    deployment_id, _ = create_rest_api_deployment(apigateway_client, restApiId=api_id)
    stage = create_rest_api_stage(
        apigateway_client, restApiId=api_id, stageName="dev", deploymentId=deployment_id
    )

    kinesis_create_stream(StreamName=stream_name, ShardCount=1)
    wait_for_stream_ready(stream_name=stream_name)
    stream_summary = kinesis_client.describe_stream_summary(StreamName=stream_name)
    assert stream_summary["StreamDescriptionSummary"]["OpenShardCount"] == 1
    first_stream_shard_data = kinesis_client.describe_stream(StreamName=stream_name)[
        "StreamDescription"
    ]["Shards"][0]
    shard_id = first_stream_shard_data["ShardId"]

    shard_iterator = kinesis_client.get_shard_iterator(
        StreamName=stream_name, ShardIteratorType="LATEST", ShardId=shard_id
    )["ShardIterator"]

    # asserts
    def _invoke_apigw_to_kinesis():
        url = api_invoke_url(api_id, stage=stage, path="/test")
        response = requests.post(url, json={"kinesis": "snapshot"})
        assert response.status_code == 200
        snapshot.match("apigateway_response", response.json())

    retry(_invoke_apigw_to_kinesis, retries=15, sleep=1)

    get_records_response = kinesis_client.get_records(ShardIterator=shard_iterator)
    snapshot.match("kinesis_records", get_records_response)

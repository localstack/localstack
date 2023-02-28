import json

import pytest

from localstack.utils.http import safe_requests as requests
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.integration.apigateway.conftest import DEFAULT_STAGE_NAME
from tests.integration.apigateway_fixtures import api_invoke_url


# PutRecord does not return EncryptionType, but it's documented as such.
# xxx requires further investigation
@pytest.mark.skip_snapshot_verify(paths=["$..EncryptionType", "$..ChildShards"])
def test_apigateway_to_kinesis(
    apigateway_client,
    kinesis_create_stream,
    wait_for_stream_ready,
    create_rest_api_with_integration,
    kinesis_client,
    snapshot,
):
    snapshot.add_transformer(snapshot.transform.apigateway_api())
    snapshot.add_transformer(snapshot.transform.kinesis_api())

    # create stream
    stream_name = f"kinesis-stream-{short_uid()}"
    kinesis_create_stream(StreamName=stream_name, ShardCount=1)
    wait_for_stream_ready(stream_name=stream_name)
    stream_summary = kinesis_client.describe_stream_summary(StreamName=stream_name)
    assert stream_summary["StreamDescriptionSummary"]["OpenShardCount"] == 1
    first_stream_shard_data = kinesis_client.describe_stream(StreamName=stream_name)[
        "StreamDescription"
    ]["Shards"][0]
    shard_id = first_stream_shard_data["ShardId"]

    # create REST API with Kinesis integration
    region_name = apigateway_client.meta.region_name
    integration_uri = f"arn:aws:apigateway:{region_name}:kinesis:action/PutRecord"
    request_templates = {
        "application/json": json.dumps(
            {
                "StreamName": stream_name,
                "Data": "$util.base64Encode($input.body)",
                "PartitionKey": "test",
            }
        )
    }
    api_id = create_rest_api_with_integration(
        integration_uri=integration_uri,
        req_templates=request_templates,
        integration_type="AWS",
    )

    def _invoke_apigw_to_kinesis():
        url = api_invoke_url(api_id, stage=DEFAULT_STAGE_NAME, path="/test")
        response = requests.post(url, json={"kinesis": "snapshot"})
        assert response.status_code == 200
        snapshot.match("apigateway_response", response.json())

    # push events to Kinesis via API
    shard_iterator = kinesis_client.get_shard_iterator(
        StreamName=stream_name, ShardIteratorType="LATEST", ShardId=shard_id
    )["ShardIterator"]
    retry(_invoke_apigw_to_kinesis, retries=15, sleep=1)

    # get records from stream
    get_records_response = kinesis_client.get_records(ShardIterator=shard_iterator)
    snapshot.match("kinesis_records", get_records_response)

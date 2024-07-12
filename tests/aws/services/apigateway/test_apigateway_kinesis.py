import json

from localstack.testing.pytest import markers
from localstack.utils.http import safe_requests as requests
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.aws.services.apigateway.apigateway_fixtures import api_invoke_url
from tests.aws.services.apigateway.conftest import DEFAULT_STAGE_NAME


# PutRecord does not return EncryptionType, but it's documented as such.
# xxx requires further investigation
@markers.snapshot.skip_snapshot_verify(paths=["$..EncryptionType", "$..ChildShards"])
@markers.aws.validated
def test_apigateway_to_kinesis(
    kinesis_create_stream,
    wait_for_stream_ready,
    create_rest_api_with_integration,
    snapshot,
    region_name,
    aws_client,
):
    snapshot.add_transformer(snapshot.transform.apigateway_api())
    snapshot.add_transformer(snapshot.transform.kinesis_api())

    # create stream
    stream_name = f"kinesis-stream-{short_uid()}"
    kinesis_create_stream(StreamName=stream_name, ShardCount=1)
    wait_for_stream_ready(stream_name=stream_name)
    stream_summary = aws_client.kinesis.describe_stream_summary(StreamName=stream_name)
    assert stream_summary["StreamDescriptionSummary"]["OpenShardCount"] == 1
    first_stream_shard_data = aws_client.kinesis.describe_stream(StreamName=stream_name)[
        "StreamDescription"
    ]["Shards"][0]
    shard_id = first_stream_shard_data["ShardId"]

    # create REST API with Kinesis integration
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
    shard_iterator = aws_client.kinesis.get_shard_iterator(
        StreamName=stream_name, ShardIteratorType="LATEST", ShardId=shard_id
    )["ShardIterator"]
    retry(_invoke_apigw_to_kinesis, retries=15, sleep=1)

    # get records from stream
    get_records_response = aws_client.kinesis.get_records(ShardIterator=shard_iterator)
    snapshot.match("kinesis_records", get_records_response)

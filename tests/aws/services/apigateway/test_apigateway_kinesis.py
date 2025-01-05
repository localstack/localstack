import pytest

from localstack.testing.pytest import markers
from localstack.utils.http import safe_requests as requests
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.aws.services.apigateway.apigateway_fixtures import api_invoke_url
from tests.aws.services.apigateway.conftest import DEFAULT_STAGE_NAME

KINESIS_PUT_RECORDS_INTEGRATION = """{
    "StreamName": "%s",
    "Records": [
        #set( $numRecords = $input.path('$.records').size() )
        #if($numRecords > 0)
            #set( $maxIndex = $numRecords - 1 )
            #foreach( $idx in [0..$maxIndex] )
                #set( $elem = $input.path("$.records[${idx}]") )
                #set( $elemJsonB64 = $util.base64Encode($elem.data) )
                {
                    "Data": "$elemJsonB64",
                    "PartitionKey": #if( $foo.bar.stuff != '')"$elem.partitionKey"#else"$elemJsonB64.length()"#end
                }#if($foreach.hasNext),#end
            #end
        #end
    ]
}"""

KINESIS_PUT_RECORD_INTEGRATION = """
{
    "StreamName": "%s",
    "Data": "$util.base64Encode($input.body)",
    "PartitionKey": "test"
}"""


# PutRecord does not return EncryptionType, but it's documented as such.
# xxx requires further investigation
@pytest.mark.parametrize("action", ("PutRecord", "PutRecords"))
@markers.snapshot.skip_snapshot_verify(paths=["$..EncryptionType", "$..ChildShards"])
@markers.aws.validated
def test_apigateway_to_kinesis(
    kinesis_create_stream,
    wait_for_stream_ready,
    create_rest_api_with_integration,
    snapshot,
    region_name,
    aws_client,
    action,
):
    snapshot.add_transformer(snapshot.transform.apigateway_api())
    snapshot.add_transformer(snapshot.transform.kinesis_api())

    if action == "PutRecord":
        template = KINESIS_PUT_RECORD_INTEGRATION
        payload = {"kinesis": "snapshot"}
        expected_key = "SequenceNumber"
    else:
        template = KINESIS_PUT_RECORDS_INTEGRATION
        payload = {
            "records": [
                {"data": '{"foo": "bar1"}'},
                {"data": '{"foo": "bar2"}'},
                {"data": '{"foo": "bar3"}'},
            ]
        }
        expected_key = "Records"

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
    integration_uri = f"arn:aws:apigateway:{region_name}:kinesis:action/{action}"
    request_templates = {"application/json": template % stream_name}
    api_id = create_rest_api_with_integration(
        integration_uri=integration_uri,
        req_templates=request_templates,
        integration_type="AWS",
    )

    def _invoke_apigw_to_kinesis() -> dict:
        url = api_invoke_url(api_id, stage=DEFAULT_STAGE_NAME, path="/test")
        _response = requests.post(url, json=payload)
        assert _response.ok
        json_resp = _response.json()
        assert expected_key in json_resp
        return json_resp

    # push events to Kinesis via API
    shard_iterator = aws_client.kinesis.get_shard_iterator(
        StreamName=stream_name, ShardIteratorType="LATEST", ShardId=shard_id
    )["ShardIterator"]
    response = retry(_invoke_apigw_to_kinesis, retries=15, sleep=1)
    snapshot.match("apigateway_response", response)

    # get records from stream
    get_records_response = aws_client.kinesis.get_records(ShardIterator=shard_iterator)
    snapshot.match("kinesis_records", get_records_response)

import json

import pytest


@pytest.mark.aws_validated
@pytest.mark.skip_snapshot_verify(paths=["$..StreamDescription.StreamModeDetails"])
def test_stream_creation(kinesis_client, deploy_cfn_template, snapshot):
    snapshot.add_transformer(snapshot.transform.resource_name())
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("StreamName", "stream-name"),
            snapshot.transform.key_value("ShardId", "shard-id", reference_replacement=False),
            snapshot.transform.key_value("EndingHashKey", "ending-hash-key"),
            snapshot.transform.key_value("StartingSequenceNumber", "sequence-number"),
        ]
    )

    template = json.dumps(
        {
            "Resources": {
                "TestStream": {
                    "Type": "AWS::Kinesis::Stream",
                    "Properties": {"ShardCount": 1},
                },
            },
            "Outputs": {
                "StreamNameFromRef": {"Value": {"Ref": "TestStream"}},
                "StreamArnFromAtt": {"Value": {"Fn::GetAtt": "TestStream.Arn"}},
            },
        }
    )

    outputs = deploy_cfn_template(template=template).outputs
    snapshot.match("stack_output", outputs)

    stream_name = outputs.get("StreamNameFromRef")
    description = kinesis_client.describe_stream(StreamName=stream_name)
    snapshot.match("stream_description", description)

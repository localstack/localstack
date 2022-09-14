import json

import pytest


@pytest.mark.aws_validated
@pytest.mark.skip_snapshot_verify(paths=["$..StreamDescription.StreamModeDetails"])
def test_stream_creation(kinesis_client, cfn_client, deploy_cfn_template, snapshot):
    snapshot.add_transformer(snapshot.transform.resource_name())
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("StreamName", "stream-name"),
            snapshot.transform.key_value("ShardId", "shard-id", reference_replacement=False),
            snapshot.transform.key_value("EndingHashKey", "ending-hash-key"),
            snapshot.transform.key_value("StartingSequenceNumber", "sequence-number"),
        ]
    )
    snapshot.add_transformer(snapshot.transform.cloudformation_api())

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

    stack = deploy_cfn_template(template=template)
    snapshot.match("stack_output", stack.outputs)

    description = cfn_client.describe_stack_resources(StackName=stack.stack_name)
    snapshot.match("resource_description", description)

    stream_name = stack.outputs.get("StreamNameFromRef")
    description = kinesis_client.describe_stream(StreamName=stream_name)
    snapshot.match("stream_description", description)

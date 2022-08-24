import json
import time

import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.strings import short_uid


@pytest.mark.aws_validated
# TODO fix service so it returns the stream mode
@pytest.mark.skip_snapshot_verify(paths=["$..StreamDescription.StreamModeDetails"])
def test_stream_creation(kinesis_client, deploy_cfn_template, snapshot):
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("StreamName", "stream-name"),
            snapshot.transform.key_value("ShardId", "shard-id", reference_replacement=False),
            snapshot.transform.key_value("EndingHashKey", "ending-hash-key"),
            snapshot.transform.key_value("StartingSequenceNumber", "sequence-number"),
        ]
    )
    stream_name = f"stream-{short_uid()}"

    template = json.dumps(
        {
            "Resources": {
                "TestStream": {
                    "Type": "AWS::Kinesis::Stream",
                    "Properties": {"Name": stream_name, "ShardCount": 1},
                },
            },
            "Outputs": {"StreamArn": {"Value": {"Fn::GetAtt": "TestStream.Arn"}}},
        }
    )

    outputs = deploy_cfn_template(template=template).outputs
    snapshot.match("stack_output", outputs)

    # in AWS the Stack is completed when the stream status is Active
    if not is_aws_cloud():
        time.sleep(1)

    description = kinesis_client.describe_stream(StreamName=stream_name)
    snapshot.match("stream_description", description)

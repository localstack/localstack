import json

import pytest


@pytest.mark.aws_validated
def test_stream_creation(kinesis_client, deploy_cfn_template, snapshot):
    snapshot.add_transformer(snapshot.transform.resource_name())

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

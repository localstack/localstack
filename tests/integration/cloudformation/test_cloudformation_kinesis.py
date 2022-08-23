import json

from localstack.utils.strings import short_uid


# @pytest.mark.aws_validated
def test_stream_creation(kinesis_client, deploy_cfn_template, snapshot):
    # snapshot.add_transformer(snapshot.transform.)
    stream_name = f"stream-{short_uid()}"

    template = json.dumps(
        {
            "Resources": {
                "KinesisStream": {
                    "Type": "AWS::Kinesis::Stream",
                    "Properties": {"Name": stream_name},
                }
            }
        }
    )

    deploy_cfn_template(template=template)
    description = kinesis_client.describe_stream(StreamName=stream_name)
    snapshot.match("stream_description", description)

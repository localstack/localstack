import os.path

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(paths=["$..Destinations"])
def test_firehose_stack_with_kinesis_as_source(deploy_cfn_template, snapshot, aws_client):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())

    bucket_name = f"bucket-{short_uid()}"
    stream_name = f"stream-{short_uid()}"
    delivery_stream_name = f"delivery-stream-{short_uid()}"

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/firehose_kinesis_as_source.yaml"
        ),
        parameters={
            "BucketName": bucket_name,
            "StreamName": stream_name,
            "DeliveryStreamName": delivery_stream_name,
        },
        max_wait=150,
    )
    snapshot.match("outputs", stack.outputs)

    def _assert_stream_available():
        status = aws_client.firehose.describe_delivery_stream(
            DeliveryStreamName=delivery_stream_name
        )
        assert status["DeliveryStreamDescription"]["DeliveryStreamStatus"] == "ACTIVE"

    retry(_assert_stream_available, sleep=2, retries=15)

    response = aws_client.firehose.describe_delivery_stream(DeliveryStreamName=delivery_stream_name)
    assert delivery_stream_name == response["DeliveryStreamDescription"]["DeliveryStreamName"]
    snapshot.match("delivery_stream", response)

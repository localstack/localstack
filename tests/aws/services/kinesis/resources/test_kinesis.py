import json
import os

import pytest

from localstack import config
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(paths=["$..StreamDescription.StreamModeDetails"])
def test_stream_creation(deploy_cfn_template, snapshot, aws_client):
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

    description = aws_client.cloudformation.describe_stack_resources(StackName=stack.stack_name)
    snapshot.match("resource_description", description)

    stream_name = stack.outputs.get("StreamNameFromRef")
    description = aws_client.kinesis.describe_stream(StreamName=stream_name)
    snapshot.match("stream_description", description)


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(paths=["$..StreamDescription.StreamModeDetails"])
def test_default_parameters_kinesis(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/kinesis_default.yaml"
        )
    )

    stream_name = stack.outputs["KinesisStreamName"]
    rs = aws_client.kinesis.describe_stream(StreamName=stream_name)
    snapshot.match("describe_stream", rs)

    snapshot.add_transformer(snapshot.transform.key_value("StreamName"))
    snapshot.add_transformer(snapshot.transform.key_value("ShardId"))
    snapshot.add_transformer(snapshot.transform.key_value("StartingSequenceNumber"))


@markers.aws.validated
def test_cfn_handle_kinesis_firehose_resources(deploy_cfn_template, aws_client):
    kinesis_stream_name = f"kinesis-stream-{short_uid()}"
    firehose_role_name = f"firehose-role-{short_uid()}"
    firehose_stream_name = f"firehose-stream-{short_uid()}"

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/cfn_kinesis_stream.yaml"
        ),
        parameters={
            "KinesisStreamName": kinesis_stream_name,
            "DeliveryStreamName": firehose_stream_name,
            "KinesisRoleName": firehose_role_name,
        },
    )

    assert len(stack.outputs) == 1

    rs = aws_client.firehose.describe_delivery_stream(DeliveryStreamName=firehose_stream_name)
    assert rs["DeliveryStreamDescription"]["DeliveryStreamARN"] == stack.outputs["MyStreamArn"]
    assert rs["DeliveryStreamDescription"]["DeliveryStreamName"] == firehose_stream_name

    rs = aws_client.kinesis.describe_stream(StreamName=kinesis_stream_name)
    assert rs["StreamDescription"]["StreamName"] == kinesis_stream_name

    # clean up
    stack.destroy()

    rs = aws_client.kinesis.list_streams()
    assert kinesis_stream_name not in rs["StreamNames"]
    rs = aws_client.firehose.list_delivery_streams()
    assert firehose_stream_name not in rs["DeliveryStreamNames"]


# TODO: use a different template and move this test to a more generic API level test suite
@markers.aws.validated
@markers.snapshot.skip_snapshot_verify  # nothing really works here right now
def test_describe_template(s3_create_bucket, aws_client, cleanups, snapshot):
    bucket_name = f"b-{short_uid()}"
    template_body = load_file(
        os.path.join(os.path.dirname(__file__), "../../../templates/cfn_kinesis_stream.yaml")
    )
    s3_create_bucket(Bucket=bucket_name)
    aws_client.s3.put_object(Bucket=bucket_name, Key="template.yml", Body=template_body)

    if is_aws_cloud():
        template_url = (
            f"https://{bucket_name}.s3.{aws_client.s3.meta.region_name}.amazonaws.com/template.yml"
        )
    else:
        template_url = f"{config.internal_service_url()}/{bucket_name}/template.yml"

    # get summary by template URL
    get_template_summary_by_url = aws_client.cloudformation.get_template_summary(
        TemplateURL=template_url
    )
    snapshot.match("get_template_summary_by_url", get_template_summary_by_url)

    param_keys = {p["ParameterKey"] for p in get_template_summary_by_url["Parameters"]}
    assert param_keys == {"KinesisStreamName", "DeliveryStreamName", "KinesisRoleName"}

    # get summary by template body
    get_template_summary_by_body = aws_client.cloudformation.get_template_summary(
        TemplateBody=template_body
    )
    snapshot.match("get_template_summary_by_body", get_template_summary_by_body)
    param_keys = {p["ParameterKey"] for p in get_template_summary_by_url["Parameters"]}
    assert param_keys == {"KinesisStreamName", "DeliveryStreamName", "KinesisRoleName"}


@pytest.mark.skipif(
    condition=not is_aws_cloud() and config.DDB_STREAMS_PROVIDER_V2,
    reason="Not yet implemented in DDB Streams V2",
)
@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=["$..KinesisDataStreamDestinations..DestinationStatusDescription"]
)
def test_dynamodb_stream_response_with_cf(deploy_cfn_template, aws_client, snapshot):
    table_name = f"table-{short_uid()}"
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/cfn_kinesis_dynamodb.yml"
        ),
        parameters={"TableName": table_name},
    )

    response = aws_client.dynamodb.describe_kinesis_streaming_destination(TableName=table_name)
    snapshot.match("describe_kinesis_streaming_destination", response)
    snapshot.add_transformer(snapshot.transform.key_value("TableName"))


@markers.aws.validated
def test_kinesis_stream_consumer_creations(deploy_cfn_template, aws_client):
    consumer_name = f"{short_uid()}"
    stack = deploy_cfn_template(
        parameters={"TestConsumerName": consumer_name},
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/kinesis_stream_consumer.yaml"
        ),
    )
    consumer_arn = stack.outputs["KinesisSConsumerARN"]
    response = aws_client.kinesis.describe_stream_consumer(ConsumerARN=consumer_arn)
    assert response["ConsumerDescription"]["ConsumerStatus"] == "ACTIVE"

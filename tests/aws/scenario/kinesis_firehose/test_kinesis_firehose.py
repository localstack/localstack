import json

import aws_cdk as cdk
import aws_cdk.aws_iam as iam
import aws_cdk.aws_kinesis as kinesis
import aws_cdk.aws_kinesisfirehose as firehose
import aws_cdk.aws_logs as logs
import aws_cdk.aws_s3 as s3
import pytest

from localstack.testing.pytest import markers
from tests.aws.scenario.kinesis_firehose.conftest import get_all_expected_messages_from_s3

STACK_NAME = "FirehoseStack"
TEST_MESSAGE = "Test-message-2948294kdlsie"


class TestKinesisFirehoseScenario:
    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, infrastructure_setup):
        infra = infrastructure_setup("FirehoseScenario")
        stack = cdk.Stack(infra.cdk_app, STACK_NAME)
        # create kinesis stream
        kinesis_stream = kinesis.Stream(
            stack,
            "KinesisStream",
            stream_name="kinesis-stream",
            shard_count=1,
            stream_mode=kinesis.StreamMode("PROVISIONED"),
        )

        # s3 bucket
        bucket = s3.Bucket(
            stack,
            "S3Bucket",
            bucket_name="firehose-raw-data",
            removal_policy=cdk.RemovalPolicy.DESTROY,  # required since default value is RETAIN
            # auto_delete_objects=True,  # required to delete the not empty bucket
            # auto_delete requires lambda therefore not supported currently by LocalStack
        )

        # create firehose delivery stream
        role_firehose_kinesis = iam.Role(
            stack,
            "FirehoseKinesisRole",
            role_name="firehose-kinesis-role",
            assumed_by=iam.ServicePrincipal("firehose.amazonaws.com"),
        )
        policy_firehose_kinesis = iam.Policy(
            stack,
            "FirehoseKinesisPolicy",
            policy_name="firehose-kinesis-policy",
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "kinesis:DescribeStream",
                        "kinesis:GetShardIterator",
                        "kinesis:GetRecords",
                        "kinesis:ListShards",
                    ],
                    resources=[kinesis_stream.stream_arn],
                ),
            ],
        )
        role_firehose_kinesis.attach_inline_policy(policy_firehose_kinesis)

        kinesis_stream_source_configuration = (
            firehose.CfnDeliveryStream.KinesisStreamSourceConfigurationProperty(
                kinesis_stream_arn=kinesis_stream.stream_arn,
                role_arn=role_firehose_kinesis.role_arn,
            )
        )

        # cloud watch logging group and stream for firehose s3 error logging
        firehose_s3_log_group_name = "firehose-s3-log-group"
        firehose_s3_log_stream_name = "firehose-s3-log-stream"
        firehose_s3_log_group = logs.LogGroup(
            stack,
            "FirehoseLogGroup",
            log_group_name=firehose_s3_log_group_name,
            removal_policy=cdk.RemovalPolicy.DESTROY,  # required since default value is RETAIN
        )
        firehose_s3_log_group.add_stream(
            "FirehoseLogStream", log_stream_name=firehose_s3_log_stream_name
        )

        # s3 access role for firehose
        role_firehose_s3 = iam.Role(
            stack,
            "FirehoseS3Role",
            role_name="firehose-s3-role",
            assumed_by=iam.ServicePrincipal("firehose.amazonaws.com"),
        )
        policy_firehose_s3 = iam.Policy(
            stack,
            "FirehoseS3Policy",
            policy_name="firehose-s3-policy",
            statements=[
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "s3:AbortMultipartUpload",
                        "s3:GetBucketLocation",
                        "s3:GetObject",
                        "s3:ListBucket",
                        "s3:ListBucketMultipartUploads",
                        "s3:PutObject",
                    ],
                    resources=[bucket.bucket_arn, f"{bucket.bucket_arn}/*"],
                ),
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["logs:PutLogEvents", "logs:CreateLogStream"],
                    resources=[firehose_s3_log_group.log_group_arn],
                ),
            ],
        )
        role_firehose_s3.attach_inline_policy(policy_firehose_s3)

        extended_s3_destination_configuration = firehose.CfnDeliveryStream.ExtendedS3DestinationConfigurationProperty(
            bucket_arn=bucket.bucket_arn,
            role_arn=role_firehose_s3.role_arn,
            prefix="firehose-raw-data/",
            error_output_prefix="firehose-raw-data/errors/",
            compression_format="UNCOMPRESSED",
            s3_backup_mode="Disabled",
            buffering_hints=firehose.CfnDeliveryStream.BufferingHintsProperty(
                interval_in_seconds=1, size_in_m_bs=1
            ),
            encryption_configuration=firehose.CfnDeliveryStream.EncryptionConfigurationProperty(
                no_encryption_config="NoEncryption"
            ),
            cloud_watch_logging_options=firehose.CfnDeliveryStream.CloudWatchLoggingOptionsProperty(
                enabled=True,
                log_group_name=firehose_s3_log_group_name,
                log_stream_name=firehose_s3_log_stream_name,
            ),
        )

        firehose_stream = firehose.CfnDeliveryStream(
            stack,
            "FirehoseDeliveryStream",
            delivery_stream_name="firehose-deliverystream",
            delivery_stream_type="KinesisStreamAsSource",
            kinesis_stream_source_configuration=kinesis_stream_source_configuration,
            extended_s3_destination_configuration=extended_s3_destination_configuration,
        )

        # specify resource outputs
        cdk.CfnOutput(stack, "KinesisStreamName", value=kinesis_stream.stream_name)
        cdk.CfnOutput(
            stack, "FirehoseDeliveryStreamName", value=firehose_stream.delivery_stream_name
        )
        cdk.CfnOutput(stack, "BucketName", value=bucket.bucket_name)

        with infra.provisioner() as prov:
            yield prov

    @markers.aws.validated
    @pytest.mark.skip(reason="flaky")
    def test_kinesis_firehose_s3(
        self,
        infrastructure,
        cleanups,
        s3_empty_bucket,
        aws_client,
        snapshot,
    ):
        outputs = infrastructure.get_stack_outputs(STACK_NAME)
        kinesis_stream_name = outputs["KinesisStreamName"]
        bucket_name = outputs["BucketName"]

        # put message to kinesis stream
        message_count = 10
        for message_id in range(message_count):
            aws_client.kinesis.put_record(
                StreamName=kinesis_stream_name,
                Data=json.dumps(
                    {
                        "Id": f"message_id_{message_id}",
                        "Data": TEST_MESSAGE,
                    }
                ),
                PartitionKey="1",
            )
        # delete messages from bucket after read
        cleanups.append(lambda: s3_empty_bucket(bucket_name))

        bucket_data = get_all_expected_messages_from_s3(
            aws_client,
            bucket_name,
            expected_message_count=message_count,
        )
        snapshot.match("s3", bucket_data)

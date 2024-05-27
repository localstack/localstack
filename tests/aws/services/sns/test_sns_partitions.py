import json

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry


class TestSnsPartitions:
    # We only have access to the AWS partition, not CHINA/US-GOV/etc
    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-2", "aws"), ("cn-north-1", "aws-cn")])
    def test_topic_in_different_partitions(self, account_id, aws_client_factory, region, partition):
        sns = aws_client_factory(region_name=region).sns

        topic_name = f"topic-{short_uid()}"
        topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]
        assert topic_arn == f"arn:{partition}:sns:{region}:{account_id}:{topic_name}"

    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-2", "aws"), ("cn-north-1", "aws-cn")])
    def test_platform_app_in_different_partitions(
        self, account_id, aws_client_factory, region, partition
    ):
        key = "mock_server_key"
        token = "mock_token"

        sns = aws_client_factory(region_name=region).sns

        platform_name = f"platform-{short_uid()}"
        platform_app_arn = sns.create_platform_application(
            Name=platform_name, Platform="GCM", Attributes={"PlatformCredential": key}
        )["PlatformApplicationArn"]
        assert (
            platform_app_arn == f"arn:{partition}:sns:{region}:{account_id}:app/GCM/{platform_name}"
        )

        endpoint_arn = sns.create_platform_endpoint(
            PlatformApplicationArn=platform_app_arn,
            Token=token,
        )["EndpointArn"]
        assert endpoint_arn.startswith(
            f"arn:{partition}:sns:{region}:{account_id}:endpoint/GCM/{platform_name}"
        )

    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-2", "aws"), ("cn-north-1", "aws-cn")])
    def test_sqs_delivery_logs_in_different_partitions(
        self, account_id, aws_client_factory, region, partition
    ):
        topic_name = f"topic_{short_uid()}"
        queue_name = f"queue_{short_uid()}"

        sns = aws_client_factory(region_name=region).sns
        sqs = aws_client_factory(region_name=region).sqs
        logs = aws_client_factory(region_name=region).logs

        topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]
        sns.set_topic_attributes(
            TopicArn=topic_arn, AttributeName="SQSSuccessFeedbackRoleArn", AttributeValue="sth"
        )
        queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
            "Attributes"
        ]["QueueArn"]
        sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

        sns.publish(TopicArn=topic_arn, Message="test-msg-1")

        log_group_name = f"sns/{region}/{account_id}/{topic_name}"

        def assert_invocations():
            groups = logs.describe_log_groups()["logGroups"]
            assert len(groups) > 0

            streams = logs.describe_log_streams(logGroupName=log_group_name)["logStreams"]
            stream_name = streams[0]["logStreamName"]
            events = logs.get_log_events(logGroupName=log_group_name, logStreamName=stream_name)[
                "events"
            ]
            message = json.loads(events[0]["message"])
            assert (
                message["notification"]["topicArn"]
                == f"arn:{partition}:sns:{region}:{account_id}:{topic_name}"
            )
            assert (
                message["delivery"]["destination"]
                == f"arn:{partition}:sqs:{region}:{account_id}:{queue_name}"
            )

        retry(assert_invocations, sleep=1, retries=5)

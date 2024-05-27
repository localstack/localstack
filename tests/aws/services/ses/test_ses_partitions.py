import json

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry


class TestSesPartitions:
    # We only have access to the AWS partition, not CHINA/US-GOV/etc
    @markers.aws.manual_setup_required
    @pytest.mark.parametrize(
        "region,partition", [("us-east-2", "aws"), ("us-gov-east-1", "aws-us-gov")]
    )
    def test_configuration_in_different_partitions(
        self, account_id, aws_client_factory, region, partition
    ):
        ses = aws_client_factory(region_name=region).ses
        sns = aws_client_factory(region_name=region).sns
        sqs = aws_client_factory(region_name=region).sqs

        topic_name = f"topic-{short_uid()}"
        topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
            "Attributes"
        ]["QueueArn"]
        sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

        config_set = f"config-{short_uid()}"
        ses.create_configuration_set(ConfigurationSet={"Name": config_set})
        ses.create_configuration_set_event_destination(
            ConfigurationSetName=config_set,
            EventDestination={
                "Name": f"destination_{short_uid()}",
                "Enabled": True,
                "MatchingEventTypes": ["send", "delivery"],
                "SNSDestination": {
                    "TopicARN": topic_arn,
                },
            },
        )

        ses.verify_email_address(EmailAddress="source@localstack.cloud")
        ses.send_email(
            Source="source@localstack.cloud",
            Destination={"ToAddresses": ["target@localstack.cloud"]},
            Message={"Subject": {"Data": "subj"}, "Body": {"Text": {"Data": "body"}}},
        )

        message_bodies = []

        def _collect_messages():
            messages = sqs.receive_message(
                QueueUrl=queue_url,
                MessageAttributeNames=["All"],
                VisibilityTimeout=1,
                WaitTimeSeconds=4,
            )["Messages"]

            for msg in messages:
                body = json.loads(msg["Body"])
                message = json.loads(body["Message"])

                if message["eventType"] in ["Send", "Delivery"]:
                    message_bodies.append(message)
                assert len(message_bodies) == 2

        retry(_collect_messages, retries=5, sleep=0.5)

        for message in message_bodies:
            assert (
                message["mail"]["sourceArn"]
                == f"arn:{partition}:ses:{region}:{account_id}:identity/source@localstack.cloud"
            )

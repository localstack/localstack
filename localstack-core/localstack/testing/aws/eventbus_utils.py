import json

import requests

from localstack import config
from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.aws.client_types import TypedServiceClientFactory


def trigger_scheduled_rule(rule_arn: str):
    """
    Call the internal /_aws/events/rules/<rule_arn>/trigger endpoint to expire the deadline of a rule and
    trigger it ASAP.

    :param rule_arn: the rule to run
    :raises ValueError: if the response return a >=400 code
    """
    if is_aws_cloud():
        return

    url = config.internal_service_url() + f"/_aws/events/rules/{rule_arn}/trigger"
    response = requests.get(url)
    if not response.ok:
        raise ValueError(
            f"Error triggering rule {rule_arn}: {response.status_code},{response.text}"
        )


def allow_event_rule_to_sqs_queue(
    aws_client: TypedServiceClientFactory,
    sqs_queue_url: str,
    sqs_queue_arn: str,
    event_rule_arn: str,
):
    """Creates an SQS Queue Policy that allows te given eventbus rule to write tho the given sqs queue."""
    return aws_client.sqs.set_queue_attributes(
        QueueUrl=sqs_queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Statement": [
                        {
                            "Sid": "AllowEventsToQueue",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": sqs_queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": event_rule_arn}},
                        }
                    ]
                }
            )
        },
    )

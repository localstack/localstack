import json
import logging
import uuid
from json import JSONDecodeError
from typing import Dict, List

from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_models import LambdaFunction
from localstack.utils.common import first_char_to_upper

LOG = logging.getLogger(__name__)


def sqs_error_to_dead_letter_queue(queue_arn: str, event: Dict, error):
    client = aws_stack.connect_to_service("sqs")
    queue_url = aws_stack.get_sqs_queue_url(queue_arn)
    attrs = client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["RedrivePolicy"])
    attrs = attrs.get("Attributes", {})
    try:
        policy = json.loads(attrs.get("RedrivePolicy") or "{}")
    except JSONDecodeError:
        LOG.warning(
            "Parsing RedrivePolicy {} failed, Queue: {}".format(
                attrs.get("RedrivePolicy"), queue_arn
            )
        )
        return

    target_arn = policy.get("deadLetterTargetArn")
    if not target_arn:
        return
    return _send_to_dead_letter_queue("SQS", queue_arn, target_arn, event, error)


def sns_error_to_dead_letter_queue(sns_subscriber_arn: str, event: Dict, error):
    client = aws_stack.connect_to_service("sns")
    attrs = client.get_subscription_attributes(SubscriptionArn=sns_subscriber_arn)
    attrs = attrs.get("Attributes", {})
    policy = json.loads(attrs.get("RedrivePolicy") or "{}")
    target_arn = policy.get("deadLetterTargetArn")
    if not target_arn:
        return
    return _send_to_dead_letter_queue("SNS", sns_subscriber_arn, target_arn, event, error)


def lambda_error_to_dead_letter_queue(func_details: LambdaFunction, event: Dict, error):
    dlq_arn = (func_details.dead_letter_config or {}).get("TargetArn")
    source_arn = func_details.id
    return _send_to_dead_letter_queue("Lambda", source_arn, dlq_arn, event, error)


def _send_to_dead_letter_queue(source_type: str, source_arn: str, dlq_arn: str, event: Dict, error):
    if not dlq_arn:
        return
    LOG.info("Sending failed execution %s to dead letter queue %s" % (source_arn, dlq_arn))
    messages = _prepare_messages_to_dlq(source_arn, event, error)
    if ":sqs:" in dlq_arn:
        queue_url = aws_stack.get_sqs_queue_url(dlq_arn)
        sqs_client = aws_stack.connect_to_service("sqs")
        error = None
        result_code = None
        try:
            result = sqs_client.send_message_batch(QueueUrl=queue_url, Entries=messages)
            result_code = result.get("ResponseMetadata", {}).get("HTTPStatusCode")
        except Exception as e:
            error = e
        if error or not result_code or result_code >= 400:
            msg = "Unable to send message to dead letter queue %s (code %s): %s" % (
                queue_url,
                result_code,
                error,
            )
            LOG.info(msg)
            raise Exception(msg)
    elif ":sns:" in dlq_arn:
        sns_client = aws_stack.connect_to_service("sns")
        for message in messages:
            sns_client.publish(
                TopicArn=dlq_arn,
                Message=message["MessageBody"],
                MessageAttributes=message["MessageAttributes"],
            )
    else:
        LOG.warning("Unsupported dead letter queue type: %s" % dlq_arn)
    return dlq_arn


def _prepare_messages_to_dlq(source_arn: str, event: Dict, error) -> List[Dict]:
    messages = []
    custom_attrs = {
        "RequestID": {"DataType": "String", "StringValue": str(uuid.uuid4())},
        "ErrorCode": {"DataType": "String", "StringValue": "200"},
        "ErrorMessage": {"DataType": "String", "StringValue": str(error)},
    }
    if ":sqs:" in source_arn:
        custom_attrs["ErrorMessage"]["StringValue"] = str(error.result)
        for record in event.get("Records", []):
            msg_attrs = message_attributes_to_upper(record.get("messageAttributes"))
            message_attrs = {**msg_attrs, **custom_attrs}
            messages.append(
                {
                    "Id": record.get("messageId"),
                    "MessageBody": record.get("body"),
                    "MessageAttributes": message_attrs,
                }
            )
    elif ":sns:" in source_arn:
        messages.append(
            {
                "Id": str(uuid.uuid4()),
                "MessageBody": json.dumps(event),
                "MessageAttributes": custom_attrs,
            }
        )
    elif ":lambda:" in source_arn:
        if event.get("Records") and "sns" in event["Records"][0]["EventSource"]:
            for record in event["Records"]:
                sns_rec = record.get("Sns", {})
                message_attrs = {**sns_rec.get("MessageAttributes"), **custom_attrs}
                messages.append(
                    {
                        "Id": sns_rec.get("MessageId"),
                        "MessageBody": sns_rec.get("Message"),
                        "MessageAttributes": message_attrs,
                    }
                )
        else:
            messages.append(
                {
                    "Id": str(uuid.uuid4()),
                    "MessageBody": json.dumps(event),
                    "MessageAttributes": custom_attrs,
                }
            )
    return messages


def message_attributes_to_upper(message_attrs: Dict) -> Dict:
    """Convert message attribute details (first characters) to upper case (e.g., StringValue, DataType)."""
    message_attrs = message_attrs or {}
    for _, attr in message_attrs.items():
        if not isinstance(attr, dict):
            continue
        for key, value in dict(attr).items():
            attr[first_char_to_upper(key)] = attr.pop(key)
    return message_attrs

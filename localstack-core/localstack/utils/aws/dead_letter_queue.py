import json
import logging
import uuid
from typing import Dict, List

from localstack.aws.connect import connect_to
from localstack.utils.aws import arns
from localstack.utils.strings import convert_to_printable_chars, first_char_to_upper

LOG = logging.getLogger(__name__)


def sns_error_to_dead_letter_queue(
    sns_subscriber: dict,
    message: str,
    error: str,
    **kwargs,
):
    policy = json.loads(sns_subscriber.get("RedrivePolicy") or "{}")
    target_arn = policy.get("deadLetterTargetArn")
    if not target_arn:
        return
    if not_supported := (
        set(kwargs) - {"MessageAttributes", "MessageGroupId", "MessageDeduplicationId"}
    ):
        LOG.warning(
            "Not publishing to the DLQ - invalid arguments passed to the DLQ '%s'", not_supported
        )
        return
    event = {
        "message": message,
        **kwargs,
    }
    return _send_to_dead_letter_queue(sns_subscriber["SubscriptionArn"], target_arn, event, error)


def _send_to_dead_letter_queue(source_arn: str, dlq_arn: str, event: Dict, error, role: str = None):
    if not dlq_arn:
        return
    LOG.info("Sending failed execution %s to dead letter queue %s", source_arn, dlq_arn)
    messages = _prepare_messages_to_dlq(source_arn, event, error)
    source_service = arns.extract_service_from_arn(source_arn)
    region = arns.extract_region_from_arn(dlq_arn)
    if role:
        clients = connect_to.with_assumed_role(
            role_arn=role, service_principal=source_service, region_name=region
        )
    else:
        clients = connect_to(region_name=region)
    if ":sqs:" in dlq_arn:
        queue_url = arns.sqs_queue_url_for_arn(dlq_arn)
        sqs_client = clients.sqs.request_metadata(
            source_arn=source_arn, service_principal=source_service
        )
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
            if "InvalidMessageContents" in str(error):
                msg += f" - messages: {messages}"
            LOG.info(msg)
            raise Exception(msg)
    elif ":sns:" in dlq_arn:
        sns_client = clients.sns.request_metadata(
            source_arn=source_arn, service_principal=source_service
        )
        for message in messages:
            sns_client.publish(
                TopicArn=dlq_arn,
                Message=message["MessageBody"],
                MessageAttributes=message["MessageAttributes"],
            )
    else:
        LOG.warning("Unsupported dead letter queue type: %s", dlq_arn)
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
        # event can also contain: MessageAttributes, MessageGroupId, MessageDeduplicationId
        message = {
            "Id": str(uuid.uuid4()),
            "MessageBody": event.pop("message"),
            **event,
        }
        messages.append(message)

    elif ":lambda:" in source_arn:
        custom_attrs["ErrorCode"]["DataType"] = "Number"
        # not sure about what type of error can come here
        try:
            error_message = json.loads(error.result)["errorMessage"]
            custom_attrs["ErrorMessage"]["StringValue"] = error_message
        except (ValueError, KeyError):
            # using old behaviour
            custom_attrs["ErrorMessage"]["StringValue"] = str(error)

        messages.append(
            {
                "Id": str(uuid.uuid4()),
                "MessageBody": json.dumps(event),
                "MessageAttributes": custom_attrs,
            }
        )
    # make sure we only have printable strings in the message attributes
    for message in messages:
        if message.get("MessageAttributes"):
            message["MessageAttributes"] = convert_to_printable_chars(message["MessageAttributes"])
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

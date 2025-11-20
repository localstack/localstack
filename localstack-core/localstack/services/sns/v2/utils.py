import base64
import json
from uuid import uuid4

from botocore.utils import InvalidArnException

from localstack.aws.api.sns import InvalidParameterException
from localstack.services.sns.constants import E164_REGEX, VALID_SUBSCRIPTION_ATTR_NAME
from localstack.services.sns.v2.models import SnsStore, SnsSubscription
from localstack.utils.aws.arns import ArnData, parse_arn
from localstack.utils.strings import short_uid, to_bytes, to_str


def parse_and_validate_topic_arn(topic_arn: str | None) -> ArnData:
    return _parse_and_validate_arn(topic_arn, "Topic")


def parse_and_validate_platform_application_arn(platform_application_arn: str | None) -> ArnData:
    return _parse_and_validate_arn(platform_application_arn, "PlatformApplication")


def _parse_and_validate_arn(arn: str | None, resource_type: str) -> ArnData:
    arn = arn or ""
    try:
        return parse_arn(arn)
    except InvalidArnException:
        count = len(arn.split(":"))
        raise InvalidParameterException(
            f"Invalid parameter: {resource_type}Arn Reason: An ARN must have at least 6 elements, not {count}"
        )


def is_valid_e164_number(number: str) -> bool:
    return E164_REGEX.match(number) is not None


def validate_subscription_attribute(
    attribute_name: str,
    attribute_value: str,
    topic_arn: str,
    endpoint: str,
    is_subscribe_call: bool = False,
) -> None:
    """
    Validate the subscription attribute to be set. See:
    https://docs.aws.amazon.com/sns/latest/api/API_SetSubscriptionAttributes.html
    :param attribute_name: the subscription attribute name, must be in VALID_SUBSCRIPTION_ATTR_NAME
    :param attribute_value: the subscription attribute value
    :param topic_arn: the topic_arn of the subscription, needed to know if it is FIFO
    :param endpoint: the subscription endpoint (like an SQS queue ARN)
    :param is_subscribe_call: the error message is different if called from Subscribe or SetSubscriptionAttributes
    :raises InvalidParameterException
    :return:
    """
    error_prefix = (
        "Invalid parameter: Attributes Reason: " if is_subscribe_call else "Invalid parameter: "
    )
    if attribute_name not in VALID_SUBSCRIPTION_ATTR_NAME:
        raise InvalidParameterException(f"{error_prefix}AttributeName")

    if attribute_name == "FilterPolicy":
        try:
            json.loads(attribute_value or "{}")
        except json.JSONDecodeError:
            raise InvalidParameterException(f"{error_prefix}FilterPolicy: failed to parse JSON.")
    elif attribute_name == "FilterPolicyScope":
        if attribute_value not in ("MessageAttributes", "MessageBody"):
            raise InvalidParameterException(
                f"{error_prefix}FilterPolicyScope: Invalid value [{attribute_value}]. "
                f"Please use either MessageBody or MessageAttributes"
            )
    elif attribute_name == "RawMessageDelivery":
        # TODO: only for SQS and https(s) subs, + firehose
        if attribute_value.lower() not in ("true", "false"):
            raise InvalidParameterException(
                f"{error_prefix}RawMessageDelivery: Invalid value [{attribute_value}]. "
                f"Must be true or false."
            )

    elif attribute_name == "RedrivePolicy":
        try:
            dlq_target_arn = json.loads(attribute_value).get("deadLetterTargetArn", "")
        except json.JSONDecodeError:
            raise InvalidParameterException(f"{error_prefix}RedrivePolicy: failed to parse JSON.")
        try:
            parsed_arn = parse_arn(dlq_target_arn)
        except InvalidArnException:
            raise InvalidParameterException(
                f"{error_prefix}RedrivePolicy: deadLetterTargetArn is an invalid arn"
            )

        if topic_arn.endswith(".fifo"):
            if endpoint.endswith(".fifo") and (
                not parsed_arn["resource"].endswith(".fifo") or "sqs" not in parsed_arn["service"]
            ):
                raise InvalidParameterException(
                    f"{error_prefix}RedrivePolicy: must use a FIFO queue as DLQ for a FIFO Subscription to a FIFO Topic."
                )


def create_subscription_arn(topic_arn: str) -> str:
    # This is the format of a Subscription ARN
    # arn:aws:sns:us-west-2:123456789012:my-topic:8a21d249-4329-4871-acc6-7be709c6ea7f
    return f"{topic_arn}:{uuid4()}"


def create_platform_endpoint_arn(
    platform_application_arn: str,
) -> str:
    # This is the format of an Endpoint Arn
    # arn:aws:sns:us-west-2:1234567890:endpoint/GCM/MyApplication/12345678-abcd-9012-efgh-345678901234
    return f"{platform_application_arn.replace('app', 'endpoint', 1)}/{uuid4()}"


def encode_subscription_token_with_region(region: str) -> str:
    """
    Create a 64 characters Subscription Token with the region encoded
    :param region:
    :return: a subscription token with the region encoded
    """
    return ((region.encode() + b"/").hex() + short_uid() * 8)[:64]


def get_next_page_token_from_arn(resource_arn: str) -> str:
    return to_str(base64.b64encode(to_bytes(resource_arn)))


def get_region_from_subscription_token(token: str) -> str:
    """
    Try to decode and return the region from a subscription token
    :param token:
    :return: the region if able to decode it
    :raises: InvalidParameterException if the token is invalid
    """
    try:
        region = token.split("2f", maxsplit=1)[0]
        return bytes.fromhex(region).decode("utf-8")
    except (IndexError, ValueError, TypeError, UnicodeDecodeError):
        raise InvalidParameterException("Invalid parameter: Token")


def get_topic_subscriptions(store: SnsStore, topic_arn: str) -> list[SnsSubscription]:
    # TODO: delete this once the legacy v1 implementation has been removed
    if hasattr(store, "topic_subscriptions"):
        sub_arns = store.topic_subscriptions.get(topic_arn, [])
    else:
        sub_arns: list[str] = store.topics[topic_arn].get("subscriptions", [])

    subscriptions = [store.subscriptions[k] for k in sub_arns if k in store.subscriptions]
    return subscriptions

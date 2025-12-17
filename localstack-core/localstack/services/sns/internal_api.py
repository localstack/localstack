import functools
import json

from botocore.utils import InvalidArnException

from localstack.constants import AWS_REGION_US_EAST_1, DEFAULT_AWS_ACCOUNT_ID
from localstack.http import Request, Response, Router, route
from localstack.services.sns import constants as sns_constants
from localstack.services.sns.models import SnsStore, sns_stores
from localstack.utils.aws.arns import extract_account_id_from_arn, extract_region_from_arn, parse_arn

from .analytics import internal_api_calls


def register_sns_api_resource(router: Router):
    """Register the retrospection endpoints as internal LocalStack endpoints."""
    router.add(SNSServicePlatformEndpointMessagesApiResource())
    router.add(SNSServiceSMSMessagesApiResource())
    router.add(SNSServiceSubscriptionTokenApiResource())


def _format_messages(sent_messages: list[dict[str, str]], validated_keys: list[str]):
    """
    Format the messages to be more readable and undo the format change that was needed for Moto.
    """
    formatted_messages = []
    for sent_message in sent_messages:
        msg = {
            key: json.dumps(value)
            if key == "Message" and sent_message.get("MessageStructure") == "json"
            else value
            for key, value in sent_message.items()
            if key in validated_keys
        }
        formatted_messages.append(msg)

    return formatted_messages


class SNSInternalResource:
    resource_type: str
    """Base class with helper to properly track usage of internal endpoints"""

    def count_usage(self):
        internal_api_calls.labels(resource_type=self.resource_type).increment()


def count_usage(f):
    @functools.wraps(f)
    def _wrapper(self, *args, **kwargs):
        self.count_usage()
        return f(self, *args, **kwargs)

    return _wrapper


class SNSServicePlatformEndpointMessagesApiResource(SNSInternalResource):
    resource_type = "platform-endpoint-message"
    """Provides a REST API for retrospective access to platform endpoint messages sent via SNS."""

    _PAYLOAD_FIELDS = [
        "TargetArn",
        "TopicArn",
        "Message",
        "MessageAttributes",
        "MessageStructure",
        "Subject",
        "MessageId",
    ]

    @route(sns_constants.PLATFORM_ENDPOINT_MSGS_ENDPOINT, methods=["GET"])
    @count_usage
    def on_get(self, request: Request):
        filter_endpoint_arn = request.args.get("endpointArn")
        account_id = (
            request.args.get("accountId", DEFAULT_AWS_ACCOUNT_ID)
            if not filter_endpoint_arn
            else extract_account_id_from_arn(filter_endpoint_arn)
        )
        region = (
            request.args.get("region", AWS_REGION_US_EAST_1)
            if not filter_endpoint_arn
            else extract_region_from_arn(filter_endpoint_arn)
        )
        store: SnsStore = sns_stores[account_id][region]
        if filter_endpoint_arn:
            messages = store.platform_endpoint_messages.get(filter_endpoint_arn, [])
            messages = _format_messages(messages, self._PAYLOAD_FIELDS)
            return {
                "platform_endpoint_messages": {filter_endpoint_arn: messages},
                "region": region,
            }

        platform_endpoint_messages = {
            endpoint_arn: _format_messages(messages, self._PAYLOAD_FIELDS)
            for endpoint_arn, messages in store.platform_endpoint_messages.items()
        }
        return {
            "platform_endpoint_messages": platform_endpoint_messages,
            "region": region,
        }

    @route(sns_constants.PLATFORM_ENDPOINT_MSGS_ENDPOINT, methods=["DELETE"])
    @count_usage
    def on_delete(self, request: Request) -> Response:
        filter_endpoint_arn = request.args.get("endpointArn")
        account_id = (
            request.args.get("accountId", DEFAULT_AWS_ACCOUNT_ID)
            if not filter_endpoint_arn
            else extract_account_id_from_arn(filter_endpoint_arn)
        )
        region = (
            request.args.get("region", AWS_REGION_US_EAST_1)
            if not filter_endpoint_arn
            else extract_region_from_arn(filter_endpoint_arn)
        )
        store: SnsStore = sns_stores[account_id][region]
        if filter_endpoint_arn:
            store.platform_endpoint_messages.pop(filter_endpoint_arn, None)
            return Response("", status=204)

        store.platform_endpoint_messages.clear()
        return Response("", status=204)


class SNSServiceSMSMessagesApiResource(SNSInternalResource):
    resource_type = "sms-message"
    """Provides a REST API for retrospective access to SMS messages sent via SNS."""

    _PAYLOAD_FIELDS = [
        "PhoneNumber",
        "TopicArn",
        "SubscriptionArn",
        "MessageId",
        "Message",
        "MessageAttributes",
        "MessageStructure",
        "Subject",
    ]

    @route(sns_constants.SMS_MSGS_ENDPOINT, methods=["GET"])
    @count_usage
    def on_get(self, request: Request):
        account_id = request.args.get("accountId", DEFAULT_AWS_ACCOUNT_ID)
        region = request.args.get("region", AWS_REGION_US_EAST_1)
        filter_phone_number = request.args.get("phoneNumber")
        store: SnsStore = sns_stores[account_id][region]
        if filter_phone_number:
            messages = [m for m in store.sms_messages if m.get("PhoneNumber") == filter_phone_number]
            messages = _format_messages(messages, self._PAYLOAD_FIELDS)
            return {
                "sms_messages": {filter_phone_number: messages},
                "region": region,
            }

        sms_messages = {}

        for m in _format_messages(store.sms_messages, self._PAYLOAD_FIELDS):
            sms_messages.setdefault(m.get("PhoneNumber"), []).append(m)

        return {
            "sms_messages": sms_messages,
            "region": region,
        }

    @route(sns_constants.SMS_MSGS_ENDPOINT, methods=["DELETE"])
    @count_usage
    def on_delete(self, request: Request) -> Response:
        account_id = request.args.get("accountId", DEFAULT_AWS_ACCOUNT_ID)
        region = request.args.get("region", AWS_REGION_US_EAST_1)
        filter_phone_number = request.args.get("phoneNumber")
        store: SnsStore = sns_stores[account_id][region]
        if filter_phone_number:
            store.sms_messages = [m for m in store.sms_messages if m.get("PhoneNumber") != filter_phone_number]
            return Response("", status=204)

        store.sms_messages.clear()
        return Response("", status=204)


class SNSServiceSubscriptionTokenApiResource(SNSInternalResource):
    resource_type = "subscription-token"
    """Provides a REST API for retrospective access to Subscription Confirmation Tokens."""

    @route(f"{sns_constants.SUBSCRIPTION_TOKENS_ENDPOINT}/<path:subscription_arn>", methods=["GET"])
    @count_usage
    def on_get(self, _request: Request, subscription_arn: str):
        try:
            parsed_arn = parse_arn(subscription_arn)
        except InvalidArnException:
            response = Response("", 400)
            response.set_json(
                {
                    "error": "The provided SubscriptionARN is invalid",
                    "subscription_arn": subscription_arn,
                }
            )
            return response

        store: SnsStore = sns_stores[parsed_arn["account"]][parsed_arn["region"]]

        for token, sub_arn in store.subscription_tokens.items():
            if sub_arn == subscription_arn:
                return {
                    "subscription_token": token,
                    "subscription_arn": subscription_arn,
                }

        response = Response("", 404)
        response.set_json(
            {
                "error": "The provided SubscriptionARN is not found",
                "subscription_arn": subscription_arn,
            }
        )
        return response


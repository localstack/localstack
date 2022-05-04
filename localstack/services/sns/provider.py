import ast
import asyncio
import base64
import datetime
import json
import logging
import time
import traceback
import uuid
from typing import Dict, List

import requests as requests
from flask import Response as FlaskResponse
from moto.sns.exceptions import DuplicateSnsEndpointError
from requests.models import Response

from localstack.aws.api import RequestContext
from localstack.aws.api.sns import (
    ActionsList,
    AmazonResourceName,
    BatchEntryIdsNotDistinctException,
    CheckIfPhoneNumberIsOptedOutResponse,
    ConfirmSubscriptionResponse,
    CreateEndpointResponse,
    CreatePlatformApplicationResponse,
    CreateSMSSandboxPhoneNumberResult,
    CreateTopicResponse,
    DelegatesList,
    DeleteSMSSandboxPhoneNumberResult,
    GetEndpointAttributesResponse,
    GetPlatformApplicationAttributesResponse,
    GetSMSAttributesResponse,
    GetSMSSandboxAccountStatusResult,
    GetSubscriptionAttributesResponse,
    GetTopicAttributesResponse,
    InvalidParameterException,
    LanguageCodeString,
    ListEndpointsByPlatformApplicationResponse,
    ListOriginationNumbersResult,
    ListPhoneNumbersOptedOutResponse,
    ListPlatformApplicationsResponse,
    ListSMSSandboxPhoneNumbersResult,
    ListString,
    ListSubscriptionsByTopicResponse,
    ListSubscriptionsResponse,
    ListTagsForResourceResponse,
    ListTopicsResponse,
    MapStringToString,
    MaxItems,
    MaxItemsListOriginationNumbers,
    MessageAttributeMap,
    NotFoundException,
    OptInPhoneNumberResponse,
    OTPCode,
    PhoneNumber,
    PhoneNumberString,
    PublishBatchRequestEntryList,
    PublishBatchResponse,
    PublishResponse,
    SetSMSAttributesResponse,
    SnsApi,
    String,
    SubscribeResponse,
    SubscriptionAttributesMap,
    TagKeyList,
    TagList,
    TagResourceResponse,
    TooManyEntriesInBatchRequestException,
    TopicAttributesMap,
    UntagResourceResponse,
    VerifySMSSandboxPhoneNumberResult,
    attributeName,
    attributeValue,
    authenticateOnUnsubscribe,
    boolean,
    endpoint,
    label,
    message,
    messageStructure,
    nextToken,
    protocol,
    string,
    subject,
    subscriptionARN,
    token,
    topicARN,
    topicName,
)
from localstack.config import external_service_url
from localstack.services.awslambda import lambda_api
from localstack.services.generic_proxy import RegionBackend
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import create_sqs_system_attributes, parse_urlencoded_data
from localstack.utils.aws.dead_letter_queue import sns_error_to_dead_letter_queue
from localstack.utils.cloudwatch.cloudwatch_util import store_cloudwatch_logs
from localstack.utils.json import json_safe
from localstack.utils.objects import not_none_or
from localstack.utils.strings import long_uid, md5, short_uid, to_bytes
from localstack.utils.threads import start_thread
from localstack.utils.time import timestamp_millis

SNS_PROTOCOLS = [
    "http",
    "https",
    "email",
    "email-json",
    "sms",
    "sqs",
    "application",
    "lambda",
    "firehose",
]

# set up logger
LOG = logging.getLogger(__name__)
HTTP_SUBSCRIPTION_ATTRIBUTES = ["UnsubscribeURL"]


class SNSBackend(RegionBackend):
    # maps topic ARN to list of subscriptions
    sns_subscriptions: Dict[str, List[Dict]]
    # maps subscription ARN to subscription status
    subscription_status: Dict[str, Dict]
    # maps topic ARN to list of tags
    sns_tags: Dict[str, List[Dict]]
    # cache of topic ARN to platform endpoint messages (used primarily for testing)
    platform_endpoint_messages: Dict[str, List[Dict]]
    # list of sent SMS messages - TODO: expose via internal API
    sms_messages: List[Dict]

    def __init__(self):
        self.sns_subscriptions = {}
        self.subscription_status = {}
        self.sns_tags = {}
        self.platform_endpoint_messages = {}
        self.sms_messages = []


def publish_message(
    topic_arn, req_data, headers, subscription_arn=None, skip_checks=False, message_attributes={}
):
    sns_backend = SNSBackend.get()
    message = req_data["Message"][0]
    message_id = str(uuid.uuid4())

    target_arn = req_data.get("TargetArn")
    if target_arn and ":endpoint/" in target_arn:
        # cache messages published to platform endpoints
        cache = sns_backend.platform_endpoint_messages[target_arn] = (
            sns_backend.platform_endpoint_messages.get(target_arn) or []
        )
        # TODO: check this in the old provider
        cache.append(req_data)

    LOG.debug("Publishing message to TopicArn: %s | Message: %s", topic_arn, message)
    start_thread(
        lambda _: message_to_subscribers(
            message_id,
            message,
            topic_arn,
            # TODO: check
            req_data,
            headers,
            subscription_arn,
            skip_checks,
            message_attributes,
        )
    )
    return message_id


class SnsProvider(SnsApi, ServiceLifecycleHook):
    def add_permission(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        label: label,
        aws_account_id: DelegatesList,
        action_name: ActionsList,
    ) -> None:
        call_moto(context)

    def check_if_phone_number_is_opted_out(
        self, context: RequestContext, phone_number: PhoneNumber
    ) -> CheckIfPhoneNumberIsOptedOutResponse:
        moto_response = call_moto(context)
        return CheckIfPhoneNumberIsOptedOutResponse(**moto_response)

    def create_sms_sandbox_phone_number(
        self,
        context: RequestContext,
        phone_number: PhoneNumberString,
        language_code: LanguageCodeString = None,
    ) -> CreateSMSSandboxPhoneNumberResult:
        call_moto(context)
        return CreateSMSSandboxPhoneNumberResult()

    def delete_sms_sandbox_phone_number(
        self, context: RequestContext, phone_number: PhoneNumberString
    ) -> DeleteSMSSandboxPhoneNumberResult:
        call_moto(context)
        return DeleteSMSSandboxPhoneNumberResult()

    def get_endpoint_attributes(
        self, context: RequestContext, endpoint_arn: String
    ) -> GetEndpointAttributesResponse:
        moto_response = call_moto(context)
        return GetEndpointAttributesResponse(**moto_response)

    def get_platform_application_attributes(
        self, context: RequestContext, platform_application_arn: String
    ) -> GetPlatformApplicationAttributesResponse:
        moto_response = call_moto(context)
        return GetPlatformApplicationAttributesResponse(**moto_response)

    def get_sms_attributes(
        self, context: RequestContext, attributes: ListString = None
    ) -> GetSMSAttributesResponse:
        moto_response = call_moto(context)
        return GetSMSAttributesResponse(**moto_response)

    def get_sms_sandbox_account_status(
        self, context: RequestContext
    ) -> GetSMSSandboxAccountStatusResult:
        moto_response = call_moto(context)
        return GetSMSSandboxAccountStatusResult(**moto_response)

    def list_endpoints_by_platform_application(
        self, context: RequestContext, platform_application_arn: String, next_token: String = None
    ) -> ListEndpointsByPlatformApplicationResponse:
        moto_response = call_moto(context)
        return ListEndpointsByPlatformApplicationResponse(**moto_response)

    def list_origination_numbers(
        self,
        context: RequestContext,
        next_token: nextToken = None,
        max_results: MaxItemsListOriginationNumbers = None,
    ) -> ListOriginationNumbersResult:
        moto_response = call_moto(context)
        return ListOriginationNumbersResult(**moto_response)

    def list_phone_numbers_opted_out(
        self, context: RequestContext, next_token: string = None
    ) -> ListPhoneNumbersOptedOutResponse:
        moto_response = call_moto(context)
        return ListPhoneNumbersOptedOutResponse(**moto_response)

    def list_platform_applications(
        self, context: RequestContext, next_token: String = None
    ) -> ListPlatformApplicationsResponse:
        moto_response = call_moto(context)
        return ListPlatformApplicationsResponse(**moto_response)

    def list_sms_sandbox_phone_numbers(
        self, context: RequestContext, next_token: nextToken = None, max_results: MaxItems = None
    ) -> ListSMSSandboxPhoneNumbersResult:
        moto_response = call_moto(context)
        return ListSMSSandboxPhoneNumbersResult(**moto_response)

    def list_subscriptions_by_topic(
        self, context: RequestContext, topic_arn: topicARN, next_token: nextToken = None
    ) -> ListSubscriptionsByTopicResponse:
        moto_response = call_moto(context)
        return ListSubscriptionsByTopicResponse(**moto_response)

    def list_topics(
        self, context: RequestContext, next_token: nextToken = None
    ) -> ListTopicsResponse:
        moto_response = call_moto(context)
        return ListTopicsResponse(**moto_response)

    def opt_in_phone_number(
        self, context: RequestContext, phone_number: PhoneNumber
    ) -> OptInPhoneNumberResponse:
        call_moto(context)
        return OptInPhoneNumberResponse()

    def remove_permission(self, context: RequestContext, topic_arn: topicARN, label: label) -> None:
        call_moto(context)

    def set_endpoint_attributes(
        self, context: RequestContext, endpoint_arn: String, attributes: MapStringToString
    ) -> None:
        call_moto(context)

    def set_platform_application_attributes(
        self,
        context: RequestContext,
        platform_application_arn: String,
        attributes: MapStringToString,
    ) -> None:
        call_moto(context)

    def set_sms_attributes(
        self, context: RequestContext, attributes: MapStringToString
    ) -> SetSMSAttributesResponse:
        call_moto(context)
        return SetSMSAttributesResponse()

    def set_topic_attributes(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        attribute_name: attributeName,
        attribute_value: attributeValue = None,
    ) -> None:
        call_moto(context)

    def verify_sms_sandbox_phone_number(
        self, context: RequestContext, phone_number: PhoneNumberString, one_time_password: OTPCode
    ) -> VerifySMSSandboxPhoneNumberResult:
        call_moto(context)
        return VerifySMSSandboxPhoneNumberResult()

    def get_topic_attributes(
        self, context: RequestContext, topic_arn: topicARN
    ) -> GetTopicAttributesResponse:
        moto_response = call_moto(context)
        return GetTopicAttributesResponse(**moto_response)

    def publish_batch(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        publish_batch_request_entries: PublishBatchRequestEntryList,
    ) -> PublishBatchResponse:
        if len(publish_batch_request_entries) > 10:
            raise TooManyEntriesInBatchRequestException(
                "The batch request contains more entries than permissible"
            )

        ids = [entry["Id"] for entry in publish_batch_request_entries]
        if len(set(ids)) != len(publish_batch_request_entries):
            raise BatchEntryIdsNotDistinctException(
                "Two or more batch entries in the request have the same Id"
            )

        if topic_arn and ".fifo" in topic_arn:
            if not all(["MessageGroupId" in entry for entry in publish_batch_request_entries]):
                raise InvalidParameterException(
                    "The MessageGroupId parameter is required for FIFO topics"
                )
        response = {"Successful": [], "Failed": []}
        for entry in publish_batch_request_entries:
            message_id = str(uuid.uuid4())
            data = {}
            data["TopicArn"] = [topic_arn]
            data["Message"] = [entry["Message"]]
            data["Subject"] = [entry.get("Subject")]
            if ".fifo" in topic_arn:
                data["MessageGroupId"] = [entry.get("MessageGroupId")]
            # TODO: add MessageDeduplication checks once ASF-SQS implementation becomes default

            message_attributes = entry.get("MessageAttributes", [])
            try:
                message_to_subscribers(
                    message_id,
                    entry["Message"],
                    topic_arn,
                    data,
                    context.request.headers,
                    message_attributes=message_attributes,
                )
                response["Successful"].append({"Id": entry["Id"], "MessageId": message_id})
            except Exception:
                response["Failed"].append({"Id": entry["Id"]})

        return PublishBatchResponse(**response)

    def set_subscription_attributes(
        self,
        context: RequestContext,
        subscription_arn: subscriptionARN,
        attribute_name: attributeName,
        attribute_value: attributeValue = None,
    ) -> None:
        sub = get_subscription_by_arn(subscription_arn)
        if not sub:
            raise NotFoundException(
                f"Unable to find subscription for given ARN: {subscription_arn}"
            )
        sub[attribute_name] = attribute_value

    def confirm_subscription(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        token: token,
        authenticate_on_unsubscribe: authenticateOnUnsubscribe = None,
    ) -> ConfirmSubscriptionResponse:
        sns_backend = SNSBackend.get()
        sub_arn = None
        for k, v in sns_backend.subscription_status.items():
            if v["Token"] == token and v["TopicArn"] == topic_arn:
                v["Status"] = "Subscribed"
                sub_arn = k
        for k, v in sns_backend.sns_subscriptions.items():
            for i in v:
                if i["TopicArn"] == topic_arn:
                    i["PendingConfirmation"] = "false"
        return ConfirmSubscriptionResponse(SubscriptionArn=sub_arn)

    def untag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        call_moto(context)
        sns_backend = SNSBackend.get()
        sns_backend.sns_tags[resource_arn] = [
            t for t in _get_tags(resource_arn) if t["Key"] not in tag_keys
        ]
        return UntagResourceResponse()

    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName
    ) -> ListTagsForResourceResponse:
        return ListTagsForResourceResponse(Tags=_get_tags(resource_arn))

    def delete_platform_application(
        self, context: RequestContext, platform_application_arn: String
    ) -> None:
        call_moto(context)

    def delete_endpoint(self, context: RequestContext, endpoint_arn: String) -> None:
        call_moto(context)

    def create_platform_application(
        self, context: RequestContext, name: String, platform: String, attributes: MapStringToString
    ) -> CreatePlatformApplicationResponse:
        moto_response = call_moto(context)
        return CreatePlatformApplicationResponse(**moto_response)

    def create_platform_endpoint(
        self,
        context: RequestContext,
        platform_application_arn: String,
        token: String,
        custom_user_data: String = None,
        attributes: MapStringToString = None,
    ) -> CreateEndpointResponse:
        result = None
        try:
            result = call_moto(context)
        except DuplicateSnsEndpointError:
            # TODO: this was unclear in the old provider, check against aws and moto
            for e in self.platform_endpoints.values():
                if e.token == token:
                    if custom_user_data and custom_user_data != e.custom_user_data:
                        # TODO: check error against aws
                        raise DuplicateSnsEndpointError(
                            f"Endpoint already exist for token: {token} with different attributes"
                        )
        return CreateEndpointResponse(**result)

    def unsubscribe(self, context: RequestContext, subscription_arn: subscriptionARN) -> None:
        sns_backend = SNSBackend.get()

        def should_be_kept(current_subscription, target_subscription_arn):
            if current_subscription["SubscriptionArn"] != target_subscription_arn:
                return True

            if current_subscription["Protocol"] in ["http", "https"]:
                external_url = external_service_url("sns")
                token = short_uid()
                message_id = long_uid()
                subscription_url = "%s/?Action=ConfirmSubscription&SubscriptionArn=%s&Token=%s" % (
                    external_url,
                    target_subscription_arn,
                    token,
                )
                message = {
                    "Type": ["UnsubscribeConfirmation"],
                    "MessageId": [message_id],
                    "Token": [token],
                    "TopicArn": [current_subscription["TopicArn"]],
                    "Message": [
                        "You have chosen to deactivate subscription %s.\nTo cancel this operation and restore the subscription, visit the SubscribeURL included in this message."
                        % target_subscription_arn
                    ],
                    "SubscribeURL": [subscription_url],
                    "Timestamp": [datetime.datetime.utcnow().timestamp()],
                }

                headers = {
                    "x-amz-sns-message-type": "UnsubscribeConfirmation",
                    "x-amz-sns-message-id": message_id,
                    "x-amz-sns-topic-arn": current_subscription["TopicArn"],
                    "x-amz-sns-subscription-arn": target_subscription_arn,
                }
                publish_message(
                    current_subscription["TopicArn"],
                    message,
                    headers,
                    subscription_arn,
                    skip_checks=True,
                )

            return False

        for topic_arn, existing_subs in sns_backend.sns_subscriptions.items():
            sns_backend.sns_subscriptions[topic_arn] = [
                sub for sub in existing_subs if should_be_kept(sub, subscription_arn)
            ]

    def get_subscription_attributes(
        self, context: RequestContext, subscription_arn: subscriptionARN
    ) -> GetSubscriptionAttributesResponse:
        sub = get_subscription_by_arn(subscription_arn)
        if not sub:
            raise NotFoundException(f"Subscription with arn {subscription_arn} not found")
        return GetSubscriptionAttributesResponse(Attributes=sub)

    def list_subscriptions(
        self, context: RequestContext, next_token: nextToken = None
    ) -> ListSubscriptionsResponse:
        moto_response = call_moto(context)
        return ListSubscriptionsResponse(**moto_response)

    def publish(
        self,
        context: RequestContext,
        message: message,
        topic_arn: topicARN = None,
        target_arn: String = None,
        phone_number: String = None,
        subject: subject = None,
        message_structure: messageStructure = None,
        message_attributes: MessageAttributeMap = None,
        message_deduplication_id: String = None,
        message_group_id: String = None,
    ) -> PublishResponse:
        # We do not want the request to be forwarded to SNS backend
        if subject == "":
            raise InvalidParameterException("Empty string for subject is not supported")
        if not message or all(not m for m in message):
            raise InvalidParameterException("Empty message")

        if topic_arn and ".fifo" in topic_arn and not message_group_id:
            raise InvalidParameterException(
                "The MessageGroupId parameter is required for FIFO topics",
            )

        sns_backend = SNSBackend.get()
        # No need to create a topic to send SMS or single push notifications with SNS
        # but we can't mock a sending so we only return that it went well
        if not phone_number and not target_arn:
            if topic_arn not in sns_backend.sns_subscriptions:
                raise NotFoundException(
                    "Topic does not exist",
                )
        # Legacy format to easily leverage existing publishing code
        # added parameters parsed by ASF. TODO: check/remove
        req_data = {
            "Action": ["Publish"],
            "TopicArn": [topic_arn],
            "TargetArn": target_arn,
            "Message": [message],
            "MessageAttributes": [message_attributes],
            "MessageDeduplicationId": [message_deduplication_id],
            "MessageGroupId": [message_group_id],
            "MessageStructure": [message_structure],
            "PhoneNumber": [phone_number],
            "Subject": [subject],
        }
        message_id = publish_message(
            topic_arn, req_data, context.request.headers, message_attributes=message_attributes
        )
        return PublishResponse(MessageId=message_id)

    def subscribe(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        protocol: protocol,
        endpoint: endpoint = None,
        attributes: SubscriptionAttributesMap = None,
        return_subscription_arn: boolean = None,
    ) -> SubscribeResponse:
        if not endpoint:
            # TODO: check AWS behaviour (because endpoint is optional)
            raise NotFoundException("Endpoint not specified in subscription")
        if protocol not in SNS_PROTOCOLS:
            raise InvalidParameterException(
                f"Invalid parameter: Amazon SNS does not support this protocol string: {protocol}"
            )
        if ".fifo" in endpoint and ".fifo" not in topic_arn:
            raise InvalidParameterException(
                "FIFO SQS Queues can not be subscribed to standard SNS topics"
            )
        moto_response = call_moto(context)
        subscription_arn = moto_response.get("SubscriptionArn")
        filter_policy = moto_response.get("FilterPolicy")
        sns_backend = SNSBackend.get()
        topic_subs = sns_backend.sns_subscriptions[topic_arn] = (
            sns_backend.sns_subscriptions.get(topic_arn) or []
        )
        # An endpoint may only be subscribed to a topic once. Subsequent
        # subscribe calls do nothing (subscribe is idempotent).
        for existing_topic_subscription in topic_subs:
            if existing_topic_subscription.get("Endpoint") == endpoint:
                return SubscribeResponse(
                    SubscriptionArn=existing_topic_subscription["SubscriptionArn"]
                )

        subscription = {
            # http://docs.aws.amazon.com/cli/latest/reference/sns/get-subscription-attributes.html
            "TopicArn": topic_arn,
            "Endpoint": endpoint,
            "Protocol": protocol,
            "SubscriptionArn": subscription_arn,
            "FilterPolicy": filter_policy,
            "PendingConfirmation": "true",
        }
        if attributes:
            subscription.update(attributes)
        topic_subs.append(subscription)

        if subscription_arn not in sns_backend.subscription_status:
            sns_backend.subscription_status[subscription_arn] = {}

        token = short_uid()
        sns_backend.subscription_status[subscription_arn].update(
            {"TopicArn": topic_arn, "Token": token, "Status": "Not Subscribed"}
        )
        # Send out confirmation message for HTTP(S), fix for https://github.com/localstack/localstack/issues/881
        if protocol in ["http", "https"]:
            token = short_uid()
            external_url = external_service_url("sns")
            subscription["UnsubscribeURL"] = "%s/?Action=Unsubscribe&SubscriptionArn=%s" % (
                external_url,
                subscription_arn,
            )
            confirmation = {
                "Type": ["SubscriptionConfirmation"],
                "Token": [token],
                "Message": [
                    ("You have chosen to subscribe to the topic %s.\n" % topic_arn)
                    + "To confirm the subscription, visit the SubscribeURL included in this message."
                ],
                "SubscribeURL": [
                    "%s/?Action=ConfirmSubscription&TopicArn=%s&Token=%s"
                    % (external_url, topic_arn, token)
                ],
            }
            publish_message(topic_arn, confirmation, {}, subscription_arn, skip_checks=True)
        elif protocol == "sqs":
            # Auto-confirm sqs subscriptions for now
            # TODO: revisit for multi-account
            self.confirm_subscription(context, topic_arn, token)
        return SubscribeResponse(SubscriptionArn=subscription_arn)

    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: TagList
    ) -> TagResourceResponse:
        # TODO: can this be used to tag any resource when using AWS?
        call_moto(context)
        sns_backend = SNSBackend.get()
        existing_tags = sns_backend.sns_tags.get(resource_arn, [])
        tags = [tag for idx, tag in enumerate(tags) if tag not in tags[:idx]]

        def existing_tag_index(item):
            for idx, tag in enumerate(existing_tags):
                if item["Key"] == tag["Key"]:
                    return idx
            return None

        for item in tags:
            existing_index = existing_tag_index(item)
            if existing_index is None:
                existing_tags.append(item)
            else:
                existing_tags[existing_index] = item

        sns_backend.sns_tags[resource_arn] = existing_tags
        return TagResourceResponse()

    def delete_topic(self, context: RequestContext, topic_arn: topicARN) -> None:
        call_moto(context)
        sns_backend = SNSBackend.get()
        sns_backend.sns_subscriptions.pop(topic_arn, None)
        sns_backend.sns_tags.pop(topic_arn, None)
        event_publisher.fire_event(
            event_publisher.EVENT_SNS_DELETE_TOPIC,
            payload={"t": event_publisher.get_hash(topic_arn)},
        )

    def create_topic(
        self,
        context: RequestContext,
        name: topicName,
        attributes: TopicAttributesMap = None,
        tags: TagList = None,
    ) -> CreateTopicResponse:
        moto_response = call_moto(context)
        sns_backend = SNSBackend.get()
        topic_arn = moto_response["TopicArn"]
        tag_resource_success = extract_tags(topic_arn, tags, True, sns_backend)
        if not tag_resource_success:
            raise InvalidParameterException("Topic already exists with different tags")
        if tags:
            self.tag_resource(context=context, resource_arn=topic_arn, tags=tags)
        sns_backend.sns_subscriptions[topic_arn] = (
            sns_backend.sns_subscriptions.get(topic_arn) or []
        )
        # publish event
        event_publisher.fire_event(
            event_publisher.EVENT_SNS_CREATE_TOPIC,
            payload={"t": event_publisher.get_hash(topic_arn)},
        )
        return CreateTopicResponse(TopicArn=topic_arn)


def message_to_subscribers(
    message_id,
    message,
    topic_arn,
    req_data,
    headers,
    subscription_arn=None,
    skip_checks=False,
    message_attributes=None,
):
    if not topic_arn:
        topic_arn = req_data.get("TargetArn")
    sns_backend = SNSBackend.get()
    subscriptions = sns_backend.sns_subscriptions.get(topic_arn, [])

    async def wait_for_messages_sent():
        subs = [
            message_to_subscriber(
                message_id,
                message,
                topic_arn,
                req_data,
                headers,
                subscription_arn,
                skip_checks,
                sns_backend,
                subscriber,
                subscriptions,
                message_attributes,
            )
            for subscriber in list(subscriptions)
        ]
        if subs:
            await asyncio.wait(subs)

    asyncio.run(wait_for_messages_sent())


async def message_to_subscriber(
    message_id,
    message,
    topic_arn,
    req_data,
    headers,
    subscription_arn,
    skip_checks,
    sns_backend,
    subscriber,
    subscriptions,
    message_attributes,
):

    if subscription_arn not in [None, subscriber["SubscriptionArn"]]:
        return

    filter_policy = json.loads(subscriber.get("FilterPolicy") or "{}")
    if not message_attributes:
        message_attributes = get_message_attributes(req_data)
    if not skip_checks and not check_filter_policy(filter_policy, message_attributes):
        LOG.info(
            "SNS filter policy %s does not match attributes %s", filter_policy, message_attributes
        )
        return
    if subscriber["Protocol"] == "sms":
        event = {
            "topic_arn": topic_arn,
            "endpoint": subscriber["Endpoint"],
            "message_content": req_data["Message"][0],
        }
        sns_backend.sms_messages.append(event)
        LOG.info(
            "Delivering SMS message to %s: %s",
            subscriber["Endpoint"],
            req_data["Message"][0],
        )

        # MOCK DATA
        delivery = {
            "phoneCarrier": "Mock Carrier",
            "mnc": 270,
            "priceInUSD": 0.00645,
            "smsType": "Transactional",
            "mcc": 310,
            "providerResponse": "Message has been accepted by phone carrier",
            "dwellTimeMsUntilDeviceAck": 200,
        }
        store_delivery_log(subscriber, True, message, message_id, delivery)
        return

    elif subscriber["Protocol"] == "sqs":
        queue_url = None

        try:
            endpoint = subscriber["Endpoint"]

            if "sqs_queue_url" in subscriber:
                queue_url = subscriber.get("sqs_queue_url")
            elif "://" in endpoint:
                queue_url = endpoint
            else:
                queue_name = endpoint.split(":")[5]
                queue_url = aws_stack.get_sqs_queue_url(queue_name)
                subscriber["sqs_queue_url"] = queue_url

            message_group_id = req_data.get("MessageGroupId", [""])[0]

            message_deduplication_id = req_data.get("MessageDeduplicationId", [""])[0]

            sqs_client = aws_stack.connect_to_service("sqs")

            kwargs = {}
            if message_group_id:
                kwargs["MessageGroupId"] = message_group_id
            if message_deduplication_id:
                kwargs["MessageDeduplicationId"] = message_deduplication_id

            sqs_client.send_message(
                QueueUrl=queue_url,
                MessageBody=create_sns_message_body(subscriber, req_data, message_id),
                MessageAttributes=create_sqs_message_attributes(subscriber, message_attributes),
                MessageSystemAttributes=create_sqs_system_attributes(headers),
                **kwargs,
            )
            store_delivery_log(subscriber, True, message, message_id)
        except Exception as exc:
            LOG.info("Unable to forward SNS message to SQS: %s %s", exc, traceback.format_exc())
            store_delivery_log(subscriber, False, message, message_id)
            sns_error_to_dead_letter_queue(subscriber["SubscriptionArn"], req_data, str(exc))
            if "NonExistentQueue" in str(exc):
                LOG.info(
                    'Removing non-existent queue "%s" subscribed to topic "%s"',
                    queue_url,
                    topic_arn,
                )
                subscriptions.remove(subscriber)
        return

    elif subscriber["Protocol"] == "lambda":
        try:
            external_url = external_service_url("sns")
            unsubscribe_url = "%s/?Action=Unsubscribe&SubscriptionArn=%s" % (
                external_url,
                subscriber["SubscriptionArn"],
            )
            response = lambda_api.process_sns_notification(
                subscriber["Endpoint"],
                topic_arn,
                subscriber["SubscriptionArn"],
                message,
                message_id,
                message_attributes,
                unsubscribe_url,
                subject=req_data.get("Subject")[0],
            )

            if response is not None:
                delivery = {
                    "statusCode": response.status_code,
                    "providerResponse": response.get_data(),
                }
                store_delivery_log(subscriber, True, message, message_id, delivery)

            # TODO: Check if it can be removed
            if isinstance(response, Response):
                response.raise_for_status()
            elif isinstance(response, FlaskResponse):
                if response.status_code >= 400:
                    raise Exception(
                        "Error response (code %s): %s" % (response.status_code, response.data)
                    )
        except Exception as exc:
            LOG.info(
                "Unable to run Lambda function on SNS message: %s %s", exc, traceback.format_exc()
            )
            store_delivery_log(subscriber, False, message, message_id)
            sns_error_to_dead_letter_queue(subscriber["SubscriptionArn"], req_data, str(exc))
        return

    elif subscriber["Protocol"] in ["http", "https"]:
        msg_type = (req_data.get("Type") or ["Notification"])[0]
        try:
            message_body = create_sns_message_body(subscriber, req_data, message_id)
        except Exception:
            return
        try:
            response = requests.post(
                subscriber["Endpoint"],
                headers={
                    "Content-Type": "text/plain",
                    # AWS headers according to
                    # https://docs.aws.amazon.com/sns/latest/dg/sns-message-and-json-formats.html#http-header
                    "x-amz-sns-message-type": msg_type,
                    "x-amz-sns-topic-arn": subscriber["TopicArn"],
                    "x-amz-sns-subscription-arn": subscriber["SubscriptionArn"],
                    "User-Agent": "Amazon Simple Notification Service Agent",
                },
                data=message_body,
                verify=False,
            )

            delivery = {
                "statusCode": response.status_code,
                "providerResponse": response.content.decode("utf-8"),
            }
            store_delivery_log(subscriber, True, message, message_id, delivery)

            response.raise_for_status()
        except Exception as exc:
            LOG.info(
                "Received error on sending SNS message, putting to DLQ (if configured): %s", exc
            )
            store_delivery_log(subscriber, False, message, message_id)
            sns_error_to_dead_letter_queue(subscriber["SubscriptionArn"], req_data, str(exc))
        return

    elif subscriber["Protocol"] == "application":
        try:
            sns_client = aws_stack.connect_to_service("sns")
            sns_client.publish(TargetArn=subscriber["Endpoint"], Message=message)
            store_delivery_log(subscriber, True, message, message_id)
        except Exception as exc:
            LOG.warning(
                "Unable to forward SNS message to SNS platform app: %s %s",
                exc,
                traceback.format_exc(),
            )
            store_delivery_log(subscriber, False, message, message_id)
            sns_error_to_dead_letter_queue(subscriber["SubscriptionArn"], req_data, str(exc))
        return

    elif subscriber["Protocol"] in ["email", "email-json"]:
        ses_client = aws_stack.connect_to_service("ses")
        if subscriber.get("Endpoint"):
            ses_client.verify_email_address(EmailAddress=subscriber.get("Endpoint"))
            ses_client.verify_email_address(EmailAddress="admin@localstack.com")

            ses_client.send_email(
                Source="admin@localstack.com",
                Message={
                    "Body": {
                        "Text": {
                            "Data": create_sns_message_body(
                                subscriber=subscriber, req_data=req_data, message_id=message_id
                            )
                            if subscriber["Protocol"] == "email-json"
                            else message
                        }
                    },
                    "Subject": {"Data": "SNS-Subscriber-Endpoint"},
                },
                Destination={"ToAddresses": [subscriber.get("Endpoint")]},
            )
            store_delivery_log(subscriber, True, message, message_id)
    else:
        LOG.warning('Unexpected protocol "%s" for SNS subscription', subscriber["Protocol"])


def get_subscription_by_arn(sub_arn):
    sns_backend = SNSBackend.get()
    # TODO maintain separate map instead of traversing all items
    for key, subscriptions in sns_backend.sns_subscriptions.items():
        for sub in subscriptions:
            if sub["SubscriptionArn"] == sub_arn:
                return sub


def create_sns_message_body(subscriber, req_data, message_id=None):
    message = req_data["Message"][0]
    protocol = subscriber["Protocol"]
    attributes = get_message_attributes(req_data)

    if req_data.get("MessageStructure") == ["json"]:
        message = json.loads(message)
        try:
            message = message.get(protocol, message["default"])
        except KeyError:
            raise Exception("Unable to find 'default' key in message payload")

    if is_raw_message_delivery(subscriber):
        if attributes:
            message["MessageAttributes"] = attributes
        return message

    data = {
        "Type": req_data.get("Type", ["Notification"])[0],
        "MessageId": message_id,
        "TopicArn": subscriber["TopicArn"],
        "Message": message,
        "Timestamp": timestamp_millis(),
        "SignatureVersion": "1",
        # TODO Add a more sophisticated solution with an actual signature
        # Hardcoded
        "Signature": "EXAMPLEpH+..",
        "SigningCertURL": "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-0000000000000000000000.pem",
    }

    for key in ["Subject", "SubscribeURL", "Token"]:
        if req_data.get(key):
            data[key] = req_data[key][0]

    for key in HTTP_SUBSCRIPTION_ATTRIBUTES:
        if key in subscriber:
            data[key] = subscriber[key]

    if attributes:
        data["MessageAttributes"] = attributes

    return json.dumps(data)


def _get_tags(topic_arn):
    sns_backend = SNSBackend.get()
    if topic_arn not in sns_backend.sns_tags:
        sns_backend.sns_tags[topic_arn] = []

    return sns_backend.sns_tags[topic_arn]


def get_message_attributes(req_data):
    extracted_msg_attrs = parse_urlencoded_data(req_data, "MessageAttributes.entry")
    return prepare_message_attributes(extracted_msg_attrs)


def is_raw_message_delivery(susbcriber):
    return susbcriber.get("RawMessageDelivery") in ("true", True, "True")


def create_sqs_message_attributes(subscriber, attributes):

    message_attributes = {}
    for key, value in attributes.items():
        # TODO: check if naming differs between ASF and QueryParameters, if not remove .get("Type") and .get("Value")
        if value.get("Type") or value.get("DataType"):
            tpe = value.get("Type") or value.get("DataType")
            attribute = {"DataType": tpe}
            if tpe == "Binary":
                val = value.get("BinaryValue") or value.get("Value")
                attribute["BinaryValue"] = base64.decodebytes(to_bytes(val))
                # base64 decoding might already have happened, in which decode fails.
                # If decode fails, fallback to whatever is in there.
                if not attribute["BinaryValue"]:
                    attribute["BinaryValue"] = val

            else:
                val = value.get("StringValue") or value.get("Value", "")
                attribute["StringValue"] = str(val)

            message_attributes[key] = attribute

    return message_attributes


def prepare_message_attributes(message_attributes):
    attributes = {}
    for attr in message_attributes:
        attributes[attr["Name"]] = {
            "Type": attr["Value"]["DataType"],
            "Value": attr["Value"]["StringValue"]
            if attr["Value"].get("StringValue", None)
            else attr["Value"]["BinaryValue"],
        }
    return attributes


def is_number(x):
    try:
        float(x)
        return True
    except ValueError:
        return False


def evaluate_numeric_condition(conditions, value):
    if not is_number(value):
        return False

    for i in range(0, len(conditions), 2):
        value = float(value)
        operator = conditions[i]
        operand = float(conditions[i + 1])

        if operator == "=":
            if value != operand:
                return False
        elif operator == ">":
            if value <= operand:
                return False
        elif operator == "<":
            if value >= operand:
                return False
        elif operator == ">=":
            if value < operand:
                return False
        elif operator == "<=":
            if value > operand:
                return False

    return True


def evaluate_exists_condition(conditions, message_attributes, criteria):
    # support for exists: false was added in april 2021
    # https://aws.amazon.com/about-aws/whats-new/2021/04/amazon-sns-grows-the-set-of-message-filtering-operators/
    if conditions:
        return message_attributes.get(criteria) is not None
    else:
        return message_attributes.get(criteria) is None


def evaluate_condition(value, condition, message_attributes, criteria):
    if type(condition) is not dict:
        return value == condition
    elif condition.get("exists") is not None:
        return evaluate_exists_condition(condition.get("exists"), message_attributes, criteria)
    elif value is None:
        # the remaining conditions require the value to not be None
        return False
    elif condition.get("anything-but"):
        return value not in condition.get("anything-but")
    elif condition.get("prefix"):
        prefix = condition.get("prefix")
        return value.startswith(prefix)
    elif condition.get("numeric"):
        return evaluate_numeric_condition(condition.get("numeric"), value)
    return False


def check_filter_policy(filter_policy, message_attributes):
    if not filter_policy:
        return True

    for criteria in filter_policy:
        conditions = filter_policy.get(criteria)
        attribute = message_attributes.get(criteria)

        if (
            evaluate_filter_policy_conditions(conditions, attribute, message_attributes, criteria)
            is False
        ):
            return False

    return True


def evaluate_filter_policy_conditions(conditions, attribute, message_attributes, criteria):
    if type(conditions) is not list:
        conditions = [conditions]

    if attribute is None:
        return False

    tpe = attribute.get("DataType") or attribute.get("Type")
    val = attribute.get("StringValue") or attribute.get("Value")
    if tpe == "String.Array":
        values = ast.literal_eval(val)
        for value in values:
            for condition in conditions:
                if evaluate_condition(value, condition, message_attributes, criteria):
                    return True
    else:
        for condition in conditions:
            value = val or None
            if evaluate_condition(value, condition, message_attributes, criteria):
                return True

    return False


def store_delivery_log(
    subscriber: dict, success: bool, message: str, message_id: str, delivery: dict = None
):

    log_group_name = subscriber.get("TopicArn", "").replace("arn:aws:", "").replace(":", "/")
    log_stream_name = long_uid()
    invocation_time = int(time.time() * 1000)

    delivery = not_none_or(delivery, {})
    delivery["deliveryId"] = (long_uid(),)
    delivery["destination"] = (subscriber.get("Endpoint", ""),)
    delivery["dwellTimeMs"] = 200
    if not success:
        delivery["attemps"] = 1

    delivery_log = {
        "notification": {
            "messageMD5Sum": md5(message),
            "messageId": message_id,
            "topicArn": subscriber.get("TopicArn"),
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f%z"),
        },
        "delivery": delivery,
        "status": "SUCCESS" if success else "FAILURE",
    }

    log_output = json.dumps(json_safe(delivery_log))

    return store_cloudwatch_logs(log_group_name, log_stream_name, log_output, invocation_time)


def extract_tags(topic_arn, tags, is_create_topic_request, sns_backend):
    existing_tags = list(sns_backend.sns_tags.get(topic_arn, []))
    existing_sub = sns_backend.sns_subscriptions.get(topic_arn, None)
    # if this is none there is nothing to check
    if existing_sub is not None:
        if tags is None:
            tags = []
        for tag in tags:
            # this means topic already created with empty tags and when we try to create it
            # again with other tag value then it should fail according to aws documentation.
            if is_create_topic_request and existing_tags is not None and tag not in existing_tags:
                return False
    return True

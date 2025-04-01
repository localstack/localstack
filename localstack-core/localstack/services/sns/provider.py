import base64
import copy
import functools
import json
import logging
from typing import Dict, List
from uuid import uuid4

from botocore.utils import InvalidArnException
from moto.core.utils import camelcase_to_pascal, underscores_to_camelcase
from moto.sns import sns_backends
from moto.sns.models import MAXIMUM_MESSAGE_LENGTH, SNSBackend, Topic
from moto.sns.utils import is_e164

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.api.sns import (
    AmazonResourceName,
    BatchEntryIdsNotDistinctException,
    ConfirmSubscriptionResponse,
    CreateEndpointResponse,
    CreatePlatformApplicationResponse,
    CreateTopicResponse,
    EndpointDisabledException,
    GetSubscriptionAttributesResponse,
    GetTopicAttributesResponse,
    InvalidParameterException,
    InvalidParameterValueException,
    ListSubscriptionsByTopicResponse,
    ListSubscriptionsResponse,
    ListTagsForResourceResponse,
    MapStringToString,
    MessageAttributeMap,
    NotFoundException,
    PublishBatchRequestEntryList,
    PublishBatchResponse,
    PublishBatchResultEntry,
    PublishResponse,
    SnsApi,
    String,
    SubscribeResponse,
    Subscription,
    SubscriptionAttributesMap,
    TagKeyList,
    TagList,
    TagResourceResponse,
    TooManyEntriesInBatchRequestException,
    TopicAttributesMap,
    UntagResourceResponse,
    attributeName,
    attributeValue,
    authenticateOnUnsubscribe,
    boolean,
    messageStructure,
    nextToken,
    subscriptionARN,
    topicARN,
    topicName,
)
from localstack.constants import AWS_REGION_US_EAST_1, DEFAULT_AWS_ACCOUNT_ID
from localstack.http import Request, Response, Router, route
from localstack.services.edge import ROUTER
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.sns import constants as sns_constants
from localstack.services.sns.certificate import SNS_SERVER_CERT
from localstack.services.sns.filter import FilterPolicyValidator
from localstack.services.sns.models import (
    SnsMessage,
    SnsMessageType,
    SnsStore,
    SnsSubscription,
    sns_stores,
)
from localstack.services.sns.publisher import (
    PublishDispatcher,
    SnsBatchPublishContext,
    SnsPublishContext,
)
from localstack.utils.aws.arns import (
    ArnData,
    extract_account_id_from_arn,
    extract_region_from_arn,
    get_partition,
    parse_arn,
)
from localstack.utils.collections import PaginatedList, select_from_typed_dict
from localstack.utils.strings import short_uid, to_bytes, to_str

from .analytics import internal_api_calls

# set up logger
LOG = logging.getLogger(__name__)


class SnsProvider(SnsApi, ServiceLifecycleHook):
    """
    Provider class for AWS Simple Notification Service.

    AWS supports following operations in a cross-account setup:
    - GetTopicAttributes
    - SetTopicAttributes
    - AddPermission
    - RemovePermission
    - Publish
    - Subscribe
    - ListSubscriptionByTopic
    - DeleteTopic
    """

    @route(sns_constants.SNS_CERT_ENDPOINT, methods=["GET"])
    def get_signature_cert_pem_file(self, request: Request):
        # see http://sns-public-resources.s3.amazonaws.com/SNS_Message_Signing_Release_Note_Jan_25_2011.pdf
        # see https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html
        return Response(self._signature_cert_pem, 200)

    def __init__(self) -> None:
        super().__init__()
        self._publisher = PublishDispatcher()
        self._signature_cert_pem: str = SNS_SERVER_CERT

    def on_before_stop(self):
        self._publisher.shutdown()

    def on_after_init(self):
        # Allow sent platform endpoint messages to be retrieved from the SNS endpoint
        register_sns_api_resource(ROUTER)
        # add the route to serve the certificate used to validate message signatures
        ROUTER.add(self.get_signature_cert_pem_file)

    @staticmethod
    def get_store(account_id: str, region_name: str) -> SnsStore:
        return sns_stores[account_id][region_name]

    @staticmethod
    def get_moto_backend(account_id: str, region_name: str) -> SNSBackend:
        return sns_backends[account_id][region_name]

    @staticmethod
    def _get_topic(arn: str, context: RequestContext, multiregion: bool = True) -> Topic:
        """
        :param arn: the Topic ARN
        :param context: the RequestContext of the request
        :param multiregion: if the request can fetch the topic across regions or not (ex. Publish cannot publish to a
        topic in a different region than the request)
        :return: the Moto model Topic
        """
        arn_data = parse_and_validate_topic_arn(arn)
        try:
            return sns_backends[arn_data["account"]][context.region].topics[arn]
        except KeyError:
            if multiregion or context.region == arn_data["region"]:
                raise NotFoundException("Topic does not exist")
            else:
                raise InvalidParameterException("Invalid parameter: TopicArn")

    def get_topic_attributes(
        self, context: RequestContext, topic_arn: topicARN, **kwargs
    ) -> GetTopicAttributesResponse:
        # get the Topic from moto manually first, because Moto does not handle well the case where the ARN is malformed
        # (raises ValueError: not enough values to unpack (expected 6, got 1))
        moto_topic_model = self._get_topic(topic_arn, context)
        moto_response: GetTopicAttributesResponse = call_moto(context)
        # TODO: fix some attributes by moto, see snapshot
        # DeliveryPolicy
        # EffectiveDeliveryPolicy
        # Policy.Statement..Action -> SNS:Receive is added by moto but not returned in AWS
        # TODO: very hacky way to get the attributes we need instead of a moto patch
        # see the attributes we need: https://docs.aws.amazon.com/sns/latest/dg/sns-topic-attributes.html
        # would need more work to have the proper format out of moto, maybe extract the model to our store
        attributes = moto_response["Attributes"]
        for attr in vars(moto_topic_model):
            if "_feedback" in attr:
                key = camelcase_to_pascal(underscores_to_camelcase(attr))
                attributes[key] = getattr(moto_topic_model, attr)
            elif attr == "signature_version":
                attributes["SignatureVersion"] = moto_topic_model.signature_version
            elif attr == "archive_policy":
                attributes["ArchivePolicy"] = moto_topic_model.archive_policy

        return moto_response

    def publish_batch(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        publish_batch_request_entries: PublishBatchRequestEntryList,
        **kwargs,
    ) -> PublishBatchResponse:
        if len(publish_batch_request_entries) > 10:
            raise TooManyEntriesInBatchRequestException(
                "The batch request contains more entries than permissible."
            )

        parsed_arn = parse_and_validate_topic_arn(topic_arn)
        store = self.get_store(account_id=parsed_arn["account"], region_name=context.region)
        moto_topic = self._get_topic(topic_arn, context, multiregion=False)

        ids = [entry["Id"] for entry in publish_batch_request_entries]
        if len(set(ids)) != len(publish_batch_request_entries):
            raise BatchEntryIdsNotDistinctException(
                "Two or more batch entries in the request have the same Id."
            )

        response: PublishBatchResponse = {"Successful": [], "Failed": []}

        # TODO: write AWS validated tests with FilterPolicy and batching
        # TODO: find a scenario where we can fail to send a message synchronously to be able to report it
        # right now, it seems that AWS fails the whole publish if something is wrong in the format of 1 message

        total_batch_size = 0
        message_contexts = []
        for entry_index, entry in enumerate(publish_batch_request_entries, start=1):
            message_payload = entry.get("Message")
            message_attributes = entry.get("MessageAttributes", {})
            if message_attributes:
                # if a message contains non-valid message attributes
                # will fail for the first non-valid message encountered, and raise ParameterValueInvalid
                validate_message_attributes(message_attributes, position=entry_index)

            total_batch_size += get_total_publish_size(message_payload, message_attributes)

            # TODO: WRITE AWS VALIDATED
            if entry.get("MessageStructure") == "json":
                try:
                    message = json.loads(message_payload)
                    # Keys in the JSON object that correspond to supported transport protocols must have
                    # simple JSON string values.
                    # Non-string values will cause the key to be ignored.
                    message = {
                        key: field for key, field in message.items() if isinstance(field, str)
                    }
                    if "default" not in message:
                        raise InvalidParameterException(
                            "Invalid parameter: Message Structure - No default entry in JSON message body"
                        )
                    entry["Message"] = message  # noqa
                except json.JSONDecodeError:
                    raise InvalidParameterException(
                        "Invalid parameter: Message Structure - JSON message body failed to parse"
                    )

            if is_fifo := (".fifo" in topic_arn):
                if not all("MessageGroupId" in entry for entry in publish_batch_request_entries):
                    raise InvalidParameterException(
                        "Invalid parameter: The MessageGroupId parameter is required for FIFO topics"
                    )
                if moto_topic.content_based_deduplication == "false":
                    if not all(
                        "MessageDeduplicationId" in entry for entry in publish_batch_request_entries
                    ):
                        raise InvalidParameterException(
                            "Invalid parameter: The topic should either have ContentBasedDeduplication enabled or MessageDeduplicationId provided explicitly",
                        )

            msg_ctx = SnsMessage.from_batch_entry(entry, is_fifo=is_fifo)
            message_contexts.append(msg_ctx)
            success = PublishBatchResultEntry(
                Id=entry["Id"],
                MessageId=msg_ctx.message_id,
            )
            if is_fifo:
                success["SequenceNumber"] = msg_ctx.sequencer_number
            response["Successful"].append(success)

        if total_batch_size > MAXIMUM_MESSAGE_LENGTH:
            raise CommonServiceException(
                code="BatchRequestTooLong",
                message="The length of all the messages put together is more than the limit.",
                sender_fault=True,
            )

        publish_ctx = SnsBatchPublishContext(
            messages=message_contexts,
            store=store,
            request_headers=context.request.headers,
            topic_attributes=vars(moto_topic),
        )
        self._publisher.publish_batch_to_topic(publish_ctx, topic_arn)

        return response

    def set_subscription_attributes(
        self,
        context: RequestContext,
        subscription_arn: subscriptionARN,
        attribute_name: attributeName,
        attribute_value: attributeValue = None,
        **kwargs,
    ) -> None:
        store = self.get_store(account_id=context.account_id, region_name=context.region)
        sub = store.subscriptions.get(subscription_arn)
        if not sub:
            raise NotFoundException("Subscription does not exist")

        validate_subscription_attribute(
            attribute_name=attribute_name,
            attribute_value=attribute_value,
            topic_arn=sub["TopicArn"],
            endpoint=sub["Endpoint"],
        )
        if attribute_name == "RawMessageDelivery":
            attribute_value = attribute_value.lower()

        elif attribute_name == "FilterPolicy":
            filter_policy = json.loads(attribute_value) if attribute_value else None
            if filter_policy:
                validator = FilterPolicyValidator(
                    scope=sub.get("FilterPolicyScope", "MessageAttributes"),
                    is_subscribe_call=False,
                )
                validator.validate_filter_policy(filter_policy)

            store.subscription_filter_policy[subscription_arn] = filter_policy

        sub[attribute_name] = attribute_value

    def confirm_subscription(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        token: String,
        authenticate_on_unsubscribe: authenticateOnUnsubscribe = None,
        **kwargs,
    ) -> ConfirmSubscriptionResponse:
        # TODO: validate format on the token (seems to be 288 hex chars)
        # this request can come from any http client, it might not be signed (we would need to implement
        # `authenticate_on_unsubscribe` to force a signing client to do this request.
        # so, the region and account_id might not be in the request. Use the ones from the topic_arn
        try:
            parsed_arn = parse_arn(topic_arn)
        except InvalidArnException:
            raise InvalidParameterException("Invalid parameter: Topic")

        store = self.get_store(account_id=parsed_arn["account"], region_name=parsed_arn["region"])

        # it seems SNS is able to know what the region of the topic should be, even though a wrong topic is accepted
        if parsed_arn["region"] != get_region_from_subscription_token(token):
            raise InvalidParameterException("Invalid parameter: Topic")

        subscription_arn = store.subscription_tokens.get(token)
        if not subscription_arn:
            raise InvalidParameterException("Invalid parameter: Token")

        subscription = store.subscriptions.get(subscription_arn)
        if not subscription:
            # subscription could have been deleted in the meantime
            raise InvalidParameterException("Invalid parameter: Token")

        # ConfirmSubscription is idempotent
        if subscription.get("PendingConfirmation") == "false":
            return ConfirmSubscriptionResponse(SubscriptionArn=subscription_arn)

        subscription["PendingConfirmation"] = "false"
        subscription["ConfirmationWasAuthenticated"] = "true"

        return ConfirmSubscriptionResponse(SubscriptionArn=subscription_arn)

    def untag_resource(
        self,
        context: RequestContext,
        resource_arn: AmazonResourceName,
        tag_keys: TagKeyList,
        **kwargs,
    ) -> UntagResourceResponse:
        call_moto(context)
        # TODO: probably get the account_id and region from the `resource_arn`
        store = self.get_store(context.account_id, context.region)
        existing_tags = store.sns_tags.setdefault(resource_arn, [])
        store.sns_tags[resource_arn] = [t for t in existing_tags if t["Key"] not in tag_keys]
        return UntagResourceResponse()

    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, **kwargs
    ) -> ListTagsForResourceResponse:
        # TODO: probably get the account_id and region from the `resource_arn`
        store = self.get_store(context.account_id, context.region)
        tags = store.sns_tags.setdefault(resource_arn, [])
        return ListTagsForResourceResponse(Tags=tags)

    def create_platform_application(
        self,
        context: RequestContext,
        name: String,
        platform: String,
        attributes: MapStringToString,
        **kwargs,
    ) -> CreatePlatformApplicationResponse:
        # TODO: validate platform
        # see https://docs.aws.amazon.com/cli/latest/reference/sns/create-platform-application.html
        # list of possible values: ADM, Baidu, APNS, APNS_SANDBOX, GCM, MPNS, WNS
        # each platform has a specific way to handle credentials
        # this can also be used for dispatching message to the right platform
        return call_moto(context)

    def create_platform_endpoint(
        self,
        context: RequestContext,
        platform_application_arn: String,
        token: String,
        custom_user_data: String = None,
        attributes: MapStringToString = None,
        **kwargs,
    ) -> CreateEndpointResponse:
        # TODO: support mobile app events
        # see https://docs.aws.amazon.com/sns/latest/dg/application-event-notifications.html
        return call_moto(context)

    def unsubscribe(
        self, context: RequestContext, subscription_arn: subscriptionARN, **kwargs
    ) -> None:
        count = len(subscription_arn.split(":"))
        try:
            parsed_arn = parse_arn(subscription_arn)
        except InvalidArnException:
            # TODO: check for invalid SubscriptionGUID
            raise InvalidParameterException(
                f"Invalid parameter: SubscriptionArn Reason: An ARN must have at least 6 elements, not {count}"
            )

        account_id = parsed_arn["account"]
        region_name = parsed_arn["region"]

        store = self.get_store(account_id=account_id, region_name=region_name)
        if count == 6 and subscription_arn not in store.subscriptions:
            raise InvalidParameterException("Invalid parameter: SubscriptionId")

        moto_sns_backend = self.get_moto_backend(account_id, region_name)
        moto_sns_backend.unsubscribe(subscription_arn)

        # pop the subscription at the end, to avoid race condition by iterating over the topic subscriptions
        subscription = store.subscriptions.get(subscription_arn)

        if not subscription:
            # unsubscribe is idempotent, so unsubscribing from a non-existing topic does nothing
            return

        if subscription["Protocol"] in ["http", "https"]:
            # TODO: actually validate this (re)subscribe behaviour somehow (localhost.run?)
            #  we might need to save the sub token in the store
            # TODO: AWS only sends the UnsubscribeConfirmation if the call is unauthenticated or the requester is not
            #  the owner
            subscription_token = encode_subscription_token_with_region(region=context.region)
            message_ctx = SnsMessage(
                type=SnsMessageType.UnsubscribeConfirmation,
                token=subscription_token,
                message=f"You have chosen to deactivate subscription {subscription_arn}.\nTo cancel this operation and restore the subscription, visit the SubscribeURL included in this message.",
            )
            moto_topic = moto_sns_backend.topics.get(subscription["TopicArn"])
            publish_ctx = SnsPublishContext(
                message=message_ctx,
                store=store,
                request_headers=context.request.headers,
                topic_attributes=vars(moto_topic),
            )
            self._publisher.publish_to_topic_subscriber(
                publish_ctx,
                topic_arn=subscription["TopicArn"],
                subscription_arn=subscription_arn,
            )

        store.topic_subscriptions[subscription["TopicArn"]].remove(subscription_arn)
        store.subscription_filter_policy.pop(subscription_arn, None)
        store.subscriptions.pop(subscription_arn, None)

    def get_subscription_attributes(
        self, context: RequestContext, subscription_arn: subscriptionARN, **kwargs
    ) -> GetSubscriptionAttributesResponse:
        store = self.get_store(account_id=context.account_id, region_name=context.region)
        sub = store.subscriptions.get(subscription_arn)
        if not sub:
            raise NotFoundException("Subscription does not exist")
        removed_attrs = ["sqs_queue_url"]
        if "FilterPolicyScope" in sub and not sub.get("FilterPolicy"):
            removed_attrs.append("FilterPolicyScope")
            removed_attrs.append("FilterPolicy")
        elif "FilterPolicy" in sub and "FilterPolicyScope" not in sub:
            sub["FilterPolicyScope"] = "MessageAttributes"

        attributes = {k: v for k, v in sub.items() if k not in removed_attrs}
        return GetSubscriptionAttributesResponse(Attributes=attributes)

    def list_subscriptions(
        self, context: RequestContext, next_token: nextToken = None, **kwargs
    ) -> ListSubscriptionsResponse:
        store = self.get_store(context.account_id, context.region)
        subscriptions = [
            select_from_typed_dict(Subscription, sub) for sub in list(store.subscriptions.values())
        ]
        paginated_subscriptions = PaginatedList(subscriptions)
        page, next_token = paginated_subscriptions.get_page(
            token_generator=lambda x: get_next_page_token_from_arn(x["SubscriptionArn"]),
            page_size=100,
            next_token=next_token,
        )

        response = ListSubscriptionsResponse(Subscriptions=page)
        if next_token:
            response["NextToken"] = next_token
        return response

    def list_subscriptions_by_topic(
        self, context: RequestContext, topic_arn: topicARN, next_token: nextToken = None, **kwargs
    ) -> ListSubscriptionsByTopicResponse:
        self._get_topic(topic_arn, context)
        parsed_topic_arn = parse_and_validate_topic_arn(topic_arn)
        store = self.get_store(parsed_topic_arn["account"], parsed_topic_arn["region"])
        sns_subscriptions = store.get_topic_subscriptions(topic_arn)
        subscriptions = [select_from_typed_dict(Subscription, sub) for sub in sns_subscriptions]

        paginated_subscriptions = PaginatedList(subscriptions)
        page, next_token = paginated_subscriptions.get_page(
            token_generator=lambda x: get_next_page_token_from_arn(x["SubscriptionArn"]),
            page_size=100,
            next_token=next_token,
        )

        response = ListSubscriptionsResponse(Subscriptions=page)
        if next_token:
            response["NextToken"] = next_token
        return response

    def publish(
        self,
        context: RequestContext,
        message: String,
        topic_arn: topicARN = None,
        target_arn: String = None,
        phone_number: String = None,
        subject: String = None,
        message_structure: messageStructure = None,
        message_attributes: MessageAttributeMap = None,
        message_deduplication_id: String = None,
        message_group_id: String = None,
        **kwargs,
    ) -> PublishResponse:
        if subject == "":
            raise InvalidParameterException("Invalid parameter: Subject")
        if not message or all(not m for m in message):
            raise InvalidParameterException("Invalid parameter: Empty message")

        # TODO: check for topic + target + phone number at the same time?
        # TODO: more validation on phone, it might be opted out?
        if phone_number and not is_e164(phone_number):
            raise InvalidParameterException(
                f"Invalid parameter: PhoneNumber Reason: {phone_number} is not valid to publish to"
            )

        if message_attributes:
            validate_message_attributes(message_attributes)

        if get_total_publish_size(message, message_attributes) > MAXIMUM_MESSAGE_LENGTH:
            raise InvalidParameterException("Invalid parameter: Message too long")

        # for compatibility reasons, AWS allows users to use either TargetArn or TopicArn for publishing to a topic
        # use any of them for topic validation
        topic_or_target_arn = topic_arn or target_arn
        topic_model = None

        if is_fifo := (topic_or_target_arn and ".fifo" in topic_or_target_arn):
            if not message_group_id:
                raise InvalidParameterException(
                    "Invalid parameter: The MessageGroupId parameter is required for FIFO topics",
                )
            topic_model = self._get_topic(topic_or_target_arn, context, multiregion=False)
            if topic_model.content_based_deduplication == "false":
                if not message_deduplication_id:
                    raise InvalidParameterException(
                        "Invalid parameter: The topic should either have ContentBasedDeduplication enabled or MessageDeduplicationId provided explicitly",
                    )
        elif message_deduplication_id:
            # this is the first one to raise if both are set while the topic is not fifo
            raise InvalidParameterException(
                "Invalid parameter: MessageDeduplicationId Reason: The request includes MessageDeduplicationId parameter that is not valid for this topic type"
            )
        elif message_group_id:
            raise InvalidParameterException(
                "Invalid parameter: MessageGroupId Reason: The request includes MessageGroupId parameter that is not valid for this topic type"
            )
        is_endpoint_publish = target_arn and ":endpoint/" in target_arn
        if message_structure == "json":
            try:
                message = json.loads(message)
                # Keys in the JSON object that correspond to supported transport protocols must have
                # simple JSON string values.
                # Non-string values will cause the key to be ignored.
                message = {key: field for key, field in message.items() if isinstance(field, str)}
                # TODO: check no default key for direct TargetArn endpoint publish, need credentials
                # see example: https://docs.aws.amazon.com/sns/latest/dg/sns-send-custom-platform-specific-payloads-mobile-devices.html
                if "default" not in message and not is_endpoint_publish:
                    raise InvalidParameterException(
                        "Invalid parameter: Message Structure - No default entry in JSON message body"
                    )
            except json.JSONDecodeError:
                raise InvalidParameterException(
                    "Invalid parameter: Message Structure - JSON message body failed to parse"
                )

        if not phone_number:
            # use the account to get the store from the TopicArn (you can only publish in the same region as the topic)
            parsed_arn = parse_and_validate_topic_arn(topic_or_target_arn)
            store = self.get_store(account_id=parsed_arn["account"], region_name=context.region)
            moto_sns_backend = self.get_moto_backend(parsed_arn["account"], context.region)
            if is_endpoint_publish:
                if not (platform_endpoint := moto_sns_backend.platform_endpoints.get(target_arn)):
                    raise InvalidParameterException(
                        "Invalid parameter: TargetArn Reason: No endpoint found for the target arn specified"
                    )
                elif not platform_endpoint.enabled:
                    raise EndpointDisabledException("Endpoint is disabled")
            else:
                topic_model = self._get_topic(topic_or_target_arn, context, multiregion=False)
        else:
            # use the store from the request context
            store = self.get_store(account_id=context.account_id, region_name=context.region)

        message_ctx = SnsMessage(
            type=SnsMessageType.Notification,
            message=message,
            message_attributes=message_attributes,
            message_deduplication_id=message_deduplication_id,
            message_group_id=message_group_id,
            message_structure=message_structure,
            subject=subject,
            is_fifo=is_fifo,
        )
        publish_ctx = SnsPublishContext(
            message=message_ctx, store=store, request_headers=context.request.headers
        )

        if is_endpoint_publish:
            self._publisher.publish_to_application_endpoint(
                ctx=publish_ctx, endpoint_arn=target_arn
            )
        elif phone_number:
            self._publisher.publish_to_phone_number(ctx=publish_ctx, phone_number=phone_number)
        else:
            # beware if the subscription is FIFO, the order might not be guaranteed.
            # 2 quick call to this method in succession might not be executed in order in the executor?
            # TODO: test how this behaves in a FIFO context with a lot of threads.
            publish_ctx.topic_attributes |= vars(topic_model)
            self._publisher.publish_to_topic(publish_ctx, topic_or_target_arn)

        if is_fifo:
            return PublishResponse(
                MessageId=message_ctx.message_id, SequenceNumber=message_ctx.sequencer_number
            )

        return PublishResponse(MessageId=message_ctx.message_id)

    def subscribe(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        protocol: String,
        endpoint: String = None,
        attributes: SubscriptionAttributesMap = None,
        return_subscription_arn: boolean = None,
        **kwargs,
    ) -> SubscribeResponse:
        # TODO: check validation ordering
        parsed_topic_arn = parse_and_validate_topic_arn(topic_arn)
        store = self.get_store(account_id=parsed_topic_arn["account"], region_name=context.region)

        if topic_arn not in store.topic_subscriptions:
            raise NotFoundException("Topic does not exist")

        if not endpoint:
            # TODO: check AWS behaviour (because endpoint is optional)
            raise NotFoundException("Endpoint not specified in subscription")
        if protocol not in sns_constants.SNS_PROTOCOLS:
            raise InvalidParameterException(
                f"Invalid parameter: Amazon SNS does not support this protocol string: {protocol}"
            )
        elif protocol in ["http", "https"] and not endpoint.startswith(f"{protocol}://"):
            raise InvalidParameterException(
                "Invalid parameter: Endpoint must match the specified protocol"
            )
        elif protocol == "sms" and not is_e164(endpoint):
            raise InvalidParameterException(f"Invalid SMS endpoint: {endpoint}")

        elif protocol == "sqs":
            try:
                parse_arn(endpoint)
            except InvalidArnException:
                raise InvalidParameterException("Invalid parameter: SQS endpoint ARN")

        elif protocol == "application":
            # TODO: this is taken from moto, validate it
            moto_backend = self.get_moto_backend(
                account_id=parsed_topic_arn["account"], region_name=context.region
            )
            if endpoint not in moto_backend.platform_endpoints:
                raise NotFoundException("Endpoint does not exist")

        if ".fifo" in endpoint and ".fifo" not in topic_arn:
            raise InvalidParameterException(
                "Invalid parameter: Invalid parameter: Endpoint Reason: FIFO SQS Queues can not be subscribed to standard SNS topics"
            )

        sub_attributes = copy.deepcopy(attributes) if attributes else None
        if sub_attributes:
            for attr_name, attr_value in sub_attributes.items():
                validate_subscription_attribute(
                    attribute_name=attr_name,
                    attribute_value=attr_value,
                    topic_arn=topic_arn,
                    endpoint=endpoint,
                    is_subscribe_call=True,
                )
                if raw_msg_delivery := sub_attributes.get("RawMessageDelivery"):
                    sub_attributes["RawMessageDelivery"] = raw_msg_delivery.lower()

        # An endpoint may only be subscribed to a topic once. Subsequent
        # subscribe calls do nothing (subscribe is idempotent), except if its attributes are different.
        for existing_topic_subscription in store.topic_subscriptions.get(topic_arn, []):
            sub = store.subscriptions.get(existing_topic_subscription, {})
            if sub.get("Endpoint") == endpoint:
                if sub_attributes:
                    # validate the subscription attributes aren't different
                    for attr in sns_constants.VALID_SUBSCRIPTION_ATTR_NAME:
                        # if a new attribute is present and different from an existent one, raise
                        if (new_attr := sub_attributes.get(attr)) and sub.get(attr) != new_attr:
                            raise InvalidParameterException(
                                "Invalid parameter: Attributes Reason: Subscription already exists with different attributes"
                            )

                return SubscribeResponse(SubscriptionArn=sub["SubscriptionArn"])

        principal = sns_constants.DUMMY_SUBSCRIPTION_PRINCIPAL.format(
            partition=get_partition(context.region), account_id=context.account_id
        )
        subscription_arn = create_subscription_arn(topic_arn)
        subscription = SnsSubscription(
            # http://docs.aws.amazon.com/cli/latest/reference/sns/get-subscription-attributes.html
            TopicArn=topic_arn,
            Endpoint=endpoint,
            Protocol=protocol,
            SubscriptionArn=subscription_arn,
            PendingConfirmation="true",
            Owner=context.account_id,
            RawMessageDelivery="false",  # default value, will be overridden if set
            FilterPolicyScope="MessageAttributes",  # default value, will be overridden if set
            SubscriptionPrincipal=principal,  # dummy value, could be fetched with a call to STS?
        )
        if sub_attributes:
            subscription.update(sub_attributes)
            if "FilterPolicy" in sub_attributes:
                filter_policy = (
                    json.loads(sub_attributes["FilterPolicy"])
                    if sub_attributes["FilterPolicy"]
                    else None
                )
                if filter_policy:
                    validator = FilterPolicyValidator(
                        scope=subscription.get("FilterPolicyScope", "MessageAttributes"),
                        is_subscribe_call=True,
                    )
                    validator.validate_filter_policy(filter_policy)

                store.subscription_filter_policy[subscription_arn] = filter_policy

        store.subscriptions[subscription_arn] = subscription

        topic_subscriptions = store.topic_subscriptions.setdefault(topic_arn, [])
        topic_subscriptions.append(subscription_arn)

        # store the token and subscription arn
        # TODO: the token is a 288 hex char string
        subscription_token = encode_subscription_token_with_region(region=context.region)
        store.subscription_tokens[subscription_token] = subscription_arn

        response_subscription_arn = subscription_arn
        # Send out confirmation message for HTTP(S), fix for https://github.com/localstack/localstack/issues/881
        if protocol in ["http", "https"]:
            message_ctx = SnsMessage(
                type=SnsMessageType.SubscriptionConfirmation,
                token=subscription_token,
                message=f"You have chosen to subscribe to the topic {topic_arn}.\nTo confirm the subscription, visit the SubscribeURL included in this message.",
            )
            publish_ctx = SnsPublishContext(
                message=message_ctx,
                store=store,
                request_headers=context.request.headers,
                topic_attributes=vars(self._get_topic(topic_arn, context)),
            )
            self._publisher.publish_to_topic_subscriber(
                ctx=publish_ctx,
                topic_arn=topic_arn,
                subscription_arn=subscription_arn,
            )
            if not return_subscription_arn:
                response_subscription_arn = "pending confirmation"

        elif protocol not in ["email", "email-json"]:
            # Only HTTP(S) and email subscriptions are not auto validated
            # Except if the endpoint and the topic are not in the same AWS account, then you'd need to manually confirm
            # the subscription with the token
            # TODO: revisit for multi-account
            # TODO: test with AWS for email & email-json confirmation message
            # we need to add the following check:
            # if parsed_topic_arn["account"] == endpoint account (depending on the type, SQS, lambda, parse the arn)
            subscription["PendingConfirmation"] = "false"
            subscription["ConfirmationWasAuthenticated"] = "true"

        return SubscribeResponse(SubscriptionArn=response_subscription_arn)

    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: TagList, **kwargs
    ) -> TagResourceResponse:
        # each tag key must be unique
        # https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html#tag-best-practices
        unique_tag_keys = {tag["Key"] for tag in tags}
        if len(unique_tag_keys) < len(tags):
            raise InvalidParameterException("Invalid parameter: Duplicated keys are not allowed.")

        call_moto(context)
        store = self.get_store(context.account_id, context.region)
        existing_tags = store.sns_tags.get(resource_arn, [])

        def existing_tag_index(_item):
            for idx, tag in enumerate(existing_tags):
                if _item["Key"] == tag["Key"]:
                    return idx
            return None

        for item in tags:
            existing_index = existing_tag_index(item)
            if existing_index is None:
                existing_tags.append(item)
            else:
                existing_tags[existing_index] = item

        store.sns_tags[resource_arn] = existing_tags
        return TagResourceResponse()

    def delete_topic(self, context: RequestContext, topic_arn: topicARN, **kwargs) -> None:
        call_moto(context)
        parsed_arn = parse_and_validate_topic_arn(topic_arn)
        store = self.get_store(account_id=parsed_arn["account"], region_name=context.region)
        topic_subscriptions = store.topic_subscriptions.pop(topic_arn, [])
        for topic_sub in topic_subscriptions:
            store.subscriptions.pop(topic_sub, None)

        store.sns_tags.pop(topic_arn, None)

    def create_topic(
        self,
        context: RequestContext,
        name: topicName,
        attributes: TopicAttributesMap = None,
        tags: TagList = None,
        data_protection_policy: attributeValue = None,
        **kwargs,
    ) -> CreateTopicResponse:
        moto_response = call_moto(context)
        store = self.get_store(account_id=context.account_id, region_name=context.region)
        topic_arn = moto_response["TopicArn"]
        tag_resource_success = extract_tags(topic_arn, tags, True, store)
        if not tag_resource_success:
            raise InvalidParameterException(
                "Invalid parameter: Tags Reason: Topic already exists with different tags"
            )
        if tags:
            self.tag_resource(context=context, resource_arn=topic_arn, tags=tags)
        store.topic_subscriptions.setdefault(topic_arn, [])
        return CreateTopicResponse(TopicArn=topic_arn)


def is_raw_message_delivery(susbcriber):
    return susbcriber.get("RawMessageDelivery") in ("true", True, "True")


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
    if attribute_name not in sns_constants.VALID_SUBSCRIPTION_ATTR_NAME:
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


def validate_message_attributes(
    message_attributes: MessageAttributeMap, position: int | None = None
) -> None:
    """
    Validate the message attributes, and raises an exception if those do not follow AWS validation
    See: https://docs.aws.amazon.com/sns/latest/dg/sns-message-attributes.html
    Regex from: https://stackoverflow.com/questions/40718851/regex-that-does-not-allow-consecutive-dots
    :param message_attributes: the message attributes map for the message
    :param position: given to give the Batch Entry position if coming from `publishBatch`
    :raises: InvalidParameterValueException
    :return: None
    """
    for attr_name, attr in message_attributes.items():
        if len(attr_name) > 256:
            raise InvalidParameterValueException(
                "Length of message attribute name must be less than 256 bytes."
            )
        validate_message_attribute_name(attr_name)
        # `DataType` is a required field for MessageAttributeValue
        if (data_type := attr.get("DataType")) is None:
            if position:
                at = f"publishBatchRequestEntries.{position}.member.messageAttributes.{attr_name}.member.dataType"
            else:
                at = f"messageAttributes.{attr_name}.member.dataType"

            raise CommonServiceException(
                code="ValidationError",
                message=f"1 validation error detected: Value null at '{at}' failed to satisfy constraint: Member must not be null",
                sender_fault=True,
            )

        if data_type not in (
            "String",
            "Number",
            "Binary",
        ) and not sns_constants.ATTR_TYPE_REGEX.match(data_type):
            raise InvalidParameterValueException(
                f"The message attribute '{attr_name}' has an invalid message attribute type, the set of supported type prefixes is Binary, Number, and String."
            )
        if not any(attr_value.endswith("Value") for attr_value in attr):
            raise InvalidParameterValueException(
                f"The message attribute '{attr_name}' must contain non-empty message attribute value for message attribute type '{data_type}'."
            )

        value_key_data_type = "Binary" if data_type.startswith("Binary") else "String"
        value_key = f"{value_key_data_type}Value"
        if value_key not in attr:
            raise InvalidParameterValueException(
                f"The message attribute '{attr_name}' with type '{data_type}' must use field '{value_key_data_type}'."
            )
        elif not attr[value_key]:
            raise InvalidParameterValueException(
                f"The message attribute '{attr_name}' must contain non-empty message attribute value for message attribute type '{data_type}'.",
            )


def validate_message_attribute_name(name: str) -> None:
    """
    Validate the message attribute name with the specification of AWS.
    The message attribute name can contain the following characters: A-Z, a-z, 0-9, underscore(_), hyphen(-), and period (.). The name must not start or end with a period, and it should not have successive periods.
    :param name: message attribute name
    :raises InvalidParameterValueException: if the name does not conform to the spec
    """
    if not sns_constants.MSG_ATTR_NAME_REGEX.match(name):
        # find the proper exception
        if name[0] == ".":
            raise InvalidParameterValueException(
                "Invalid message attribute name starting with character '.' was found."
            )
        elif name[-1] == ".":
            raise InvalidParameterValueException(
                "Invalid message attribute name ending with character '.' was found."
            )

        for idx, char in enumerate(name):
            if char not in sns_constants.VALID_MSG_ATTR_NAME_CHARS:
                # change prefix from 0x to #x, without capitalizing the x
                hex_char = "#x" + hex(ord(char)).upper()[2:]
                raise InvalidParameterValueException(
                    f"Invalid non-alphanumeric character '{hex_char}' was found in the message attribute name. Can only include alphanumeric characters, hyphens, underscores, or dots."
                )
            # even if we go negative index, it will be covered by starting/ending with dot
            if char == "." and name[idx - 1] == ".":
                raise InvalidParameterValueException(
                    "Message attribute name can not have successive '.' character."
                )


def extract_tags(
    topic_arn: str, tags: TagList, is_create_topic_request: bool, store: SnsStore
) -> bool:
    existing_tags = list(store.sns_tags.get(topic_arn, []))
    # if this is none there is nothing to check
    if topic_arn in store.topic_subscriptions:
        if tags is None:
            tags = []
        for tag in tags:
            # this means topic already created with empty tags and when we try to create it
            # again with other tag value then it should fail according to aws documentation.
            if is_create_topic_request and existing_tags is not None and tag not in existing_tags:
                return False
    return True


def parse_and_validate_topic_arn(topic_arn: str | None) -> ArnData:
    topic_arn = topic_arn or ""
    try:
        return parse_arn(topic_arn)
    except InvalidArnException:
        count = len(topic_arn.split(":"))
        raise InvalidParameterException(
            f"Invalid parameter: TopicArn Reason: An ARN must have at least 6 elements, not {count}"
        )


def create_subscription_arn(topic_arn: str) -> str:
    # This is the format of a Subscription ARN
    # arn:aws:sns:us-west-2:123456789012:my-topic:8a21d249-4329-4871-acc6-7be709c6ea7f
    return f"{topic_arn}:{uuid4()}"


def encode_subscription_token_with_region(region: str) -> str:
    """
    Create a 64 characters Subscription Token with the region encoded
    :param region:
    :return: a subscription token with the region encoded
    """
    return ((region.encode() + b"/").hex() + short_uid() * 8)[:64]


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


def get_next_page_token_from_arn(resource_arn: str) -> str:
    return to_str(base64.b64encode(to_bytes(resource_arn)))


def _get_byte_size(payload: str | bytes) -> int:
    # Calculate the real length of the byte object if the object is a string
    return len(to_bytes(payload))


def get_total_publish_size(
    message_body: str, message_attributes: MessageAttributeMap | None
) -> int:
    size = _get_byte_size(message_body)
    if message_attributes:
        # https://docs.aws.amazon.com/sns/latest/dg/sns-message-attributes.html
        # All parts of the message attribute, including name, type, and value, are included in the message size
        # restriction, which is 256 KB.
        # iterate over the Keys and Attributes, adding the length of the Key to the length of all Attributes values
        # (DataType and StringValue or BinaryValue)
        size += sum(
            _get_byte_size(key) + sum(_get_byte_size(attr_value) for attr_value in attr.values())
            for key, attr in message_attributes.items()
        )

    return size


def register_sns_api_resource(router: Router):
    """Register the retrospection endpoints as internal LocalStack endpoints."""
    router.add(SNSServicePlatformEndpointMessagesApiResource())
    router.add(SNSServiceSMSMessagesApiResource())
    router.add(SNSServiceSubscriptionTokenApiResource())


def _format_messages(sent_messages: List[Dict[str, str]], validated_keys: List[str]):
    """
    This method format the messages to be more readable and undo the format change that was needed for Moto
    Should be removed once we refactor SNS.
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
    """Provides a REST API for retrospective access to platform endpoint messages sent via SNS.

    This is registered as a LocalStack internal HTTP resource.

    This endpoint accepts:
    - GET param `accountId`: selector for AWS account. If not specified, return fallback `000000000000` test ID
    - GET param `region`: selector for AWS `region`. If not specified, return default "us-east-1"
    - GET param `endpointArn`: filter for `endpointArn` resource in SNS
    - DELETE param `accountId`: selector for AWS account
    - DELETE param `region`: will delete saved messages for `region`
    - DELETE param `endpointArn`: will delete saved messages for `endpointArn`
    """

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
    """Provides a REST API for retrospective access to SMS messages sent via SNS.

    This is registered as a LocalStack internal HTTP resource.

    This endpoint accepts:
    - GET param `accountId`: selector for AWS account. If not specified, return fallback `000000000000` test ID
    - GET param `region`: selector for AWS `region`. If not specified, return default "us-east-1"
    - GET param `phoneNumber`: filter for `phoneNumber` resource in SNS
    """

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
            messages = [
                m for m in store.sms_messages if m.get("PhoneNumber") == filter_phone_number
            ]
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
            store.sms_messages = [
                m for m in store.sms_messages if m.get("PhoneNumber") != filter_phone_number
            ]
            return Response("", status=204)

        store.sms_messages.clear()
        return Response("", status=204)


class SNSServiceSubscriptionTokenApiResource(SNSInternalResource):
    resource_type = "subscription-token"
    """Provides a REST API for retrospective access to Subscription Confirmation Tokens to confirm subscriptions.
    Those are not sent for email, and sometimes inaccessible when working with external HTTPS endpoint which won't be
    able to reach your local host.

    This is registered as a LocalStack internal HTTP resource.

    This endpoint has the following parameter:
    - GET `subscription_arn`: `subscriptionArn`resource in SNS for which you want the SubscriptionToken
    """

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

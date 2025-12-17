import contextlib
import copy
import functools
import json
import logging
import re

from botocore.utils import InvalidArnException
from rolo import Request, Router, route

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.api.sns import (
    ActionsList,
    AmazonResourceName,
    BatchEntryIdsNotDistinctException,
    CheckIfPhoneNumberIsOptedOutResponse,
    ConfirmSubscriptionResponse,
    CreateEndpointResponse,
    CreatePlatformApplicationResponse,
    CreateTopicResponse,
    DelegatesList,
    Endpoint,
    EndpointDisabledException,
    GetDataProtectionPolicyResponse,
    GetEndpointAttributesResponse,
    GetPlatformApplicationAttributesResponse,
    GetSMSAttributesResponse,
    GetSubscriptionAttributesResponse,
    GetTopicAttributesResponse,
    InvalidParameterException,
    InvalidParameterValueException,
    ListEndpointsByPlatformApplicationResponse,
    ListPhoneNumbersOptedOutResponse,
    ListPlatformApplicationsResponse,
    ListString,
    ListSubscriptionsByTopicResponse,
    ListSubscriptionsResponse,
    ListTagsForResourceResponse,
    ListTopicsResponse,
    MapStringToString,
    MessageAttributeMap,
    NotFoundException,
    OptInPhoneNumberResponse,
    PhoneNumber,
    PlatformApplication,
    PublishBatchRequestEntryList,
    PublishBatchResponse,
    PublishBatchResultEntry,
    PublishResponse,
    SetSMSAttributesResponse,
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
    endpoint,
    label,
    message,
    messageStructure,
    nextToken,
    protocol,
    string,
    subject,
    subscriptionARN,
    topicARN,
    topicName,
)
from localstack.constants import AWS_REGION_US_EAST_1, DEFAULT_AWS_ACCOUNT_ID
from localstack.http import Response
from localstack.services.edge import ROUTER
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.sns.analytics import internal_api_calls
from localstack.services.sns.certificate import SNS_SERVER_CERT
from localstack.services.sns.constants import (
    ATTR_TYPE_REGEX,
    DUMMY_SUBSCRIPTION_PRINCIPAL,
    MAXIMUM_MESSAGE_LENGTH,
    MSG_ATTR_NAME_REGEX,
    PLATFORM_ENDPOINT_MSGS_ENDPOINT,
    SMS_MSGS_ENDPOINT,
    SNS_CERT_ENDPOINT,
    SNS_PROTOCOLS,
    SUBSCRIPTION_TOKENS_ENDPOINT,
    VALID_APPLICATION_PLATFORMS,
    VALID_MSG_ATTR_NAME_CHARS,
    VALID_POLICY_ACTIONS,
    VALID_SUBSCRIPTION_ATTR_NAME,
)
from localstack.services.sns.filter import FilterPolicyValidator
from localstack.services.sns.publisher import (
    PublishDispatcher,
    SnsBatchPublishContext,
    SnsPublishContext,
)
from localstack.services.sns.v2.models import (
    SMS_ATTRIBUTE_NAMES,
    SMS_DEFAULT_SENDER_REGEX,
    SMS_TYPES,
    EndpointAttributeNames,
    PlatformApplicationDetails,
    PlatformEndpoint,
    SnsMessage,
    SnsMessageType,
    SnsStore,
    SnsSubscription,
    Topic,
    sns_stores,
)
from localstack.services.sns.v2.utils import (
    create_platform_endpoint_arn,
    create_subscription_arn,
    encode_subscription_token_with_region,
    get_next_page_token_from_arn,
    get_region_from_subscription_token,
    get_topic_subscriptions,
    is_valid_e164_number,
    parse_and_validate_platform_application_arn,
    parse_and_validate_topic_arn,
    validate_subscription_attribute,
)
from localstack.state import StateVisitor
from localstack.utils.aws.arns import (
    extract_account_id_from_arn,
    extract_region_from_arn,
    get_partition,
    parse_arn,
    sns_platform_application_arn,
    sns_topic_arn,
)
from localstack.utils.collections import PaginatedList, select_from_typed_dict
from localstack.utils.strings import to_bytes

# set up logger
LOG = logging.getLogger(__name__)

SNS_TOPIC_NAME_PATTERN_FIFO = r"^[a-zA-Z0-9_-]{1,256}\.fifo$"
SNS_TOPIC_NAME_PATTERN = r"^[a-zA-Z0-9_-]{1,256}$"


class SnsProvider(SnsApi, ServiceLifecycleHook):
    def __init__(self) -> None:
        super().__init__()
        self._publisher = PublishDispatcher()
        self._signature_cert_pem: str = SNS_SERVER_CERT

    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(sns_stores)

    def on_before_stop(self):
        self._publisher.shutdown()

    def on_after_init(self):
        # Allow sent platform endpoint messages to be retrieved from the SNS endpoint
        register_sns_api_resource(ROUTER)
        # add the route to serve the certificate used to validate message signatures
        ROUTER.add(self.get_signature_cert_pem_file)

    @route(SNS_CERT_ENDPOINT, methods=["GET"])
    def get_signature_cert_pem_file(self, request: Request):
        # see http://sns-public-resources.s3.amazonaws.com/SNS_Message_Signing_Release_Note_Jan_25_2011.pdf
        # see https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html
        return Response(self._signature_cert_pem, 200)

    ## Topic Operations

    def create_topic(
        self,
        context: RequestContext,
        name: topicName,
        attributes: TopicAttributesMap | None = None,
        tags: TagList | None = None,
        data_protection_policy: attributeValue | None = None,
        **kwargs,
    ) -> CreateTopicResponse:
        store = self.get_store(context.account_id, context.region)
        topic_arn = sns_topic_arn(
            topic_name=name, region_name=context.region, account_id=context.account_id
        )
        topic: Topic = store.topics.get(topic_arn)
        attributes = attributes or {}
        if topic:
            attrs = topic["attributes"]
            for k, v in attributes.values():
                if not attrs.get(k) or not attrs.get(k) == v:
                    # TODO:
                    raise InvalidParameterException("Fix this Exception message and type")
            tag_resource_success = _check_matching_tags(topic_arn, tags, store)
            if not tag_resource_success:
                raise InvalidParameterException(
                    "Invalid parameter: Tags Reason: Topic already exists with different tags"
                )
            return CreateTopicResponse(TopicArn=topic_arn)

        if attributes.get("FifoTopic") and attributes["FifoTopic"].lower() == "true":
            fifo_match = re.match(SNS_TOPIC_NAME_PATTERN_FIFO, name)
            if not fifo_match:
                # TODO: check this with a separate test
                raise InvalidParameterException(
                    "Fifo Topic names must end with .fifo and must be made up of only uppercase and lowercase ASCII letters, numbers, underscores, and hyphens, and must be between 1 and 256 characters long."
                )
        else:
            # AWS does not seem to save explicit settings of fifo = false

            attributes.pop("FifoTopic", None)
            name_match = re.match(SNS_TOPIC_NAME_PATTERN, name)
            if not name_match:
                raise InvalidParameterException("Invalid parameter: Topic Name")

        attributes["EffectiveDeliveryPolicy"] = _create_default_effective_delivery_policy()

        topic = _create_topic(name=name, attributes=attributes, context=context)
        if tags:
            self.tag_resource(context=context, resource_arn=topic_arn, tags=tags)

        store.topics[topic_arn] = topic

        return CreateTopicResponse(TopicArn=topic_arn)

    def get_topic_attributes(
        self, context: RequestContext, topic_arn: topicARN, **kwargs
    ) -> GetTopicAttributesResponse:
        topic: Topic = self._get_topic(arn=topic_arn, context=context)
        if topic:
            attributes = topic["attributes"]
            return GetTopicAttributesResponse(Attributes=attributes)
        else:
            raise NotFoundException("Topic does not exist")

    def delete_topic(self, context: RequestContext, topic_arn: topicARN, **kwargs) -> None:
        store = self.get_store(context.account_id, context.region)

        store.topics.pop(topic_arn, None)

    def list_topics(
        self, context: RequestContext, next_token: nextToken | None = None, **kwargs
    ) -> ListTopicsResponse:
        store = self.get_store(context.account_id, context.region)
        topics = [{"TopicArn": t["arn"]} for t in list(store.topics.values())]
        topics = PaginatedList(topics)
        page, nxt = topics.get_page(
            token_generator=lambda x: get_next_page_token_from_arn(x["TopicArn"]),
            next_token=next_token,
            page_size=100,
        )
        topics = {"Topics": page, "NextToken": nxt}
        return ListTopicsResponse(**topics)

    def set_topic_attributes(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        attribute_name: attributeName,
        attribute_value: attributeValue | None = None,
        **kwargs,
    ) -> None:
        topic: Topic = self._get_topic(arn=topic_arn, context=context)
        if attribute_name == "FifoTopic":
            raise InvalidParameterException("Invalid parameter: AttributeName")
        topic["attributes"][attribute_name] = attribute_value

    ## Subscribe operations

    def subscribe(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        protocol: protocol,
        endpoint: endpoint | None = None,
        attributes: SubscriptionAttributesMap | None = None,
        return_subscription_arn: bool | None = None,
        **kwargs,
    ) -> SubscribeResponse:
        parsed_topic_arn = parse_and_validate_topic_arn(topic_arn)
        if context.region != parsed_topic_arn["region"]:
            raise InvalidParameterException("Invalid parameter: TopicArn")

        store = self.get_store(account_id=parsed_topic_arn["account"], region=context.region)

        topic = self._get_topic(arn=topic_arn, context=context)
        topic_subscriptions = topic["subscriptions"]
        if not endpoint:
            # TODO: check AWS behaviour (because endpoint is optional)
            raise NotFoundException("Endpoint not specified in subscription")
        if protocol not in SNS_PROTOCOLS:
            raise InvalidParameterException(
                f"Invalid parameter: Amazon SNS does not support this protocol string: {protocol}"
            )
        elif protocol in ["http", "https"] and not endpoint.startswith(f"{protocol}://"):
            raise InvalidParameterException(
                "Invalid parameter: Endpoint must match the specified protocol"
            )
        elif protocol == "sms" and not is_valid_e164_number(endpoint):
            raise InvalidParameterException(f"Invalid SMS endpoint: {endpoint}")

        elif protocol == "sqs":
            try:
                parse_arn(endpoint)
            except InvalidArnException:
                raise InvalidParameterException("Invalid parameter: SQS endpoint ARN")

        elif protocol == "application":
            # TODO: Validate exact behaviour
            try:
                parse_arn(endpoint)
            except InvalidArnException:
                raise InvalidParameterException("Invalid parameter: ApplicationEndpoint ARN")

        if ".fifo" in endpoint and ".fifo" not in topic_arn:
            # TODO: move to sqs protocol block if possible
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
        for existing_topic_subscription in topic_subscriptions:
            sub = store.subscriptions.get(existing_topic_subscription, {})
            if sub.get("Endpoint") == endpoint:
                if sub_attributes:
                    # validate the subscription attributes aren't different
                    for attr in VALID_SUBSCRIPTION_ATTR_NAME:
                        # if a new attribute is present and different from an existent one, raise
                        if (new_attr := sub_attributes.get(attr)) and sub.get(attr) != new_attr:
                            raise InvalidParameterException(
                                "Invalid parameter: Attributes Reason: Subscription already exists with different attributes"
                            )

                return SubscribeResponse(SubscriptionArn=sub["SubscriptionArn"])
        principal = DUMMY_SUBSCRIPTION_PRINCIPAL.format(
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
                topic_attributes=topic["attributes"],
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

    def unsubscribe(
        self, context: RequestContext, subscription_arn: subscriptionARN, **kwargs
    ) -> None:
        if subscription_arn is None:
            raise InvalidParameterException(
                "Invalid parameter: SubscriptionArn Reason: no value for required parameter",
            )
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

        store = self.get_store(account_id=account_id, region=region_name)
        if count == 6 and subscription_arn not in store.subscriptions:
            raise InvalidParameterException("Invalid parameter: SubscriptionId")

        # TODO: here was a moto_backend.unsubscribe call, check correct functionality and remove this comment
        #  before switching to v2 for production

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
            publish_ctx = SnsPublishContext(
                message=message_ctx,
                store=store,
                request_headers=context.request.headers,
                # TODO: add the topic attributes once we ported them from moto to LocalStack
                # topic_attributes=vars(moto_topic),
            )
            self._publisher.publish_to_topic_subscriber(
                publish_ctx,
                topic_arn=subscription["TopicArn"],
                subscription_arn=subscription_arn,
            )

        with contextlib.suppress(KeyError):
            store.topics[subscription["TopicArn"]]["subscriptions"].remove(subscription_arn)
        store.subscription_filter_policy.pop(subscription_arn, None)
        store.subscriptions.pop(subscription_arn, None)

    def get_subscription_attributes(
        self, context: RequestContext, subscription_arn: subscriptionARN, **kwargs
    ) -> GetSubscriptionAttributesResponse:
        store = self.get_store(account_id=context.account_id, region=context.region)
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

    def set_subscription_attributes(
        self,
        context: RequestContext,
        subscription_arn: subscriptionARN,
        attribute_name: attributeName,
        attribute_value: attributeValue = None,
        **kwargs,
    ) -> None:
        store = self.get_store(account_id=context.account_id, region=context.region)
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

        store = self.get_store(account_id=parsed_arn["account"], region=parsed_arn["region"])

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
        self._get_topic(topic_arn, context)  # for validation purposes only
        parsed_topic_arn = parse_and_validate_topic_arn(topic_arn)
        store = self.get_store(parsed_topic_arn["account"], parsed_topic_arn["region"])
        subscriptions = get_topic_subscriptions(store, topic_arn)

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

    #
    # Publish
    #

    def publish(
        self,
        context: RequestContext,
        message: message,
        topic_arn: topicARN | None = None,
        target_arn: String | None = None,
        phone_number: PhoneNumber | None = None,
        subject: subject | None = None,
        message_structure: messageStructure | None = None,
        message_attributes: MessageAttributeMap | None = None,
        message_deduplication_id: String | None = None,
        message_group_id: String | None = None,
        **kwargs,
    ) -> PublishResponse:
        if subject == "":
            raise InvalidParameterException("Invalid parameter: Subject")
        if not message or all(not m for m in message):
            raise InvalidParameterException("Invalid parameter: Empty message")

        # TODO: check for topic + target + phone number at the same time?
        # TODO: more validation on phone, it might be opted out?
        if phone_number and not is_valid_e164_number(phone_number):
            raise InvalidParameterException(
                f"Invalid parameter: PhoneNumber Reason: {phone_number} is not valid to publish to"
            )

        if message_attributes:
            _validate_message_attributes(message_attributes)

        if _get_total_publish_size(message, message_attributes) > MAXIMUM_MESSAGE_LENGTH:
            raise InvalidParameterException("Invalid parameter: Message too long")

        # for compatibility reasons, AWS allows users to use either TargetArn or TopicArn for publishing to a topic
        # use any of them for topic validation
        topic_or_target_arn = topic_arn or target_arn
        topic = None

        if is_fifo := (topic_or_target_arn and ".fifo" in topic_or_target_arn):
            if not message_group_id:
                raise InvalidParameterException(
                    "Invalid parameter: The MessageGroupId parameter is required for FIFO topics",
                )
            topic = self._get_topic(topic_or_target_arn, context)
            if topic["attributes"]["ContentBasedDeduplication"] == "false":
                if not message_deduplication_id:
                    raise InvalidParameterException(
                        "Invalid parameter: The topic should either have ContentBasedDeduplication enabled or MessageDeduplicationId provided explicitly",
                    )
        elif message_deduplication_id:
            # this is the first one to raise if both are set while the topic is not fifo
            raise InvalidParameterException(
                "Invalid parameter: MessageDeduplicationId Reason: The request includes MessageDeduplicationId parameter that is not valid for this topic type"
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
            store = self.get_store(account_id=parsed_arn["account"], region=context.region)
            if is_endpoint_publish:
                if not (platform_endpoint := store.platform_endpoints.get(target_arn)):
                    raise InvalidParameterException(
                        "Invalid parameter: TargetArn Reason: No endpoint found for the target arn specified"
                    )
                elif (
                    not platform_endpoint.platform_endpoint["Attributes"]
                    .get("Enabled", "false")
                    .lower()
                    == "true"
                ):
                    raise EndpointDisabledException("Endpoint is disabled")
            else:
                topic = self._get_topic(topic_or_target_arn, context)
        else:
            # use the store from the request context
            store = self.get_store(account_id=context.account_id, region=context.region)

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
            publish_ctx.topic_attributes |= topic["attributes"]
            self._publisher.publish_to_topic(publish_ctx, topic_or_target_arn)

        if is_fifo:
            return PublishResponse(
                MessageId=message_ctx.message_id, SequenceNumber=message_ctx.sequencer_number
            )

        return PublishResponse(MessageId=message_ctx.message_id)

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
        store = self.get_store(account_id=parsed_arn["account"], region=context.region)
        topic = self._get_topic(topic_arn, context)
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
                # if a message contains non-valid message attributes, it
                # will fail for the first non-valid message encountered, and raise ParameterValueInvalid
                _validate_message_attributes(message_attributes, position=entry_index)

            total_batch_size += _get_total_publish_size(message_payload, message_attributes)

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

            if is_fifo := (topic_arn.endswith(".fifo")):
                if not all("MessageGroupId" in entry for entry in publish_batch_request_entries):
                    raise InvalidParameterException(
                        "Invalid parameter: The MessageGroupId parameter is required for FIFO topics"
                    )
                if topic["attributes"]["ContentBasedDeduplication"] == "false":
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
            topic_attributes=topic["attributes"],
        )
        self._publisher.publish_batch_to_topic(publish_ctx, topic_arn)

        return response

    #
    # PlatformApplications
    #
    def create_platform_application(
        self,
        context: RequestContext,
        name: String,
        platform: String,
        attributes: MapStringToString,
        **kwargs,
    ) -> CreatePlatformApplicationResponse:
        _validate_platform_application_name(name)
        if platform not in VALID_APPLICATION_PLATFORMS:
            raise InvalidParameterException(
                f"Invalid parameter: Platform Reason: {platform} is not supported"
            )

        _validate_platform_application_attributes(attributes)

        # attribute validation specific to create_platform_application
        if "PlatformCredential" in attributes and "PlatformPrincipal" not in attributes:
            raise InvalidParameterException(
                "Invalid parameter: Attributes Reason: PlatformCredential attribute provided without PlatformPrincipal"
            )

        elif "PlatformPrincipal" in attributes and "PlatformCredential" not in attributes:
            raise InvalidParameterException(
                "Invalid parameter: Attributes Reason: PlatformPrincipal attribute provided without PlatformCredential"
            )

        store = self.get_store(context.account_id, context.region)
        # We are not validating the access data here like AWS does (against ADM and the like)
        attributes.pop("PlatformPrincipal")
        attributes.pop("PlatformCredential")
        _attributes = {"Enabled": "true"}
        _attributes.update(attributes)
        application_arn = sns_platform_application_arn(
            platform_application_name=name,
            platform=platform,
            account_id=context.account_id,
            region_name=context.region,
        )
        platform_application_details = PlatformApplicationDetails(
            platform_application=PlatformApplication(
                PlatformApplicationArn=application_arn,
                Attributes=_attributes,
            ),
            platform_endpoints={},
        )
        store.platform_applications[application_arn] = platform_application_details

        return platform_application_details.platform_application

    def delete_platform_application(
        self, context: RequestContext, platform_application_arn: String, **kwargs
    ) -> None:
        store = self.get_store(context.account_id, context.region)
        store.platform_applications.pop(platform_application_arn, None)
        # TODO: if the platform had endpoints, should we remove them from the store? There is no way to list
        #   endpoints without an application, so this is impossible to check the state of AWS here

    def list_platform_applications(
        self, context: RequestContext, next_token: String | None = None, **kwargs
    ) -> ListPlatformApplicationsResponse:
        store = self.get_store(context.account_id, context.region)
        platform_applications = store.platform_applications.values()
        paginated_applications = PaginatedList(platform_applications)
        page, token = paginated_applications.get_page(
            token_generator=lambda x: get_next_page_token_from_arn(x["PlatformApplicationArn"]),
            page_size=100,
            next_token=next_token,
        )

        response = ListPlatformApplicationsResponse(
            PlatformApplications=[platform_app.platform_application for platform_app in page]
        )
        if token:
            response["NextToken"] = token
        return response

    def get_platform_application_attributes(
        self, context: RequestContext, platform_application_arn: String, **kwargs
    ) -> GetPlatformApplicationAttributesResponse:
        platform_application = self._get_platform_application(platform_application_arn, context)
        attributes = platform_application["Attributes"]
        return GetPlatformApplicationAttributesResponse(Attributes=attributes)

    def set_platform_application_attributes(
        self,
        context: RequestContext,
        platform_application_arn: String,
        attributes: MapStringToString,
        **kwargs,
    ) -> None:
        parse_and_validate_platform_application_arn(platform_application_arn)
        _validate_platform_application_attributes(attributes)

        platform_application = self._get_platform_application(platform_application_arn, context)
        platform_application["Attributes"].update(attributes)

    #
    # Platform Endpoints
    #

    def create_platform_endpoint(
        self,
        context: RequestContext,
        platform_application_arn: String,
        token: String,
        custom_user_data: String | None = None,
        attributes: MapStringToString | None = None,
        **kwargs,
    ) -> CreateEndpointResponse:
        store = self.get_store(context.account_id, context.region)
        application = store.platform_applications.get(platform_application_arn)
        if not application:
            raise NotFoundException("PlatformApplication does not exist")
        endpoint_arn = application.platform_endpoints.get(token, {})
        attributes = attributes or {}
        _validate_endpoint_attributes(attributes, allow_empty=True)
        # CustomUserData can be specified both in attributes and as parameter. Attributes take precedence
        attributes.setdefault(EndpointAttributeNames.CUSTOM_USER_DATA, custom_user_data)
        _attributes = {"Enabled": "true", "Token": token, **attributes}
        if endpoint_arn and (
            platform_endpoint_details := store.platform_endpoints.get(endpoint_arn)
        ):
            # endpoint for that application with that particular token already exists
            if not platform_endpoint_details.platform_endpoint["Attributes"] == _attributes:
                raise InvalidParameterException(
                    f"Invalid parameter: Token Reason: Endpoint {endpoint_arn} already exists with the same Token, but different attributes."
                )
            else:
                return CreateEndpointResponse(EndpointArn=endpoint_arn)

        endpoint_arn = create_platform_endpoint_arn(platform_application_arn)
        platform_endpoint = PlatformEndpoint(
            platform_application_arn=endpoint_arn,
            platform_endpoint=Endpoint(
                Attributes=_attributes,
                EndpointArn=endpoint_arn,
            ),
        )
        store.platform_endpoints[endpoint_arn] = platform_endpoint
        application.platform_endpoints[token] = endpoint_arn

        return CreateEndpointResponse(EndpointArn=endpoint_arn)

    def delete_endpoint(self, context: RequestContext, endpoint_arn: String, **kwargs) -> None:
        store = self.get_store(context.account_id, context.region)
        platform_endpoint_details = store.platform_endpoints.pop(endpoint_arn, None)
        if platform_endpoint_details:
            platform_application = store.platform_applications.get(
                platform_endpoint_details.platform_application_arn
            )
            if platform_application:
                platform_endpoint = platform_endpoint_details.platform_endpoint
                platform_application.platform_endpoints.pop(
                    platform_endpoint["Attributes"]["Token"], None
                )

    def list_endpoints_by_platform_application(
        self,
        context: RequestContext,
        platform_application_arn: String,
        next_token: String | None = None,
        **kwargs,
    ) -> ListEndpointsByPlatformApplicationResponse:
        store = self.get_store(context.account_id, context.region)
        platform_application = store.platform_applications.get(platform_application_arn)
        if not platform_application:
            raise NotFoundException("PlatformApplication does not exist")
        endpoint_arns = platform_application.platform_endpoints.values()
        paginated_endpoint_arns = PaginatedList(endpoint_arns)
        page, token = paginated_endpoint_arns.get_page(
            token_generator=lambda x: get_next_page_token_from_arn(x),
            page_size=100,
            next_token=next_token,
        )

        response = ListEndpointsByPlatformApplicationResponse(
            Endpoints=[
                store.platform_endpoints[endpoint_arn].platform_endpoint
                for endpoint_arn in page
                if endpoint_arn in store.platform_endpoints
            ]
        )
        if token:
            response["NextToken"] = token
        return response

    def get_endpoint_attributes(
        self, context: RequestContext, endpoint_arn: String, **kwargs
    ) -> GetEndpointAttributesResponse:
        store = self.get_store(context.account_id, context.region)
        platform_endpoint_details = store.platform_endpoints.get(endpoint_arn)
        if not platform_endpoint_details:
            raise NotFoundException("Endpoint does not exist")
        attributes = platform_endpoint_details.platform_endpoint["Attributes"]
        return GetEndpointAttributesResponse(Attributes=attributes)

    def set_endpoint_attributes(
        self, context: RequestContext, endpoint_arn: String, attributes: MapStringToString, **kwargs
    ) -> None:
        store = self.get_store(context.account_id, context.region)
        platform_endpoint_details = store.platform_endpoints.get(endpoint_arn)
        if not platform_endpoint_details:
            raise NotFoundException("Endpoint does not exist")
        _validate_endpoint_attributes(attributes)
        attributes = attributes or {}
        platform_endpoint_details.platform_endpoint["Attributes"].update(attributes)

    #
    # Sms operations
    #

    def set_sms_attributes(
        self, context: RequestContext, attributes: MapStringToString, **kwargs
    ) -> SetSMSAttributesResponse:
        store = self.get_store(context.account_id, context.region)
        _validate_sms_attributes(attributes)
        _set_sms_attribute_default(store)
        store.sms_attributes.update(attributes or {})
        return SetSMSAttributesResponse()

    def get_sms_attributes(
        self, context: RequestContext, attributes: ListString | None = None, **kwargs
    ) -> GetSMSAttributesResponse:
        store = self.get_store(context.account_id, context.region)
        _set_sms_attribute_default(store)
        store_attributes = store.sms_attributes
        return_attributes = {}
        for k, v in store_attributes.items():
            if not attributes or k in attributes:
                return_attributes[k] = store_attributes[k]

        return GetSMSAttributesResponse(attributes=return_attributes)

    #
    # Phone number operations
    #

    def check_if_phone_number_is_opted_out(
        self, context: RequestContext, phone_number: PhoneNumber, **kwargs
    ) -> CheckIfPhoneNumberIsOptedOutResponse:
        store = sns_stores[context.account_id][context.region]
        return CheckIfPhoneNumberIsOptedOutResponse(
            isOptedOut=phone_number in store.PHONE_NUMBERS_OPTED_OUT
        )

    def list_phone_numbers_opted_out(
        self, context: RequestContext, next_token: string | None = None, **kwargs
    ) -> ListPhoneNumbersOptedOutResponse:
        store = self.get_store(context.account_id, context.region)
        numbers_opted_out = PaginatedList(store.PHONE_NUMBERS_OPTED_OUT)
        page, nxt = numbers_opted_out.get_page(
            token_generator=lambda x: x,
            next_token=next_token,
            page_size=100,
        )
        phone_numbers = {"phoneNumbers": page, "nextToken": nxt}
        return ListPhoneNumbersOptedOutResponse(**phone_numbers)

    def opt_in_phone_number(
        self, context: RequestContext, phone_number: PhoneNumber, **kwargs
    ) -> OptInPhoneNumberResponse:
        store = self.get_store(context.account_id, context.region)
        if phone_number in store.PHONE_NUMBERS_OPTED_OUT:
            store.PHONE_NUMBERS_OPTED_OUT.remove(phone_number)
        return OptInPhoneNumberResponse()

    #
    # Permission operations
    #

    def add_permission(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        label: label,
        aws_account_id: DelegatesList,
        action_name: ActionsList,
        **kwargs,
    ) -> None:
        topic: Topic = self._get_topic(topic_arn, context)
        policy = json.loads(topic["attributes"]["Policy"])
        statement = next(
            (statement for statement in policy["Statement"] if statement["Sid"] == label),
            None,
        )

        if statement:
            raise InvalidParameterException("Invalid parameter: Statement already exists")

        if any(action not in VALID_POLICY_ACTIONS for action in action_name):
            raise InvalidParameterException(
                "Invalid parameter: Policy statement action out of service scope!"
            )

        principals = [
            f"arn:{get_partition(context.region)}:iam::{account_id}:root"
            for account_id in aws_account_id
        ]
        actions = [f"SNS:{action}" for action in action_name]

        statement = {
            "Sid": label,
            "Effect": "Allow",
            "Principal": {"AWS": principals[0] if len(principals) == 1 else principals},
            "Action": actions[0] if len(actions) == 1 else actions,
            "Resource": topic_arn,
        }

        policy["Statement"].append(statement)
        topic["attributes"]["Policy"] = json.dumps(policy)

    def remove_permission(
        self, context: RequestContext, topic_arn: topicARN, label: label, **kwargs
    ) -> None:
        topic = self._get_topic(topic_arn, context)
        policy = json.loads(topic["attributes"]["Policy"])
        statements = policy["Statement"]
        statements = [statement for statement in statements if statement["Sid"] != label]
        policy["Statement"] = statements
        topic["attributes"]["Policy"] = json.dumps(policy)

    #
    # Data Protection Policy operations
    #

    def get_data_protection_policy(
        self, context: RequestContext, resource_arn: topicARN, **kwargs
    ) -> GetDataProtectionPolicyResponse:
        topic = self._get_topic(resource_arn, context)
        return GetDataProtectionPolicyResponse(
            DataProtectionPolicy=topic.get("data_protection_policy")
        )

    def put_data_protection_policy(
        self,
        context: RequestContext,
        resource_arn: topicARN,
        data_protection_policy: attributeValue,
        **kwargs,
    ) -> None:
        topic = self._get_topic(resource_arn, context)
        topic["data_protection_policy"] = data_protection_policy

    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, **kwargs
    ) -> ListTagsForResourceResponse:
        store = sns_stores[context.account_id][context.region]
        tags = store.TAGS.list_tags_for_resource(resource_arn)
        return ListTagsForResourceResponse(Tags=tags.get("Tags"))

    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: TagList, **kwargs
    ) -> TagResourceResponse:
        unique_tag_keys = {tag["Key"] for tag in tags}
        if len(unique_tag_keys) < len(tags):
            raise InvalidParameterException("Invalid parameter: Duplicated keys are not allowed.")
        store = sns_stores[context.account_id][context.region]
        store.TAGS.tag_resource(resource_arn, tags)
        return TagResourceResponse()

    def untag_resource(
        self,
        context: RequestContext,
        resource_arn: AmazonResourceName,
        tag_keys: TagKeyList,
        **kwargs,
    ) -> UntagResourceResponse:
        store = sns_stores[context.account_id][context.region]
        store.TAGS.untag_resource(resource_arn, tag_keys)
        return UntagResourceResponse()

    @staticmethod
    def get_store(account_id: str, region: str) -> SnsStore:
        return sns_stores[account_id][region]

    @staticmethod
    def _get_topic(arn: str, context: RequestContext, multi_region: bool = False) -> Topic:
        """
        :param arn: the Topic ARN
        :param context: the RequestContext of the request
        :return: the model Topic
        """
        arn_data = parse_and_validate_topic_arn(arn)
        if not multi_region and context.region != arn_data["region"]:
            raise InvalidParameterException("Invalid parameter: TopicArn")
        try:
            store = SnsProvider.get_store(context.account_id, context.region)
            return store.topics[arn]
        except KeyError:
            raise NotFoundException("Topic does not exist")

    @staticmethod
    def _get_platform_application(
        platform_application_arn: str, context: RequestContext
    ) -> PlatformApplication:
        parse_and_validate_platform_application_arn(platform_application_arn)
        try:
            store = SnsProvider.get_store(context.account_id, context.region)
            return store.platform_applications[platform_application_arn].platform_application
        except KeyError:
            raise NotFoundException("PlatformApplication does not exist")


def _create_topic(name: str, attributes: dict, context: RequestContext) -> Topic:
    topic_arn = sns_topic_arn(
        topic_name=name, region_name=context.region, account_id=context.account_id
    )
    topic: Topic = {
        "name": name,
        "arn": topic_arn,
        "attributes": {},
        "subscriptions": [],
    }
    attrs = _default_attributes(topic, context)
    attrs.update(attributes or {})
    topic["attributes"] = attrs

    return topic


def _default_attributes(topic: Topic, context: RequestContext) -> TopicAttributesMap:
    default_attributes = {
        "DisplayName": "",
        "Owner": context.account_id,
        "Policy": _create_default_topic_policy(topic, context),
        "SubscriptionsConfirmed": "0",
        "SubscriptionsDeleted": "0",
        "SubscriptionsPending": "0",
        "TopicArn": topic["arn"],
    }
    if topic["name"].endswith(".fifo"):
        default_attributes.update(
            {
                "ContentBasedDeduplication": "false",
                "FifoTopic": "false",
            }
        )
    return default_attributes


def _create_default_effective_delivery_policy():
    return json.dumps(
        {
            "http": {
                "defaultHealthyRetryPolicy": {
                    "minDelayTarget": 20,
                    "maxDelayTarget": 20,
                    "numRetries": 3,
                    "numMaxDelayRetries": 0,
                    "numNoDelayRetries": 0,
                    "numMinDelayRetries": 0,
                    "backoffFunction": "linear",
                },
                "disableSubscriptionOverrides": False,
                "defaultRequestPolicy": {"headerContentType": "text/plain; charset=UTF-8"},
            }
        }
    )


def _create_default_topic_policy(topic: Topic, context: RequestContext) -> str:
    return json.dumps(
        {
            "Version": "2008-10-17",
            "Id": "__default_policy_ID",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Sid": "__default_statement_ID",
                    "Principal": {"AWS": "*"},
                    "Action": [
                        "SNS:GetTopicAttributes",
                        "SNS:SetTopicAttributes",
                        "SNS:AddPermission",
                        "SNS:RemovePermission",
                        "SNS:DeleteTopic",
                        "SNS:Subscribe",
                        "SNS:ListSubscriptionsByTopic",
                        "SNS:Publish",
                    ],
                    "Resource": topic["arn"],
                    "Condition": {"StringEquals": {"AWS:SourceOwner": context.account_id}},
                }
            ],
        }
    )


def _validate_message_attributes(
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
        _validate_message_attribute_name(attr_name)
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
        ) and not ATTR_TYPE_REGEX.match(data_type):
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


def _validate_message_attribute_name(name: str) -> None:
    """
    Validate the message attribute name with the specification of AWS.
    The message attribute name can contain the following characters: A-Z, a-z, 0-9, underscore(_), hyphen(-), and period (.). The name must not start or end with a period, and it should not have successive periods.
    :param name: message attribute name
    :raises InvalidParameterValueException: if the name does not conform to the spec
    """
    if not MSG_ATTR_NAME_REGEX.match(name):
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
            if char not in VALID_MSG_ATTR_NAME_CHARS:
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


def _validate_platform_application_name(name: str) -> None:
    reason = ""
    if not name:
        reason = "cannot be empty"
    elif not re.match(r"^.{0,256}$", name):
        reason = "must be at most 256 characters long"
    elif not re.match(r"^[A-Za-z0-9._-]+$", name):
        reason = "must contain only characters 'a'-'z', 'A'-'Z', '0'-'9', '_', '-', and '.'"

    if reason:
        raise InvalidParameterException(f"Invalid parameter: {name} Reason: {reason}")


def _validate_platform_application_attributes(attributes: dict) -> None:
    _check_empty_attributes(attributes)


def _check_empty_attributes(attributes: dict) -> None:
    if not attributes:
        raise CommonServiceException(
            code="ValidationError",
            message="1 validation error detected: Value null at 'attributes' failed to satisfy constraint: Member must not be null",
            sender_fault=True,
        )


def _validate_endpoint_attributes(attributes: dict, allow_empty: bool = False) -> None:
    if not allow_empty:
        _check_empty_attributes(attributes)
    for key in attributes:
        if key not in EndpointAttributeNames:
            raise InvalidParameterException(
                f"Invalid parameter: Attributes Reason: Invalid attribute name: {key}"
            )
    if len(attributes.get(EndpointAttributeNames.CUSTOM_USER_DATA, "")) > 2048:
        raise InvalidParameterException(
            "Invalid parameter: Attributes Reason: Invalid value for attribute: CustomUserData: must be at most 2048 bytes long in UTF-8 encoding"
        )


def _validate_sms_attributes(attributes: dict) -> None:
    for k, v in attributes.items():
        if k not in SMS_ATTRIBUTE_NAMES:
            raise InvalidParameterException(f"{k} is not a valid attribute")
    default_send_id = attributes.get("DefaultSendID")
    if default_send_id and not re.match(SMS_DEFAULT_SENDER_REGEX, default_send_id):
        raise InvalidParameterException("DefaultSendID is not a valid attribute")
    sms_type = attributes.get("DefaultSMSType")
    if sms_type and sms_type not in SMS_TYPES:
        raise InvalidParameterException("DefaultSMSType is invalid")


def _set_sms_attribute_default(store: SnsStore) -> None:
    # TODO: don't call this on every sms attribute crud api call
    store.sms_attributes.setdefault("MonthlySpendLimit", "1")


def _check_matching_tags(topic_arn: str, tags: TagList | None, store: SnsStore) -> bool:
    """
    Checks if a topic to be created doesn't already exist with different tags
    :param topic_arn: Arn of the topic
    :param tags: Tags to be checked
    :param store: Store object that holds the topics and tags
    :return: False if there is a mismatch in tags, True otherwise
    """
    existing_tags = store.TAGS.list_tags_for_resource(topic_arn)["Tags"]
    # if this is none there is nothing to check
    if topic_arn in store.topics:
        if tags is None:
            tags = []
        for tag in tags:
            # this means topic already created with empty tags and when we try to create it
            # again with other tag value then it should fail according to aws documentation.
            if existing_tags is not None and tag not in existing_tags:
                return False
    return True


def _get_total_publish_size(
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


def _get_byte_size(payload: str | bytes) -> int:
    # Calculate the real length of the byte object if the object is a string
    return len(to_bytes(payload))


def _register_sns_api_resource(router: Router):
    """Register the retrospection endpoints as internal LocalStack endpoints."""
    router.add(SNSServicePlatformEndpointMessagesApiResource())
    router.add(SNSServiceSMSMessagesApiResource())
    router.add(SNSServiceSubscriptionTokenApiResource())


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

    @route(PLATFORM_ENDPOINT_MSGS_ENDPOINT, methods=["GET"])
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

    @route(PLATFORM_ENDPOINT_MSGS_ENDPOINT, methods=["DELETE"])
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


def register_sns_api_resource(router: Router):
    """Register the retrospection endpoints as internal LocalStack endpoints."""
    router.add(SNSServicePlatformEndpointMessagesApiResource())
    router.add(SNSServiceSMSMessagesApiResource())
    router.add(SNSServiceSubscriptionTokenApiResource())


def _format_messages(sent_messages: list[dict[str, str]], validated_keys: list[str]):
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

    @route(SMS_MSGS_ENDPOINT, methods=["GET"])
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

    @route(SMS_MSGS_ENDPOINT, methods=["DELETE"])
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

    @route(f"{SUBSCRIPTION_TOKENS_ENDPOINT}/<path:subscription_arn>", methods=["GET"])
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

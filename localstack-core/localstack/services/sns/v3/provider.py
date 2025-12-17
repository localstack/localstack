import base64
import contextlib
import copy
import json
import logging
import re
from uuid import uuid4

from botocore.utils import InvalidArnException

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
    EndpointDisabledException,
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
    ListSubscriptionsByTopicResponse,
    ListSubscriptionsResponse,
    ListTagsForResourceResponse,
    ListTopicsResponse,
    MapStringToString,
    MessageAttributeMap,
    NotFoundException,
    OptInPhoneNumberResponse,
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
    Topic,
    TopicAttributesMap,
    UntagResourceResponse,
    attributeName,
    attributeValue,
    authenticateOnUnsubscribe,
    boolean,
    label,
    messageStructure,
    nextToken,
    PhoneNumber,
    subscriptionARN,
    token,
    topicARN,
    topicName,
)
from localstack.http import Request, Response, route
from localstack.services.edge import ROUTER
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.sns import constants as sns_constants
from localstack.services.sns.certificate import SNS_SERVER_CERT
from localstack.services.sns.filter import FilterPolicyValidator
from localstack.services.sns.internal_api import register_sns_api_resource
from localstack.services.sns.models import (
    SnsMessage,
    SnsMessageType,
    SnsStore,
    SnsSubscription,
    create_default_sns_topic_policy,
    sns_stores,
)
from localstack.services.sns.publisher import PublishDispatcher, SnsBatchPublishContext, SnsPublishContext
from localstack.utils.aws.arns import ArnData, get_partition, parse_arn
from localstack.utils.collections import PaginatedList, select_from_typed_dict
from localstack.utils.strings import short_uid, to_bytes, to_str

from localstack.state import StateVisitor

LOG = logging.getLogger(__name__)


DEFAULT_EFFECTIVE_DELIVERY_POLICY = {
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


TOPIC_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
PLATFORM_APP_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,256}$")
SMS_ALLOWED_CHARS_RE = re.compile(r"[^0-9+./-]")
SMS_NORMALIZABLE_RE = re.compile(r"^\+?[0-9](?:[0-9]|[./-](?=[0-9]))*$")


class SnsProvider(SnsApi, ServiceLifecycleHook):
    @route(sns_constants.SNS_CERT_ENDPOINT, methods=["GET"])
    def get_signature_cert_pem_file(self, _request: Request):
        return Response(self._signature_cert_pem, 200)

    def __init__(self) -> None:
        super().__init__()
        self._publisher = PublishDispatcher()
        self._signature_cert_pem: str = SNS_SERVER_CERT

    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(sns_stores)

    def on_before_stop(self):
        self._publisher.shutdown()

    def on_after_init(self):
        register_sns_api_resource(ROUTER)
        ROUTER.add(self.get_signature_cert_pem_file)

    @staticmethod
    def get_store(account_id: str, region_name: str) -> SnsStore:
        return sns_stores[account_id][region_name]

    # -------------------
    # Permissions (policy)
    # -------------------

    def add_permission(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        label: label,
        aws_account_id: DelegatesList,
        action_name: ActionsList,
        **kwargs,
    ) -> None:
        parsed = parse_and_validate_topic_arn(topic_arn)
        store = self.get_store(account_id=parsed["account"], region_name=parsed["region"])
        topic_attrs = store.topics.get(topic_arn)
        if not topic_attrs:
            raise NotFoundException("Topic does not exist")

        policy_doc = _load_topic_policy(topic_attrs.get("Policy"), topic_arn)
        policy_doc.setdefault("Statement", []).append(
            {
                "Sid": label,
                "Effect": "Allow",
                "Principal": {"AWS": aws_account_id},
                "Action": [f"SNS:{a}" if not a.startswith("SNS:") else a for a in action_name],
                "Resource": topic_arn,
            }
        )
        topic_attrs["Policy"] = json.dumps(policy_doc)

    def remove_permission(
        self, context: RequestContext, topic_arn: topicARN, label: label, **kwargs
    ) -> None:
        parsed = parse_and_validate_topic_arn(topic_arn)
        store = self.get_store(account_id=parsed["account"], region_name=parsed["region"])
        topic_attrs = store.topics.get(topic_arn)
        if not topic_attrs:
            raise NotFoundException("Topic does not exist")

        policy_doc = _load_topic_policy(topic_attrs.get("Policy"), topic_arn)
        statements = policy_doc.get("Statement") or []
        policy_doc["Statement"] = [s for s in statements if s.get("Sid") != label]
        topic_attrs["Policy"] = json.dumps(policy_doc)

    # ---------------
    # Topic operations
    # ---------------

    def list_topics(
        self, context: RequestContext, next_token: nextToken = None, **kwargs
    ) -> ListTopicsResponse:
        store = self.get_store(context.account_id, context.region)
        topics = [Topic(TopicArn=arn) for arn in sorted(store.topics.keys())]
        paginated = PaginatedList(topics)
        page, next_token = paginated.get_page(
            token_generator=lambda x: get_next_page_token_from_arn(x["TopicArn"]),
            page_size=100,
            next_token=next_token,
        )
        response: ListTopicsResponse = {"Topics": page}
        if next_token:
            response["NextToken"] = next_token
        return response

    def create_topic(
        self,
        context: RequestContext,
        name: topicName,
        attributes: TopicAttributesMap = None,
        tags: TagList = None,
        data_protection_policy: attributeValue = None,
        **kwargs,
    ) -> CreateTopicResponse:
        del data_protection_policy
        _validate_topic_name(name)
        store = self.get_store(account_id=context.account_id, region_name=context.region)
        topic_arn = _topic_arn(context.account_id, context.region, name)

        # validate tags up front (duplicate key error ordering)
        if tags is not None:
            _validate_unique_tag_keys(tags)

        topic_exists = topic_arn in store.topics
        if topic_exists and not extract_tags(topic_arn, tags, is_create_topic_request=True, store=store):
            raise InvalidParameterException(
                "Invalid parameter: Tags Reason: Topic already exists with different tags"
            )

        if not topic_exists:
            topic_attrs = _create_default_topic_attributes(context, topic_arn)
            if attributes:
                topic_attrs.update(_normalize_create_topic_attributes(attributes, topic_arn))
            store.topics[topic_arn] = topic_attrs
            store.topic_subscriptions.setdefault(topic_arn, [])

        if tags:
            self.tag_resource(context=context, resource_arn=topic_arn, tags=tags)

        return CreateTopicResponse(TopicArn=topic_arn)

    def delete_topic(
        self, context: RequestContext, topic_arn: topicARN, **kwargs
    ) -> None:
        parsed = parse_and_validate_topic_arn(topic_arn)
        if context.region != parsed["region"]:
            raise InvalidParameterException("Invalid parameter: TopicArn")

        store = self.get_store(account_id=parsed["account"], region_name=context.region)
        if topic_arn not in store.topics:
            return None

        store.topics.pop(topic_arn, None)
        topic_subscriptions = store.topic_subscriptions.pop(topic_arn, [])
        for sub_arn in topic_subscriptions:
            store.subscription_filter_policy.pop(sub_arn, None)
            store.subscriptions.pop(sub_arn, None)

        store.sns_tags.pop(topic_arn, None)
        return None

    def get_topic_attributes(
        self, context: RequestContext, topic_arn: topicARN, **kwargs
    ) -> GetTopicAttributesResponse:
        parsed = parse_and_validate_topic_arn(topic_arn)
        if context.region != parsed["region"]:
            raise InvalidParameterException("Invalid parameter: TopicArn")

        store = self.get_store(account_id=parsed["account"], region_name=context.region)
        topic_attrs = store.topics.get(topic_arn)
        if not topic_attrs:
            raise NotFoundException("Topic does not exist")

        return GetTopicAttributesResponse(Attributes=dict(topic_attrs))

    def set_topic_attributes(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        attribute_name: attributeName,
        attribute_value: attributeValue | None = None,
        **kwargs,
    ) -> None:
        parsed = parse_and_validate_topic_arn(topic_arn)
        if context.region != parsed["region"]:
            raise InvalidParameterException("Invalid parameter: TopicArn")

        store = self.get_store(account_id=parsed["account"], region_name=context.region)
        topic_attrs = store.topics.get(topic_arn)
        if not topic_attrs:
            raise NotFoundException("Topic does not exist")

        if attribute_name == "FifoTopic":
            raise InvalidParameterException("Invalid parameter: AttributeName")

        if attribute_name not in (
            "DisplayName",
            "Policy",
            "SignatureVersion",
            "ContentBasedDeduplication",
            "DeliveryPolicy",
        ):
            raise InvalidParameterException("Invalid parameter: AttributeName")

        if attribute_value is None:
            attribute_value = ""

        if attribute_name == "Policy":
            if isinstance(attribute_value, str):
                topic_attrs["Policy"] = attribute_value
            else:
                topic_attrs["Policy"] = json.dumps(attribute_value)
            return

        if attribute_name == "DeliveryPolicy":
            if attribute_value == "":
                topic_attrs.pop("DeliveryPolicy", None)
                topic_attrs["EffectiveDeliveryPolicy"] = json.dumps(DEFAULT_EFFECTIVE_DELIVERY_POLICY)
                return

            delivery_policy, effective_delivery_policy = _normalize_delivery_policy(attribute_value)
            topic_attrs["DeliveryPolicy"] = json.dumps(delivery_policy)
            topic_attrs["EffectiveDeliveryPolicy"] = json.dumps(effective_delivery_policy)
            return

        topic_attrs[attribute_name] = attribute_value

    # ----------
    # Tagging API
    # ----------

    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: TagList, **kwargs
    ) -> TagResourceResponse:
        _validate_unique_tag_keys(tags)
        store = self.get_store(context.account_id, context.region)
        existing_tags = store.sns_tags.get(resource_arn, [])

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

        store.sns_tags[resource_arn] = existing_tags
        return TagResourceResponse()

    def untag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tag_keys: TagKeyList, **kwargs
    ) -> UntagResourceResponse:
        store = self.get_store(context.account_id, context.region)
        existing_tags = store.sns_tags.setdefault(resource_arn, [])
        store.sns_tags[resource_arn] = [t for t in existing_tags if t["Key"] not in tag_keys]
        return UntagResourceResponse()

    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, **kwargs
    ) -> ListTagsForResourceResponse:
        store = self.get_store(context.account_id, context.region)
        return ListTagsForResourceResponse(Tags=store.sns_tags.setdefault(resource_arn, []))

    # ---------------------
    # Subscription operations
    # ---------------------

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
        parsed_topic_arn = parse_and_validate_topic_arn(topic_arn)
        if context.region != parsed_topic_arn["region"]:
            raise InvalidParameterException("Invalid parameter: TopicArn")

        store = self.get_store(account_id=parsed_topic_arn["account"], region_name=context.region)

        if topic_arn not in store.topic_subscriptions:
            raise NotFoundException("Topic does not exist")

        if not endpoint:
            raise NotFoundException("Endpoint not specified in subscription")

        if protocol not in sns_constants.SNS_PROTOCOLS:
            raise InvalidParameterException(
                f"Invalid parameter: Amazon SNS does not support this protocol string: {protocol}"
            )
        if protocol in ["http", "https"] and not endpoint.startswith(f"{protocol}://"):
            raise InvalidParameterException("Invalid parameter: Endpoint must match the specified protocol")
        if protocol == "sms":
            raw_endpoint = endpoint
            endpoint = normalize_sms_phone_number(endpoint)
            if not endpoint:
                raise InvalidParameterException(f"Invalid SMS endpoint: {raw_endpoint}")
        if protocol == "sqs":
            try:
                parse_arn(endpoint)
            except InvalidArnException:
                raise InvalidParameterException("Invalid parameter: SQS endpoint ARN")
        if protocol == "application":
            if endpoint not in store.platform_endpoints:
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

        for existing_subscription_arn in store.topic_subscriptions.get(topic_arn, []):
            sub = store.subscriptions.get(existing_subscription_arn, {})
            if sub.get("Endpoint") == endpoint:
                if sub_attributes:
                    for attr in sns_constants.VALID_SUBSCRIPTION_ATTR_NAME:
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
            TopicArn=topic_arn,
            Endpoint=endpoint,
            Protocol=protocol,
            SubscriptionArn=subscription_arn,
            PendingConfirmation="true",
            Owner=context.account_id,
            RawMessageDelivery="false",
            FilterPolicyScope="MessageAttributes",
            SubscriptionPrincipal=principal,
        )

        if sub_attributes:
            subscription.update(sub_attributes)
            if "FilterPolicy" in sub_attributes:
                filter_policy = json.loads(sub_attributes["FilterPolicy"]) if sub_attributes["FilterPolicy"] else None
                if filter_policy:
                    validator = FilterPolicyValidator(
                        scope=subscription.get("FilterPolicyScope", "MessageAttributes"),
                        is_subscribe_call=True,
                    )
                    validator.validate_filter_policy(filter_policy)
                store.subscription_filter_policy[subscription_arn] = filter_policy

        store.subscriptions[subscription_arn] = subscription
        store.topic_subscriptions.setdefault(topic_arn, []).append(subscription_arn)

        subscription_token = encode_subscription_token_with_region(region=context.region)
        store.subscription_tokens[subscription_token] = subscription_arn

        response_subscription_arn = subscription_arn
        if protocol in ["http", "https"]:
            message_ctx = SnsMessage(
                type=SnsMessageType.SubscriptionConfirmation,
                token=subscription_token,
                message=(
                    f"You have chosen to subscribe to the topic {topic_arn}.\n"
                    "To confirm the subscription, visit the SubscribeURL included in this message."
                ),
            )
            publish_ctx = SnsPublishContext(
                message=message_ctx,
                store=store,
                request_headers=context.request.headers,
                topic_attributes=store.topics.get(topic_arn, {}),
            )
            self._publisher.publish_to_topic_subscriber(
                ctx=publish_ctx, topic_arn=topic_arn, subscription_arn=subscription_arn
            )
            if not return_subscription_arn:
                response_subscription_arn = "pending confirmation"
        elif protocol not in ["email", "email-json"]:
            subscription["PendingConfirmation"] = "false"
            subscription["ConfirmationWasAuthenticated"] = "true"

        return SubscribeResponse(SubscriptionArn=response_subscription_arn)

    def unsubscribe(self, context: RequestContext, subscription_arn: subscriptionARN, **kwargs) -> None:
        if subscription_arn is None:
            raise InvalidParameterException(
                "Invalid parameter: SubscriptionArn Reason: no value for required parameter",
            )
        count = len(subscription_arn.split(":"))
        try:
            parsed_arn = parse_arn(subscription_arn)
        except InvalidArnException:
            raise InvalidParameterException(
                f"Invalid parameter: SubscriptionArn Reason: An ARN must have at least 6 elements, not {count}"
            )

        store = self.get_store(account_id=parsed_arn["account"], region_name=parsed_arn["region"])
        if count == 6 and subscription_arn not in store.subscriptions:
            raise InvalidParameterException("Invalid parameter: SubscriptionId")

        subscription = store.subscriptions.get(subscription_arn)
        if not subscription:
            return

        if subscription["Protocol"] in ["http", "https"]:
            subscription_token = encode_subscription_token_with_region(region=context.region)
            message_ctx = SnsMessage(
                type=SnsMessageType.UnsubscribeConfirmation,
                token=subscription_token,
                message=(
                    f"You have chosen to deactivate subscription {subscription_arn}.\n"
                    "To cancel this operation and restore the subscription, visit the SubscribeURL included in this message."
                ),
            )
            publish_ctx = SnsPublishContext(
                message=message_ctx,
                store=store,
                request_headers=context.request.headers,
                topic_attributes=store.topics.get(subscription["TopicArn"], {}),
            )
            self._publisher.publish_to_topic_subscriber(
                publish_ctx, topic_arn=subscription["TopicArn"], subscription_arn=subscription_arn
            )

        with contextlib.suppress(ValueError):
            store.topic_subscriptions[subscription["TopicArn"]].remove(subscription_arn)
        store.subscription_filter_policy.pop(subscription_arn, None)
        store.subscriptions.pop(subscription_arn, None)

    def confirm_subscription(
        self,
        context: RequestContext,
        topic_arn: topicARN,
        token: token,
        authenticate_on_unsubscribe: authenticateOnUnsubscribe = None,
        **kwargs,
    ) -> ConfirmSubscriptionResponse:
        del authenticate_on_unsubscribe
        try:
            parsed_arn = parse_arn(topic_arn)
        except InvalidArnException:
            raise InvalidParameterException("Invalid parameter: Topic")

        store = self.get_store(account_id=parsed_arn["account"], region_name=parsed_arn["region"])
        if parsed_arn["region"] != get_region_from_subscription_token(token):
            raise InvalidParameterException("Invalid parameter: Topic")

        subscription_arn = store.subscription_tokens.get(token)
        if not subscription_arn:
            raise InvalidParameterException("Invalid parameter: Token")

        subscription = store.subscriptions.get(subscription_arn)
        if not subscription:
            raise InvalidParameterException("Invalid parameter: Token")

        if subscription.get("PendingConfirmation") == "false":
            return ConfirmSubscriptionResponse(SubscriptionArn=subscription_arn)

        subscription["PendingConfirmation"] = "false"
        subscription["ConfirmationWasAuthenticated"] = "true"
        return ConfirmSubscriptionResponse(SubscriptionArn=subscription_arn)

    def get_subscription_attributes(
        self, context: RequestContext, subscription_arn: subscriptionARN, **kwargs
    ) -> GetSubscriptionAttributesResponse:
        parsed_arn, arn_count = parse_and_validate_subscription_arn(subscription_arn)
        store = self.get_store(account_id=parsed_arn["account"], region_name=parsed_arn["region"])
        sub = store.subscriptions.get(subscription_arn)
        if not sub:
            # For topic-like ARNs (missing the subscription id suffix), AWS uses "Invalid parameter: SubscriptionId"
            if arn_count == 6:
                raise InvalidParameterException("Invalid parameter: SubscriptionId")
            raise NotFoundException("Subscription does not exist")
        removed_attrs = ["sqs_queue_url"]
        if "FilterPolicyScope" in sub and not sub.get("FilterPolicy"):
            removed_attrs.extend(["FilterPolicyScope", "FilterPolicy"])
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
        parsed_arn, _arn_count = parse_and_validate_subscription_arn(subscription_arn)
        store = self.get_store(account_id=parsed_arn["account"], region_name=parsed_arn["region"])
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

    def list_subscriptions(
        self, context: RequestContext, next_token: nextToken = None, **kwargs
    ) -> ListSubscriptionsResponse:
        store = self.get_store(context.account_id, context.region)
        subscriptions = [select_from_typed_dict(Subscription, sub) for sub in list(store.subscriptions.values())]
        paginated = PaginatedList(subscriptions)
        page, next_token = paginated.get_page(
            token_generator=lambda x: get_next_page_token_from_arn(x["SubscriptionArn"]),
            page_size=100,
            next_token=next_token,
        )
        response: ListSubscriptionsResponse = {"Subscriptions": page}
        if next_token:
            response["NextToken"] = next_token
        return response

    def list_subscriptions_by_topic(
        self, context: RequestContext, topic_arn: topicARN, next_token: nextToken = None, **kwargs
    ) -> ListSubscriptionsByTopicResponse:
        parsed = parse_and_validate_topic_arn(topic_arn)
        if context.region != parsed["region"]:
            raise InvalidParameterException("Invalid parameter: TopicArn")

        store = self.get_store(parsed["account"], parsed["region"])
        if topic_arn not in store.topic_subscriptions:
            raise NotFoundException("Topic does not exist")

        sns_subscriptions = store.get_topic_subscriptions(topic_arn)
        subscriptions = [select_from_typed_dict(Subscription, sub) for sub in sns_subscriptions]
        paginated = PaginatedList(subscriptions)
        page, next_token = paginated.get_page(
            token_generator=lambda x: get_next_page_token_from_arn(x["SubscriptionArn"]),
            page_size=100,
            next_token=next_token,
        )
        response: ListSubscriptionsResponse = {"Subscriptions": page}
        if next_token:
            response["NextToken"] = next_token
        return response

    # -----------
    # Publish APIs
    # -----------

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

        if phone_number and not is_e164(phone_number):
            raise InvalidParameterException(
                f"Invalid parameter: PhoneNumber Reason: {phone_number} is not valid to publish to"
            )

        if message_attributes:
            validate_message_attributes(message_attributes)

        if get_total_publish_size(message, message_attributes) > sns_constants.MAXIMUM_MESSAGE_LENGTH:
            raise InvalidParameterException("Invalid parameter: Message too long")

        topic_or_target_arn = topic_arn or target_arn
        is_endpoint_publish = target_arn and ":endpoint/" in target_arn

        is_fifo = bool(topic_or_target_arn and topic_or_target_arn.endswith(".fifo"))
        if is_fifo:
            if not message_group_id:
                raise InvalidParameterException(
                    "Invalid parameter: The MessageGroupId parameter is required for FIFO topics",
                )
        elif message_deduplication_id:
            raise InvalidParameterException(
                "Invalid parameter: MessageDeduplicationId Reason: The request includes MessageDeduplicationId parameter that is not valid for this topic type"
            )

        if message_structure == "json":
            try:
                parsed = json.loads(message)
                parsed = {key: field for key, field in parsed.items() if isinstance(field, str)}
                if "default" not in parsed and not is_endpoint_publish:
                    raise InvalidParameterException(
                        "Invalid parameter: Message Structure - No default entry in JSON message body"
                    )
                message = parsed  # noqa: PLW2901 - used by SnsMessage for structure=json
            except json.JSONDecodeError:
                raise InvalidParameterException(
                    "Invalid parameter: Message Structure - JSON message body failed to parse"
                )

        if not phone_number:
            parsed_topic = parse_and_validate_topic_arn(topic_or_target_arn)
            if context.region != parsed_topic["region"]:
                raise InvalidParameterException("Invalid parameter: TopicArn")
            store = self.get_store(account_id=parsed_topic["account"], region_name=context.region)
            if is_endpoint_publish:
                endpoint = store.platform_endpoints.get(target_arn)
                if not endpoint:
                    raise InvalidParameterException(
                        "Invalid parameter: TargetArn Reason: No endpoint found for the target arn specified"
                    )
                if endpoint.get("Enabled") == "false":
                    raise EndpointDisabledException("Endpoint is disabled")
            else:
                if topic_or_target_arn not in store.topics:
                    raise NotFoundException("Topic does not exist")
                topic_attrs = store.topics.get(topic_or_target_arn, {})
                if is_fifo:
                    if topic_attrs.get("ContentBasedDeduplication", "false") == "false" and not message_deduplication_id:
                        raise InvalidParameterException(
                            "Invalid parameter: The topic should either have ContentBasedDeduplication enabled or MessageDeduplicationId provided explicitly",
                        )
        else:
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
        publish_ctx = SnsPublishContext(message=message_ctx, store=store, request_headers=context.request.headers)

        if is_endpoint_publish:
            self._publisher.publish_to_application_endpoint(ctx=publish_ctx, endpoint_arn=target_arn)
        elif phone_number:
            self._publisher.publish_to_phone_number(ctx=publish_ctx, phone_number=phone_number)
        else:
            publish_ctx.topic_attributes |= store.topics.get(topic_or_target_arn, {})
            self._publisher.publish_to_topic(publish_ctx, topic_or_target_arn)

        if is_fifo:
            return PublishResponse(MessageId=message_ctx.message_id, SequenceNumber=message_ctx.sequencer_number)
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

        parsed_topic = parse_and_validate_topic_arn(topic_arn)
        if context.region != parsed_topic["region"]:
            raise InvalidParameterException("Invalid parameter: TopicArn")

        store = self.get_store(account_id=parsed_topic["account"], region_name=context.region)
        topic_attrs = store.topics.get(topic_arn)
        if not topic_attrs:
            raise NotFoundException("Topic does not exist")

        ids = [entry["Id"] for entry in publish_batch_request_entries]
        if len(set(ids)) != len(publish_batch_request_entries):
            raise BatchEntryIdsNotDistinctException(
                "Two or more batch entries in the request have the same Id."
            )

        response: PublishBatchResponse = {"Successful": [], "Failed": []}

        total_batch_size = 0
        message_contexts = []
        is_fifo = topic_arn.endswith(".fifo")
        content_based_dedup = topic_attrs.get("ContentBasedDeduplication", "false")

        for entry_index, entry in enumerate(publish_batch_request_entries, start=1):
            message_payload = entry.get("Message")
            message_attributes = entry.get("MessageAttributes", {})
            if message_attributes:
                validate_message_attributes(message_attributes, position=entry_index)

            total_batch_size += get_total_publish_size(message_payload, message_attributes)

            if entry.get("MessageStructure") == "json":
                try:
                    parsed = json.loads(message_payload)
                    parsed = {key: field for key, field in parsed.items() if isinstance(field, str)}
                    if "default" not in parsed:
                        raise InvalidParameterException(
                            "Invalid parameter: Message Structure - No default entry in JSON message body"
                        )
                    entry["Message"] = parsed  # noqa
                except json.JSONDecodeError:
                    raise InvalidParameterException(
                        "Invalid parameter: Message Structure - JSON message body failed to parse"
                    )

            if is_fifo:
                if not all("MessageGroupId" in e for e in publish_batch_request_entries):
                    raise InvalidParameterException(
                        "Invalid parameter: The MessageGroupId parameter is required for FIFO topics"
                    )
                if content_based_dedup == "false":
                    if not all("MessageDeduplicationId" in e for e in publish_batch_request_entries):
                        raise InvalidParameterException(
                            "Invalid parameter: The topic should either have ContentBasedDeduplication enabled or MessageDeduplicationId provided explicitly",
                        )

            msg_ctx = SnsMessage.from_batch_entry(entry, is_fifo=is_fifo)
            message_contexts.append(msg_ctx)
            success = PublishBatchResultEntry(Id=entry["Id"], MessageId=msg_ctx.message_id)
            if is_fifo:
                success["SequenceNumber"] = msg_ctx.sequencer_number
            response["Successful"].append(success)

        if total_batch_size > sns_constants.MAXIMUM_MESSAGE_LENGTH:
            raise CommonServiceException(
                code="BatchRequestTooLong",
                message="The length of all the messages put together is more than the limit.",
                sender_fault=True,
            )

        publish_ctx = SnsBatchPublishContext(
            messages=message_contexts,
            store=store,
            request_headers=context.request.headers,
            topic_attributes=dict(topic_attrs),
        )
        self._publisher.publish_batch_to_topic(publish_ctx, topic_arn)
        return response

    # ------------------------
    # Platform application APIs
    # ------------------------

    def create_platform_application(
        self, context: RequestContext, name: String, platform: String, attributes: MapStringToString, **kwargs
    ) -> CreatePlatformApplicationResponse:
        _validate_platform_application_name(name)
        _validate_platform(platform)
        if not attributes:
            raise CommonServiceException(
                code="ValidationError",
                message="1 validation error detected: Value null at 'attributes' failed to satisfy constraint: Member must not be null",
                sender_fault=True,
            )

        has_principal = "PlatformPrincipal" in attributes
        has_credential = "PlatformCredential" in attributes

        platform_requires_principal = platform not in ("GCM", "FCM")
        if platform_requires_principal:
            if has_principal and not has_credential:
                raise InvalidParameterException(
                    "Invalid parameter: Attributes Reason: PlatformPrincipal attribute provided without PlatformCredential"
                )
            if has_credential and not has_principal:
                raise InvalidParameterException(
                    "Invalid parameter: Attributes Reason: PlatformCredential attribute provided without PlatformPrincipal"
                )
        else:
            if not has_credential:
                raise InvalidParameterException(
                    "Invalid parameter: Attributes Reason: PlatformCredential attribute required"
                )
            if has_principal and not has_credential:
                raise InvalidParameterException(
                    "Invalid parameter: Attributes Reason: PlatformPrincipal attribute provided without PlatformCredential"
                )

        store = self.get_store(context.account_id, context.region)
        partition = get_partition(context.region)
        app_arn = f"arn:{partition}:sns:{context.region}:{context.account_id}:app/{platform}/{name}"

        store.platform_applications.setdefault(app_arn, {"Enabled": "true"})
        store.platform_application_meta.setdefault(app_arn, {"Platform": platform, "Name": name})
        store.platform_application_endpoints.setdefault(app_arn, [])
        return CreatePlatformApplicationResponse(PlatformApplicationArn=app_arn)

    def delete_platform_application(
        self, context: RequestContext, platform_application_arn: String, **kwargs
    ) -> None:
        parsed = parse_and_validate_platform_application_arn(platform_application_arn)
        store = self.get_store(parsed["account"], parsed["region"])

        store.platform_applications.pop(platform_application_arn, None)
        store.platform_application_meta.pop(platform_application_arn, None)
        endpoint_arns = store.platform_application_endpoints.pop(platform_application_arn, [])
        for endpoint_arn in endpoint_arns:
            store.platform_endpoints.pop(endpoint_arn, None)
        for k, v in list(store.platform_endpoint_tokens.items()):
            if v in endpoint_arns:
                store.platform_endpoint_tokens.pop(k, None)

        return None

    def list_platform_applications(
        self, context: RequestContext, next_token: String = None, **kwargs
    ) -> ListPlatformApplicationsResponse:
        store = self.get_store(context.account_id, context.region)
        apps = [
            {"PlatformApplicationArn": arn, "Attributes": attrs}
            for arn, attrs in sorted(store.platform_applications.items())
        ]
        return ListPlatformApplicationsResponse(PlatformApplications=apps)

    def get_platform_application_attributes(
        self, context: RequestContext, platform_application_arn: String, **kwargs
    ) -> GetPlatformApplicationAttributesResponse:
        parsed = parse_and_validate_platform_application_arn(platform_application_arn)
        store = self.get_store(parsed["account"], parsed["region"])
        attrs = store.platform_applications.get(platform_application_arn)
        if not attrs:
            raise NotFoundException("PlatformApplication does not exist")
        return GetPlatformApplicationAttributesResponse(Attributes=dict(attrs))

    def set_platform_application_attributes(
        self, context: RequestContext, platform_application_arn: String, attributes: MapStringToString, **kwargs
    ) -> None:
        parse_and_validate_platform_application_arn(platform_application_arn)
        if not attributes:
            raise CommonServiceException(
                code="ValidationError",
                message="1 validation error detected: Value null at 'attributes' failed to satisfy constraint: Member must not be null",
                sender_fault=True,
            )

        store = self.get_store(context.account_id, context.region)
        existing = store.platform_applications.get(platform_application_arn)
        if not existing:
            raise NotFoundException("PlatformApplication does not exist")

        existing.update({k: v for k, v in attributes.items() if v is not None})

    # -------------------
    # Platform endpoint APIs
    # -------------------

    def create_platform_endpoint(
        self,
        context: RequestContext,
        platform_application_arn: String,
        token: String,
        custom_user_data: String = None,
        attributes: MapStringToString = None,
        **kwargs,
    ) -> CreateEndpointResponse:
        parsed_app = parse_and_validate_platform_application_arn(platform_application_arn)
        store = self.get_store(parsed_app["account"], parsed_app["region"])
        if platform_application_arn not in store.platform_applications:
            raise NotFoundException("PlatformApplication does not exist")

        endpoint_attrs = {"Enabled": "true", "Token": token}
        if attributes:
            _validate_platform_endpoint_attributes(attributes, is_create=True)
            endpoint_attrs.update(attributes)
        if custom_user_data is not None and "CustomUserData" not in endpoint_attrs:
            endpoint_attrs["CustomUserData"] = custom_user_data

        token_key = f"{platform_application_arn}:{token}"
        if existing_endpoint_arn := store.platform_endpoint_tokens.get(token_key):
            existing_attrs = store.platform_endpoints.get(existing_endpoint_arn, {})
            compare_existing = dict(existing_attrs)
            compare_new = dict(endpoint_attrs)
            if compare_existing != compare_new:
                raise InvalidParameterException(
                    f"Invalid parameter: Token Reason: Endpoint {existing_endpoint_arn} already exists with the same Token, but different attributes."
                )
            return CreateEndpointResponse(EndpointArn=existing_endpoint_arn)

        meta = store.platform_application_meta.get(platform_application_arn, {})
        platform = meta.get("Platform", "ADM")
        app_name = meta.get("Name", "unknown")
        partition = get_partition(context.region)
        endpoint_arn = (
            f"arn:{partition}:sns:{context.region}:{context.account_id}:"
            f"endpoint/{platform}/{app_name}/{uuid4()}"
        )
        store.platform_endpoints[endpoint_arn] = endpoint_attrs
        store.platform_application_endpoints.setdefault(platform_application_arn, []).append(endpoint_arn)
        store.platform_endpoint_tokens[token_key] = endpoint_arn
        return CreateEndpointResponse(EndpointArn=endpoint_arn)

    def delete_endpoint(self, context: RequestContext, endpoint_arn: String, **kwargs) -> None:
        parsed = parse_and_validate_endpoint_arn(endpoint_arn)
        store = self.get_store(parsed["account"], parsed["region"])
        store.platform_endpoints.pop(endpoint_arn, None)
        for endpoints in store.platform_application_endpoints.values():
            with contextlib.suppress(ValueError):
                endpoints.remove(endpoint_arn)
        for k, v in list(store.platform_endpoint_tokens.items()):
            if v == endpoint_arn:
                store.platform_endpoint_tokens.pop(k, None)
        return None

    def list_endpoints_by_platform_application(
        self, context: RequestContext, platform_application_arn: String, next_token: String = None, **kwargs
    ) -> ListEndpointsByPlatformApplicationResponse:
        parsed = parse_and_validate_platform_application_arn(platform_application_arn)
        store = self.get_store(parsed["account"], parsed["region"])
        if platform_application_arn not in store.platform_applications:
            raise NotFoundException("PlatformApplication does not exist")

        endpoints = []
        for endpoint_arn in store.platform_application_endpoints.get(platform_application_arn, []):
            attrs = store.platform_endpoints.get(endpoint_arn)
            if attrs is None:
                continue
            endpoints.append({"EndpointArn": endpoint_arn, "Attributes": dict(attrs)})
        return ListEndpointsByPlatformApplicationResponse(Endpoints=endpoints)

    def get_endpoint_attributes(
        self, context: RequestContext, endpoint_arn: String, **kwargs
    ) -> GetEndpointAttributesResponse:
        parsed = parse_and_validate_endpoint_arn(endpoint_arn)
        store = self.get_store(parsed["account"], parsed["region"])
        attrs = store.platform_endpoints.get(endpoint_arn)
        if not attrs:
            raise NotFoundException("Endpoint does not exist")
        return GetEndpointAttributesResponse(Attributes=dict(attrs))

    def set_endpoint_attributes(
        self, context: RequestContext, endpoint_arn: String, attributes: MapStringToString, **kwargs
    ) -> None:
        parse_and_validate_endpoint_arn(endpoint_arn)
        if not attributes:
            raise CommonServiceException(
                code="ValidationError",
                message="1 validation error detected: Value null at 'attributes' failed to satisfy constraint: Member must not be null",
                sender_fault=True,
            )

        _validate_platform_endpoint_attributes(attributes, is_create=False)
        store = self.get_store(context.account_id, context.region)
        existing = store.platform_endpoints.get(endpoint_arn)
        if not existing:
            raise NotFoundException("Endpoint does not exist")
        existing.update(attributes)

    # -----
    # SMS APIs
    # -----

    def set_sms_attributes(self, context: RequestContext, attributes: MapStringToString, **kwargs) -> None:
        store = self.get_store(context.account_id, context.region)
        allowed = {"DeliveryStatusSuccessSamplingRate", "DefaultSenderID", "DefaultSMSType"}
        for key, value in attributes.items():
            if key not in allowed:
                raise InvalidParameterException(f"{key} is not a valid attribute")
            if key == "DefaultSMSType" and value not in ("Promotional", "Transactional"):
                raise InvalidParameterException("DefaultSMSType is invalid")
            store.sms_attributes[key] = value

    def get_sms_attributes(
        self, context: RequestContext, attributes: list[String] = None, **kwargs
    ) -> GetSMSAttributesResponse:
        store = self.get_store(context.account_id, context.region)
        all_attrs = {"MonthlySpendLimit": "1", **store.sms_attributes}
        if attributes is None:
            return GetSMSAttributesResponse(attributes=all_attrs)
        return GetSMSAttributesResponse(attributes={k: all_attrs[k] for k in attributes if k in all_attrs})

    def check_if_phone_number_is_opted_out(
        self, context: RequestContext, phone_number: PhoneNumber, **kwargs
    ) -> CheckIfPhoneNumberIsOptedOutResponse:
        if not is_e164(phone_number):
            raise InvalidParameterException(
                "Invalid parameter: PhoneNumber Reason: input incorrectly formatted"
            )
        store = self.get_store(context.account_id, context.region)
        return {"isOptedOut": phone_number in store.PHONE_NUMBERS_OPTED_OUT}

    def list_phone_numbers_opted_out(
        self, context: RequestContext, next_token: String = None, **kwargs
    ) -> ListPhoneNumbersOptedOutResponse:
        store = self.get_store(context.account_id, context.region)
        return {"phoneNumbers": list(store.PHONE_NUMBERS_OPTED_OUT)}

    def opt_in_phone_number(
        self, context: RequestContext, phone_number: PhoneNumber, **kwargs
    ) -> OptInPhoneNumberResponse:
        if not is_e164(phone_number):
            raise InvalidParameterException(
                "Invalid parameter: PhoneNumber Reason: input incorrectly formatted"
            )
        store = self.get_store(context.account_id, context.region)
        with contextlib.suppress(ValueError):
            store.PHONE_NUMBERS_OPTED_OUT.remove(phone_number)
        return OptInPhoneNumberResponse()


def is_e164(value: str) -> bool:
    return bool(sns_constants.E164_REGEX.match(value or ""))


def normalize_sms_phone_number(phone_number: str | None) -> str | None:
    if not phone_number:
        return None
    if not SMS_NORMALIZABLE_RE.fullmatch(phone_number):
        return None
    stripped = SMS_ALLOWED_CHARS_RE.sub("", phone_number)
    normalized = stripped.replace("/", "").replace("-", "").replace(".", "")
    if is_e164(normalized):
        return normalized
    return None


def _topic_arn(account_id: str, region_name: str, name: str) -> str:
    partition = get_partition(region_name)
    return f"arn:{partition}:sns:{region_name}:{account_id}:{name}"


def _validate_topic_name(name: str) -> None:
    if not name or len(name) > 256:
        raise InvalidParameterException("Invalid parameter: Topic Name")
    if name.endswith(".fifo"):
        base = name[: -len(".fifo")]
        if not base or not TOPIC_NAME_RE.fullmatch(base):
            raise InvalidParameterException("Invalid parameter: Topic Name")
        return
    if not TOPIC_NAME_RE.fullmatch(name):
        raise InvalidParameterException("Invalid parameter: Topic Name")


def _validate_unique_tag_keys(tags: TagList) -> None:
    unique = {tag["Key"] for tag in tags}
    if len(unique) < len(tags):
        raise InvalidParameterException("Invalid parameter: Duplicated keys are not allowed.")


def _create_default_topic_attributes(context: RequestContext, topic_arn: str) -> dict:
    return {
        "TopicArn": topic_arn,
        "Owner": context.account_id,
        # store as JSON string (Query API returns strings; test harness normalizes JSON where needed)
        "Policy": json.dumps(create_default_sns_topic_policy(topic_arn)),
        "DisplayName": "",
        "EffectiveDeliveryPolicy": json.dumps(DEFAULT_EFFECTIVE_DELIVERY_POLICY),
        "SubscriptionsConfirmed": "0",
        "SubscriptionsPending": "0",
        "SubscriptionsDeleted": "0",
    }


def _normalize_create_topic_attributes(attrs: TopicAttributesMap, topic_arn: str) -> dict:
    normalized = {}
    display_name = attrs.get("DisplayName")
    if display_name is not None:
        normalized["DisplayName"] = display_name

    sig_ver = attrs.get("SignatureVersion")
    if sig_ver is not None:
        normalized["SignatureVersion"] = sig_ver

    fifo = attrs.get("FifoTopic") == "true" or topic_arn.endswith(".fifo")
    if fifo:
        normalized["FifoTopic"] = "true"
        normalized["ContentBasedDeduplication"] = attrs.get("ContentBasedDeduplication", "false")

    delivery_policy = attrs.get("DeliveryPolicy")
    if delivery_policy is not None:
        dp, edp = _normalize_delivery_policy(delivery_policy)
        normalized["DeliveryPolicy"] = json.dumps(dp)
        normalized["EffectiveDeliveryPolicy"] = json.dumps(edp)

    # ignore "FifoTopic": "false" to match AWS snapshots (key omitted)
    return normalized


def _normalize_delivery_policy(delivery_policy_value: str | None) -> tuple[dict, dict]:
    """
    Normalize DeliveryPolicy and compute EffectiveDeliveryPolicy.
    Values are stored as JSON strings by the query API layer; snapshots decode them for matching.
    """
    if not delivery_policy_value:
        delivery_policy = {}
    else:
        try:
            delivery_policy = json.loads(delivery_policy_value)
            if not isinstance(delivery_policy, dict):
                delivery_policy = {}
        except json.JSONDecodeError:
            raise InvalidParameterException("Invalid parameter: DeliveryPolicy")

    # Remove keys explicitly set to null
    for proto, cfg in list(delivery_policy.items()):
        if not isinstance(cfg, dict):
            delivery_policy.pop(proto, None)
            continue
        delivery_policy[proto] = {k: v for k, v in cfg.items() if v is not None}
        delivery_policy[proto].setdefault("disableSubscriptionOverrides", False)

    # If "http" is present but empty, still include disableSubscriptionOverrides
    if "http" in delivery_policy and not delivery_policy["http"]:
        delivery_policy["http"] = {"disableSubscriptionOverrides": False}

    effective = copy.deepcopy(DEFAULT_EFFECTIVE_DELIVERY_POLICY)
    http_cfg = delivery_policy.get("http", {})
    if http_cfg:
        effective.setdefault("http", {})
        # recompute from defaults, then overlay policy values
        base = copy.deepcopy(DEFAULT_EFFECTIVE_DELIVERY_POLICY.get("http", {}))
        if "defaultHealthyRetryPolicy" in http_cfg:
            base_hrp = base.get("defaultHealthyRetryPolicy", {})
            base_hrp |= http_cfg.get("defaultHealthyRetryPolicy") or {}
            base["defaultHealthyRetryPolicy"] = base_hrp
        if "defaultRequestPolicy" in http_cfg:
            base["defaultRequestPolicy"] = http_cfg["defaultRequestPolicy"]
        base["disableSubscriptionOverrides"] = http_cfg.get("disableSubscriptionOverrides", False)
        effective["http"] = base

    return delivery_policy, effective


def parse_and_validate_subscription_arn(subscription_arn: str | None) -> tuple[ArnData, int]:
    subscription_arn = subscription_arn or ""
    count = len(subscription_arn.split(":"))
    try:
        parsed = parse_arn(subscription_arn)
    except InvalidArnException:
        raise InvalidParameterException(
            f"Invalid parameter: SubscriptionArn Reason: An ARN must have at least 6 elements, not {count}"
        )
    return parsed, count


def parse_and_validate_topic_arn(topic_arn: str | None) -> ArnData:
    topic_arn = topic_arn or ""
    try:
        return parse_arn(topic_arn)
    except InvalidArnException:
        count = len(topic_arn.split(":"))
        raise InvalidParameterException(
            f"Invalid parameter: TopicArn Reason: An ARN must have at least 6 elements, not {count}"
        )


def parse_and_validate_platform_application_arn(app_arn: str | None) -> ArnData:
    app_arn = app_arn or ""
    try:
        return parse_arn(app_arn)
    except InvalidArnException:
        count = len(app_arn.split(":"))
        raise InvalidParameterException(
            f"Invalid parameter: PlatformApplicationArn Reason: An ARN must have at least 6 elements, not {count}"
        )


def parse_and_validate_endpoint_arn(endpoint_arn: str | None) -> ArnData:
    endpoint_arn = endpoint_arn or ""
    try:
        arn_data = parse_arn(endpoint_arn)
    except InvalidArnException:
        count = len(endpoint_arn.split(":"))
        raise InvalidParameterException(
            f"Invalid parameter: EndpointArn Reason: An ARN must have at least 6 elements, not {count}"
        )

    # validate the relative resource shape: endpoint/<platform>/<app_name>/<uuid>
    resource = arn_data.get("resource") or ""
    if not resource.startswith("endpoint/") or resource.count("/") != 3:
        raise InvalidParameterException(
            "Invalid parameter: EndpointArn Reason: Wrong number of slashes in relative portion of the ARN."
        )
    return arn_data


def _validate_platform(platform: str) -> None:
    if platform not in sns_constants.VALID_APPLICATION_PLATFORMS:
        raise InvalidParameterException(f"Invalid parameter: Platform Reason: {platform} is not supported")


def _validate_platform_application_name(name: str) -> None:
    if name == "":
        raise InvalidParameterException("Invalid parameter:  Reason: cannot be empty")
    if name is None or len(name) > 256:
        raise InvalidParameterException(f"Invalid parameter: {name} Reason: must be at most 256 characters long")
    if not PLATFORM_APP_NAME_RE.fullmatch(name):
        raise InvalidParameterException(
            f"Invalid parameter: {name} Reason: must contain only characters 'a'-'z', 'A'-'Z', '0'-'9', '_', '-', and '.'"
        )


def _validate_platform_endpoint_attributes(attributes: dict[str, str], *, is_create: bool) -> None:
    allowed = {"Enabled", "Token", "CustomUserData"}
    for key, value in attributes.items():
        if key not in allowed:
            raise InvalidParameterException(
                f"Invalid parameter: Attributes Reason: Invalid attribute name: {key}"
            )
        if key == "CustomUserData" and value is not None:
            if len(to_bytes(value)) > 2048:
                raise InvalidParameterException(
                    "Invalid parameter: Attributes Reason: Invalid value for attribute: CustomUserData: must be at most 2048 bytes long in UTF-8 encoding"
                )
        if key == "Enabled" and value not in ("true", "false"):
            raise InvalidParameterException(
                "Invalid parameter: Attributes Reason: Invalid value for attribute: Enabled"
            )


def create_subscription_arn(topic_arn: str) -> str:
    return f"{topic_arn}:{uuid4()}"


def encode_subscription_token_with_region(region: str) -> str:
    return ((region.encode() + b"/").hex() + short_uid() * 8)[:64]


def get_region_from_subscription_token(token: str) -> str:
    try:
        region = token.split("2f", maxsplit=1)[0]
        return bytes.fromhex(region).decode("utf-8")
    except (IndexError, ValueError, TypeError, UnicodeDecodeError):
        raise InvalidParameterException("Invalid parameter: Token")


def get_next_page_token_from_arn(resource_arn: str) -> str:
    return to_str(base64.b64encode(to_bytes(resource_arn)))


def validate_subscription_attribute(
    attribute_name: str,
    attribute_value: str,
    topic_arn: str,
    endpoint: str,
    is_subscribe_call: bool = False,
) -> None:
    error_prefix = "Invalid parameter: Attributes Reason: " if is_subscribe_call else "Invalid parameter: "
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
                "Please use either MessageBody or MessageAttributes"
            )
    elif attribute_name == "RawMessageDelivery":
        if attribute_value.lower() not in ("true", "false"):
            raise InvalidParameterException(
                f"{error_prefix}RawMessageDelivery: Invalid value [{attribute_value}]. Must be true or false."
            )
    elif attribute_name == "RedrivePolicy":
        try:
            dlq_target_arn = json.loads(attribute_value).get("deadLetterTargetArn", "")
        except json.JSONDecodeError:
            raise InvalidParameterException(f"{error_prefix}RedrivePolicy: failed to parse JSON.")
        try:
            parsed = parse_arn(dlq_target_arn)
        except InvalidArnException:
            raise InvalidParameterException(
                f"{error_prefix}RedrivePolicy: deadLetterTargetArn is an invalid arn"
            )
        if topic_arn.endswith(".fifo"):
            if endpoint.endswith(".fifo") and (
                not parsed["resource"].endswith(".fifo") or "sqs" not in parsed["service"]
            ):
                raise InvalidParameterException(
                    f"{error_prefix}RedrivePolicy: must use a FIFO queue as DLQ for a FIFO Subscription to a FIFO Topic."
                )


def validate_message_attributes(message_attributes: MessageAttributeMap, position: int | None = None) -> None:
    for attr_name, attr in message_attributes.items():
        if len(attr_name) > 256:
            raise InvalidParameterValueException(
                "Length of message attribute name must be less than 256 bytes."
            )
        validate_message_attribute_name(attr_name)
        if (data_type := attr.get("DataType")) is None:
            if position:
                at = (
                    f"publishBatchRequestEntries.{position}.member.messageAttributes."
                    f"{attr_name}.member.dataType"
                )
            else:
                at = f"messageAttributes.{attr_name}.member.dataType"

            raise CommonServiceException(
                code="ValidationError",
                message=(
                    "1 validation error detected: Value null at "
                    f"'{at}' failed to satisfy constraint: Member must not be null"
                ),
                sender_fault=True,
            )

        if data_type not in ("String", "Number", "Binary") and not sns_constants.ATTR_TYPE_REGEX.match(data_type):
            raise InvalidParameterValueException(
                f"The message attribute '{attr_name}' has an invalid message attribute type, the set of supported type prefixes is Binary, Number, and String."
            )
        if not any(k.endswith("Value") for k in attr):
            raise InvalidParameterValueException(
                f"The message attribute '{attr_name}' must contain non-empty message attribute value for message attribute type '{data_type}'."
            )

        value_key_data_type = "Binary" if data_type.startswith("Binary") else "String"
        value_key = f"{value_key_data_type}Value"
        if value_key not in attr:
            raise InvalidParameterValueException(
                f"The message attribute '{attr_name}' with type '{data_type}' must use field '{value_key_data_type}'."
            )
        if not attr[value_key]:
            raise InvalidParameterValueException(
                f"The message attribute '{attr_name}' must contain non-empty message attribute value for message attribute type '{data_type}'.",
            )


def validate_message_attribute_name(name: str) -> None:
    if not sns_constants.MSG_ATTR_NAME_REGEX.match(name):
        if name[0] == ".":
            raise InvalidParameterValueException(
                "Invalid message attribute name starting with character '.' was found."
            )
        if name[-1] == ".":
            raise InvalidParameterValueException(
                "Invalid message attribute name ending with character '.' was found."
            )
        for idx, char in enumerate(name):
            if char not in sns_constants.VALID_MSG_ATTR_NAME_CHARS:
                hex_char = "#x" + hex(ord(char)).upper()[2:]
                raise InvalidParameterValueException(
                    "Invalid non-alphanumeric character "
                    f"'{hex_char}' was found in the message attribute name. "
                    "Can only include alphanumeric characters, hyphens, underscores, or dots."
                )
            if char == "." and name[idx - 1] == ".":
                raise InvalidParameterValueException(
                    "Message attribute name can not have successive '.' character."
                )


def _get_byte_size(payload: str | bytes) -> int:
    return len(to_bytes(payload))


def get_total_publish_size(message_body: str, message_attributes: MessageAttributeMap | None) -> int:
    size = _get_byte_size(message_body)
    if message_attributes:
        size += sum(
            _get_byte_size(key) + sum(_get_byte_size(v) for v in attr.values())
            for key, attr in message_attributes.items()
        )
    return size


def extract_tags(topic_arn: str, tags: TagList, is_create_topic_request: bool, store: SnsStore) -> bool:
    existing_tags = list(store.sns_tags.get(topic_arn, []))
    if topic_arn in store.topics:
        if tags is None:
            tags = []
        for tag in tags:
            if is_create_topic_request and existing_tags is not None and tag not in existing_tags:
                return False
    return True


def _load_topic_policy(policy_value: object, topic_arn: str) -> dict:
    if not policy_value:
        return create_default_sns_topic_policy(topic_arn)
    if isinstance(policy_value, dict):
        return policy_value
    if isinstance(policy_value, str):
        try:
            return json.loads(policy_value)
        except json.JSONDecodeError:
            return create_default_sns_topic_policy(topic_arn)
    return create_default_sns_topic_policy(topic_arn)
    ActionsList,
    DelegatesList,
    label,
    DelegatesList,

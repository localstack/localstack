import contextlib
import copy
import json
import logging
import re

from botocore.utils import InvalidArnException

from localstack.aws.api import RequestContext
from localstack.aws.api.sns import (
    CreateTopicResponse,
    GetTopicAttributesResponse,
    InvalidParameterException,
    ListTopicsResponse,
    NotFoundException,
    SnsApi,
    SubscribeResponse,
    SubscriptionAttributesMap,
    TagList,
    TopicAttributesMap,
    attributeName,
    attributeValue,
    endpoint,
    nextToken,
    protocol,
    subscriptionARN,
    topicARN,
    topicName,
)
from localstack.services.sns import constants as sns_constants
from localstack.services.sns.certificate import SNS_SERVER_CERT
from localstack.services.sns.constants import DUMMY_SUBSCRIPTION_PRINCIPAL
from localstack.services.sns.filter import FilterPolicyValidator
from localstack.services.sns.models import (
    SnsStore,
    sns_stores,
)
from localstack.services.sns.publisher import PublishDispatcher, SnsPublishContext
from localstack.services.sns.v2.models import SnsMessage, SnsMessageType, SnsSubscription, Topic
from localstack.services.sns.v2.models import create_topic, sns_stores
from localstack.services.sns.v2.utils import (
    create_subscription_arn,
    encode_subscription_token_with_region,
    is_valid_e164_number,
    parse_and_validate_topic_arn,
    validate_subscription_attribute,
)
from localstack.utils.aws.arns import get_partition, parse_arn, sns_topic_arn
from localstack.services.sns.v2.models import SnsStore, Topic, sns_stores
from localstack.utils.aws.arns import ArnData, parse_arn, sns_topic_arn
from localstack.utils.collections import PaginatedList

# set up logger
LOG = logging.getLogger(__name__)

SNS_TOPIC_NAME_PATTERN_FIFO = r"^[a-zA-Z0-9_-]{1,256}\.fifo$"
SNS_TOPIC_NAME_PATTERN = r"^[a-zA-Z0-9_-]{1,256}$"


class SnsProvider(SnsApi):
    def __init__(self) -> None:
        super().__init__()
        self._publisher = PublishDispatcher()
        self._signature_cert_pem: str = SNS_SERVER_CERT

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
            return CreateTopicResponse(TopicArn=topic_arn)

        attributes = attributes or {}
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

        topic = _create_topic(name=name, attributes=attributes, context=context)
        store.topics[topic_arn] = topic
        # todo: tags

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
            lambda topic: topic["TopicArn"], next_token=next_token, page_size=100
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
        elif protocol == "sms" and not is_valid_e164_number(endpoint):
            raise InvalidParameterException(f"Invalid SMS endpoint: {endpoint}")

        elif protocol == "sqs":
            try:
                parse_arn(endpoint)
            except InvalidArnException:
                raise InvalidParameterException("Invalid parameter: SQS endpoint ARN")

        elif protocol == "application":
            # TODO: This needs to be implemented once applications are ported from moto to the new provider
            raise NotImplementedError(
                "This functionality needs yet to be ported to the new SNS provider"
            )

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
                # TODO: add topic attributes once they are ported from moto to LocalStack
                # topic_attributes=vars(self._get_topic(topic_arn, context)),
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

        store = self.get_store(account_id=account_id, region_name=region_name)
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

        with contextlib.suppress(ValueError):
            store.topic_subscriptions[subscription["TopicArn"]].remove(subscription_arn)
        store.subscription_filter_policy.pop(subscription_arn, None)
        store.subscriptions.pop(subscription_arn, None)

    @staticmethod
    def get_store(account_id: str, region: str) -> SnsStore:
        return sns_stores[account_id][region]

    # TODO: reintroduce multi-region parameter (latest before final migration from v1)
    @staticmethod
    def _get_topic(arn: str, context: RequestContext) -> Topic:
        """
        :param arn: the Topic ARN
        :param context: the RequestContext of the request
        :return: the model Topic
        """
        arn_data = parse_and_validate_topic_arn(arn)
        if context.region != arn_data["region"]:
            raise InvalidParameterException("Invalid parameter: TopicArn")
        try:
            store = SnsProvider.get_store(context.account_id, context.region)
            return store.topics[arn]
        except KeyError:
            raise NotFoundException("Topic does not exist")


def parse_and_validate_topic_arn(topic_arn: str | None) -> ArnData:
    topic_arn = topic_arn or ""
    try:
        return parse_arn(topic_arn)
    except InvalidArnException:
        count = len(topic_arn.split(":"))
        raise InvalidParameterException(
            f"Invalid parameter: TopicArn Reason: An ARN must have at least 6 elements, not {count}"
        )


def _create_topic(name: str, attributes: dict, context: RequestContext) -> Topic:
    topic_arn = sns_topic_arn(
        topic_name=name, region_name=context.region, account_id=context.account_id
    )
    topic: Topic = {
        "name": name,
        "arn": topic_arn,
        "attributes": {},
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
                "SignatureVersion": "2",
            }
        )
    return default_attributes


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

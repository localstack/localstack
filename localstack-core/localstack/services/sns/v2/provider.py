import contextlib
import copy
import json
import logging
import re

from botocore.utils import InvalidArnException

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.api.sns import (
    AmazonResourceName,
    ConfirmSubscriptionResponse,
    CreateEndpointResponse,
    CreatePlatformApplicationResponse,
    CreateTopicResponse,
    Endpoint,
    GetEndpointAttributesResponse,
    GetPlatformApplicationAttributesResponse,
    GetSMSAttributesResponse,
    GetSubscriptionAttributesResponse,
    GetTopicAttributesResponse,
    InvalidParameterException,
    ListEndpointsByPlatformApplicationResponse,
    ListPlatformApplicationsResponse,
    ListString,
    ListSubscriptionsByTopicResponse,
    ListSubscriptionsResponse,
    ListTagsForResourceResponse,
    ListTopicsResponse,
    MapStringToString,
    NotFoundException,
    PlatformApplication,
    SetSMSAttributesResponse,
    SnsApi,
    String,
    SubscribeResponse,
    Subscription,
    SubscriptionAttributesMap,
    TagKeyList,
    TagList,
    TagResourceResponse,
    TopicAttributesMap,
    UntagResourceResponse,
    attributeName,
    attributeValue,
    authenticateOnUnsubscribe,
    endpoint,
    nextToken,
    protocol,
    subscriptionARN,
    topicARN,
    topicName,
)
from localstack.services.sns import constants as sns_constants
from localstack.services.sns.certificate import SNS_SERVER_CERT
from localstack.services.sns.constants import (
    DUMMY_SUBSCRIPTION_PRINCIPAL,
    VALID_APPLICATION_PLATFORMS,
)
from localstack.services.sns.filter import FilterPolicyValidator
from localstack.services.sns.publisher import PublishDispatcher, SnsPublishContext
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
    is_valid_e164_number,
    parse_and_validate_platform_application_arn,
    parse_and_validate_topic_arn,
    validate_subscription_attribute,
)
from localstack.utils.aws.arns import (
    get_partition,
    parse_arn,
    sns_platform_application_arn,
    sns_topic_arn,
)
from localstack.utils.collections import PaginatedList, select_from_typed_dict

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
            tag_resource_success = _check_matching_tags(topic_arn, tags, store)
            if not tag_resource_success:
                raise InvalidParameterException(
                    "Invalid parameter: Tags Reason: Topic already exists with different tags"
                )
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

        if topic_arn not in store.topics:
            raise NotFoundException("Topic does not exist")

        topic_subscriptions = store.topics[topic_arn]["subscriptions"]
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
        topic: Topic = self._get_topic(topic_arn, context)
        parsed_topic_arn = parse_and_validate_topic_arn(topic_arn)
        store = self.get_store(parsed_topic_arn["account"], parsed_topic_arn["region"])
        sub_arns: list[str] = topic.get("subscriptions", [])
        subscriptions = [store.subscriptions[k] for k in sub_arns if k in store.subscriptions]

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

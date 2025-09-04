import logging
from concurrent.futures.thread import ThreadPoolExecutor
from dataclasses import dataclass, field

from localstack.services.sns.executor import TopicPartitionedThreadPoolExecutor
from localstack.services.sns.models import (
    SnsMessage,
    SnsStore,
)
from localstack.services.sns.v2.filter import SubscriptionFilter
from localstack.services.sns.v2.models import SnsSubscription

LOG = logging.getLogger(__name__)


@dataclass
class SnsPublishContext:
    message: SnsMessage
    store: SnsStore
    request_headers: dict[str, str]
    topic_attributes: dict[str, str] = field(default_factory=dict)


@dataclass
class SnsBatchPublishContext:
    messages: list[SnsMessage]
    store: SnsStore
    request_headers: dict[str, str]
    topic_attributes: dict[str, str] = field(default_factory=dict)


class PublishDispatcher:
    """
    The PublishDispatcher is responsible for dispatching the publishing of SNS messages asynchronously to worker
    threads via a `ThreadPoolExecutor`, depending on the SNS subscriber protocol and filter policy.
    """

    # TODO: port these one by one when verifying publish
    topic_notifiers = {
        # "http": HttpTopicPublisher(),
        # "https": HttpTopicPublisher(),
        # "email": EmailTopicPublisher(),
        # "email-json": EmailJsonTopicPublisher(),
        # "sms": SmsTopicPublisher(),
        # "sqs": SqsTopicPublisher(),
        # "application": ApplicationTopicPublisher(),
        # "lambda": LambdaTopicPublisher(),
        # "firehose": FirehoseTopicPublisher(),
    }
    # batch_topic_notifiers = {"sqs": SqsBatchTopicPublisher()}
    # sms_notifier = SmsPhoneNumberPublisher()
    # application_notifier = ApplicationEndpointPublisher()

    subscription_filter = SubscriptionFilter()

    def __init__(self, num_thread: int = 10):
        self.executor = ThreadPoolExecutor(num_thread, thread_name_prefix="sns_pub")
        self.topic_partitioned_executor = TopicPartitionedThreadPoolExecutor(
            max_workers=num_thread, thread_name_prefix="sns_pub_fifo"
        )

    def shutdown(self):
        self.executor.shutdown(wait=False)
        self.topic_partitioned_executor.shutdown(wait=False)

    def _should_publish(
        self,
        subscription_filter_policy: dict[str, dict],
        message_ctx: SnsMessage,
        subscriber: SnsSubscription,
    ):
        """
        Validate that the message should be relayed to the subscriber, depending on the filter policy and the
        subscription status
        """
        # FIXME: for now, send to email even if not confirmed, as we do not send the token to confirm to email
        # subscriptions
        if (
            not subscriber["PendingConfirmation"] == "false"
            and "email" not in subscriber["Protocol"]
        ):
            return

        subscriber_arn = subscriber["SubscriptionArn"]
        filter_policy = subscription_filter_policy.get(subscriber_arn)
        if not filter_policy:
            return True
        # default value is `MessageAttributes`
        match subscriber.get("FilterPolicyScope", "MessageAttributes"):
            case "MessageAttributes":
                return self.subscription_filter.check_filter_policy_on_message_attributes(
                    filter_policy=filter_policy, message_attributes=message_ctx.message_attributes
                )
            case "MessageBody":
                return self.subscription_filter.check_filter_policy_on_message_body(
                    filter_policy=filter_policy,
                    message_body=message_ctx.message_content(subscriber["Protocol"]),
                )

    def publish_to_topic(self, ctx: SnsPublishContext, topic_arn: str) -> None:
        subscriptions = ctx.store.get_topic_subscriptions(topic_arn)
        for subscriber in subscriptions:
            if self._should_publish(ctx.store.subscription_filter_policy, ctx.message, subscriber):
                notifier = self.topic_notifiers[subscriber["Protocol"]]
                LOG.debug(
                    "Topic '%s' publishing '%s' to subscribed '%s' with protocol '%s' (subscription '%s')",
                    topic_arn,
                    ctx.message.message_id,
                    subscriber.get("Endpoint"),
                    subscriber["Protocol"],
                    subscriber["SubscriptionArn"],
                )
                self._submit_notification(notifier, ctx, subscriber)

    def _submit_notification(
        self, notifier, ctx: SnsPublishContext | SnsBatchPublishContext, subscriber: SnsSubscription
    ):
        if (topic_arn := subscriber.get("TopicArn", "")).endswith(".fifo"):
            # TODO: we still need to implement Message deduplication on the topic level with `should_publish` for FIFO
            self.topic_partitioned_executor.submit(
                notifier.publish, topic_arn, context=ctx, subscriber=subscriber
            )
        else:
            self.executor.submit(notifier.publish, context=ctx, subscriber=subscriber)

    def publish_to_topic_subscriber(
        self, ctx: SnsPublishContext, topic_arn: str, subscription_arn: str
    ) -> None:
        """
        This allows us to publish specific HTTP(S) messages specific to those endpoints, namely
        `SubscriptionConfirmation` and `UnsubscribeConfirmation`. Those are "topic" messages in shape, but are sent
        only to the endpoint subscribing or unsubscribing.
        This is only used internally.
        Note: might be needed for multi account SQS and Lambda `SubscriptionConfirmation`
        :param ctx: SnsPublishContext
        :param topic_arn: the topic of the subscriber
        :param subscription_arn: the ARN of the subscriber
        :return: None
        """
        subscriber = ctx.store.subscriptions.get(subscription_arn)
        if not subscriber:
            return
        notifier = self.topic_notifiers[subscriber["Protocol"]]
        LOG.debug(
            "Topic '%s' publishing '%s' to subscribed '%s' with protocol '%s' (Id='%s', Subscription='%s')",
            topic_arn,
            ctx.message.type,
            subscription_arn,
            subscriber["Protocol"],
            ctx.message.message_id,
            subscriber.get("Endpoint"),
        )
        self.executor.submit(notifier.publish, context=ctx, subscriber=subscriber)

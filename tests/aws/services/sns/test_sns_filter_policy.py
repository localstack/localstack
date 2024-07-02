import copy
import json
from operator import itemgetter

import pytest
from botocore.exceptions import ClientError

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws.arns import get_partition
from localstack.utils.sync import poll_condition, retry


@pytest.fixture(autouse=True)
def sns_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.sns_api())


@pytest.fixture
def sns_create_sqs_subscription_with_filter_policy(sns_create_sqs_subscription, aws_client):
    def _inner(topic_arn: str, queue_url: str, filter_scope: str, filter_policy: dict):
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicyScope",
            AttributeValue=filter_scope,
        )

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicy",
            AttributeValue=json.dumps(filter_policy),
        )

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="RawMessageDelivery",
            AttributeValue="true",
        )
        return subscription_arn

    yield _inner


class TestSNSFilterPolicyCrud:
    @markers.aws.validated
    def test_set_subscription_filter_policy_scope(
        self, sqs_create_queue, sns_create_topic, sns_create_sqs_subscription, snapshot, aws_client
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]

        # we fetch the default subscription attributes
        # note: the FilterPolicyScope is not present in the response
        subscription_attrs = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )
        snapshot.match("sub-attrs-default", subscription_attrs)

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicyScope",
            AttributeValue="MessageBody",
        )

        # we fetch the subscription attributes after setting the FilterPolicyScope
        # note: the FilterPolicyScope is still not present in the response
        subscription_attrs = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )
        snapshot.match("sub-attrs-filter-scope-body", subscription_attrs)

        # we try to set random values to the FilterPolicyScope
        with pytest.raises(ClientError) as e:
            aws_client.sns.set_subscription_attributes(
                SubscriptionArn=subscription_arn,
                AttributeName="FilterPolicyScope",
                AttributeValue="RandomValue",
            )

        snapshot.match("sub-attrs-filter-scope-error", e.value.response)

        # we try to set a FilterPolicy to see if it will show the FilterPolicyScope in the attributes
        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicy",
            AttributeValue=json.dumps({"attr": ["match-this"]}),
        )
        # the FilterPolicyScope is now present in the attributes
        subscription_attrs = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )
        snapshot.match("sub-attrs-after-setting-policy", subscription_attrs)

    @markers.aws.validated
    def test_sub_filter_policy_nested_property(
        self, sqs_create_queue, sns_create_topic, sns_create_sqs_subscription, snapshot, aws_client
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]

        # see https://aws.amazon.com/blogs/compute/introducing-payload-based-message-filtering-for-amazon-sns/
        nested_filter_policy = {"object": {"key": [{"prefix": "auto-"}]}}
        with pytest.raises(ClientError) as e:
            aws_client.sns.set_subscription_attributes(
                SubscriptionArn=subscription_arn,
                AttributeName="FilterPolicy",
                AttributeValue=json.dumps(nested_filter_policy),
            )
        snapshot.match("sub-filter-policy-nested-error", e.value.response)

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicyScope",
            AttributeValue="MessageBody",
        )

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicy",
            AttributeValue=json.dumps(nested_filter_policy),
        )

        # the FilterPolicyScope is now present in the attributes
        subscription_attrs = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )
        snapshot.match("sub-attrs-after-setting-nested-policy", subscription_attrs)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$.sub-filter-policy-rule-no-list.Error.Message",  # message contains java trace in AWS, assert instead
        ]
    )
    def test_sub_filter_policy_nested_property_constraints(
        self, sqs_create_queue, sns_create_topic, sns_create_sqs_subscription, snapshot, aws_client
    ):
        # https://docs.aws.amazon.com/sns/latest/dg/subscription-filter-policy-constraints.html
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicyScope",
            AttributeValue="MessageBody",
        )

        nested_filter_policy = {
            "key_a": {
                "key_b": {"key_c": ["value_one", "value_two", "value_three", "value_four"]},
            },
            "key_d": {"key_e": ["value_one", "value_two", "value_three"]},
            "key_f": ["value_one", "value_two", "value_three"],
        }
        # The first array has four values in a three-level nested key, and the second has three values in a two-level
        # nested key. The total combination is calculated as follows:
        # 3 x 4 x 2 x 3 x 1 x 3 = 216
        with pytest.raises(ClientError) as e:
            aws_client.sns.set_subscription_attributes(
                SubscriptionArn=subscription_arn,
                AttributeName="FilterPolicy",
                AttributeValue=json.dumps(nested_filter_policy),
            )
        snapshot.match("sub-filter-policy-nested-error-too-many-combinations", e.value.response)

        flat_filter_policy = {
            "key_a": ["value_one"],
            "key_b": ["value_two"],
            "key_c": ["value_three"],
            "key_d": ["value_four"],
            "key_e": ["value_five"],
            "key_f": ["value_six"],
        }
        # A filter policy can have a maximum of five attribute names. For a nested policy, only parent keys are counted.
        with pytest.raises(ClientError) as e:
            aws_client.sns.set_subscription_attributes(
                SubscriptionArn=subscription_arn,
                AttributeName="FilterPolicy",
                AttributeValue=json.dumps(flat_filter_policy),
            )
        snapshot.match("sub-filter-policy-max-attr-keys", e.value.response)

        flat_filter_policy = {"key_a": "value_one"}
        # Rules should be contained in a list
        with pytest.raises(ClientError) as e:
            aws_client.sns.set_subscription_attributes(
                SubscriptionArn=subscription_arn,
                AttributeName="FilterPolicy",
                AttributeValue=json.dumps(flat_filter_policy),
            )
        snapshot.match("sub-filter-policy-rule-no-list", e.value.response)
        assert e.value.response["Error"]["Message"].startswith(
            'Invalid parameter: FilterPolicy: "key_a" must be an object or an array'
        )


class TestSNSFilterPolicyAttributes:
    @markers.aws.validated
    def test_filter_policy(
        self, sqs_create_queue, sns_create_topic, sns_create_sqs_subscription, snapshot, aws_client
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]

        filter_policy = {"attr1": [{"numeric": [">", 0, "<=", 100]}]}
        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicy",
            AttributeValue=json.dumps(filter_policy),
        )

        response_attributes = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )
        snapshot.match("subscription-attributes", response_attributes)

        response_0 = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=1
        )
        snapshot.match("messages-0", response_0)
        # get number of messages
        num_msgs_0 = len(response_0.get("Messages", []))

        # publish message that satisfies the filter policy, assert that message is received
        message = "This is a test message"
        message_attributes = {"attr1": {"DataType": "Number", "StringValue": "99"}}
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message,
            MessageAttributes=message_attributes,
        )

        response_1 = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )
        snapshot.match("messages-1", response_1)

        num_msgs_1 = len(response_1["Messages"])
        assert num_msgs_1 == (num_msgs_0 + 1)

        # publish message that does not satisfy the filter policy, assert that message is not received
        message = "This is another test message"
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message,
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "111"}},
        )

        response_2 = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )
        snapshot.match("messages-2", response_2)
        num_msgs_2 = len(response_2["Messages"])
        assert num_msgs_2 == num_msgs_1

        # remove all messages from the queue
        receipt_handle = response_1["Messages"][0]["ReceiptHandle"]
        aws_client.sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)

        # test with a property value set to null with an OR operator with anything-but
        filter_policy = json.dumps({"attr1": [None, {"anything-but": "whatever"}]})
        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicy",
            AttributeValue=filter_policy,
        )

        def get_filter_policy():
            subscription_attrs = aws_client.sns.get_subscription_attributes(
                SubscriptionArn=subscription_arn
            )
            return subscription_attrs["Attributes"]["FilterPolicy"]

        # wait for the new filter policy to be in effect
        poll_condition(lambda: get_filter_policy() == filter_policy, timeout=4)
        response_attributes_2 = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )
        snapshot.match("subscription-attributes-2", response_attributes_2)

        # publish message that does not satisfy the filter policy, assert that message is not received
        message = "This the test message for null"
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message,
        )

        response_3 = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )
        snapshot.match("messages-3", response_3)
        assert "Messages" not in response_3 or response_3["Messages"] == []

        # unset the filter policy
        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicy",
            AttributeValue="",
        )

        def check_no_filter_policy():
            subscription_attrs = aws_client.sns.get_subscription_attributes(
                SubscriptionArn=subscription_arn
            )
            return "FilterPolicy" not in subscription_attrs["Attributes"]

        poll_condition(check_no_filter_policy, timeout=4)

        # publish message that does not satisfy the previous filter policy, but assert that the message is received now
        message = "This the test message for null"
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message,
        )

        response_4 = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )
        snapshot.match("messages-4", response_4)

    @markers.aws.validated
    def test_exists_filter_policy(
        self, sqs_create_queue, sns_create_topic, sns_create_sqs_subscription, snapshot, aws_client
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]

        filter_policy = {"store": [{"exists": True}]}
        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicy",
            AttributeValue=json.dumps(filter_policy),
        )

        response_attributes = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )
        snapshot.match("subscription-attributes-policy-1", response_attributes)

        response_0 = aws_client.sqs.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)
        snapshot.match("messages-0", response_0)
        # get number of messages
        num_msgs_0 = len(response_0.get("Messages", []))

        # publish message that satisfies the filter policy, assert that message is received
        message_1 = "message-1"
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message_1,
            MessageAttributes={
                "store": {"DataType": "Number", "StringValue": "99"},
                "def": {"DataType": "Number", "StringValue": "99"},
            },
        )
        response_1 = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )
        snapshot.match("messages-1", response_1)
        num_msgs_1 = len(response_1["Messages"])
        assert num_msgs_1 == (num_msgs_0 + 1)

        # publish message that does not satisfy the filter policy, assert that message is not received
        message_2 = "message-2"
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message_2,
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "111"}},
        )

        response_2 = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )
        snapshot.match("messages-2", response_2)
        num_msgs_2 = len(response_2["Messages"])
        assert num_msgs_2 == num_msgs_1

        # delete first message
        aws_client.sqs.delete_message(
            QueueUrl=queue_url, ReceiptHandle=response_1["Messages"][0]["ReceiptHandle"]
        )

        # test with exist operator set to false.
        filter_policy = json.dumps({"store": [{"exists": False}]})
        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicy",
            AttributeValue=filter_policy,
        )

        def get_filter_policy():
            subscription_attrs = aws_client.sns.get_subscription_attributes(
                SubscriptionArn=subscription_arn
            )
            return subscription_attrs["Attributes"]["FilterPolicy"]

        # wait for the new filter policy to be in effect
        poll_condition(lambda: get_filter_policy() == filter_policy, timeout=4)
        response_attributes_2 = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )
        snapshot.match("subscription-attributes-policy-2", response_attributes_2)

        # publish message that satisfies the filter policy, assert that message is received
        message_3 = "message-3"
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message_3,
            MessageAttributes={"def": {"DataType": "Number", "StringValue": "99"}},
        )

        response_3 = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )
        snapshot.match("messages-3", response_3)
        num_msgs_3 = len(response_3["Messages"])
        assert num_msgs_3 == num_msgs_1

        # publish message that does not satisfy the filter policy, assert that message is not received
        message_4 = "message-4"
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message_4,
            MessageAttributes={
                "store": {"DataType": "Number", "StringValue": "99"},
                "def": {"DataType": "Number", "StringValue": "99"},
            },
        )

        response_4 = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )
        snapshot.match("messages-4", response_4)
        num_msgs_4 = len(response_4["Messages"])
        assert num_msgs_4 == num_msgs_3

    @markers.aws.validated
    def test_exists_filter_policy_attributes_array(
        self,
        sqs_create_queue,
        sns_create_topic,
        sns_create_sqs_subscription_with_filter_policy,
        snapshot,
        aws_client,
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        filter_policy = {"store": ["value1"]}
        subscription_arn = sns_create_sqs_subscription_with_filter_policy(
            topic_arn=topic_arn,
            queue_url=queue_url,
            filter_scope="MessageAttributes",
            filter_policy=filter_policy,
        )

        response_attributes = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )
        snapshot.match("subscription-attributes-policy", response_attributes)

        response_0 = aws_client.sqs.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)
        snapshot.match("messages-init", response_0)

        # publish message that satisfies the filter policy, assert that message is received
        message = "message-1"
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message,
            MessageAttributes={
                "store": {"DataType": "String", "StringValue": "value1"},
            },
        )
        response_1 = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )
        aws_client.sqs.delete_message(
            QueueUrl=queue_url, ReceiptHandle=response_1["Messages"][0]["ReceiptHandle"]
        )
        snapshot.match("messages-1", response_1)

        # publish message that satisfies the filter policy but with String.Array
        message = "message-2"
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message,
            MessageAttributes={
                "store": {
                    "DataType": "String.Array",
                    "StringValue": json.dumps(["value1", "value2"]),
                },
            },
        )
        response_2 = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )
        aws_client.sqs.delete_message(
            QueueUrl=queue_url, ReceiptHandle=response_2["Messages"][0]["ReceiptHandle"]
        )
        snapshot.match("messages-2", response_2)

        # publish message that does not satisfy the filter policy with String.Array
        message = "message-3"
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message,
            MessageAttributes={
                "store": {
                    "DataType": "String.Array",
                    "StringValue": json.dumps(["value2", "value3"]),
                },
            },
        )
        response_3 = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )
        snapshot.match("messages-3", response_3)


class TestSNSFilterPolicyBody:
    @markers.aws.validated
    @pytest.mark.parametrize("raw_message_delivery", [True, False])
    def test_filter_policy_on_message_body(
        self,
        sqs_create_queue,
        sns_create_topic,
        sns_create_sqs_subscription,
        snapshot,
        raw_message_delivery,
        aws_client,
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]
        # see https://aws.amazon.com/blogs/compute/introducing-payload-based-message-filtering-for-amazon-sns/
        nested_filter_policy = {
            "object": {
                "key": [{"prefix": "auto-"}, "hardcodedvalue"],
                "nested_key": [{"exists": False}],
            },
            "test": [{"exists": False}],
        }

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicyScope",
            AttributeValue="MessageBody",
        )

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicy",
            AttributeValue=json.dumps(nested_filter_policy),
        )

        if raw_message_delivery:
            aws_client.sns.set_subscription_attributes(
                SubscriptionArn=subscription_arn,
                AttributeName="RawMessageDelivery",
                AttributeValue="true",
            )

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=1
        )
        snapshot.match("recv-init", response)
        # assert there are no messages in the queue
        assert "Messages" not in response or response["Messages"] == []

        # publish messages that satisfies the filter policy, assert that messages are received
        messages = [
            {"object": {"key": "auto-test"}},
            {"object": {"key": "hardcodedvalue"}},
        ]
        for i, message in enumerate(messages):
            aws_client.sns.publish(
                TopicArn=topic_arn,
                Message=json.dumps(message),
            )

            response = aws_client.sqs.receive_message(
                QueueUrl=queue_url,
                VisibilityTimeout=0,
                WaitTimeSeconds=5 if is_aws_cloud() else 2,
            )
            snapshot.match(f"recv-passed-msg-{i}", response)
            receipt_handle = response["Messages"][0]["ReceiptHandle"]
            aws_client.sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)

        # publish messages that do not satisfy the filter policy, assert those messages are not received
        messages = [
            {"object": {"key": "test-auto"}},
            {"object": {"key": "auto-test"}, "test": "just-exists"},
            {"object": {"key": "auto-test", "nested_key": "just-exists"}},
            {"object": {"test": "auto-test"}},
            {"test": "auto-test"},
        ]
        for message in messages:
            aws_client.sns.publish(
                TopicArn=topic_arn,
                Message=json.dumps(message),
            )

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=5 if is_aws_cloud() else 2
        )
        # assert there are no messages in the queue
        assert "Messages" not in response or response["Messages"] == []

        # publish message that does not satisfy the filter policy as it's not even JSON, or not a JSON object
        message = "Regular string message"
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message,
        )
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=json.dumps(message),  # send it JSON encoded, but not an object
        )

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=2
        )
        # assert there are no messages in the queue
        assert "Messages" not in response or response["Messages"] == []

    @markers.aws.validated
    def test_filter_policy_for_batch(
        self, sqs_create_queue, sns_create_topic, sns_create_sqs_subscription, snapshot, aws_client
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url_with_filter = sqs_create_queue()
        subscription_with_filter = sns_create_sqs_subscription(
            topic_arn=topic_arn, queue_url=queue_url_with_filter
        )
        subscription_with_filter_arn = subscription_with_filter["SubscriptionArn"]

        queue_url_no_filter = sqs_create_queue()
        subscription_no_filter = sns_create_sqs_subscription(
            topic_arn=topic_arn, queue_url=queue_url_no_filter
        )
        subscription_no_filter_arn = subscription_no_filter["SubscriptionArn"]

        filter_policy = {"attr1": [{"numeric": [">", 0, "<=", 100]}]}
        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_with_filter_arn,
            AttributeName="FilterPolicy",
            AttributeValue=json.dumps(filter_policy),
        )

        response_attributes = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscription_with_filter_arn
        )
        snapshot.match("subscription-attributes-with-filter", response_attributes)

        response_attributes = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscription_no_filter_arn
        )
        snapshot.match("subscription-attributes-no-filter", response_attributes)

        sqs_wait_time = 4 if is_aws_cloud() else 1

        response_before_publish_no_filter = aws_client.sqs.receive_message(
            QueueUrl=queue_url_with_filter, VisibilityTimeout=0, WaitTimeSeconds=sqs_wait_time
        )
        snapshot.match("messages-no-filter-before-publish", response_before_publish_no_filter)

        response_before_publish_filter = aws_client.sqs.receive_message(
            QueueUrl=queue_url_with_filter, VisibilityTimeout=0, WaitTimeSeconds=sqs_wait_time
        )
        snapshot.match("messages-with-filter-before-publish", response_before_publish_filter)

        # publish message that satisfies the filter policy, assert that message is received
        message = "This is a test message"
        message_attributes = {"attr1": {"DataType": "Number", "StringValue": "99"}}
        aws_client.sns.publish_batch(
            TopicArn=topic_arn,
            PublishBatchRequestEntries=[
                {
                    "Id": "1",
                    "Message": message,
                    "MessageAttributes": message_attributes,
                }
            ],
        )

        response_after_publish_no_filter = aws_client.sqs.receive_message(
            QueueUrl=queue_url_no_filter, VisibilityTimeout=0, WaitTimeSeconds=sqs_wait_time
        )
        snapshot.match("messages-no-filter-after-publish-ok", response_after_publish_no_filter)
        aws_client.sqs.delete_message(
            QueueUrl=queue_url_no_filter,
            ReceiptHandle=response_after_publish_no_filter["Messages"][0]["ReceiptHandle"],
        )

        response_after_publish_filter = aws_client.sqs.receive_message(
            QueueUrl=queue_url_with_filter, VisibilityTimeout=0, WaitTimeSeconds=sqs_wait_time
        )
        snapshot.match("messages-with-filter-after-publish-ok", response_after_publish_filter)
        aws_client.sqs.delete_message(
            QueueUrl=queue_url_with_filter,
            ReceiptHandle=response_after_publish_filter["Messages"][0]["ReceiptHandle"],
        )

        # publish message that does not satisfy the filter policy, assert that message is not received by the
        # subscription with the filter and received by the other
        aws_client.sns.publish_batch(
            TopicArn=topic_arn,
            PublishBatchRequestEntries=[
                {
                    "Id": "1",
                    "Message": "This is another test message",
                    "MessageAttributes": {"attr1": {"DataType": "Number", "StringValue": "111"}},
                }
            ],
        )

        response_after_publish_no_filter = aws_client.sqs.receive_message(
            QueueUrl=queue_url_no_filter, VisibilityTimeout=0, WaitTimeSeconds=sqs_wait_time
        )
        # there should be 1 message in the queue, latest sent
        snapshot.match("messages-no-filter-after-publish-ok-1", response_after_publish_no_filter)

        response_after_publish_filter = aws_client.sqs.receive_message(
            QueueUrl=queue_url_with_filter, VisibilityTimeout=0, WaitTimeSeconds=sqs_wait_time
        )
        # there should be no messages in this queue
        snapshot.match("messages-with-filter-after-publish-filtered", response_after_publish_filter)

    @markers.aws.validated
    def test_filter_policy_on_message_body_dot_attribute(
        self,
        sqs_create_queue,
        sns_create_topic,
        sns_create_sqs_subscription,
        snapshot,
        aws_client,
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]

        nested_filter_policy = json.dumps(
            {
                "object.nested": ["string.value"],
            }
        )

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicyScope",
            AttributeValue="MessageBody",
        )

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicy",
            AttributeValue=nested_filter_policy,
        )

        def get_filter_policy():
            subscription_attrs = aws_client.sns.get_subscription_attributes(
                SubscriptionArn=subscription_arn
            )
            return subscription_attrs["Attributes"]["FilterPolicy"]

        # wait for the new filter policy to be in effect
        poll_condition(lambda: get_filter_policy() == nested_filter_policy, timeout=4)

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=1
        )
        snapshot.match("recv-init", response)
        # assert there are no messages in the queue
        assert "Messages" not in response or response["Messages"] == []

        def _verify_and_snapshot_sqs_messages(msg_to_send: list[dict], snapshot_prefix: str):
            for i, _message in enumerate(msg_to_send):
                aws_client.sns.publish(
                    TopicArn=topic_arn,
                    Message=json.dumps(_message),
                )

                _response = aws_client.sqs.receive_message(
                    QueueUrl=queue_url,
                    VisibilityTimeout=0,
                    WaitTimeSeconds=5 if is_aws_cloud() else 2,
                )
                snapshot.match(f"{snapshot_prefix}-{i}", _response)
                receipt_handle = _response["Messages"][0]["ReceiptHandle"]
                aws_client.sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)

        # publish messages that satisfies the filter policy, assert that messages are received
        messages = [
            {"object": {"nested": "string.value"}},
            {"object.nested": "string.value"},
        ]
        _verify_and_snapshot_sqs_messages(messages, snapshot_prefix="recv-nested-msg")

        # publish messages that do not satisfy the filter policy, assert those messages are not received
        messages = [
            {"object": {"nested": "test-auto"}},
        ]
        for message in messages:
            aws_client.sns.publish(
                TopicArn=topic_arn,
                Message=json.dumps(message),
            )

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=5 if is_aws_cloud() else 2
        )
        # assert there are no messages in the queue
        assert "Messages" not in response or response["Messages"] == []

        # assert with more nesting
        deep_nested_filter_policy = json.dumps(
            {
                "object.nested.test": ["string.value"],
            }
        )

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicy",
            AttributeValue=deep_nested_filter_policy,
        )
        # wait for the new filter policy to be in effect
        poll_condition(lambda: get_filter_policy() == deep_nested_filter_policy, timeout=4)

        messages = [
            {"object": {"nested": {"test": "string.value"}}},
            {"object.nested.test": "string.value"},
            {"object.nested": {"test": "string.value"}},
            {"object": {"nested.test": "string.value"}},
        ]
        _verify_and_snapshot_sqs_messages(messages, snapshot_prefix="recv-deep-nested-msg")
        # publish messages that do not satisfy the filter policy, assert those messages are not received
        messages = [
            {"object": {"nested": {"test": "string.notvalue"}}},
        ]
        for message in messages:
            aws_client.sns.publish(
                TopicArn=topic_arn,
                Message=json.dumps(message),
            )

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=5 if is_aws_cloud() else 2
        )
        # assert there are no messages in the queue
        assert "Messages" not in response or response["Messages"] == []

    @markers.aws.validated
    def test_filter_policy_on_message_body_array_attributes(
        self,
        sqs_create_queue,
        sns_create_topic,
        sns_create_sqs_subscription_with_filter_policy,
        snapshot,
        aws_client,
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url_1 = sqs_create_queue()
        queue_url_2 = sqs_create_queue()

        filter_policy_1 = {"headers": {"route-to": ["queue1"]}}
        sns_create_sqs_subscription_with_filter_policy(
            topic_arn=topic_arn,
            queue_url=queue_url_1,
            filter_scope="MessageBody",
            filter_policy=filter_policy_1,
        )

        filter_policy_2 = {"headers": {"route-to": ["queue2"]}}
        sns_create_sqs_subscription_with_filter_policy(
            topic_arn=topic_arn,
            queue_url=queue_url_2,
            filter_scope="MessageBody",
            filter_policy=filter_policy_2,
        )

        queues = [queue_url_1, queue_url_2]

        # publish messages that satisfies the filter policy, assert that messages are received
        messages = [
            {"headers": {"route-to": ["queue3"]}},
            {"headers": {"route-to": ["queue1"]}},
            {"headers": {"route-to": ["queue2"]}},
            {"headers": {"route-to": ["queue1", "queue2"]}},
        ]
        for i, message in enumerate(messages):
            aws_client.sns.publish(
                TopicArn=topic_arn,
                Message=json.dumps(message),
            )

        def get_messages(_queue_url: str, _recv_messages: list):
            # due to the random nature of receiving SQS messages, we need to consolidate a single object to match
            sqs_response = aws_client.sqs.receive_message(
                QueueUrl=_queue_url,
                WaitTimeSeconds=1,
                VisibilityTimeout=0,
                MessageAttributeNames=["All"],
                AttributeNames=["All"],
            )
            for _message in sqs_response["Messages"]:
                _recv_messages.append(_message)
                aws_client.sqs.delete_message(
                    QueueUrl=_queue_url, ReceiptHandle=_message["ReceiptHandle"]
                )

            assert len(_recv_messages) == 2

        for i, queue_url in enumerate(queues):
            recv_messages = []
            retry(
                get_messages,
                retries=10,
                sleep=0.1,
                _queue_url=queue_url,
                _recv_messages=recv_messages,
            )
            # we need to sort the list (the order does not matter as we're not using FIFO)
            recv_messages.sort(key=itemgetter("Body"))
            snapshot.match(f"messages-queue-{i}", {"Messages": recv_messages})

    @markers.aws.validated
    def test_filter_policy_on_message_body_array_of_object_attributes(
        self,
        sqs_create_queue,
        sns_create_topic,
        sns_create_sqs_subscription_with_filter_policy,
        snapshot,
        aws_client,
        region_name,
    ):
        # example from https://aws.amazon.com/blogs/compute/introducing-payload-based-message-filtering-for-amazon-sns/
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        # complex filter policy with different level of nesting
        filter_policy = {
            "Records": {
                "s3": {"object": {"key": [{"prefix": "auto-"}]}},
                "eventName": [{"prefix": "ObjectCreated:"}],
            }
        }

        sns_create_sqs_subscription_with_filter_policy(
            topic_arn=topic_arn,
            queue_url=queue_url,
            filter_scope="MessageBody",
            filter_policy=filter_policy,
        )

        # stripped down events
        s3_event_auto_insurance_created = {
            "Records": [
                {
                    "eventSource": "aws:s3",
                    "eventTime": "2022-11-21T03:41:29.743Z",
                    "eventName": "ObjectCreated:Put",
                    "s3": {
                        "bucket": {
                            "name": "insurance-bucket-demo",
                            "arn": f"arn:{get_partition(region_name)}:s3:::insurance-bucket-demo",
                        },
                        "object": {
                            "key": "auto-insurance-2314.xml",
                            "size": 17,
                        },
                    },
                }
            ]
        }
        # copy the object to modify it
        s3_event_auto_insurance_removed = copy.deepcopy(s3_event_auto_insurance_created)
        s3_event_auto_insurance_removed["Records"][0]["eventName"] = "ObjectRemoved:Delete"

        # copy the object to modify it
        s3_event_home_insurance_created = copy.deepcopy(s3_event_auto_insurance_created)
        s3_event_home_insurance_created["Records"][0]["s3"]["object"]["key"] = (
            "home-insurance-2314.xml"
        )

        # stripped down events
        s3_event_multiple_records = {
            "Records": [
                {
                    "eventSource": "aws:s3",
                    "eventName": "ObjectCreated:Put",
                    "s3": {
                        # this object is a list of list of dict, and it works in AWS
                        "object": [
                            [
                                {
                                    "key": "auto-insurance-2314.xml",
                                    "size": 17,
                                }
                            ]
                        ],
                    },
                },
                {
                    "eventSource": "aws:s3",
                    "eventName": "ObjectRemoved:Delete",
                    "s3": {
                        "object": {
                            "key": "home-insurance-2314.xml",
                            "size": 17,
                        }
                    },
                },
            ]
        }

        messages = [
            s3_event_multiple_records,
            s3_event_auto_insurance_removed,
            s3_event_home_insurance_created,
            s3_event_auto_insurance_created,
        ]
        for i, message in enumerate(messages):
            aws_client.sns.publish(
                TopicArn=topic_arn,
                Message=json.dumps(message),
            )

        def get_messages(_queue_url: str, _received_messages: list):
            # due to the random nature of receiving SQS messages, we need to consolidate a single object to match
            sqs_response = aws_client.sqs.receive_message(
                QueueUrl=_queue_url,
                WaitTimeSeconds=1,
                VisibilityTimeout=0,
                MessageAttributeNames=["All"],
                AttributeNames=["All"],
            )
            for _message in sqs_response["Messages"]:
                _received_messages.append(_message)
                aws_client.sqs.delete_message(
                    QueueUrl=_queue_url, ReceiptHandle=_message["ReceiptHandle"]
                )

            assert len(_received_messages) == 2

        received_messages = []
        retry(
            get_messages,
            retries=10,
            sleep=0.1,
            _queue_url=queue_url,
            _received_messages=received_messages,
        )
        # we need to sort the list (the order does not matter as we're not using FIFO)
        received_messages.sort(key=itemgetter("Body"))
        snapshot.match("messages", {"Messages": received_messages})

    @markers.aws.validated
    def test_filter_policy_on_message_body_or_attribute(
        self,
        sqs_create_queue,
        sns_create_topic,
        sns_create_sqs_subscription_with_filter_policy,
        snapshot,
        aws_client,
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()

        filter_policy = {
            "$or": [
                {"metricName": ["CPUUtilization", "ReadLatency"]},
                {"namespace": ["AWS/EC2", "AWS/ES"]},
            ],
            "detail": {
                "scope": ["Service"],
                "$or": [
                    {"source": ["aws.cloudwatch"]},
                    {"type": ["CloudWatch Alarm State Change"]},
                ],
            },
        }
        sns_create_sqs_subscription_with_filter_policy(
            topic_arn=topic_arn,
            queue_url=queue_url,
            filter_scope="MessageBody",
            filter_policy=filter_policy,
        )

        # publish messages that satisfies the filter policy, assert that messages are received
        messages = [
            # not passing
            # wrong value for `metricName`
            {
                "metricName": "CPUUtilization",
                "detail": {"scope": "aws.cloudwatch", "type": "CloudWatch Alarm State Change"},
            },
            # wrong value for `detail.type`
            {
                "metricName": "CPUUtilization",
                "detail": {"scope": "Service", "type": "CPUUtilization"},
            },
            # missing value for `detail.scope`
            {"metricName": "CPUUtilization", "detail": {"type": "CloudWatch Alarm State Change"}},
            # missing value for `detail.type` or `detail.source`
            {"metricName": "CPUUtilization", "detail": {"scope": "Service"}},
            # missing value for `detail.scope` AND `detail.source` or `detail.type`
            {"metricName": "CPUUtilization", "scope": "Service"},
            # passing
            {
                "metricName": "CPUUtilization",
                "detail": {"scope": "Service", "source": "aws.cloudwatch"},
            },
            {
                "metricName": "ReadLatency",
                "detail": {"scope": "Service", "source": "aws.cloudwatch"},
            },
            {"namespace": "AWS/EC2", "detail": {"scope": "Service", "source": "aws.cloudwatch"}},
            {"namespace": "AWS/ES", "detail": {"scope": "Service", "source": "aws.cloudwatch"}},
            {
                "metricName": "CPUUtilization",
                "detail": {"scope": "Service", "type": "CloudWatch Alarm State Change"},
            },
            {
                "metricName": "AWS/EC2",
                "detail": {"scope": "Service", "type": "CloudWatch Alarm State Change"},
            },
            {
                "namespace": "CPUUtilization",
                "detail": {"scope": "Service", "type": "CloudWatch Alarm State Change"},
            },
        ]
        for message in messages:
            aws_client.sns.publish(
                TopicArn=topic_arn,
                Message=json.dumps(message),
            )

        def get_messages(_queue_url: str, _recv_messages: list):
            # due to the random nature of receiving SQS messages, we need to consolidate a single object to match
            sqs_response = aws_client.sqs.receive_message(
                QueueUrl=_queue_url,
                WaitTimeSeconds=1,
                VisibilityTimeout=0,
                MessageAttributeNames=["All"],
                AttributeNames=["All"],
            )
            for _message in sqs_response["Messages"]:
                _recv_messages.append(_message)
                aws_client.sqs.delete_message(
                    QueueUrl=_queue_url, ReceiptHandle=_message["ReceiptHandle"]
                )

            assert len(_recv_messages) == 7

            recv_messages = []
            retry(
                get_messages,
                retries=10,
                sleep=0.1,
                _queue_url=queue_url,
                _recv_messages=recv_messages,
            )
            # we need to sort the list (the order does not matter as we're not using FIFO)
            recv_messages.sort(key=itemgetter("Body"))
            snapshot.match("messages-queue", {"Messages": recv_messages})


class TestSNSFilterPolicyConditions:
    @staticmethod
    def _add_normalized_field_to_snapshot(error_dict):
        error_dict["Error"]["_normalized"] = error_dict["Error"]["Message"].split("\n")[0]

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        # AWS adds JSON position error: `\n at [Source: (String)"{"key":[["value"]]}"; line: 1, column: 10]`
        paths=["$..Error.Message"]
    )
    def test_validate_policy(
        self,
        sns_create_topic,
        sns_subscription,
        snapshot,
        aws_client,
    ):
        phone_number = "+123123123"
        topic_arn = sns_create_topic()["TopicArn"]

        def _subscribe(policy: dict):
            sns_subscription(
                TopicArn=topic_arn,
                Protocol="sms",
                Endpoint=phone_number,
                Attributes={"FilterPolicy": json.dumps(policy)},
            )

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [["value"]]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-condition-list", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"wrong-operator": True}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-condition-operator", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"suffix": "value", "prefix": "value2"}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-condition-two-operators", e.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_validate_policy_string_operators(
        self,
        sns_create_topic,
        sns_subscription,
        snapshot,
        aws_client,
    ):
        phone_number = "+123123123"
        topic_arn = sns_create_topic()["TopicArn"]

        def _subscribe(policy: dict):
            return sns_subscription(
                TopicArn=topic_arn,
                Protocol="sms",
                Endpoint=phone_number,
                Attributes={"FilterPolicy": json.dumps(policy)},
            )

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"suffix": 100}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-condition-is-numeric", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"suffix": None}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-condition-is-none", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": {"suffix": "value"}}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-condition-is-not-list-and-operator", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"suffix": []}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-condition-empty-list", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"suffix": ["test", "test2"]}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-condition-list-wrong-type", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": {"suffix": "value", "prefix": "value"}}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-condition-is-not-list-two-ops", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": {"not-an-operator": "value"}}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-condition-is-not-list-and-no-operator", e.value.response)

        # TODO: add `cidr` string operator

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_validate_policy_numeric_operator(
        self,
        sns_create_topic,
        sns_subscription,
        snapshot,
        aws_client,
    ):
        phone_number = "+123123123"
        topic_arn = sns_create_topic()["TopicArn"]

        def _subscribe(policy: dict):
            sns_subscription(
                TopicArn=topic_arn,
                Protocol="sms",
                Endpoint=phone_number,
                Attributes={"FilterPolicy": json.dumps(policy)},
            )

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"numeric": []}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-numeric-empty", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"numeric": ["operator"]}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-numeric-wrong-operator", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"numeric": [1, "<="]}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-numeric-operator-order", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"numeric": ["=", "000"]}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-numeric-type", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"numeric": [">="]}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-numeric-missing-value", e.value.response)

        # dealing with range numeric
        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"numeric": ["<", 100, ">", 10]}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-numeric-wrong-range-order", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"numeric": [">=", 1, ">", 2]}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-numeric-wrong-range-operators", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"numeric": [">", 3, "<", 1]}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-numeric-wrong-value-order", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"numeric": [">", 20, "<="]}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-numeric-missing-range-value", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"numeric": [">", 20, 30]}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-numeric-missing-range-operator", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"numeric": [">", 20, "test"]}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-numeric-wrong-second-range-operator", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"numeric": [">", "20", "<", "30"]}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-numeric-wrong-range-value-1-type", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"numeric": [">", 20, "<", "30"]}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-numeric-wrong-range-value-2-type", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"numeric": [">", 20, "<", 30, "<", 50]}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-numeric-too-many-range", e.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_validate_policy_exists_operator(
        self,
        sns_create_topic,
        sns_subscription,
        snapshot,
        aws_client,
    ):
        phone_number = "+123123123"
        topic_arn = sns_create_topic()["TopicArn"]

        def _subscribe(policy: dict):
            sns_subscription(
                TopicArn=topic_arn,
                Protocol="sms",
                Endpoint=phone_number,
                Attributes={"FilterPolicy": json.dumps(policy)},
            )

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"exists": None}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-condition-none", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"exists": "no"}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-condition-string", e.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_validate_policy_nested_anything_but_operator(
        self,
        sns_create_topic,
        sns_subscription,
        snapshot,
        aws_client,
    ):
        phone_number = "+123123123"
        topic_arn = sns_create_topic()["TopicArn"]

        def _subscribe(policy: dict):
            return sns_subscription(
                TopicArn=topic_arn,
                Protocol="sms",
                Endpoint=phone_number,
                Attributes={"FilterPolicy": json.dumps(policy)},
            )

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"anything-but": {"wrong-operator": None}}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-condition-wrong-operator", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"anything-but": {"suffix": "test"}}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-condition-anything-but-suffix", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"anything-but": {"exists": False}}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-condition-anything-but-exists", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [{"anything-but": {"prefix": False}}]}
            _subscribe(filter_policy)
        self._add_normalized_field_to_snapshot(e.value.response)
        snapshot.match("error-condition-anything-but-prefix-wrong-type", e.value.response)

        # positive testing
        filter_policy = {"key": [{"anything-but": {"prefix": "test-"}}]}
        response = _subscribe(filter_policy)
        assert "SubscriptionArn" in response
        subscription_arn = response["SubscriptionArn"]

        filter_policy = {"key": [{"anything-but": ["test", "test2"]}]}
        response = aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicy",
            AttributeValue=json.dumps(filter_policy),
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        filter_policy = {"key": [{"anything-but": "test"}]}
        response = aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicy",
            AttributeValue=json.dumps(filter_policy),
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    @markers.aws.validated
    def test_policy_complexity(
        self,
        sns_create_topic,
        sns_subscription,
        snapshot,
        aws_client,
    ):
        phone_number = "+123123123"
        topic_arn = sns_create_topic()["TopicArn"]

        def _subscribe(policy: dict):
            sns_subscription(
                TopicArn=topic_arn,
                Protocol="sms",
                Endpoint=phone_number,
                Attributes={"FilterPolicy": json.dumps(policy)},
            )

        with pytest.raises(ClientError) as e:
            filter_policy = {"key": [f"value{i}" for i in range(151)]}
            _subscribe(filter_policy)
        snapshot.match("error-complexity-in-one-condition", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {
                "key1": [f"value{i}" for i in range(100)],
                "key2": [f"value{i}" for i in range(51)],
            }
            _subscribe(filter_policy)
        snapshot.match("error-complexity-in-two-conditions", e.value.response)

        with pytest.raises(ClientError) as e:
            filter_policy = {
                "key1": ["value1"],
                "key2": ["value2"],
                "key3": ["value3"],
                "key4": ["value4"],
                "key5": ["value5"],
                "key6": ["value6"],
            }
            _subscribe(filter_policy)
        snapshot.match("error-complexity-too-many-fields", e.value.response)

    @markers.aws.validated
    def test_policy_complexity_with_or(
        self,
        sns_create_topic,
        sns_subscription,
        snapshot,
        aws_client,
    ):
        phone_number = "+123123123"
        topic_arn = sns_create_topic()["TopicArn"]

        def _subscribe(policy: dict, scope: str):
            attributes = {"FilterPolicy": json.dumps(policy)}
            if scope:
                attributes["FilterPolicyScope"] = scope

            return sns_subscription(
                TopicArn=topic_arn,
                Protocol="sms",
                Endpoint=phone_number,
                Attributes=attributes,
            )

        with pytest.raises(ClientError) as e:
            # (source * metricName) + (source * metricType * metricId) + (source * metricType * spaceId)
            # = (4 * 6) + (4 * 4 * 4) + (4 * 4 * 4)
            # = 24 + 64 + 64
            # = 152
            filter_policy = {
                "source": ["aws.cloudwatch", "aws.events", "aws.test", "aws.test2"],
                "$or": [
                    {"metricName": ["CPUUtilization", "ReadLatency", "t1", "t2", "t3", "t4"]},
                    {
                        "metricType": ["MetricType", "TestType", "TestType2", "TestType3"],
                        "$or": [{"metricId": [1234, 4321, 5678, 9012]}, {"spaceId": [1, 2, 3, 4]}],
                    },
                ],
            }

            _subscribe(filter_policy, scope="MessageAttributes")
        snapshot.match("error-complexity-or-flat", e.value.response)

        with pytest.raises(ClientError) as e:
            # ("metricName" AND ("detail"."scope" AND "detail"."source")
            # OR
            # ("metricName" AND ("detail"."scope" AND "detail"."type")
            # OR
            # ("namespace" AND ("detail"."scope" AND "detail"."source")
            # OR
            # ("namespace" AND ("detail"."scope" AND "detail"."type")
            # (3 * 4 * 2) + (3 * 4 * 6) + (2 * 4 * 2) + (2 * 4 * 6)
            # = 24 + 72 + 16 + 48
            # = 160
            filter_policy = {
                "$or": [
                    {"metricName": ["CPUUtilization", "ReadLatency", "TestValue"]},
                    {"namespace": ["AWS/EC2", "AWS/ES"]},
                ],
                "detail": {
                    "scope": ["Service", "Test"],
                    "$or": [
                        {"source": ["aws.cloudwatch"]},
                        {"type": ["CloudWatch Alarm State Change", "TestValue", "TestValue2"]},
                    ],
                },
            }

            _subscribe(filter_policy, scope="MessageBody")
        snapshot.match("error-complexity-or-nested", e.value.response)

        # (source * metricName) + (source * metricType * metricId) + (source * metricType * spaceId)
        # = (3 * 6) + (3 * 4 * 4) + (3 * 4 * 7)
        # = 18 + 48 + 84
        # = 150
        filter_policy = {
            "source": ["aws.cloudwatch", "aws.events", "aws.test"],
            "$or": [
                {
                    "metricName": [
                        "CPUUtilization",
                        "ReadLatency",
                        "TestVal",
                        "TestVal2",
                        "TestVal3",
                        "TestVal4",
                    ]
                },
                {
                    "metricType": ["MetricType", "TestType", "TestType2", "TestType3"],
                    "$or": [
                        {"metricId": [1234, 4321, 5678, 9012]},
                        {"spaceId": [1, 2, 3, 4, 5, 6, 7]},
                    ],
                },
            ],
        }
        response = _subscribe(filter_policy, scope="MessageAttributes")
        assert "SubscriptionArn" in response

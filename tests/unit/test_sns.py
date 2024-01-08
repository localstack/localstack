import base64
import json
import re
import uuid
from base64 import b64encode

import dateutil.parser
import pytest

from localstack.aws.api.sns import InvalidParameterException
from localstack.services.sns.models import SnsMessage
from localstack.services.sns.provider import (
    encode_subscription_token_with_region,
    get_region_from_subscription_token,
    is_raw_message_delivery,
)
from localstack.services.sns.publisher import (
    SubscriptionFilter,
    compute_canonical_string,
    create_sns_message_body,
)
from localstack.utils.time import timestamp_millis


@pytest.fixture
def subscriber():
    return {
        "SubscriptionArn": "arn:aws:sns:jupiter-south-1:123456789012:MyTopic:6b0e71bd-7e97-4d97-80ce-4a0994e55286",
        "Protocol": "sqs",
        "RawMessageDelivery": "false",
        "TopicArn": "arn",
    }


@pytest.mark.usefixtures("subscriber")
class TestSns:
    def test_create_sns_message_body_raw_message_delivery(self, subscriber):
        subscriber["RawMessageDelivery"] = "true"
        message_ctx = SnsMessage(
            message="msg",
            type="Notification",
        )
        result = create_sns_message_body(message_ctx, subscriber)
        assert "msg" == result

    def test_create_sns_message_body(self, subscriber):
        message_ctx = SnsMessage(
            message="msg",
            type="Notification",
        )
        result_str = create_sns_message_body(message_ctx, subscriber)
        result = json.loads(result_str)
        try:
            uuid.UUID(result.pop("MessageId"))
        except KeyError:
            assert False, "MessageId missing in SNS response message body"
        except ValueError:
            assert False, "SNS response MessageId not a valid UUID"

        try:
            dateutil.parser.parse(result.pop("Timestamp"))
        except KeyError:
            assert False, "Timestamp missing in SNS response message body"
        except ValueError:
            assert False, "SNS response Timestamp not a valid ISO 8601 date"

        try:
            base64.b64decode(result.pop("Signature"))
        except KeyError:
            assert False, "Signature missing in SNS response message body"
        except ValueError:
            assert False, "SNS response Signature is not a valid base64 encoded value"

        expected_sns_body = {
            "Message": "msg",
            "SignatureVersion": "1",
            "SigningCertURL": "http://localhost.localstack.cloud:4566/_aws/sns/SimpleNotificationService-6c6f63616c737461636b69736e696365.pem",
            "TopicArn": "arn",
            "Type": "Notification",
            "UnsubscribeURL": f"http://localhost.localstack.cloud:4566/?Action=Unsubscribe&SubscriptionArn={subscriber['SubscriptionArn']}",
        }

        assert expected_sns_body == result

        # Now add a subject and message attributes
        message_attributes = {
            "attr1": {
                "DataType": "String",
                "StringValue": "value1",
            },
            "attr2": {
                "DataType": "Binary",
                "BinaryValue": b"\x02\x03\x04",
            },
        }
        message_ctx = SnsMessage(
            type="Notification",
            message="msg",
            subject="subject",
            message_attributes=message_attributes,
        )
        result_str = create_sns_message_body(message_ctx, subscriber)
        result = json.loads(result_str)
        del result["MessageId"]
        del result["Timestamp"]
        del result["Signature"]
        msg = {
            "Message": "msg",
            "Subject": "subject",
            "SignatureVersion": "1",
            "SigningCertURL": "http://localhost.localstack.cloud:4566/_aws/sns/SimpleNotificationService-6c6f63616c737461636b69736e696365.pem",
            "TopicArn": "arn",
            "Type": "Notification",
            "UnsubscribeURL": f"http://localhost.localstack.cloud:4566/?Action=Unsubscribe&SubscriptionArn={subscriber['SubscriptionArn']}",
            "MessageAttributes": {
                "attr1": {
                    "Type": "String",
                    "Value": "value1",
                },
                "attr2": {
                    "Type": "Binary",
                    "Value": b64encode(b"\x02\x03\x04").decode("utf-8"),
                },
            },
        }
        assert msg == result

    def test_create_sns_message_body_json_structure(self, subscriber):
        message_ctx = SnsMessage(
            type="Notification",
            message=json.loads('{"default": {"message": "abc"}}'),
            message_structure="json",
        )

        result_str = create_sns_message_body(message_ctx, subscriber)
        result = json.loads(result_str)

        assert {"message": "abc"} == result["Message"]

    def test_create_sns_message_body_json_structure_raw_delivery(self, subscriber):
        subscriber["RawMessageDelivery"] = "true"
        message_ctx = SnsMessage(
            type="Notification",
            message=json.loads('{"default": {"message": "abc"}}'),
            message_structure="json",
        )

        result = create_sns_message_body(message_ctx, subscriber)

        assert {"message": "abc"} == result

    def test_create_sns_message_body_json_structure_sqs_protocol(self, subscriber):
        message_ctx = SnsMessage(
            type="Notification",
            message=json.loads('{"default": "default message", "sqs": "sqs message"}'),
            message_structure="json",
        )

        result_str = create_sns_message_body(message_ctx, subscriber)
        result = json.loads(result_str)
        assert "sqs message" == result["Message"]

    def test_create_sns_message_body_json_structure_raw_delivery_sqs_protocol(self, subscriber):
        subscriber["RawMessageDelivery"] = "true"
        message_ctx = SnsMessage(
            type="Notification",
            message=json.loads(
                '{"default": {"message": "default version"}, "sqs": {"message": "sqs version"}}'
            ),
            message_structure="json",
        )

        result = create_sns_message_body(message_ctx, subscriber)

        assert {"message": "sqs version"} == result

    def test_create_sns_message_timestamp_millis(self, subscriber):
        message_ctx = SnsMessage(
            type="Notification",
            message="msg",
        )

        result_str = create_sns_message_body(message_ctx, subscriber)
        result = json.loads(result_str)
        timestamp = result.pop("Timestamp")
        end = timestamp[-5:]
        matcher = re.compile(r"\.[0-9]{3}Z")
        match = matcher.match(end)
        assert match

    def test_filter_policy(self):
        test_data = [
            ("no filter with no attributes", {}, {}, True),
            (
                "no filter with attributes",
                {},
                {"filter": {"Type": "String", "Value": "type1"}},
                True,
            ),
            (
                "exact string filter",
                {"filter": "type1"},
                {"filter": {"Type": "String", "Value": "type1"}},
                True,
            ),
            (
                "exact string filter on an array",
                {"filter": "soccer"},
                {
                    "filter": {
                        "Type": "String.Array",
                        "Value": '["soccer", "rugby", "hockey"]',
                    }
                },
                True,
            ),
            ("exact string filter with no attributes", {"filter": "type1"}, {}, False),
            (
                "exact string filter with no match",
                {"filter": "type1"},
                {"filter": {"Type": "String", "Value": "type2"}},
                False,
            ),
            (
                "or string filter with match",
                {"filter": ["type1", "type2"]},
                {"filter": {"Type": "String", "Value": "type1"}},
                True,
            ),
            (
                "or string filter with other match",
                {"filter": ["type1", "type2"]},
                {"filter": {"Type": "String", "Value": "type2"}},
                True,
            ),
            (
                "or string filter match with an array",
                {"filter": ["soccer", "basketball"]},
                {
                    "filter": {
                        "Type": "String.Array",
                        "Value": '["soccer", "rugby", "hockey"]',
                    }
                },
                True,
            ),
            (
                "or string filter with no attributes",
                {"filter": ["type1", "type2"]},
                {},
                False,
            ),
            (
                "or string filter with no match",
                {"filter": ["type1", "type2"]},
                {"filter": {"Type": "String", "Value": "type3"}},
                False,
            ),
            (
                "or string filter no match with an array",
                {"filter": ["volleyball", "basketball"]},
                {
                    "filter": {
                        "Type": "String.Array",
                        "Value": '["soccer", "rugby", "hockey"]',
                    }
                },
                False,
            ),
            (
                "anything-but string filter with match",
                {"filter": [{"anything-but": "type1"}]},
                {"filter": {"Type": "String", "Value": "type1"}},
                False,
            ),
            (
                "anything-but string filter with no match",
                {"filter": [{"anything-but": "type1"}]},
                {"filter": {"Type": "String", "Value": "type2"}},
                True,
            ),
            (
                "prefix string filter with match",
                {"filter": [{"prefix": "typ"}]},
                {"filter": {"Type": "String", "Value": "type1"}},
                True,
            ),
            (
                "prefix string filter match with an array",
                {"filter": [{"prefix": "soc"}]},
                {
                    "filter": {
                        "Type": "String.Array",
                        "Value": '["soccer", "rugby", "hockey"]',
                    }
                },
                True,
            ),
            (
                "prefix string filter with no match",
                {"filter": [{"prefix": "test"}]},
                {"filter": {"Type": "String", "Value": "type2"}},
                False,
            ),
            (
                "numeric = filter with match",
                {"filter": [{"numeric": ["=", 300]}]},
                {"filter": {"Type": "Number", "Value": 300}},
                True,
            ),
            (
                "numeric = filter with no match",
                {"filter": [{"numeric": ["=", 300]}]},
                {"filter": {"Type": "Number", "Value": 301}},
                False,
            ),
            (
                "numeric > filter with match",
                {"filter": [{"numeric": [">", 300]}]},
                {"filter": {"Type": "Number", "Value": 301}},
                True,
            ),
            (
                "numeric > filter with no match",
                {"filter": [{"numeric": [">", 300]}]},
                {"filter": {"Type": "Number", "Value": 300}},
                False,
            ),
            (
                "numeric < filter with match",
                {"filter": [{"numeric": ["<", 300]}]},
                {"filter": {"Type": "Number", "Value": 299}},
                True,
            ),
            (
                "numeric < filter with no match",
                {"filter": [{"numeric": ["<", 300]}]},
                {"filter": {"Type": "Number", "Value": 300}},
                False,
            ),
            (
                "numeric >= filter with match",
                {"filter": [{"numeric": [">=", 300]}]},
                {"filter": {"Type": "Number", "Value": 300}},
                True,
            ),
            (
                "numeric >= filter with no match",
                {"filter": [{"numeric": [">=", 300]}]},
                {"filter": {"Type": "Number", "Value": 299}},
                False,
            ),
            (
                "numeric <= filter with match",
                {"filter": [{"numeric": ["<=", 300]}]},
                {"filter": {"Type": "Number", "Value": 300}},
                True,
            ),
            (
                "numeric <= filter with no match",
                {"filter": [{"numeric": ["<=", 300]}]},
                {"filter": {"Type": "Number", "Value": 301}},
                False,
            ),
            (
                "numeric filter with bad data",
                {"filter": [{"numeric": ["=", 300]}]},
                {"filter": {"Type": "String", "Value": "test"}},
                False,
            ),
            (
                "logical OR with match",
                {"filter": ["test1", "test2", {"prefix": "typ"}]},
                {"filter": {"Type": "String", "Value": "test2"}},
                True,
            ),
            (
                "logical OR with match",
                {"filter": ["test1", "test2", {"prefix": "typ"}]},
                {"filter": {"Type": "String", "Value": "test1"}},
                True,
            ),
            (
                "logical OR with match on an array",
                {"filter": ["test1", "test2", {"prefix": "typ"}]},
                {"filter": {"Type": "String.Array", "Value": '["test1", "other"]'}},
                True,
            ),
            (
                "logical OR no match",
                {"filter": ["test1", "test2", {"prefix": "typ"}]},
                {"filter": {"Type": "String", "Value": "test3"}},
                False,
            ),
            (
                "logical OR no match on an array",
                {"filter": ["test1", "test2", {"prefix": "typ"}]},
                {
                    "filter": {
                        "Type": "String.Array",
                        "Value": '["anything", "something"]',
                    }
                },
                False,
            ),
            (
                "logical AND with match",
                {"filter": [{"numeric": ["=", 300]}], "other": [{"prefix": "typ"}]},
                {
                    "filter": {"Type": "Number", "Value": 300},
                    "other": {"Type": "String", "Value": "type1"},
                },
                True,
            ),
            (
                "logical AND missing first attribute",
                {"filter": [{"numeric": ["=", 300]}], "other": [{"prefix": "typ"}]},
                {"other": {"Type": "String", "Value": "type1"}},
                False,
            ),
            (
                "logical AND missing second attribute",
                {"filter": [{"numeric": ["=", 300]}], "other": [{"prefix": "typ"}]},
                {"filter": {"Type": "Number", "Value": 300}},
                False,
            ),
            (
                "logical AND no match",
                {"filter": [{"numeric": ["=", 300]}], "other": [{"prefix": "typ"}]},
                {
                    "filter": {"Type": "Number", "Value": 299},
                    "other": {"Type": "String", "Value": "type1"},
                },
                False,
            ),
            (
                "multiple numeric filters with first match",
                {"filter": [{"numeric": ["=", 300]}, {"numeric": ["=", 500]}]},
                {"filter": {"Type": "Number", "Value": 300}},
                True,
            ),
            (
                "multiple numeric filters with second match",
                {"filter": [{"numeric": ["=", 300]}, {"numeric": ["=", 500]}]},
                {"filter": {"Type": "Number", "Value": 500}},
                True,
            ),
            (
                "multiple prefix filters with first match",
                {"filter": [{"prefix": "typ"}, {"prefix": "tes"}]},
                {"filter": {"Type": "String", "Value": "type1"}},
                True,
            ),
            (
                "multiple prefix filters with second match",
                {"filter": [{"prefix": "typ"}, {"prefix": "tes"}]},
                {"filter": {"Type": "String", "Value": "test"}},
                True,
            ),
            (
                "multiple anything-but filters with second match",
                {"filter": [{"anything-but": "type1"}, {"anything-but": "type2"}]},
                {"filter": {"Type": "String", "Value": "type2"}},
                True,
            ),
            (
                "multiple numeric conditions",
                {"filter": [{"numeric": [">", 0, "<=", 150]}]},
                {"filter": {"Type": "Number", "Value": 122}},
                True,
            ),
            (
                "multiple numeric conditions",
                {"filter": [{"numeric": [">", 0, "<=", 150]}]},
                {"filter": {"Type": "Number", "Value": 200}},
                False,
            ),
            (
                "multiple numeric conditions",
                {"filter": [{"numeric": [">", 0, "<=", 150]}]},
                {"filter": {"Type": "Number", "Value": -1}},
                False,
            ),
            (
                "multiple conditions on an array",
                {"filter": ["test1", "test2", {"prefix": "som"}]},
                {
                    "filter": {
                        "Type": "String.Array",
                        "Value": '["anything", "something"]',
                    }
                },
                True,
            ),
            (
                "exists with existing attribute",
                {"field": [{"exists": True}]},
                {"field": {"Type": "String", "Value": "anything"}},
                True,
            ),
            (
                "exists without existing attribute",
                {"field": [{"exists": True}]},
                {"other_field": {"Type": "String", "Value": "anything"}},
                False,
            ),
            (
                "does not exists without existing attribute",
                {"field": [{"exists": False}]},
                {"other_field": {"Type": "String", "Value": "anything"}},
                True,
            ),
            (
                "does not exists with existing attribute",
                {"field": [{"exists": False}]},
                {"field": {"Type": "String", "Value": "anything"}},
                False,
            ),
            (
                "can match on String.Array containing boolean",
                {"field": [True]},
                {"field": {"Type": "String.Array", "Value": "[true]"}},
                True,
            ),
            (
                "can not match on values that are not valid JSON strings",
                {"field": ["anything"]},
                {"field": {"Type": "String.Array", "Value": "['anything']"}},
                False,
            ),
        ]

        sub_filter = SubscriptionFilter()
        for test in test_data:
            filter_policy = test[1]
            attributes = test[2]
            expected = test[3]
            assert expected == sub_filter.check_filter_policy_on_message_attributes(
                filter_policy, attributes
            )

    def test_is_raw_message_delivery(self, subscriber):
        valid_true_values = ["true", "True", True]

        for true_value in valid_true_values:
            subscriber["RawMessageDelivery"] = true_value
            assert is_raw_message_delivery(subscriber)

    def test_is_not_raw_message_delivery(self, subscriber):
        invalid_values = ["false", "False", False, "somevalue", ""]

        for invalid_values in invalid_values:
            subscriber["RawMessageDelivery"] = invalid_values
            assert not is_raw_message_delivery(subscriber)

        del subscriber["RawMessageDelivery"]
        assert not is_raw_message_delivery(subscriber)

    def test_filter_policy_on_message_body(self):
        test_data = [
            (
                {"f1": ["v1", "v2"]},  # f1 must be v1 OR v2 (f1=v1 OR f1=v2)
                (
                    ({"f1": "v1", "f2": "v4"}, True),
                    ({"f1": "v2", "f2": "v5"}, True),
                    ({"f1": "v3", "f2": "v5"}, False),
                ),
            ),
            (
                {"f1": ["v1"]},  # f1 must be v1 (f1=v1)
                (
                    ({"f1": "v1", "f2": "v4"}, True),
                    ({"f1": "v2", "f2": "v5"}, False),
                    ({"f1": "v3", "f2": "v5"}, False),
                ),
            ),
            (
                {"f1": ["v1"], "f2": ["v4"]},  # f1 must be v1 AND f2 must be v4 (f1=v1 AND f2=v4)
                (
                    ({"f1": "v1", "f2": "v4"}, True),
                    ({"f1": "v2", "f2": "v5"}, False),
                    ({"f1": "v3", "f2": "v5"}, False),
                ),
            ),
            (
                {"f2": ["v5"]},  # f2 must be v5 (f2=v5)
                (
                    ({"f1": "v1", "f2": "v4"}, False),
                    ({"f1": "v2", "f2": "v5"}, True),
                    ({"f1": "v3", "f2": "v5"}, True),
                ),
            ),
            (
                {
                    "f1": ["v1", "v2"],
                    "f2": ["v4"],
                },  # f1 must be v1 or v2 AND f2 must be v4 ((f1=v1 OR f1=v2) AND f2=v4)
                (
                    ({"f1": "v1", "f2": "v4"}, True),
                    ({"f1": "v2", "f2": "v5"}, False),
                    ({"f1": "v3", "f2": "v5"}, False),
                ),
            ),
        ]

        sub_filter = SubscriptionFilter()
        for filter_policy, messages in test_data:
            for message_body, expected in messages:
                assert expected == sub_filter.check_filter_policy_on_message_body(
                    filter_policy, message_body=json.dumps(message_body)
                ), (filter_policy, message_body)

    @pytest.mark.parametrize("region", ["us-east-1", "eu-central-1", "us-west-2", "my-region"])
    def test_region_encoded_subscription_token(self, region):
        token = encode_subscription_token_with_region(region)
        assert len(token) == 64
        token_region = get_region_from_subscription_token(token)
        assert token_region == region

    @pytest.mark.parametrize(
        "token", ["abcdef123", "mynothexstring", "us-west-2", b"test", b"test2f", "test2f"]
    )
    def test_decode_token_with_no_region_encoded(self, token):
        with pytest.raises(InvalidParameterException) as e:
            get_region_from_subscription_token(token)

        assert e.match("Invalid parameter: Token")

    def test_canonical_string_calculation(self):
        timestamp = timestamp_millis()
        data = {
            "Type": "Notification",
            "MessageId": "abdcdef",
            "TopicArn": "arn",
            "Message": "test content",
            "Subject": "random",
            "Timestamp": timestamp,
            "UnsubscribeURL": "http://randomurl.com",
        }

        canonical_string = compute_canonical_string(data, notification_type="Notification")
        assert (
            canonical_string
            == f"Message\ntest content\nMessageId\nabdcdef\nSubject\nrandom\nTimestamp\n{timestamp}\nTopicArn\narn\nType\nNotification\n"
        )

        data_unsub = {
            "Type": "SubscriptionConfirmation",
            "MessageId": "abdcdef",
            "TopicArn": "arn",
            "Message": "test content",
            "Subject": "random",
            "Timestamp": timestamp,
            "UnsubscribeURL": "http://randomurl.com",
            "SubscribeURL": "http://randomurl.com",
            "Token": "randomtoken",
        }

        canonical_string = compute_canonical_string(
            data_unsub, notification_type="SubscriptionConfirmation"
        )
        assert (
            canonical_string
            == f"Message\ntest content\nMessageId\nabdcdef\nSubscribeURL\nhttp://randomurl.com\nTimestamp\n{timestamp}\nToken\nrandomtoken\nTopicArn\narn\nType\nSubscriptionConfirmation\n"
        )

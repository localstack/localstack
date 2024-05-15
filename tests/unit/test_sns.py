import base64
import json
import re
import uuid
from base64 import b64encode

import dateutil.parser
import pytest

from localstack.aws.api.sns import InvalidParameterException
from localstack.services.sns.filter import FilterPolicyValidator, SubscriptionFilter
from localstack.services.sns.models import SnsMessage
from localstack.services.sns.provider import (
    encode_subscription_token_with_region,
    get_region_from_subscription_token,
    is_raw_message_delivery,
)
from localstack.services.sns.publisher import (
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
            raise AssertionError("MessageId missing in SNS response message body")
        except ValueError:
            raise AssertionError("SNS response MessageId not a valid UUID")

        try:
            dateutil.parser.parse(result.pop("Timestamp"))
        except KeyError:
            raise AssertionError("Timestamp missing in SNS response message body")
        except ValueError:
            raise AssertionError("SNS response Timestamp not a valid ISO 8601 date")

        try:
            base64.b64decode(result.pop("Signature"))
        except KeyError:
            raise AssertionError("Signature missing in SNS response message body")
        except ValueError:
            raise AssertionError("SNS response Signature is not a valid base64 encoded value")

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
                "anything-but list filter with match",
                {"filter": [{"anything-but": ["type1", "type2"]}]},
                {"filter": {"Type": "String", "Value": "type1"}},
                False,
            ),
            (
                "anything-but list filter with no match",
                {"filter": [{"anything-but": ["type1", "type3"]}]},
                {"filter": {"Type": "String", "Value": "type2"}},
                True,
            ),
            (
                "anything-but string filter with prefix match",
                {"filter": [{"anything-but": {"prefix": "type"}}]},
                {"filter": {"Type": "String", "Value": "type1"}},
                False,
            ),
            (
                "anything-but string filter with no prefix match",
                {"filter": [{"anything-but": {"prefix": "type-"}}]},
                {"filter": {"Type": "String", "Value": "type1"}},
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
                "suffix string filter with match",
                {"filter": [{"suffix": "pe1"}]},
                {"filter": {"Type": "String", "Value": "type1"}},
                True,
            ),
            (
                "suffix string filter match with an array",
                {"filter": [{"suffix": "gby"}]},
                {
                    "filter": {
                        "Type": "String.Array",
                        "Value": '["soccer", "rugby", "hockey"]',
                    }
                },
                True,
            ),
            (
                "suffix string filter with no match",
                {"filter": [{"suffix": "test"}]},
                {"filter": {"Type": "String", "Value": "type2"}},
                False,
            ),
            (
                "equals-ignore-case string filter with match",
                {"filter": [{"equals-ignore-case": "TYPE1"}]},
                {"filter": {"Type": "String", "Value": "type1"}},
                True,
            ),
            (
                "equals-ignore-case string filter match with an array",
                {"filter": [{"equals-ignore-case": "RuGbY"}]},
                {
                    "filter": {
                        "Type": "String.Array",
                        "Value": '["soccer", "rugby", "hockey"]',
                    }
                },
                True,
            ),
            (
                "equals-ignore-case string filter with no match",
                {"filter": [{"equals-ignore-case": "test"}]},
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
            (
                "$or ",
                {"f1": ["v1"], "$or": [{"f2": ["v2"]}, {"f3": ["v3"]}]},
                {"f1": {"Type": "String", "Value": "v1"}, "f3": {"Type": "String", "Value": "v3"}},
                True,
            ),
            (
                "$or ",
                {"f1": ["v1"], "$or": [{"f2": ["v2"]}, {"f3": ["v3"]}]},
                {"f1": {"Type": "String", "Value": "v2"}, "f3": {"Type": "String", "Value": "v3"}},
                False,
            ),
            (
                "$or2",
                {
                    "f1": ["v1"],
                    "$or": [
                        {"f2": ["v2", "v3"]},
                        {"f3": ["v4"], "$or": [{"f4": ["v5", "v6"]}, {"f5": ["v7", "v8"]}]},
                    ],
                },
                {"f1": {"Type": "String", "Value": "v1"}, "f2": {"Type": "String", "Value": "v2"}},
                True,
            ),
            (
                "$or3",
                {
                    "f1": ["v1"],
                    "$or": [
                        {"f2": ["v2", "v3"]},
                        {"f3": ["v4"], "$or": [{"f4": ["v5", "v6"]}, {"f5": ["v7", "v8"]}]},
                    ],
                },
                {
                    "f1": {"Type": "String", "Value": "v1"},
                    "f3": {"Type": "String", "Value": "v4"},
                    "f4": {"Type": "String", "Value": "v6"},
                },
                True,
            ),
        ]

        sub_filter = SubscriptionFilter()
        for test in test_data:
            _, filter_policy, attributes, expected = test
            assert (
                sub_filter.check_filter_policy_on_message_attributes(filter_policy, attributes)
                == expected
            )

    def test_is_raw_message_delivery(self, subscriber):
        valid_true_values = ["true", "True", True]

        for true_value in valid_true_values:
            subscriber["RawMessageDelivery"] = true_value
            assert is_raw_message_delivery(subscriber)

    def test_is_not_raw_message_delivery(self, subscriber):
        invalid_values = ["false", "False", False, "somevalue", ""]

        for value in invalid_values:
            subscriber["RawMessageDelivery"] = value
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
            (
                {"f1": ["v1", "v2"]},  # f1 must be v1 OR v2 (f1=v1 OR f1=v2)
                (
                    ({"f1": ["v1"], "f2": "v4"}, True),
                    ({"f1": ["v2", "v3"], "f2": "v5"}, True),
                    ({"f1": ["v3", "v4"], "f2": "v5"}, False),
                ),
            ),
            (
                {"f1": {"f2": ["v1"]}},  # f1.f2 must be v1
                (
                    ({"f1": {"f2": "v1"}, "f3": "v4"}, True),
                    ({"f1": {"f2": ["v1"]}, "f3": "v4"}, True),
                    ({"f1": {"f4": "v1"}, "f3": "v4"}, False),
                    ({"f1": ["v1", "v3"], "f3": "v5"}, False),
                    ({"f1": "v1", "f3": "v5"}, False),
                ),
            ),
            (
                {"f1": {"f2": {"f3": {"f4": ["v1"]}}}},
                (
                    ({"f1": {"f2": {"f3": {"f4": "v1"}}}}, True),
                    ({"f1": [{"f2": {"f3": {"f4": "v1"}}}]}, True),
                    ({"f1": [{"f2": [{"f3": {"f4": "v1"}}]}]}, True),
                    ({"f1": [{"f2": [[{"f3": {"f4": "v1"}}]]}]}, True),
                    ({"f1": [{"f2": [{"f3": {"f4": "v1"}, "f5": {"f6": "v2"}}]}]}, True),
                    ({"f1": [{"f2": [[{"f3": {"f4": "v2"}}, {"f3": {"f4": "v1"}}]]}]}, True),
                    ({"f1": [{"f2": {"f3": {"f4": "v2"}}}]}, False),
                    ({"f1": [{"f2": {"fx": {"f4": "v1"}}}]}, False),
                    ({"f1": [{"fx": {"f3": {"f4": "v1"}}}]}, False),
                    ({"fx": [{"f2": {"f3": {"f4": "v1"}}}]}, False),
                    ({"f1": [{"f2": [{"f3": {"f4": "v2"}, "f5": {"f6": "v3"}}]}]}, False),
                    ({"f1": [{"f2": [[{"f3": {"f4": "v2"}}, {"f3": {"f4": "v3"}}]]}]}, False),
                ),
            ),
            (
                {"f1": {"f2": ["v2"]}},
                [
                    ({"f3": ["v3"], "f1": {"f2": "v2"}}, True),
                ],
            ),
            (
                {
                    "$or": [{"f1": ["v1", "v2"]}, {"f2": ["v3", "v4"]}],
                    "f3": {
                        "f4": ["v5"],
                        "$or": [
                            {"f5": ["v6"]},
                            {"f6": ["v7"]},
                        ],
                    },
                },
                (
                    ({"f1": "v1", "f3": {"f4": "v5", "f5": "v6"}}, True),
                    ({"f1": "v2", "f3": {"f4": "v5", "f5": "v6"}}, True),
                    ({"f2": "v3", "f3": {"f4": "v5", "f5": "v6"}}, True),
                    ({"f2": "v4", "f3": {"f4": "v5", "f5": "v6"}}, True),
                    ({"f1": "v1", "f3": {"f4": "v5", "f6": "v7"}}, True),
                    ({"f1": "v3", "f3": {"f4": "v5", "f6": "v7"}}, False),
                    ({"f2": "v1", "f3": {"f4": "v5", "f6": "v7"}}, False),
                    ({"f1": "v1", "f3": {"f4": "v6", "f6": "v7"}}, False),
                    ({"f1": "v1", "f3": {"f4": "v5", "f6": "v1"}}, False),
                    ({"f1": "v1", "f3": {"f6": "v7"}}, False),
                    ({"f1": "v1", "f3": {"f4": "v5"}}, False),
                ),
            ),
        ]

        sub_filter = SubscriptionFilter()
        for filter_policy, messages in test_data:
            for message_body, expected in messages:
                assert (
                    sub_filter.check_filter_policy_on_message_body(
                        filter_policy, message_body=json.dumps(message_body)
                    )
                    == expected
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

    def test_filter_policy_complexity(self):
        # examples taken from https://docs.aws.amazon.com/sns/latest/dg/subscription-filter-policy-constraints.html
        # and https://docs.aws.amazon.com/sns/latest/dg/and-or-logic.html
        validator_flat = FilterPolicyValidator(scope="MessageAttributes", is_subscribe_call=True)
        validator_nested = FilterPolicyValidator(scope="MessageBody", is_subscribe_call=True)

        filter_policy = {
            "key_a": {
                "key_b": {"key_c": ["value_one", "value_two", "value_three", "value_four"]},
            },
            "key_d": {"key_e": ["value_one", "value_two", "value_three"]},
            "key_f": ["value_one", "value_two", "value_three"],
        }
        rules, combinations = validator_nested.aggregate_rules(filter_policy)
        assert combinations == 216

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

        rules, combinations = validator_flat.aggregate_rules(filter_policy)
        assert combinations == 152

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

        rules, combinations = validator_nested.aggregate_rules(filter_policy)
        assert combinations == 160

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
        rules, combinations = validator_flat.aggregate_rules(filter_policy)
        assert combinations == 150

    @pytest.mark.parametrize(
        "payload,expected",
        [
            (
                {"f3": ["v3"], "f1": {"f2": "v2"}},
                [{"f3": "v3", "f1.f2": "v2"}],
            ),
            (
                {"f3": ["v3", "v4"], "f1": {"f2": "v2"}},
                [{"f3": "v3", "f1.f2": "v2"}, {"f3": "v4", "f1.f2": "v2"}],
            ),
        ],
    )
    def test_filter_flatten_payload(self, payload, expected):
        sub_filter = SubscriptionFilter()
        assert sub_filter.flatten_payload(payload) == expected

    @pytest.mark.parametrize(
        "policy,expected",
        [
            (
                {"filter": [{"anything-but": {"prefix": "type"}}]},
                [{"filter": [{"anything-but": {"prefix": "type"}}]}],
            ),
            (
                {"field1": {"field2": {"field3": "val1", "field4": "val2"}}},
                [{"field1.field2.field3": "val1", "field1.field2.field4": "val2"}],
            ),
            (
                {"$or": [{"field1": "val1"}, {"field2": "val2"}], "field3": "val3"},
                [{"field1": "val1", "field3": "val3"}, {"field2": "val2", "field3": "val3"}],
            ),
        ],
    )
    def test_filter_flatten_policy(self, policy, expected):
        sub_filter = SubscriptionFilter()
        assert sub_filter.flatten_policy(policy) == expected

import base64
import json
import re
import uuid

import dateutil.parser
import pytest

from localstack.services.sns.provider import (
    check_filter_policy,
    create_sns_message_body,
    create_sqs_message_attributes,
    get_message_attributes,
    get_subscribe_attributes,
    is_raw_message_delivery,
)


@pytest.fixture
def subscriber():
    return {
        "SubscriptionArn": "arn",
        "Protocol": "sqs",
        "RawMessageDelivery": "false",
        "TopicArn": "arn",
    }


@pytest.mark.usefixtures("subscriber")
class TestSns:
    def test_get_subscribe_attributes(self):
        req_data = {
            "Attribute.entry.1.key": ["RawMessageDelivery"],
            "Attribute.entry.1.value": ["true"],
            "Attribute.entry.2.key": ["FilterPolicy"],
            "Attribute.entry.2.value": ['{"type": ["foo", "bar"]}'],
        }
        attributes = get_subscribe_attributes(req_data)
        expected = {
            "RawMessageDelivery": "true",
            "PendingConfirmation": "false",
            "FilterPolicy": '{"type": ["foo", "bar"]}',
        }
        assert attributes == expected

    def test_create_sns_message_body_raw_message_delivery(self, subscriber):
        subscriber["RawMessageDelivery"] = "true"
        action = {"Message": ["msg"]}
        result = create_sns_message_body(subscriber, action)
        assert "msg" == result

    def test_create_sns_message_body(self, subscriber):
        action = {"Message": ["msg"]}

        result_str = create_sns_message_body(subscriber, action, str(uuid.uuid4()))
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

        expected_sns_body = {
            "Message": "msg",
            "Signature": "EXAMPLEpH+..",
            "SignatureVersion": "1",
            "SigningCertURL": "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-0000000000000000000000.pem",
            "TopicArn": "arn",
            "Type": "Notification",
            "UnsubscribeURL": "http://localhost:4566/?Action=Unsubscribe&SubscriptionArn=arn",
        }
        assert expected_sns_body == result

        # Now add a subject
        action = {
            "Message": ["msg"],
            "Subject": ["subject"],
            "MessageAttributes.entry.1.Name": ["attr1"],
            "MessageAttributes.entry.1.Value.DataType": ["String"],
            "MessageAttributes.entry.1.Value.StringValue": ["value1"],
            "MessageAttributes.entry.1.Value.BinaryValue": ["value1"],
            "MessageAttributes.entry.2.Name": ["attr2"],
            "MessageAttributes.entry.2.Value.DataType": ["String"],
            "MessageAttributes.entry.2.Value.StringValue": ["value2"],
            "MessageAttributes.entry.2.Value.BinaryValue": ["value2"],
        }
        result_str = create_sns_message_body(subscriber, action)
        result = json.loads(result_str)
        del result["MessageId"]
        del result["Timestamp"]
        msg = {
            "Message": "msg",
            "Subject": "subject",
            "Signature": "EXAMPLEpH+..",
            "SignatureVersion": "1",
            "SigningCertURL": "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-0000000000000000000000.pem",
            "TopicArn": "arn",
            "Type": "Notification",
            "UnsubscribeURL": "http://localhost:4566/?Action=Unsubscribe&SubscriptionArn=arn",
            "MessageAttributes": {
                "attr1": {
                    "Type": "String",
                    "Value": "value1",
                },
                "attr2": {
                    "Type": "String",
                    "Value": "value2",
                },
            },
        }
        assert msg == result

    def test_create_sns_message_body_json_structure(self, subscriber):
        action = {
            "Message": ['{"default": {"message": "abc"}}'],
            "MessageStructure": ["json"],
        }
        result_str = create_sns_message_body(subscriber, action)
        result = json.loads(result_str)

        assert {"message": "abc"} == result["Message"]

    def test_create_sns_message_body_json_structure_raw_delivery(self, subscriber):
        subscriber["RawMessageDelivery"] = "true"
        action = {
            "Message": ['{"default": {"message": "abc"}}'],
            "MessageStructure": ["json"],
        }
        result = create_sns_message_body(subscriber, action)

        assert {"message": "abc"} == result

    def test_create_sns_message_body_json_structure_without_default_key(self, subscriber):
        action = {"Message": ['{"message": "abc"}'], "MessageStructure": ["json"]}
        with pytest.raises(Exception) as exc:
            create_sns_message_body(subscriber, action)
        assert "Unable to find 'default' key in message payload" == str(exc.value)

    def test_create_sns_message_body_json_structure_sqs_protocol(self, subscriber):
        action = {
            "Message": ['{"default": "default message", "sqs": "sqs message"}'],
            "MessageStructure": ["json"],
        }
        result_str = create_sns_message_body(subscriber, action)
        result = json.loads(result_str)

        assert "sqs message" == result["Message"]

    def test_create_sns_message_body_json_structure_raw_delivery_sqs_protocol(self, subscriber):
        subscriber["RawMessageDelivery"] = "true"
        action = {
            "Message": [
                '{"default": {"message": "default version"}, "sqs": {"message": "sqs version"}}'
            ],
            "MessageStructure": ["json"],
        }
        result = create_sns_message_body(subscriber, action)

        assert {"message": "sqs version"} == result

    def test_create_sqs_message_attributes(self, subscriber):
        subscriber["RawMessageDelivery"] = "true"
        action = {
            "Message": ["msg"],
            "Subject": ["subject"],
            "MessageAttributes.entry.1.Name": ["attr1"],
            "MessageAttributes.entry.1.Value.DataType": ["String"],
            "MessageAttributes.entry.1.Value.StringValue": ["value1"],
            "MessageAttributes.entry.2.Name": ["attr2"],
            "MessageAttributes.entry.2.Value.DataType": ["Binary"],
            # SNS gets binary data as base64 encoded string, but it should pass raw bytes further to SQS
            "MessageAttributes.entry.2.Value.BinaryValue": [
                base64.b64encode("value2".encode("utf-8"))
            ],
            "MessageAttributes.entry.3.Name": ["attr3"],
            "MessageAttributes.entry.3.Value.DataType": ["Number"],
            "MessageAttributes.entry.3.Value.StringValue": ["3"],
        }

        attributes = get_message_attributes(action)
        result = create_sqs_message_attributes(subscriber, attributes)

        assert "String" == result["attr1"]["DataType"]
        assert "value1" == result["attr1"]["StringValue"]
        assert "Binary" == result["attr2"]["DataType"]
        assert "value2".encode("utf-8") == result["attr2"]["BinaryValue"]
        assert "Number" == result["attr3"]["DataType"]
        assert "3" == result["attr3"]["StringValue"]

    def test_create_sns_message_timestamp_millis(self, subscriber):
        action = {"Message": ["msg"]}
        result_str = create_sns_message_body(subscriber, action)
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
                        "Value": "['soccer', 'rugby', 'hockey']",
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
                        "Value": "['soccer', 'rugby', 'hockey']",
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
                        "Value": "['soccer', 'rugby', 'hockey']",
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
                        "Value": "['soccer', 'rugby', 'hockey']",
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
                {"filter": {"Type": "String.Array", "Value": "['test1', 'other']"}},
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
                        "Value": "['anything', 'something']",
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
                        "Value": "['anything', 'something']",
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
        ]

        for test in test_data:
            filter_policy = test[1]
            attributes = test[2]
            expected = test[3]
            assert expected == check_filter_policy(filter_policy, attributes)

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

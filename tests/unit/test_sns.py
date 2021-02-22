import json
import uuid
import base64
import unittest
import dateutil.parser
import re
from localstack.services.sns import sns_listener


class SNSTests(unittest.TestCase):
    def setUp(self):
        self.subscriber = {
            'Protocol': 'sqs',
            'RawMessageDelivery': 'false',
            'TopicArn': 'arn',
        }
        # Reset subscriptions
        sns_listener.SNS_SUBSCRIPTIONS = {}

    def test_unsubscribe_without_arn_should_error(self):
        sns = sns_listener.ProxyListenerSNS()
        error = sns.forward_request('POST', '/', 'Action=Unsubscribe', '')
        self.assertTrue(error is not None)
        self.assertEqual(error.status_code, 400)

    def test_unsubscribe_should_remove_listener(self):
        sub_arn = 'arn:aws:sns:us-east-1:000000000000:test-topic:45e61c7f-dca5-4fcd-be2b-4e1b0d6eef72'
        topic_arn = 'arn:aws:sns:us-east-1:000000000000:test-topic'

        sns_listener.do_subscribe(
            topic_arn,
            'arn:aws:sqs:us-east-1:000000000000:test-queue',
            'sqs',
            sub_arn,
            {}
        )
        self.assertTrue(sns_listener.get_subscription_by_arn(sub_arn))
        sns_listener.do_unsubscribe(sub_arn)
        self.assertFalse(sns_listener.get_subscription_by_arn(sub_arn))

    def test_get_subscribe_attributes(self):
        req_data = {
            'Attribute.entry.1.key': ['RawMessageDelivery'],
            'Attribute.entry.1.value': ['true'],
            'Attribute.entry.2.key': ['FilterPolicy'],
            'Attribute.entry.2.value': ['{"type": ["foo", "bar"]}']
        }
        attributes = sns_listener.get_subscribe_attributes(req_data)
        self.assertDictEqual(
            attributes,
            {
                'RawMessageDelivery': 'true',
                'FilterPolicy': '{"type": ["foo", "bar"]}'
            }
        )

    def test_create_sns_message_body_raw_message_delivery(self):
        self.subscriber['RawMessageDelivery'] = 'true'
        action = {
            'Message': ['msg']
        }
        result = sns_listener.create_sns_message_body(self.subscriber, action)
        self.assertEqual(result, 'msg')

    def test_create_sns_message_body(self):
        action = {
            'Message': ['msg']
        }

        result_str = sns_listener.create_sns_message_body(self.subscriber, action, str(uuid.uuid4()))
        result = json.loads(result_str)
        try:
            uuid.UUID(result.pop('MessageId'))
        except KeyError:
            assert False, 'MessageId missing in SNS response message body'
        except ValueError:
            assert False, 'SNS response MessageId not a valid UUID'

        try:
            dateutil.parser.parse(result.pop('Timestamp'))
        except KeyError:
            assert False, 'Timestamp missing in SNS response message body'
        except ValueError:
            assert False, 'SNS response Timestamp not a valid ISO 8601 date'

        self.assertEqual(result, {
            'Message': 'msg',
            'Signature': 'EXAMPLEpH+..',
            'SignatureVersion': '1',
            'SigningCertURL':
                'https://sns.us-east-1.amazonaws.com/SimpleNotificationService-0000000000000000000000.pem',
            'TopicArn': 'arn',
            'Type': 'Notification'
        })

        # Now add a subject
        action = {
            'Message': ['msg'],
            'Subject': ['subject'],
            'MessageAttributes.entry.1.Name': ['attr1'],
            'MessageAttributes.entry.1.Value.DataType': ['String'],
            'MessageAttributes.entry.1.Value.StringValue': ['value1'],
            'MessageAttributes.entry.1.Value.BinaryValue': ['value1'],
            'MessageAttributes.entry.2.Name': ['attr2'],
            'MessageAttributes.entry.2.Value.DataType': ['String'],
            'MessageAttributes.entry.2.Value.StringValue': ['value2'],
            'MessageAttributes.entry.2.Value.BinaryValue': ['value2'],
        }
        result_str = sns_listener.create_sns_message_body(self.subscriber, action)
        result = json.loads(result_str)
        del result['MessageId']
        del result['Timestamp']
        msg = {
            'Message': 'msg',
            'Subject': 'subject',
            'Signature': 'EXAMPLEpH+..',
            'SignatureVersion': '1',
            'SigningCertURL':
                'https://sns.us-east-1.amazonaws.com/SimpleNotificationService-0000000000000000000000.pem',
            'TopicArn': 'arn',
            'Type': 'Notification',
            'MessageAttributes': {
                'attr1': {
                    'Type': 'String',
                    'Value': 'value1',
                }, 'attr2': {
                    'Type': 'String',
                    'Value': 'value2',
                }
            }
        }
        expected = json.dumps(msg)
        self.assertEqual(result, json.loads(expected))

    def test_create_sns_message_body_json_structure(self):
        action = {
            'Message': ['{"default": {"message": "abc"}}'],
            'MessageStructure': ['json']
        }
        result_str = sns_listener.create_sns_message_body(self.subscriber, action)
        result = json.loads(result_str)

        self.assertEqual(result['Message'], {'message': 'abc'})

    def test_create_sns_message_body_json_structure_without_default_key(self):
        action = {
            'Message': ['{"message": "abc"}'],
            'MessageStructure': ['json']
        }
        with self.assertRaises(Exception) as exc:
            sns_listener.create_sns_message_body(self.subscriber, action)
        self.assertEqual(str(exc.exception), "Unable to find 'default' key in message payload")

    def test_create_sns_message_body_json_structure_sqs_protocol(self):
        action = {
            'Message': ['{"default": "default message", "sqs": "sqs message"}'],
            'MessageStructure': ['json']
        }
        result_str = sns_listener.create_sns_message_body(self.subscriber, action)
        result = json.loads(result_str)

        self.assertEqual(result['Message'], 'sqs message')

    def test_create_sqs_message_attributes(self):
        self.subscriber['RawMessageDelivery'] = 'true'
        action = {
            'Message': ['msg'],
            'Subject': ['subject'],
            'MessageAttributes.entry.1.Name': ['attr1'],
            'MessageAttributes.entry.1.Value.DataType': ['String'],
            'MessageAttributes.entry.1.Value.StringValue': ['value1'],
            'MessageAttributes.entry.2.Name': ['attr2'],
            'MessageAttributes.entry.2.Value.DataType': ['Binary'],
            # SNS gets binary data as base64 encoded string, but it should pass raw bytes further to SQS
            'MessageAttributes.entry.2.Value.BinaryValue': [base64.b64encode('value2'.encode('utf-8'))],
            'MessageAttributes.entry.3.Name': ['attr3'],
            'MessageAttributes.entry.3.Value.DataType': ['Number'],
            'MessageAttributes.entry.3.Value.StringValue': ['3'],
        }

        attributes = sns_listener.get_message_attributes(action)
        result = sns_listener.create_sqs_message_attributes(self.subscriber, attributes)

        self.assertEqual(result['attr1']['DataType'], 'String')
        self.assertEqual(result['attr1']['StringValue'], 'value1')
        self.assertEqual(result['attr2']['DataType'], 'Binary')
        self.assertEqual(result['attr2']['BinaryValue'], 'value2'.encode('utf-8'))
        self.assertEqual(result['attr3']['DataType'], 'Number')
        self.assertEqual(result['attr3']['StringValue'], '3')

    def test_create_sns_message_timestamp_millis(self):
        action = {
            'Message': ['msg']
        }
        result_str = sns_listener.create_sns_message_body(self.subscriber, action)
        result = json.loads(result_str)
        timestamp = result.pop('Timestamp')
        end = timestamp[-5:]
        matcher = re.compile(r'\.[0-9]{3}Z')
        match = matcher.match(end)
        self.assertTrue(match is not None)

    def test_only_one_subscription_per_topic_per_endpoint(self):
        sub_arn = 'arn:aws:sns:us-east-1:000000000000:test-topic:45e61c7f-dca5-4fcd-be2b-4e1b0d6eef72'
        topic_arn = 'arn:aws:sns:us-east-1:000000000000:test-topic'

        for i in [1, 2]:
            sns_listener.do_subscribe(
                topic_arn,
                'arn:aws:sqs:us-east-1:000000000000:test-queue-1',
                'sqs',
                sub_arn,
                {}
            )
            self.assertEqual(len(sns_listener.SNS_SUBSCRIPTIONS[topic_arn]), 1)

    def test_filter_policy(self):
        test_data = [
            (
                'no filter with no attributes',
                {},
                {},
                True
            ),
            (
                'no filter with attributes',
                {},
                {'filter': {'Type': 'String', 'Value': 'type1'}},
                True
            ),
            (
                'exact string filter',
                {'filter': 'type1'},
                {'filter': {'Type': 'String', 'Value': 'type1'}},
                True
            ),
            (
                'exact string filter on an array',
                {'filter': 'soccer'},
                {'filter': {'Type': 'String.Array', 'Value': "['soccer', 'rugby', 'hockey']"}},
                True
            ),
            (
                'exact string filter with no attributes',
                {'filter': 'type1'},
                {},
                False
            ),
            (
                'exact string filter with no match',
                {'filter': 'type1'},
                {'filter': {'Type': 'String', 'Value': 'type2'}},
                False
            ),
            (
                'or string filter with match',
                {'filter': ['type1', 'type2']},
                {'filter': {'Type': 'String', 'Value': 'type1'}},
                True
            ),
            (
                'or string filter with other match',
                {'filter': ['type1', 'type2']},
                {'filter': {'Type': 'String', 'Value': 'type2'}},
                True
            ),
            (
                'or string filter match with an array',
                {'filter': ['soccer', 'basketball']},
                {'filter': {'Type': 'String.Array', 'Value': "['soccer', 'rugby', 'hockey']"}},
                True
            ),
            (
                'or string filter with no attributes',
                {'filter': ['type1', 'type2']},
                {},
                False
            ),
            (
                'or string filter with no match',
                {'filter': ['type1', 'type2']},
                {'filter': {'Type': 'String', 'Value': 'type3'}},
                False
            ),
            (
                'or string filter no match with an array',
                {'filter': ['volleyball', 'basketball']},
                {'filter': {'Type': 'String.Array', 'Value': "['soccer', 'rugby', 'hockey']"}},
                False
            ),
            (
                'anything-but string filter with match',
                {'filter': [{'anything-but': 'type1'}]},
                {'filter': {'Type': 'String', 'Value': 'type1'}},
                False
            ),
            (
                'anything-but string filter with no match',
                {'filter': [{'anything-but': 'type1'}]},
                {'filter': {'Type': 'String', 'Value': 'type2'}},
                True
            ),
            (
                'prefix string filter with match',
                {'filter': [{'prefix': 'typ'}]},
                {'filter': {'Type': 'String', 'Value': 'type1'}},
                True
            ),
            (
                'prefix string filter match with an array',
                {'filter': [{'prefix': 'soc'}]},
                {'filter': {'Type': 'String.Array', 'Value': "['soccer', 'rugby', 'hockey']"}},
                True
            ),
            (
                'prefix string filter with no match',
                {'filter': [{'prefix': 'test'}]},
                {'filter': {'Type': 'String', 'Value': 'type2'}},
                False
            ),
            (
                'numeric = filter with match',
                {'filter': [{'numeric': ['=', 300]}]},
                {'filter': {'Type': 'Number', 'Value': 300}},
                True
            ),
            (
                'numeric = filter with no match',
                {'filter': [{'numeric': ['=', 300]}]},
                {'filter': {'Type': 'Number', 'Value': 301}},
                False
            ),
            (
                'numeric > filter with match',
                {'filter': [{'numeric': ['>', 300]}]},
                {'filter': {'Type': 'Number', 'Value': 301}},
                True
            ),
            (
                'numeric > filter with no match',
                {'filter': [{'numeric': ['>', 300]}]},
                {'filter': {'Type': 'Number', 'Value': 300}},
                False
            ),
            (
                'numeric < filter with match',
                {'filter': [{'numeric': ['<', 300]}]},
                {'filter': {'Type': 'Number', 'Value': 299}},
                True
            ),
            (
                'numeric < filter with no match',
                {'filter': [{'numeric': ['<', 300]}]},
                {'filter': {'Type': 'Number', 'Value': 300}},
                False
            ),
            (
                'numeric >= filter with match',
                {'filter': [{'numeric': ['>=', 300]}]},
                {'filter': {'Type': 'Number', 'Value': 300}},
                True
            ),
            (
                'numeric >= filter with no match',
                {'filter': [{'numeric': ['>=', 300]}]},
                {'filter': {'Type': 'Number', 'Value': 299}},
                False
            ),
            (
                'numeric <= filter with match',
                {'filter': [{'numeric': ['<=', 300]}]},
                {'filter': {'Type': 'Number', 'Value': 300}},
                True
            ),
            (
                'numeric <= filter with no match',
                {'filter': [{'numeric': ['<=', 300]}]},
                {'filter': {'Type': 'Number', 'Value': 301}},
                False
            ),
            (
                'numeric filter with bad data',
                {'filter': [{'numeric': ['=', 300]}]},
                {'filter': {'Type': 'String', 'Value': 'test'}},
                False
            ),
            (
                'logical OR with match',
                {'filter': ['test1', 'test2', {'prefix': 'typ'}]},
                {'filter': {'Type': 'String', 'Value': 'test2'}},
                True
            ),
            (
                'logical OR with match',
                {'filter': ['test1', 'test2', {'prefix': 'typ'}]},
                {'filter': {'Type': 'String', 'Value': 'test1'}},
                True
            ),
            (
                'logical OR with match on an array',
                {'filter': ['test1', 'test2', {'prefix': 'typ'}]},
                {'filter': {'Type': 'String.Array', 'Value': "['test1', 'other']"}},
                True
            ),
            (
                'logical OR no match',
                {'filter': ['test1', 'test2', {'prefix': 'typ'}]},
                {'filter': {'Type': 'String', 'Value': 'test3'}},
                False
            ),
            (
                'logical OR no match on an array',
                {'filter': ['test1', 'test2', {'prefix': 'typ'}]},
                {'filter': {'Type': 'String.Array', 'Value': "['anything', 'something']"}},
                False
            ),
            (
                'logical AND with match',
                {'filter': [{'numeric': ['=', 300]}], 'other': [{'prefix': 'typ'}]},
                {'filter': {'Type': 'Number', 'Value': 300}, 'other': {'Type': 'String', 'Value': 'type1'}},
                True
            ),
            (
                'logical AND missing first attribute',
                {'filter': [{'numeric': ['=', 300]}], 'other': [{'prefix': 'typ'}]},
                {'other': {'Type': 'String', 'Value': 'type1'}},
                False
            ),
            (
                'logical AND missing second attribute',
                {'filter': [{'numeric': ['=', 300]}], 'other': [{'prefix': 'typ'}]},
                {'filter': {'Type': 'Number', 'Value': 300}},
                False
            ),
            (
                'logical AND no match',
                {'filter': [{'numeric': ['=', 300]}], 'other': [{'prefix': 'typ'}]},
                {'filter': {'Type': 'Number', 'Value': 299}, 'other': {'Type': 'String', 'Value': 'type1'}},
                False
            ),
            (
                'multiple numeric filters with first match',
                {'filter': [{'numeric': ['=', 300]}, {'numeric': ['=', 500]}]},
                {'filter': {'Type': 'Number', 'Value': 300}},
                True
            ),
            (
                'multiple numeric filters with second match',
                {'filter': [{'numeric': ['=', 300]}, {'numeric': ['=', 500]}]},
                {'filter': {'Type': 'Number', 'Value': 500}},
                True
            ),
            (
                'multiple prefix filters with first match',
                {'filter': [{'prefix': 'typ'}, {'prefix': 'tes'}]},
                {'filter': {'Type': 'String', 'Value': 'type1'}},
                True
            ),
            (
                'multiple prefix filters with second match',
                {'filter': [{'prefix': 'typ'}, {'prefix': 'tes'}]},
                {'filter': {'Type': 'String', 'Value': 'test'}},
                True
            ),
            (
                'multiple anything-but filters with second match',
                {'filter': [{'anything-but': 'type1'}, {'anything-but': 'type2'}]},
                {'filter': {'Type': 'String', 'Value': 'type2'}},
                True
            ),
            (
                'multiple numeric conditions',
                {'filter': [{'numeric': ['>', 0, '<=', 150]}]},
                {'filter': {'Type': 'Number', 'Value': 122}},
                True
            ),
            (
                'multiple numeric conditions',
                {'filter': [{'numeric': ['>', 0, '<=', 150]}]},
                {'filter': {'Type': 'Number', 'Value': 200}},
                False
            ),
            (
                'multiple numeric conditions',
                {'filter': [{'numeric': ['>', 0, '<=', 150]}]},
                {'filter': {'Type': 'Number', 'Value': -1}},
                False
            ),
            (
                'multiple conditions on an array',
                {'filter': ['test1', 'test2', {'prefix': 'som'}]},
                {'filter': {'Type': 'String.Array', 'Value': "['anything', 'something']"}},
                True
            )
        ]

        for test in test_data:
            test_name = test[0]
            filter_policy = test[1]
            attributes = test[2]
            expected = test[3]
            self.assertEqual(sns_listener.check_filter_policy(filter_policy, attributes), expected, test_name)

    def test_is_raw_message_delivery(self):
        valid_true_values = ['true', 'True', True]

        for true_value in valid_true_values:
            self.subscriber['RawMessageDelivery'] = true_value
            self.assertTrue(sns_listener.is_raw_message_delivery(self.subscriber))

    def test_is_not_raw_message_delivery(self):
        invalid_values = ['false', 'False', False, 'somevalue', '']

        for invalid_values in invalid_values:
            self.subscriber['RawMessageDelivery'] = invalid_values
            self.assertFalse(sns_listener.is_raw_message_delivery(self.subscriber))

        del self.subscriber['RawMessageDelivery']
        self.assertFalse(sns_listener.is_raw_message_delivery(self.subscriber))

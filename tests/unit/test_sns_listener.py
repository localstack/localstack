import json
import unittest
import uuid

from nose.tools import assert_equal, assert_raises

from localstack.services.sns import sns_listener


class SNSTests(unittest.TestCase):
    def setUp(self):
        self.subscriber = {
            'Protocol': 'sqs',
            'RawMessageDelivery': 'false',
            'TopicArn': 'arn',
        }

    def test_unsubscribe_without_arn_should_error(self):
        sns = sns_listener.ProxyListenerSNS()
        error = sns.forward_request('POST', '/', 'Action=Unsubscribe', '')
        assert(error is not None)
        assert(error.status_code == 400)

    def test_unsubscribe_should_remove_listener(self):
        sub_arn = 'arn:aws:sns:us-east-1:123456789012:test-topic:45e61c7f-dca5-4fcd-be2b-4e1b0d6eef72'
        topic_arn = 'arn:aws:sns:us-east-1:123456789012:test-topic'

        assert(sns_listener.get_topic_by_arn(topic_arn) is None)
        sns_listener.do_create_topic(topic_arn)
        assert(sns_listener.get_topic_by_arn(topic_arn) is not None)
        sns_listener.do_subscribe(
            topic_arn,
            'http://localhost:1234/listen',
            'http',
            sub_arn
        )
        assert(sns_listener.get_subscription_by_arn(sub_arn) is not None)
        sns_listener.do_unsubscribe(sub_arn)
        assert(sns_listener.get_subscription_by_arn(sub_arn) is None)

    def test_create_sns_message_body_raw_message_delivery(self):
        self.subscriber['RawMessageDelivery'] = 'true'
        action = {
            'Message': ['msg']
        }
        result = sns_listener.create_sns_message_body(self.subscriber, action)
        assert (result == 'msg')

    def test_create_sns_message_body(self):
        action = {
            'Message': ['msg']
        }
        result_str = sns_listener.create_sns_message_body(self.subscriber, action)
        result = json.loads(result_str)
        try:
            uuid.UUID(result.pop('MessageId'))
        except KeyError:
            assert False, 'MessageId missing in SNS response message body'
        except ValueError:
            assert False, 'SNS response MessageId not a valid UUID'
        assert_equal(result, {'Message': 'msg', 'Type': 'Notification', 'TopicArn': 'arn'})

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
        expected = json.dumps({'Message': 'msg',
                               'TopicArn': 'arn',
                               'Type': 'Notification',
                               'Subject': 'subject',
                               'MessageAttributes': {
                                   'attr1': {
                                       'Type': 'String',
                                       'Value': 'value1',
                                   }, 'attr2': {
                                       'Type': 'String',
                                       'Value': 'value2',
                                   }
                               }})
        assert_equal(result, json.loads(expected))

    def test_create_sns_message_body_json_structure(self):
        action = {
            'Message': ['{"default": {"message": "abc"}}'],
            'MessageStructure': ['json']
        }
        result_str = sns_listener.create_sns_message_body(self.subscriber, action)
        result = json.loads(result_str)

        assert (result['Message'] == {'message': 'abc'})

    def test_create_sns_message_body_json_structure_without_default_key(self):
        action = {
            'Message': ['{"message": "abc"}'],
            'MessageStructure': ['json']
        }
        with assert_raises(Exception) as exc:
            sns_listener.create_sns_message_body(self.subscriber, action)
        assert str(exc.exception) == "Unable to find 'default' key in message payload"

    def test_create_sns_message_body_json_structure_sqs_protocol(self):
        action = {
            'Message': ['{"default": "default message", "sqs": "sqs message"}'],
            'MessageStructure': ['json']
        }
        result_str = sns_listener.create_sns_message_body(self.subscriber, action)
        result = json.loads(result_str)

        assert (result['Message'] == 'sqs message')

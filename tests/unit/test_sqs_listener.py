import unittest
from localstack.services.sqs import sqs_listener


class SQSListenerTest (unittest.TestCase):
    def test_sqs_listener_message_attrs(self):
        request_data = {
            'Action': ['SendMessage'],
            'MessageAttribute.1.Name': ['attr_1'],
            'MessageAttribute.1.Value.DataType': ['String'],
            'MessageAttribute.1.Value.StringValue': ['attr_1_value'],
            'MessageAttribute.2.Name': ['attr_2'],
            'MessageAttribute.2.Value.DataType': ['Custom'],
            'MessageAttribute.2.Value.StringValue': ['attr_2_value'],
            'MessageBody': ['body message'],
            'QueueUrl': ['http://localhost:4576/queue/foo-queue'],
            'Version': ['2012-11-05']
        }

        expected = {
            'attr_2': {
                'dataType': 'Custom',
                'stringValue': 'attr_2_value',
                'stringListValues': [],
                'binaryListValues': []
            },
            'attr_1': {
                'dataType': 'String',
                'stringValue': 'attr_1_value',
                'stringListValues': [],
                'binaryListValues': []
            }
        }

        result = sqs_listener.UPDATE_SQS.format_message_attributes(request_data)
        self.assertEqual(result, expected)

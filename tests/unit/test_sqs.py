import unittest
from localstack.services.sqs import sqs_listener


class SQSListenerTest (unittest.TestCase):
    def test_sqs_message_attrs_md5(self):
        msg_attrs = {
            'MessageAttribute.1.Name': 'timestamp',
            'MessageAttribute.1.Value.StringValue': '1493147359900',
            'MessageAttribute.1.Value.DataType': 'Number'
        }
        md5 = sqs_listener.ProxyListenerSQS.get_message_attributes_md5(msg_attrs)
        self.assertEqual(md5, '235c5c510d26fb653d073faed50ae77c')

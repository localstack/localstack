# -*- coding: utf-8 -*-

import unittest
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid


class CloudWatchLogsTest(unittest.TestCase):

    def test_put_events_multibyte_msg(self):
        client = aws_stack.connect_to_service('logs')

        group = 'g-%s' % short_uid()
        stream = 's-%s' % short_uid()
        response = client.create_log_group(logGroupName=group)
        self.assertEquals(response['ResponseMetadata']['HTTPStatusCode'], 200)
        response = client.create_log_stream(logGroupName=group, logStreamName=stream)
        self.assertEquals(response['ResponseMetadata']['HTTPStatusCode'], 200)

        # send message with non-ASCII (multi-byte) chars
        body_msg = '🙀 - 参よ - 日本語'
        events = [{
            'timestamp': 1234567,
            'message': body_msg
        }]
        response = client.put_log_events(logGroupName=group, logStreamName=stream, logEvents=events)
        self.assertEquals(response['ResponseMetadata']['HTTPStatusCode'], 200)

        events = client.get_log_events(logGroupName=group, logStreamName=stream)['events']
        self.assertEquals(events[0]['message'], body_msg)

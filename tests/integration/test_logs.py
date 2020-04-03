# -*- coding: utf-8 -*-

import unittest

from localstack.constants import APPLICATION_AMZ_JSON_1_1
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid


class CloudWatchLogsTest(unittest.TestCase):
    def setUp(self):
        self.logs_client = aws_stack.connect_to_service('logs')

    def test_put_events_multi_bytes_msg(self):
        group = 'g-%s' % short_uid()
        stream = 's-%s' % short_uid()

        response = self.logs_client.create_log_group(logGroupName=group)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

        response = self.logs_client.create_log_stream(logGroupName=group, logStreamName=stream)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

        # send message with non-ASCII (multi-byte) chars
        body_msg = '🙀 - 参よ - 日本語'
        events = [{
            'timestamp': 1546300800,
            'message': body_msg
        }]
        response = self.logs_client.put_log_events(logGroupName=group, logStreamName=stream, logEvents=events)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

        events = self.logs_client.get_log_events(logGroupName=group, logStreamName=stream)['events']
        self.assertEqual(events[0]['message'], body_msg)

        # clean up
        self.logs_client.delete_log_group(
            logGroupName=group
        )

    def test_filter_log_events_response_header(self):
        group = 'lg-%s' % short_uid()
        stream = 'ls-%s' % short_uid()

        self.logs_client.create_log_group(logGroupName=group)
        self.logs_client.create_log_stream(logGroupName=group, logStreamName=stream)

        events = [
            {'timestamp': 1585902800, 'message': 'log message 1'},
            {'timestamp': 1585902961, 'message': 'log message 2'}
        ]
        self.logs_client.put_log_events(logGroupName=group, logStreamName=stream, logEvents=events)

        rs = self.logs_client.filter_log_events(
            logGroupName=group
        )

        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(rs['ResponseMetadata']['HTTPHeaders']['content-type'], APPLICATION_AMZ_JSON_1_1)

        # clean up
        self.logs_client.delete_log_group(
            logGroupName=group
        )

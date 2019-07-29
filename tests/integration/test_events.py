# -*- coding: utf-8 -*-

import json
import unittest
from datetime import datetime

from localstack.utils.aws import aws_stack

TEST_RULE_NAME = 'TestRule'
TEST_EVENT_SOURCE = 'integration_tests'
TEST_DETAIL_TYPE = 'TEST_EVENT'

TEST_EVENT_PATTERN = {
    'Source': TEST_EVENT_SOURCE,
    'DetailType': TEST_DETAIL_TYPE,
    'Detail': 'something'
}


class EventsTest(unittest.TestCase):

    def setUp(self):
        self.events_client = aws_stack.connect_to_service('events')

    def test_put_rule(self):
        self.events_client.put_rule(Name='test_rule', EventPattern=json.dumps(TEST_EVENT_PATTERN))
        rules = self.events_client.list_rules(NamePrefix='test_rule')['Rules']

        self.assertEqual(1, len(rules))
        self.assertEqual(TEST_EVENT_PATTERN, json.loads(rules[0]['EventPattern']))

    def test_put_events(self):
        self.events_client.put_events(Entries=[{
            'Time': datetime(2019, 7, 29),
            'DetailType': TEST_DETAIL_TYPE,
            'Detail': 'some detail'
        }])

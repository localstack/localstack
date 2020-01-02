# -*- coding: utf-8 -*-
import json
import os
import unittest
from datetime import datetime

from localstack.services.events.events_listener import EVENTS_TMP_DIR
from localstack.utils.aws import aws_stack
from localstack.utils.common import load_file

TEST_RULE_NAME = 'TestRule'
TEST_EVENT_SOURCE = 'integration_tests'
TEST_DETAIL_TYPE = 'TEST_EVENT'
TEST_DETAIL = 'some detail'

TEST_EVENT_PATTERN = {
    'Source': TEST_EVENT_SOURCE,
    'DetailType': TEST_DETAIL_TYPE,
    'Detail': TEST_DETAIL
}


class EventsTest(unittest.TestCase):

    def setUp(self):
        self.events_client = aws_stack.connect_to_service('events')

    def test_put_rule(self):
        self.events_client.put_rule(Name=TEST_RULE_NAME, EventPattern=json.dumps(TEST_EVENT_PATTERN))
        rules = self.events_client.list_rules(NamePrefix=TEST_RULE_NAME)['Rules']

        self.assertEqual(1, len(rules))
        self.assertEqual(TEST_EVENT_PATTERN, json.loads(rules[0]['EventPattern']))

    def test_put_events(self):
        response = self.events_client.put_events(Entries=[{
            'Time': datetime(2019, 7, 29),
            'DetailType': TEST_DETAIL_TYPE,
            'Detail': TEST_DETAIL
        }])
        entries = response['Entries']
        self.assertEqual(1, len(entries))
        event_id = entries[0]['EventId']
        self.assertRegex(event_id, '[0-9a-f-]{36}')
        event_from_file = json.loads(str(load_file(os.path.join(EVENTS_TMP_DIR, event_id))))
        self.assertEqual(TEST_DETAIL_TYPE, event_from_file['DetailType'])
        self.assertEqual(TEST_DETAIL, event_from_file['Detail'])

    def test_list_tags_for_resource(self):
        rule = self.events_client.put_rule(Name=TEST_RULE_NAME, EventPattern=json.dumps(TEST_EVENT_PATTERN))
        ruleArn = rule['RuleArn']
        expected = [{'Key': 'key1', 'Value': 'value1'}, {'Key': 'key2', 'Value': 'value2'}]

        # insert two tags, verify both are visible
        self.events_client.tag_resource(ResourceARN=ruleArn, Tags=expected)
        actual = self.events_client.list_tags_for_resource(ResourceARN=ruleArn)['Tags']
        self.assertEqual(expected, actual)

        # remove 'key2', verify only 'key1' remains
        expected = [{'Key': 'key1', 'Value': 'value1'}]
        self.events_client.untag_resource(ResourceARN=ruleArn, TagKeys=['key2'])
        actual = self.events_client.list_tags_for_resource(ResourceARN=ruleArn)['Tags']
        self.assertEqual(expected, actual)

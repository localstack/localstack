# -*- coding: utf-8 -*-
import json
import os
import unittest
import uuid
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

    def test_put_event(self):
        response = self.events_client.put_events(Entries=[{
            'Time': datetime(2019, 7, 29),
            'DetailType': TEST_DETAIL_TYPE,
            'Detail': TEST_DETAIL
        }])
        entries = response['Entries']
        self.assertEqual(1, len(entries))
        event_id = entries[0]['EventId']
        self.assertRegex(event_id, '[0-9a-f-]{36}')

    def test_events_written_to_disk_are_timestamp_prefixed_for_chronological_ordering(self):
        event_type = str(uuid.uuid4())
        event_details_to_publish = list(map(lambda n: 'event %s' % n, range(100)))

        for detail in event_details_to_publish:
            self.events_client.put_events(Entries=[{
                'DetailType': event_type,
                'Detail': detail
            }])

        sorted_events_written_to_disk = map(
            lambda filename: json.loads(str(load_file(os.path.join(EVENTS_TMP_DIR, filename)))),
            sorted(os.listdir(EVENTS_TMP_DIR)))
        sorted_events = list(filter(lambda event: event['DetailType'] == event_type,
                                    sorted_events_written_to_disk))
        self.assertListEqual(event_details_to_publish, list(map(lambda event: event['Detail'], sorted_events)))

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

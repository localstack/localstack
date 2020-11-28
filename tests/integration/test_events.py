# -*- coding: utf-8 -*-
import os
import json
import uuid
import unittest
from localstack import config
from localstack.services.awslambda.lambda_api import LAMBDA_RUNTIME_PYTHON36
from localstack.services.events.events_listener import EVENTS_TMP_DIR
from localstack.services.generic_proxy import ProxyListener
from localstack.services.infra import start_proxy
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    load_file, retry, short_uid, get_free_tcp_port, wait_for_port_open, to_str, get_service_protocol
)
from localstack.utils.testutil import check_expected_lambda_log_events_length


THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))

TEST_EVENT_BUS_NAME = 'command-bus-dev'

EVENT_DETAIL = '{\"command\":\"update-account\",\"payload\":{\"acc_id\":\"0a787ecb-4015\",\"sf_id\":\"baz\"}}'
TEST_EVENT_PATTERN = {
    'Source': ['core.update-account-command'],
    'detail-type': ['core.update-account-command'],
    'Detail': [EVENT_DETAIL]
}


class EventsTest(unittest.TestCase):
    def setUp(self):
        self.events_client = aws_stack.connect_to_service('events')
        self.iam_client = aws_stack.connect_to_service('iam')
        self.sns_client = aws_stack.connect_to_service('sns')
        self.sfn_client = aws_stack.connect_to_service('stepfunctions')
        self.sqs_client = aws_stack.connect_to_service('sqs')

    def assertIsValidEvent(self, event):
        expected_fields = ('version', 'id', 'detail-type', 'source', 'account', 'time', 'region', 'resources', 'detail')
        for field in expected_fields:
            self.assertIn(field, event)

    def test_put_rule(self):
        rule_name = 'rule-{}'.format(short_uid())

        self.events_client.put_rule(
            Name=rule_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN)
        )

        rules = self.events_client.list_rules(NamePrefix=rule_name)['Rules']

        self.assertEqual(1, len(rules))
        self.assertEqual(TEST_EVENT_PATTERN, json.loads(rules[0]['EventPattern']))

        # clean up
        self.events_client.delete_rule(
            Name=rule_name,
            Force=True
        )

    def test_events_written_to_disk_are_timestamp_prefixed_for_chronological_ordering(self):
        event_type = str(uuid.uuid4())
        event_details_to_publish = list(map(lambda n: 'event %s' % n, range(10)))

        for detail in event_details_to_publish:
            self.events_client.put_events(Entries=[{
                'Source': 'unittest',
                'Resources': [],
                'DetailType': event_type,
                'Detail': json.dumps(detail)
            }])

        sorted_events_written_to_disk = map(
            lambda filename: json.loads(str(load_file(os.path.join(EVENTS_TMP_DIR, filename)))),
            sorted(os.listdir(EVENTS_TMP_DIR))
        )
        sorted_events = list(filter(lambda event: event['DetailType'] == event_type,
                                    sorted_events_written_to_disk))

        self.assertListEqual(event_details_to_publish,
                             list(map(lambda event: json.loads(event['Detail']), sorted_events)))

    def test_list_tags_for_resource(self):
        rule_name = 'rule-{}'.format(short_uid())

        rule = self.events_client.put_rule(
            Name=rule_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN)
        )
        rule_arn = rule['RuleArn']
        expected = [{'Key': 'key1', 'Value': 'value1'}, {'Key': 'key2', 'Value': 'value2'}]

        # insert two tags, verify both are visible
        self.events_client.tag_resource(ResourceARN=rule_arn, Tags=expected)
        actual = self.events_client.list_tags_for_resource(ResourceARN=rule_arn)['Tags']
        self.assertEqual(expected, actual)

        # remove 'key2', verify only 'key1' remains
        expected = [{'Key': 'key1', 'Value': 'value1'}]
        self.events_client.untag_resource(ResourceARN=rule_arn, TagKeys=['key2'])
        actual = self.events_client.list_tags_for_resource(ResourceARN=rule_arn)['Tags']
        self.assertEqual(expected, actual)

        # clean up
        self.events_client.delete_rule(
            Name=rule_name,
            Force=True
        )

    def test_put_events_with_target_sqs(self):
        queue_name = 'queue-{}'.format(short_uid())
        rule_name = 'rule-{}'.format(short_uid())
        target_id = 'target-{}'.format(short_uid())
        bus_name = 'bus-{}'.format(short_uid())

        sqs_client = aws_stack.connect_to_service('sqs')
        queue_url = sqs_client.create_queue(QueueName=queue_name)['QueueUrl']
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        self.events_client.create_event_bus(
            Name=bus_name
        )

        self.events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN)
        )

        rs = self.events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[
                {
                    'Id': target_id,
                    'Arn': queue_arn
                }
            ]
        )

        self.assertIn('FailedEntryCount', rs)
        self.assertIn('FailedEntries', rs)
        self.assertEqual(rs['FailedEntryCount'], 0)
        self.assertEqual(rs['FailedEntries'], [])

        self.events_client.put_events(
            Entries=[{
                'EventBusName': bus_name,
                'Source': TEST_EVENT_PATTERN['Source'][0],
                'DetailType': TEST_EVENT_PATTERN['detail-type'][0],
                'Detail': json.dumps(TEST_EVENT_PATTERN['Detail'][0])
            }]
        )

        def get_message(queue_url):
            resp = sqs_client.receive_message(QueueUrl=queue_url)
            return resp['Messages']

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        self.assertEqual(len(messages), 1)

        actual_event = json.loads(messages[0]['Body'])
        self.assertIsValidEvent(actual_event)
        self.assertEqual(actual_event['detail'], TEST_EVENT_PATTERN['Detail'][0])

        # clean up
        sqs_client.delete_queue(QueueUrl=queue_url)

        self.events_client.remove_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Ids=[target_id],
            Force=True
        )
        self.events_client.delete_rule(
            Name=rule_name,
            EventBusName=bus_name,
            Force=True
        )
        self.events_client.delete_event_bus(
            Name=bus_name
        )

    def test_put_events_with_target_lambda(self):
        rule_name = 'rule-{}'.format(short_uid())
        function_name = 'lambda-func-{}'.format(short_uid())
        target_id = 'target-{}'.format(short_uid())
        bus_name = 'bus-{}'.format(short_uid())

        rs = testutil.create_lambda_function(handler_file=os.path.join(THIS_FOLDER, 'lambdas', 'lambda_echo.py'),
                                             func_name=function_name,
                                             runtime=LAMBDA_RUNTIME_PYTHON36)

        func_arn = rs['CreateFunctionResponse']['FunctionArn']

        self.events_client.create_event_bus(
            Name=bus_name
        )

        self.events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN)
        )

        rs = self.events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[
                {
                    'Id': target_id,
                    'Arn': func_arn
                }
            ]
        )

        self.assertIn('FailedEntryCount', rs)
        self.assertIn('FailedEntries', rs)
        self.assertEqual(rs['FailedEntryCount'], 0)
        self.assertEqual(rs['FailedEntries'], [])

        self.events_client.put_events(
            Entries=[{
                'EventBusName': bus_name,
                'Source': TEST_EVENT_PATTERN['Source'][0],
                'DetailType': TEST_EVENT_PATTERN['detail-type'][0],
                'Detail': json.dumps(TEST_EVENT_PATTERN['Detail'][0])
            }]
        )

        # Get lambda's log events
        events = retry(check_expected_lambda_log_events_length, retries=3,
                       sleep=1, function_name=function_name, expected_length=1)
        actual_event = events[0]
        self.assertIsValidEvent(actual_event)
        self.assertDictEqual(json.loads(actual_event['detail']), json.loads(TEST_EVENT_PATTERN['Detail'][0]))

        # clean up
        testutil.delete_lambda_function(function_name)

        self.events_client.remove_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Ids=[target_id],
            Force=True
        )
        self.events_client.delete_rule(
            Name=rule_name,
            EventBusName=bus_name,
            Force=True
        )
        self.events_client.delete_event_bus(
            Name=bus_name
        )

    def test_scheduled_expression_events(self):
        class HttpEndpointListener(ProxyListener):
            def forward_request(self, method, path, data, headers):
                event = json.loads(to_str(data))
                events.append(event)
                return 200

        local_port = get_free_tcp_port()
        proxy = start_proxy(local_port, backend_url=None, update_listener=HttpEndpointListener())
        wait_for_port_open(local_port)

        topic_name = 'topic-{}'.format(short_uid())
        queue_name = 'queue-{}'.format(short_uid())
        rule_name = 'rule-{}'.format(short_uid())
        endpoint = '{}://{}:{}'.format(get_service_protocol(), config.LOCALSTACK_HOSTNAME, local_port)
        sm_role_arn = aws_stack.role_arn('sfn_role')
        sm_name = 'state-machine-{}'.format(short_uid())
        topic_target_id = 'target-{}'.format(short_uid())
        sm_target_id = 'target-{}'.format(short_uid())
        queue_target_id = 'target-{}'.format(short_uid())

        events = []
        state_machine_definition = """
        {
            "StartAt": "Hello",
            "States": {
                "Hello": {
                    "Type": "Pass",
                    "Result": "World",
                    "End": true
                }
            }
        }
        """

        state_machine_arn = self.sfn_client.create_state_machine(
            name=sm_name,
            definition=state_machine_definition,
            roleArn=sm_role_arn
        )['stateMachineArn']

        topic_arn = self.sns_client.create_topic(Name=topic_name)['TopicArn']
        self.sns_client.subscribe(TopicArn=topic_arn, Protocol='http', Endpoint=endpoint)

        queue_url = self.sqs_client.create_queue(QueueName=queue_name)['QueueUrl']
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        event = {
            'env': 'testing'
        }

        self.events_client.put_rule(
            Name=rule_name,
            ScheduleExpression='rate(1 minutes)'
        )

        self.events_client.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    'Id': topic_target_id,
                    'Arn': topic_arn,
                    'Input': json.dumps(event)
                },
                {
                    'Id': sm_target_id,
                    'Arn': state_machine_arn,
                    'Input': json.dumps(event)
                },
                {
                    'Id': queue_target_id,
                    'Arn': queue_arn,
                    'Input': json.dumps(event)
                }
            ]
        )

        def received(q_url):
            # state machine got executed
            executions = self.sfn_client.list_executions(stateMachineArn=state_machine_arn)['executions']
            self.assertGreaterEqual(len(executions), 1)

            # http endpoint got events
            self.assertGreaterEqual(len(events), 2)
            notifications = [event['Message'] for event in events if event['Type'] == 'Notification']
            self.assertGreaterEqual(len(notifications), 1)

            # get state machine execution detail
            execution_arn = executions[0]['executionArn']
            execution_input = self.sfn_client.describe_execution(executionArn=execution_arn)['input']

            # get message from queue
            msgs = self.sqs_client.receive_message(QueueUrl=q_url).get('Messages', [])
            self.assertGreaterEqual(len(msgs), 1)

            return execution_input, notifications[0], msgs[0]

        execution_input, notification, msg_received = retry(received, retries=5, sleep=15, q_url=queue_url)
        self.assertEqual(json.loads(notification), event)
        self.assertEqual(json.loads(execution_input), event)
        self.assertEqual(json.loads(msg_received['Body']), event)

        proxy.stop()

        self.events_client.remove_targets(
            Rule=rule_name,
            Ids=[topic_target_id, sm_target_id],
            Force=True
        )
        self.events_client.delete_rule(
            Name=rule_name,
            Force=True
        )

        self.sns_client.delete_topic(TopicArn=topic_arn)
        self.sfn_client.delete_state_machine(stateMachineArn=state_machine_arn)

        self.sqs_client.delete_queue(QueueUrl=queue_url)

    def test_put_events_with_target_firehose(self):
        s3_bucket = 's3-{}'.format(short_uid())
        s3_prefix = 'testeventdata'
        stream_name = 'firehose-{}'.format(short_uid())
        rule_name = 'rule-{}'.format(short_uid())
        target_id = 'target-{}'.format(short_uid())
        bus_name = 'bus-{}'.format(short_uid())

        # create firehose target bucket
        s3_client = aws_stack.connect_to_service('s3')
        s3_client.create_bucket(Bucket=s3_bucket)

        # create firehose delivery stream to s3
        firehose_client = aws_stack.connect_to_service('firehose')
        stream = firehose_client.create_delivery_stream(
            DeliveryStreamName=stream_name,
            S3DestinationConfiguration={
                'RoleARN': aws_stack.iam_resource_arn('firehose'),
                'BucketARN': aws_stack.s3_bucket_arn(s3_bucket),
                'Prefix': s3_prefix
            }
        )
        stream_arn = stream['DeliveryStreamARN']

        self.events_client.create_event_bus(
            Name=bus_name
        )

        self.events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN)
        )

        rs = self.events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[
                {
                    'Id': target_id,
                    'Arn': stream_arn
                }
            ]
        )

        self.assertIn('FailedEntryCount', rs)
        self.assertIn('FailedEntries', rs)
        self.assertEqual(rs['FailedEntryCount'], 0)
        self.assertEqual(rs['FailedEntries'], [])

        self.events_client.put_events(
            Entries=[{
                'EventBusName': bus_name,
                'Source': TEST_EVENT_PATTERN['Source'][0],
                'DetailType': TEST_EVENT_PATTERN['detail-type'][0],
                'Detail': json.dumps(TEST_EVENT_PATTERN['Detail'][0])
            }]
        )

        # run tests
        bucket_contents = s3_client.list_objects(Bucket=s3_bucket)['Contents']
        self.assertEqual(len(bucket_contents), 1)
        key = bucket_contents[0]['Key']
        s3_object = s3_client.get_object(Bucket=s3_bucket, Key=key)
        actual_event = json.loads(s3_object['Body'].read().decode())
        self.assertIsValidEvent(actual_event)
        self.assertEqual(actual_event['detail'], TEST_EVENT_PATTERN['Detail'][0])

        # clean up
        firehose_client.delete_delivery_stream(DeliveryStreamName=stream_name)
        # empty and delete bucket
        s3_client.delete_object(Bucket=s3_bucket, Key=key)
        s3_client.delete_bucket(Bucket=s3_bucket)

        self.events_client.remove_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Ids=[target_id],
            Force=True
        )
        self.events_client.delete_rule(
            Name=rule_name,
            EventBusName=bus_name,
            Force=True
        )
        self.events_client.delete_event_bus(
            Name=bus_name
        )

    def test_put_events_with_target_sqs_new_region(self):
        self.events_client = aws_stack.connect_to_service('events', Region='eu-west-1')
        queue_name = 'queue-{}'.format(short_uid())
        rule_name = 'rule-{}'.format(short_uid())
        target_id = 'target-{}'.format(short_uid())

        sqs_client = aws_stack.connect_to_service('sqs', Region='eu-west-1')
        sqs_client.create_queue(QueueName=queue_name)
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        self.events_client.put_rule(Name=rule_name)
        self.events_client.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    'Id': target_id,
                    'Arn': queue_arn
                }
            ]
        )

        response = self.events_client.put_events(
            Entries=[
                {
                    'Source': 'com.mycompany.myapp',
                    'Detail': '{ "key1": "value1", "key": "value2" }',
                    'Resources': [],
                    'DetailType': 'myDetailType'
                }
            ]
        )
        self.assertIn('Entries', response)
        self.assertEqual(len(response.get('Entries')), 1)
        self.assertIn('EventId', response.get('Entries')[0])

    def test_put_events_with_input_path(self):
        queue_name = 'queue-{}'.format(short_uid())
        rule_name = 'rule-{}'.format(short_uid())
        target_id = 'target-{}'.format(short_uid())
        bus_name = 'bus-{}'.format(short_uid())

        sqs_client = aws_stack.connect_to_service('sqs')
        queue_url = sqs_client.create_queue(QueueName=queue_name)['QueueUrl']
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        self.events_client.create_event_bus(
            Name=bus_name
        )

        self.events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN)
        )

        self.events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[
                {
                    'Id': target_id,
                    'Arn': queue_arn,
                    'InputPath': '$.detail'
                }
            ]
        )

        self.events_client.put_events(
            Entries=[{
                'EventBusName': bus_name,
                'Source': TEST_EVENT_PATTERN['Source'][0],
                'DetailType': TEST_EVENT_PATTERN['detail-type'][0],
                'Detail': json.dumps(TEST_EVENT_PATTERN['Detail'][0])
            }]
        )

        def get_message(queue_url):
            resp = sqs_client.receive_message(QueueUrl=queue_url)
            return resp.get('Messages')

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        self.assertEqual(len(messages), 1)
        self.assertEqual(json.loads(messages[0].get('Body')), EVENT_DETAIL)

        self.events_client.put_events(
            Entries=[{
                'EventBusName': bus_name,
                'Source': 'dummySource',
                'DetailType': TEST_EVENT_PATTERN['detail-type'][0],
                'Detail': json.dumps(TEST_EVENT_PATTERN['Detail'][0])
            }]
        )

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        self.assertEqual(messages, None)

        # clean up
        sqs_client.delete_queue(QueueUrl=queue_url)

        self.events_client.remove_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Ids=[target_id],
            Force=True
        )
        self.events_client.delete_rule(
            Name=rule_name,
            EventBusName=bus_name,
            Force=True
        )
        self.events_client.delete_event_bus(
            Name=bus_name
        )

    def test_put_event_without_source(self):
        self.events_client = aws_stack.connect_to_service('events', Region='eu-west-1')

        response = self.events_client.put_events(
            Entries=[
                {
                    'DetailType': 'Test',
                    'Detail': '{}'
                }
            ]
        )
        self.assertIn('Entries', response)

    def test_put_event_with_content_base_rule_in_pattern(self):
        queue_name = 'queue-{}'.format(short_uid())
        rule_name = 'rule-{}'.format(short_uid())
        target_id = 'target-{}'.format(short_uid())

        sqs_client = aws_stack.connect_to_service('sqs')
        queue_url = sqs_client.create_queue(QueueName=queue_name)['QueueUrl']
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        pattern = {
            'Source': [{'exists': True}],
            'detail-type': [{'prefix': 'core.app'}],
            'Detail': json.dumps({
                'decription': ['this-is-event-details'],
                'amount': [200],
                'salary': [2000, 4000],
                'env': ['dev', 'prod'],
                'user': ['user1', 'user2', 'user3'],
                'admins': ['skyli', {'prefix': 'hey'}, {'prefix': 'ad'}],
                'test1': [{'anything-but': 200}],
                'test2': [{'anything-but': 'test2'}],
                'test3': [{'anything-but': ['test3', 'test33']}],
                'test4': [{'anything-but': {'prefix': 'test4'}}],
                'ip': [{'cidr': '10.102.1.0/24'}],
                'num-test1': [{'numeric': ['<', 200]}],
                'num-test2': [{'numeric': ['<=', 200]}],
                'num-test3': [{'numeric': ['>', 200]}],
                'num-test4': [{'numeric': ['>=', 200]}],
                'num-test5': [{'numeric': ['>=', 200, '<=', 500]}],
                'num-test6': [{'numeric': ['>', 200, '<', 500]}],
                'num-test7': [{'numeric': ['>=', 200, '<', 500]}]
            })
        }

        event = {
            'EventBusName': TEST_EVENT_BUS_NAME,
            'Source': 'core.update-account-command',
            'DetailType': 'core.app.backend',
            'Detail': json.dumps({
                'decription': 'this-is-event-details',
                'amount': 200,
                'salary': 2000,
                'env': 'prod',
                'user': ['user4', 'user3'],
                'admins': 'admin',
                'test1': 300,
                'test2': 'test22',
                'test3': 'test333',
                'test4': 'this test4',
                'ip': '10.102.1.100',
                'num-test1': 100,
                'num-test2': 200,
                'num-test3': 300,
                'num-test4': 200,
                'num-test5': 500,
                'num-test6': 300,
                'num-test7': 300
            })
        }

        self.events_client.create_event_bus(
            Name=TEST_EVENT_BUS_NAME
        )

        self.events_client.put_rule(
            Name=rule_name,
            EventBusName=TEST_EVENT_BUS_NAME,
            EventPattern=json.dumps(pattern)
        )

        self.events_client.put_targets(
            Rule=rule_name,
            EventBusName=TEST_EVENT_BUS_NAME,
            Targets=[
                {
                    'Id': target_id,
                    'Arn': queue_arn,
                    'InputPath': '$.detail'
                }
            ]
        )
        self.events_client.put_events(
            Entries=[event]
        )

        def get_message(queue_url):
            resp = sqs_client.receive_message(QueueUrl=queue_url)
            return resp.get('Messages')

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        self.assertEqual(len(messages), 1)
        self.assertEqual(json.loads(messages[0].get('Body')), json.loads(event['Detail']))

        event_details = json.loads(event['Detail'])
        event_details['admins'] = 'not_admin'
        event['Detail'] = json.dumps(event_details)

        self.events_client.put_events(
            Entries=[event]
        )

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        self.assertEqual(messages, None)

        # clean up
        sqs_client.delete_queue(QueueUrl=queue_url)

        self.events_client.remove_targets(
            Rule=rule_name,
            EventBusName=TEST_EVENT_BUS_NAME,
            Ids=[target_id],
            Force=True
        )
        self.events_client.delete_rule(
            Name=rule_name,
            EventBusName=TEST_EVENT_BUS_NAME,
            Force=True
        )
        self.events_client.delete_event_bus(
            Name=TEST_EVENT_BUS_NAME
        )

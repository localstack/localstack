# -*- coding: utf-8 -*-
import base64
import json
import os
import unittest
import uuid
from datetime import datetime

from localstack import config
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON36
from localstack.services.events.events_listener import _get_events_tmp_dir
from localstack.services.generic_proxy import ProxyListener
from localstack.services.infra import start_proxy
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import requests_response
from localstack.utils.common import (
    get_free_tcp_port,
    get_service_protocol,
    load_file,
    retry,
    short_uid,
    to_str,
    wait_for_port_open,
)
from localstack.utils.testutil import check_expected_lambda_log_events_length

from .awslambda.test_lambda import TEST_LAMBDA_PYTHON_ECHO

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))

TEST_EVENT_BUS_NAME = "command-bus-dev"

EVENT_DETAIL = '{"command":"update-account","payload":{"acc_id":"0a787ecb-4015","sf_id":"baz"}}'
TEST_EVENT_PATTERN = {
    "Source": ["core.update-account-command"],
    "detail-type": ["core.update-account-command"],
    "Detail": [EVENT_DETAIL],
}


class EventsTest(unittest.TestCase):
    def setUp(self):
        self.events_client = aws_stack.create_external_boto_client("events")
        self.iam_client = aws_stack.create_external_boto_client("iam")
        self.sns_client = aws_stack.create_external_boto_client("sns")
        self.sfn_client = aws_stack.create_external_boto_client("stepfunctions")
        self.sqs_client = aws_stack.create_external_boto_client("sqs")

    def assertIsValidEvent(self, event):
        expected_fields = (
            "version",
            "id",
            "detail-type",
            "source",
            "account",
            "time",
            "region",
            "resources",
            "detail",
        )
        for field in expected_fields:
            self.assertIn(field, event)

    def test_put_rule(self):
        rule_name = "rule-{}".format(short_uid())

        self.events_client.put_rule(Name=rule_name, EventPattern=json.dumps(TEST_EVENT_PATTERN))

        rules = self.events_client.list_rules(NamePrefix=rule_name)["Rules"]
        self.assertEqual(1, len(rules))
        self.assertEqual(TEST_EVENT_PATTERN, json.loads(rules[0]["EventPattern"]))

        # clean up
        self.events_client.delete_rule(Name=rule_name, Force=True)

    def test_events_written_to_disk_are_timestamp_prefixed_for_chronological_ordering(
        self,
    ):
        event_type = str(uuid.uuid4())
        event_details_to_publish = list(map(lambda n: "event %s" % n, range(10)))

        for detail in event_details_to_publish:
            self.events_client.put_events(
                Entries=[
                    {
                        "Source": "unittest",
                        "Resources": [],
                        "DetailType": event_type,
                        "Detail": json.dumps(detail),
                    }
                ]
            )

        events_tmp_dir = _get_events_tmp_dir()
        sorted_events_written_to_disk = map(
            lambda filename: json.loads(str(load_file(os.path.join(events_tmp_dir, filename)))),
            sorted(os.listdir(events_tmp_dir)),
        )
        sorted_events = list(
            filter(
                lambda event: event.get("DetailType") == event_type,
                sorted_events_written_to_disk,
            )
        )

        self.assertListEqual(
            event_details_to_publish,
            list(map(lambda event: json.loads(event["Detail"]), sorted_events)),
        )

    def test_list_tags_for_resource(self):
        rule_name = "rule-{}".format(short_uid())

        rule = self.events_client.put_rule(
            Name=rule_name, EventPattern=json.dumps(TEST_EVENT_PATTERN)
        )
        rule_arn = rule["RuleArn"]
        expected = [
            {"Key": "key1", "Value": "value1"},
            {"Key": "key2", "Value": "value2"},
        ]

        # insert two tags, verify both are visible
        self.events_client.tag_resource(ResourceARN=rule_arn, Tags=expected)
        actual = self.events_client.list_tags_for_resource(ResourceARN=rule_arn)["Tags"]
        self.assertEqual(expected, actual)

        # remove 'key2', verify only 'key1' remains
        expected = [{"Key": "key1", "Value": "value1"}]
        self.events_client.untag_resource(ResourceARN=rule_arn, TagKeys=["key2"])
        actual = self.events_client.list_tags_for_resource(ResourceARN=rule_arn)["Tags"]
        self.assertEqual(expected, actual)

        # clean up
        self.events_client.delete_rule(Name=rule_name, Force=True)

    def test_put_events_with_target_sqs(self):
        queue_name = "queue-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        sqs_client = aws_stack.create_external_boto_client("sqs")
        queue_url = sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        self.events_client.create_event_bus(Name=bus_name)
        self.events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        rs = self.events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": queue_arn}],
        )

        self.assertIn("FailedEntryCount", rs)
        self.assertIn("FailedEntries", rs)
        self.assertEqual(0, rs["FailedEntryCount"])
        self.assertEqual([], rs["FailedEntries"])

        self.events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["Source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(TEST_EVENT_PATTERN["Detail"][0]),
                }
            ]
        )

        def get_message(queue_url):
            resp = sqs_client.receive_message(QueueUrl=queue_url)
            return resp["Messages"]

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        self.assertEqual(1, len(messages))

        actual_event = json.loads(messages[0]["Body"])
        self.assertIsValidEvent(actual_event)
        self.assertEqual(TEST_EVENT_PATTERN["Detail"][0], actual_event["detail"])

        # clean up
        self.cleanup(bus_name, rule_name, target_id, queue_url=queue_url)

    def test_put_events_with_target_sqs_event_detail_match(self):
        queue_name = "queue-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        sqs_client = aws_stack.create_external_boto_client("sqs")
        queue_url = sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        self.events_client.create_event_bus(Name=bus_name)

        self.events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps({"detail": {"EventType": ["0", "1"]}}),
        )

        rs = self.events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"}],
        )

        self.assertIn("FailedEntryCount", rs)
        self.assertIn("FailedEntries", rs)
        self.assertEqual(0, rs["FailedEntryCount"])
        self.assertEqual([], rs["FailedEntries"])

        self.events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["Source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps({"EventType": "1"}),
                }
            ]
        )

        def get_message(queue_url):
            resp = sqs_client.receive_message(QueueUrl=queue_url)
            return resp.get("Messages")

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        self.assertEqual(1, len(messages))

        actual_event = json.loads(messages[0]["Body"])
        self.assertEqual({"EventType": "1"}, actual_event)

        self.events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["Source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps({"EventType": "2"}),
                }
            ]
        )

        def get_message(queue_url):
            resp = sqs_client.receive_message(QueueUrl=queue_url)
            return resp.get("Messages", [])

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        self.assertEqual(0, len(messages))

        # clean up
        self.cleanup(bus_name, rule_name, target_id, queue_url=queue_url)

    def test_put_events_with_target_sns(self):
        queue_name = "test-%s" % short_uid()
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        sns_client = aws_stack.create_external_boto_client("sns")
        sqs_client = aws_stack.create_external_boto_client("sqs")
        topic_name = "topic-{}".format(short_uid())
        topic_arn = sns_client.create_topic(Name=topic_name)["TopicArn"]

        queue_url = sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        sns_client.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

        self.events_client.create_event_bus(Name=bus_name)
        self.events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        rs = self.events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": topic_arn}],
        )

        self.assertIn("FailedEntryCount", rs)
        self.assertIn("FailedEntries", rs)
        self.assertEqual(0, rs["FailedEntryCount"])
        self.assertEqual([], rs["FailedEntries"])

        self.events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["Source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(TEST_EVENT_PATTERN["Detail"][0]),
                }
            ]
        )

        def get_message(queue_url):
            resp = sqs_client.receive_message(QueueUrl=queue_url)
            return resp["Messages"]

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        self.assertEqual(1, len(messages))

        actual_event = json.loads(messages[0]["Body"]).get("Message")
        self.assertIsValidEvent(actual_event)
        self.assertEqual(TEST_EVENT_PATTERN["Detail"][0], json.loads(actual_event).get("detail"))

        # clean up
        sns_client.delete_topic(TopicArn=topic_arn)
        self.cleanup(bus_name, rule_name, target_id, queue_url=queue_url)

    def test_put_events_into_event_bus(self):
        queue_name = "queue-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name_1 = "bus1-{}".format(short_uid())
        bus_name_2 = "bus2-{}".format(short_uid())

        sqs_client = aws_stack.create_external_boto_client("sqs")
        queue_url = sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        self.events_client.create_event_bus(Name=bus_name_1)
        resp = self.events_client.create_event_bus(Name=bus_name_2)
        self.events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name_1,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        self.events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name_1,
            Targets=[{"Id": target_id, "Arn": resp.get("EventBusArn")}],
        )
        self.events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name_2,
            Targets=[{"Id": target_id, "Arn": queue_arn}],
        )

        self.events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name_1,
                    "Source": TEST_EVENT_PATTERN["Source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(TEST_EVENT_PATTERN["Detail"][0]),
                }
            ]
        )

        def get_message(queue_url):
            resp = sqs_client.receive_message(QueueUrl=queue_url)
            return resp["Messages"]

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        self.assertEqual(1, len(messages))

        actual_event = json.loads(messages[0]["Body"])
        self.assertIsValidEvent(actual_event)
        self.assertEqual(TEST_EVENT_PATTERN["Detail"][0], actual_event["detail"])

        # clean up
        self.cleanup(bus_name_1, rule_name, target_id)
        self.cleanup(bus_name_2)
        sqs_client.delete_queue(QueueUrl=queue_url)

    def test_put_events_with_target_lambda(self):
        rule_name = "rule-{}".format(short_uid())
        function_name = "lambda-func-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        rs = testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )

        func_arn = rs["CreateFunctionResponse"]["FunctionArn"]

        self.events_client.create_event_bus(Name=bus_name)
        self.events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        rs = self.events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": func_arn}],
        )

        self.assertIn("FailedEntryCount", rs)
        self.assertIn("FailedEntries", rs)
        self.assertEqual(0, rs["FailedEntryCount"])
        self.assertEqual([], rs["FailedEntries"])

        self.events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["Source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(TEST_EVENT_PATTERN["Detail"][0]),
                }
            ]
        )

        # Get lambda's log events
        events = retry(
            check_expected_lambda_log_events_length,
            retries=3,
            sleep=1,
            function_name=function_name,
            expected_length=1,
        )
        actual_event = events[0]
        self.assertIsValidEvent(actual_event)
        self.assertDictEqual(
            json.loads(actual_event["detail"]),
            json.loads(TEST_EVENT_PATTERN["Detail"][0]),
        )

        # clean up
        testutil.delete_lambda_function(function_name)
        self.cleanup(bus_name, rule_name, target_id)

    def test_rule_disable(self):
        rule_name = "rule-{}".format(short_uid())
        self.events_client.put_rule(Name=rule_name, ScheduleExpression="rate(1 minutes)")

        response = self.events_client.list_rules()
        self.assertEqual("ENABLED", response["Rules"][0]["State"])
        _ = self.events_client.disable_rule(Name=rule_name)
        response = self.events_client.list_rules(NamePrefix=rule_name)
        self.assertEqual("DISABLED", response["Rules"][0]["State"])

        # clean up
        self.events_client.delete_rule(Name=rule_name, Force=True)

    def test_scheduled_expression_events(self):
        class HttpEndpointListener(ProxyListener):
            def forward_request(self, method, path, data, headers):
                event = json.loads(to_str(data))
                events.append(event)
                return 200

        local_port = get_free_tcp_port()
        proxy = start_proxy(local_port, update_listener=HttpEndpointListener())
        wait_for_port_open(local_port)

        topic_name = "topic-{}".format(short_uid())
        queue_name = "queue-{}".format(short_uid())
        fifo_queue_name = "queue-{}.fifo".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        endpoint = "{}://{}:{}".format(
            get_service_protocol(), config.LOCALSTACK_HOSTNAME, local_port
        )
        sm_role_arn = aws_stack.role_arn("sfn_role")
        sm_name = "state-machine-{}".format(short_uid())
        topic_target_id = "target-{}".format(short_uid())
        sm_target_id = "target-{}".format(short_uid())
        queue_target_id = "target-{}".format(short_uid())
        fifo_queue_target_id = "target-{}".format(short_uid())

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
            name=sm_name, definition=state_machine_definition, roleArn=sm_role_arn
        )["stateMachineArn"]

        topic_arn = self.sns_client.create_topic(Name=topic_name)["TopicArn"]
        self.sns_client.subscribe(TopicArn=topic_arn, Protocol="http", Endpoint=endpoint)

        queue_url = self.sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        fifo_queue_url = self.sqs_client.create_queue(
            QueueName=fifo_queue_name,
            Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        )["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)
        fifo_queue_arn = aws_stack.sqs_queue_arn(fifo_queue_name)

        event = {"env": "testing"}

        self.events_client.put_rule(Name=rule_name, ScheduleExpression="rate(1 minutes)")

        self.events_client.put_targets(
            Rule=rule_name,
            Targets=[
                {"Id": topic_target_id, "Arn": topic_arn, "Input": json.dumps(event)},
                {
                    "Id": sm_target_id,
                    "Arn": state_machine_arn,
                    "Input": json.dumps(event),
                },
                {"Id": queue_target_id, "Arn": queue_arn, "Input": json.dumps(event)},
                {
                    "Id": fifo_queue_target_id,
                    "Arn": fifo_queue_arn,
                    "Input": json.dumps(event),
                    "SqsParameters": {"MessageGroupId": "123"},
                },
            ],
        )

        def received(q_urls):
            # state machine got executed
            executions = self.sfn_client.list_executions(stateMachineArn=state_machine_arn)[
                "executions"
            ]
            self.assertGreaterEqual(len(executions), 1)

            # http endpoint got events
            self.assertGreaterEqual(len(events), 2)
            notifications = [
                event["Message"] for event in events if event["Type"] == "Notification"
            ]
            self.assertGreaterEqual(len(notifications), 1)

            # get state machine execution detail
            execution_arn = executions[0]["executionArn"]
            execution_input = self.sfn_client.describe_execution(executionArn=execution_arn)[
                "input"
            ]

            all_msgs = []
            # get message from queue
            for url in q_urls:
                msgs = self.sqs_client.receive_message(QueueUrl=url).get("Messages", [])
                self.assertGreaterEqual(len(msgs), 1)
                all_msgs.append(msgs[0])

            return execution_input, notifications[0], all_msgs

        execution_input, notification, msgs_received = retry(
            received, retries=5, sleep=15, q_urls=[queue_url, fifo_queue_url]
        )
        self.assertEqual(event, json.loads(notification))
        self.assertEqual(event, json.loads(execution_input))
        for msg_received in msgs_received:
            self.assertEqual(event, json.loads(msg_received["Body"]))

        # clean up
        proxy.stop()
        self.cleanup(
            None,
            rule_name,
            target_ids=[topic_target_id, sm_target_id],
            queue_url=queue_url,
        )
        self.sns_client.delete_topic(TopicArn=topic_arn)
        self.sfn_client.delete_state_machine(stateMachineArn=state_machine_arn)

    def test_api_destinations(self):

        token = short_uid()
        bearer = "Bearer %s" % token

        class HttpEndpointListener(ProxyListener):
            def forward_request(self, method, path, data, headers):
                event = json.loads(to_str(data))
                events.append(event)
                paths_list.append(path)
                auth = headers.get("Api") or headers.get("Authorization")
                if auth not in headers_list:
                    headers_list.append(auth)

                return requests_response(
                    {
                        "access_token": token,
                        "token_type": "Bearer",
                        "expires_in": 86400,
                    }
                )

        events = []
        paths_list = []
        headers_list = []

        local_port = get_free_tcp_port()
        proxy = start_proxy(local_port, update_listener=HttpEndpointListener())
        wait_for_port_open(local_port)
        events_client = aws_stack.create_external_boto_client("events")
        url = "http://localhost:%s" % local_port

        auth_types = [
            {
                "type": "BASIC",
                "key": "BasicAuthParameters",
                "parameters": {"Username": "user", "Password": "pass"},
            },
            {
                "type": "API_KEY",
                "key": "ApiKeyAuthParameters",
                "parameters": {"ApiKeyName": "Api", "ApiKeyValue": "apikey_secret"},
            },
            {
                "type": "OAUTH_CLIENT_CREDENTIALS",
                "key": "OAuthParameters",
                "parameters": {
                    "AuthorizationEndpoint": url,
                    "ClientParameters": {"ClientID": "id", "ClientSecret": "password"},
                    "HttpMethod": "put",
                },
            },
        ]

        for auth in auth_types:
            connection_name = "c-%s" % short_uid()
            connection_arn = events_client.create_connection(
                Name=connection_name,
                AuthorizationType=auth.get("type"),
                AuthParameters={
                    auth.get("key"): auth.get("parameters"),
                    "InvocationHttpParameters": {
                        "BodyParameters": [
                            {"Key": "key", "Value": "value", "IsValueSecret": False}
                        ],
                        "HeaderParameters": [
                            {"Key": "key", "Value": "value", "IsValueSecret": False}
                        ],
                        "QueryStringParameters": [
                            {"Key": "key", "Value": "value", "IsValueSecret": False}
                        ],
                    },
                },
            )["ConnectionArn"]

            # create api destination
            dest_name = "d-%s" % short_uid()
            result = self.events_client.create_api_destination(
                Name=dest_name,
                ConnectionArn=connection_arn,
                InvocationEndpoint=url,
                HttpMethod="POST",
            )

            # create rule and target
            rule_name = "r-%s" % short_uid()
            target_id = "target-{}".format(short_uid())
            pattern = json.dumps({"source": ["source-123"], "detail-type": ["type-123"]})
            self.events_client.put_rule(Name=rule_name, EventPattern=pattern)
            self.events_client.put_targets(
                Rule=rule_name,
                Targets=[{"Id": target_id, "Arn": result["ApiDestinationArn"]}],
            )

            entries = [
                {
                    "Source": "source-123",
                    "DetailType": "type-123",
                    "Detail": '{"i": %s}' % 0,
                }
            ]
            self.events_client.put_events(Entries=entries)

            # cleaning
            self.events_client.delete_connection(Name=connection_name)
            self.events_client.delete_api_destination(Name=dest_name)
            self.events_client.delete_rule(Name=rule_name, Force=True)

        # assert that all events have been received in the HTTP server listener
        def check():
            self.assertTrue(len(events) >= len(auth_types))
            self.assertTrue("key" in paths_list[0] and "value" in paths_list[0])
            self.assertTrue(events[0].get("key") == "value")

            # TODO examine behavior difference between LS pro/community
            # Pro seems to (correctly) use base64 for basic authentication instead of plaintext
            user_pass = to_str(base64.b64encode(b"user:pass"))
            self.assertTrue(
                "Basic user:pass" in headers_list or f"Basic {user_pass}" in headers_list
            )
            self.assertTrue("apikey_secret" in headers_list)
            self.assertTrue(bearer in headers_list)

        retry(check, sleep=0.5, retries=5)

        # clean up
        proxy.stop()

    def test_put_events_with_target_firehose(self):
        s3_bucket = "s3-{}".format(short_uid())
        s3_prefix = "testeventdata"
        stream_name = "firehose-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        # create firehose target bucket
        s3_client = aws_stack.create_external_boto_client("s3")
        s3_client.create_bucket(Bucket=s3_bucket)

        # create firehose delivery stream to s3
        firehose_client = aws_stack.create_external_boto_client("firehose")
        stream = firehose_client.create_delivery_stream(
            DeliveryStreamName=stream_name,
            S3DestinationConfiguration={
                "RoleARN": aws_stack.iam_resource_arn("firehose"),
                "BucketARN": aws_stack.s3_bucket_arn(s3_bucket),
                "Prefix": s3_prefix,
            },
        )
        stream_arn = stream["DeliveryStreamARN"]

        self.events_client.create_event_bus(Name=bus_name)
        self.events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        rs = self.events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": stream_arn}],
        )

        self.assertIn("FailedEntryCount", rs)
        self.assertIn("FailedEntries", rs)
        self.assertEqual(0, rs["FailedEntryCount"])
        self.assertEqual([], rs["FailedEntries"])

        self.events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["Source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(TEST_EVENT_PATTERN["Detail"][0]),
                }
            ]
        )

        # run tests
        bucket_contents = s3_client.list_objects(Bucket=s3_bucket)["Contents"]
        self.assertEqual(1, len(bucket_contents))
        key = bucket_contents[0]["Key"]
        s3_object = s3_client.get_object(Bucket=s3_bucket, Key=key)
        actual_event = json.loads(s3_object["Body"].read().decode())
        self.assertIsValidEvent(actual_event)
        self.assertEqual(TEST_EVENT_PATTERN["Detail"][0], actual_event["detail"])

        # clean up
        firehose_client.delete_delivery_stream(DeliveryStreamName=stream_name)
        # empty and delete bucket
        s3_client.delete_object(Bucket=s3_bucket, Key=key)
        s3_client.delete_bucket(Bucket=s3_bucket)
        self.cleanup(bus_name, rule_name, target_id)

    def test_put_events_with_target_sqs_new_region(self):
        self.events_client = aws_stack.create_external_boto_client(
            "events", region_name="eu-west-1"
        )
        queue_name = "queue-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        sqs_client = aws_stack.create_external_boto_client("sqs", region_name="eu-west-1")
        sqs_client.create_queue(QueueName=queue_name)
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        self.events_client.create_event_bus(Name=bus_name)

        self.events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        self.events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": queue_arn}],
        )

        response = self.events_client.put_events(
            Entries=[
                {
                    "Source": "com.mycompany.myapp",
                    "Detail": '{ "key1": "value1", "key": "value2" }',
                    "Resources": [],
                    "DetailType": "myDetailType",
                }
            ]
        )
        self.assertIn("Entries", response)
        self.assertEqual(1, len(response.get("Entries")))
        self.assertIn("EventId", response.get("Entries")[0])

    def test_put_events_with_target_kinesis(self):
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())
        stream_name = "stream-{}".format(short_uid())
        stream_arn = aws_stack.kinesis_stream_arn(stream_name)

        kinesis_client = aws_stack.create_external_boto_client("kinesis")
        kinesis_client.create_stream(StreamName=stream_name, ShardCount=1)

        self.events_client.create_event_bus(Name=bus_name)

        self.events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        put_response = self.events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[
                {
                    "Id": target_id,
                    "Arn": stream_arn,
                    "KinesisParameters": {"PartitionKeyPath": "$.detail-type"},
                }
            ],
        )

        self.assertIn("FailedEntryCount", put_response)
        self.assertIn("FailedEntries", put_response)
        self.assertEqual(0, put_response["FailedEntryCount"])
        self.assertEqual([], put_response["FailedEntries"])

        def check_stream_status():
            _stream = kinesis_client.describe_stream(StreamName=stream_name)
            assert _stream["StreamDescription"]["StreamStatus"] == "ACTIVE"

        # wait until stream becomes available
        retry(check_stream_status, retries=7, sleep=0.8)

        self.events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["Source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(TEST_EVENT_PATTERN["Detail"][0]),
                }
            ]
        )

        stream = kinesis_client.describe_stream(StreamName=stream_name)
        shard_id = stream["StreamDescription"]["Shards"][0]["ShardId"]
        shard_iterator = kinesis_client.get_shard_iterator(
            StreamName=stream_name,
            ShardId=shard_id,
            ShardIteratorType="AT_TIMESTAMP",
            Timestamp=datetime(2020, 1, 1),
        )["ShardIterator"]

        record = kinesis_client.get_records(ShardIterator=shard_iterator)["Records"][0]

        partition_key = record["PartitionKey"]
        data = json.loads(record["Data"].decode())

        self.assertEqual(TEST_EVENT_PATTERN["detail-type"][0], partition_key)
        self.assertEqual(EVENT_DETAIL, data["detail"])
        self.assertIsValidEvent(data)

    def test_put_events_with_input_path(self):
        queue_name = "queue-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        sqs_client = aws_stack.create_external_boto_client("sqs")
        queue_url = sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        self.events_client.create_event_bus(Name=bus_name)
        self.events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        self.events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"}],
        )

        self.events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["Source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(TEST_EVENT_PATTERN["Detail"][0]),
                }
            ]
        )

        def get_message(queue_url):
            resp = sqs_client.receive_message(QueueUrl=queue_url)
            return resp.get("Messages")

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        self.assertEqual(1, len(messages))
        self.assertEqual(EVENT_DETAIL, json.loads(messages[0].get("Body")))

        self.events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": "dummySource",
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(TEST_EVENT_PATTERN["Detail"][0]),
                }
            ]
        )

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        self.assertIsNone(messages)

        # clean up
        self.cleanup(bus_name, rule_name, target_id, queue_url=queue_url)

    def test_put_events_with_input_path_multiple(self):
        queue_name = "queue-{}".format(short_uid())
        queue_name_1 = "queue-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        target_id_1 = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        sqs_client = aws_stack.create_external_boto_client("sqs")
        queue_url = sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        queue_url_1 = sqs_client.create_queue(QueueName=queue_name_1)["QueueUrl"]
        queue_arn_1 = aws_stack.sqs_queue_arn(queue_name_1)

        self.events_client.create_event_bus(Name=bus_name)

        self.events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        self.events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[
                {"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"},
                {
                    "Id": target_id_1,
                    "Arn": queue_arn_1,
                },
            ],
        )

        self.events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["Source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(TEST_EVENT_PATTERN["Detail"][0]),
                }
            ]
        )

        def get_message(queue_url):
            resp = sqs_client.receive_message(QueueUrl=queue_url)
            return resp.get("Messages")

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        self.assertEqual(1, len(messages))
        self.assertEqual(EVENT_DETAIL, json.loads(messages[0].get("Body")))

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url_1)
        self.assertEqual(1, len(messages))
        self.assertEqual(EVENT_DETAIL, json.loads(messages[0].get("Body")).get("detail"))

        self.events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": "dummySource",
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(TEST_EVENT_PATTERN["Detail"][0]),
                }
            ]
        )

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        self.assertIsNone(messages)

        # clean up
        self.cleanup(bus_name, rule_name, target_id, queue_url=queue_url)

    def test_put_event_without_source(self):
        self.events_client = aws_stack.create_external_boto_client(
            "events", region_name="eu-west-1"
        )

        response = self.events_client.put_events(Entries=[{"DetailType": "Test", "Detail": "{}"}])
        self.assertIn("Entries", response)

    def test_put_event_without_detail(self):
        self.events_client = aws_stack.create_external_boto_client(
            "events", region_name="eu-west-1"
        )

        response = self.events_client.put_events(
            Entries=[
                {
                    "DetailType": "Test",
                }
            ]
        )
        self.assertIn("Entries", response)

    def test_trigger_event_on_ssm_change(self):
        sqs = aws_stack.create_external_boto_client("sqs")
        ssm = aws_stack.create_external_boto_client("ssm")
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())

        # create queue
        queue_name = "queue-{}".format(short_uid())
        queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        # put rule listening on SSM changes
        ssm_prefix = "/test/local/"
        self.events_client.put_rule(
            Name=rule_name,
            EventPattern=json.dumps(
                {
                    "detail": {
                        "name": [{"prefix": ssm_prefix}],
                        "operation": ["Create", "Update", "Delete", "LabelParameterVersion"],
                    },
                    "detail-type": ["Parameter Store Change"],
                    "source": ["aws.ssm"],
                }
            ),
            State="ENABLED",
            Description="Trigger on SSM parameter changes",
        )

        # put target
        self.events_client.put_targets(
            Rule=rule_name,
            EventBusName=TEST_EVENT_BUS_NAME,
            Targets=[{"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"}],
        )

        # change SSM param to trigger event
        ssm.put_parameter(Name=f"{ssm_prefix}/test123", Value="value1", Type="String")

        def assert_message():
            resp = sqs.receive_message(QueueUrl=queue_url)
            result = resp.get("Messages")
            body = json.loads(result[0]["Body"])
            assert body == {"name": "/test/local/test123", "operation": "Create"}

        # assert that message has been received
        retry(assert_message, retries=7, sleep=0.3)

        # clean up
        self.cleanup(rule_name=rule_name, target_ids=target_id)

    def test_put_event_with_content_base_rule_in_pattern(self):
        queue_name = "queue-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())

        sqs_client = aws_stack.create_external_boto_client("sqs")
        queue_url = sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        pattern = {
            "Source": [{"exists": True}],
            "detail-type": [{"prefix": "core.app"}],
            "Detail": {
                "decription": ["this-is-event-details"],
                "amount": [200],
                "salary": [2000, 4000],
                "env": ["dev", "prod"],
                "user": ["user1", "user2", "user3"],
                "admins": ["skyli", {"prefix": "hey"}, {"prefix": "ad"}],
                "test1": [{"anything-but": 200}],
                "test2": [{"anything-but": "test2"}],
                "test3": [{"anything-but": ["test3", "test33"]}],
                "test4": [{"anything-but": {"prefix": "test4"}}],
                "ip": [{"cidr": "10.102.1.0/24"}],
                "num-test1": [{"numeric": ["<", 200]}],
                "num-test2": [{"numeric": ["<=", 200]}],
                "num-test3": [{"numeric": [">", 200]}],
                "num-test4": [{"numeric": [">=", 200]}],
                "num-test5": [{"numeric": [">=", 200, "<=", 500]}],
                "num-test6": [{"numeric": [">", 200, "<", 500]}],
                "num-test7": [{"numeric": [">=", 200, "<", 500]}],
            },
        }

        event = {
            "EventBusName": TEST_EVENT_BUS_NAME,
            "Source": "core.update-account-command",
            "DetailType": "core.app.backend",
            "Detail": json.dumps(
                {
                    "decription": "this-is-event-details",
                    "amount": 200,
                    "salary": 2000,
                    "env": "prod",
                    "user": "user3",
                    "admins": "admin",
                    "test1": 300,
                    "test2": "test22",
                    "test3": "test333",
                    "test4": "this test4",
                    "ip": "10.102.1.100",
                    "num-test1": 100,
                    "num-test2": 200,
                    "num-test3": 300,
                    "num-test4": 200,
                    "num-test5": 500,
                    "num-test6": 300,
                    "num-test7": 300,
                }
            ),
        }

        self.events_client.create_event_bus(Name=TEST_EVENT_BUS_NAME)
        self.events_client.put_rule(
            Name=rule_name,
            EventBusName=TEST_EVENT_BUS_NAME,
            EventPattern=json.dumps(pattern),
        )

        self.events_client.put_targets(
            Rule=rule_name,
            EventBusName=TEST_EVENT_BUS_NAME,
            Targets=[{"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"}],
        )
        self.events_client.put_events(Entries=[event])

        def get_message(queue_url):
            resp = sqs_client.receive_message(QueueUrl=queue_url)
            return resp.get("Messages")

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        self.assertEqual(1, len(messages))
        self.assertEqual(json.loads(event["Detail"]), json.loads(messages[0].get("Body")))
        event_details = json.loads(event["Detail"])
        event_details["admins"] = "no"
        event["Detail"] = json.dumps(event_details)

        self.events_client.put_events(Entries=[event])

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        self.assertIsNone(messages)

        # clean up
        self.cleanup(TEST_EVENT_BUS_NAME, rule_name, target_id, queue_url=queue_url)

    def cleanup(self, bus_name=None, rule_name=None, target_ids=None, queue_url=None):
        kwargs = {"EventBusName": bus_name} if bus_name else {}
        if target_ids:
            target_ids = target_ids if isinstance(target_ids, list) else [target_ids]
            self.events_client.remove_targets(Rule=rule_name, Ids=target_ids, Force=True, **kwargs)
        if rule_name:
            self.events_client.delete_rule(Name=rule_name, Force=True, **kwargs)
        if bus_name:
            self.events_client.delete_event_bus(Name=bus_name)
        if queue_url:
            sqs_client = aws_stack.create_external_boto_client("sqs")
            sqs_client.delete_queue(QueueUrl=queue_url)

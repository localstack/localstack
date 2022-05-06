# -*- coding: utf-8 -*-
import base64
import json
import os
import uuid
from datetime import datetime
from typing import Dict, List, Tuple

import pytest

from localstack import config
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON36
from localstack.services.events.provider import _get_events_tmp_dir
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

EVENT_DETAIL = {"command": "update-account", "payload": {"acc_id": "0a787ecb-4015", "sf_id": "baz"}}
TEST_EVENT_PATTERN = {
    "source": ["core.update-account-command"],
    "detail-type": ["core.update-account-command"],
    "detail": {"command": ["update-account"]},
}


class TestEvents:
    def assert_valid_event(self, event):
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
            assert field in event

    def test_put_rule(self, events_client):
        rule_name = "rule-{}".format(short_uid())

        events_client.put_rule(Name=rule_name, EventPattern=json.dumps(TEST_EVENT_PATTERN))

        rules = events_client.list_rules(NamePrefix=rule_name)["Rules"]
        assert len(rules) == 1
        assert json.loads(rules[0]["EventPattern"]) == TEST_EVENT_PATTERN

        # clean up
        self.cleanup(rule_name=rule_name)

    def test_events_written_to_disk_are_timestamp_prefixed_for_chronological_ordering(
        self, events_client
    ):
        event_type = str(uuid.uuid4())
        event_details_to_publish = list(map(lambda n: f"event {n}", range(10)))

        for detail in event_details_to_publish:
            events_client.put_events(
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

        assert (
            list(map(lambda event: json.loads(event["Detail"]), sorted_events))
            == event_details_to_publish
        )

    def test_list_tags_for_resource(self, events_client):
        rule_name = "rule-{}".format(short_uid())

        rule = events_client.put_rule(Name=rule_name, EventPattern=json.dumps(TEST_EVENT_PATTERN))
        rule_arn = rule["RuleArn"]
        expected = [
            {"Key": "key1", "Value": "value1"},
            {"Key": "key2", "Value": "value2"},
        ]

        # insert two tags, verify both are visible
        events_client.tag_resource(ResourceARN=rule_arn, Tags=expected)
        actual = events_client.list_tags_for_resource(ResourceARN=rule_arn)["Tags"]
        assert actual == expected

        # remove 'key2', verify only 'key1' remains
        expected = [{"Key": "key1", "Value": "value1"}]
        events_client.untag_resource(ResourceARN=rule_arn, TagKeys=["key2"])
        actual = events_client.list_tags_for_resource(ResourceARN=rule_arn)["Tags"]
        assert actual == expected

        # clean up
        self.cleanup(rule_name=rule_name)

    @pytest.mark.aws_validated
    def test_put_events_with_target_sqs(self, events_client, sqs_client):
        entries = [
            {
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps(EVENT_DETAIL),
            }
        ]
        self._put_events_with_filter_to_sqs(
            events_client, sqs_client, pattern=TEST_EVENT_PATTERN, entries_asserts=[(entries, True)]
        )

    @pytest.mark.aws_validated
    def test_put_events_with_nested_event_pattern(self, events_client, sqs_client):
        pattern = {"detail": {"event": {"data": {"type": ["1"]}}}}
        entries1 = [
            {
                "Source": "test",
                "DetailType": "test",
                "Detail": json.dumps({"event": {"data": {"type": "1"}}}),
            }
        ]
        entries2 = [
            {
                "Source": "test",
                "DetailType": "test",
                "Detail": json.dumps({"event": {"data": {"type": "2"}}}),
            }
        ]
        entries3 = [
            {
                "Source": "test",
                "DetailType": "test",
                "Detail": json.dumps({"hello": "world"}),
            }
        ]
        entries_asserts = [(entries1, True), (entries2, False), (entries3, False)]
        self._put_events_with_filter_to_sqs(
            events_client,
            sqs_client,
            pattern=pattern,
            entries_asserts=entries_asserts,
            input_path="$.detail",
        )

    def test_put_events_with_target_sqs_event_detail_match(self, events_client, sqs_client):
        entries1 = [
            {
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps({"EventType": "1"}),
            }
        ]
        entries2 = [
            {
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps({"EventType": "2"}),
            }
        ]
        entries_asserts = [(entries1, True), (entries2, False)]
        self._put_events_with_filter_to_sqs(
            events_client,
            sqs_client,
            pattern={"detail": {"EventType": ["0", "1"]}},
            entries_asserts=entries_asserts,
            input_path="$.detail",
        )

    def _put_events_with_filter_to_sqs(
        self,
        events_client,
        sqs_client,
        pattern: Dict,
        entries_asserts: List[Tuple[List[Dict], bool]],
        input_path: str = None,
    ):
        queue_name = f"queue-{short_uid()}"
        rule_name = f"rule-{short_uid()}"
        target_id = f"target-{short_uid()}"
        bus_name = f"bus-{short_uid()}"

        queue_url = sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = self._get_queue_arn(queue_url, sqs_client)
        policy = {
            "Version": "2012-10-17",
            "Id": f"sqs-eventbridge-{short_uid()}",
            "Statement": [
                {
                    "Sid": f"SendMessage-{short_uid()}",
                    "Effect": "Allow",
                    "Principal": {"Service": "events.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn,
                }
            ],
        }
        sqs_client.set_queue_attributes(
            QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)}
        )

        events_client.create_event_bus(Name=bus_name)
        events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(pattern),
        )
        kwargs = {"InputPath": input_path} if input_path else {}
        rs = events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": queue_arn, **kwargs}],
        )

        assert rs["FailedEntryCount"] == 0
        assert rs["FailedEntries"] == []

        try:
            for entry_asserts in entries_asserts:
                entries = entry_asserts[0]
                for entry in entries:
                    entry.setdefault("EventBusName", bus_name)
                self._put_entries_assert_results_sqs(
                    events_client,
                    sqs_client,
                    queue_url,
                    entries=entries,
                    should_match=entry_asserts[1],
                )
        finally:
            self.cleanup(
                bus_name,
                rule_name,
                target_id,
                queue_url=queue_url,
                events_client=events_client,
                sqs_client=sqs_client,
            )

    def _put_entries_assert_results_sqs(
        self, events_client, sqs_client, queue_url: str, entries: List[Dict], should_match: bool
    ):
        response = events_client.put_events(Entries=entries)
        assert not response.get("FailedEntryCount")

        def get_message(queue_url):
            resp = sqs_client.receive_message(QueueUrl=queue_url)
            messages = resp.get("Messages")
            if should_match:
                assert len(messages) == 1
            return messages

        messages = retry(get_message, retries=5, sleep=1, queue_url=queue_url)

        if should_match:
            actual_event = json.loads(messages[0]["Body"])
            if "detail" in actual_event:
                self.assert_valid_event(actual_event)
        else:
            assert not messages

        return messages

    # TODO: further unify/parameterize the tests for the different target types below

    def test_put_events_with_target_sns(
        self, events_client, sns_client, sqs_client, sns_subscription
    ):
        queue_name = "test-%s" % short_uid()
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        topic_name = "topic-{}".format(short_uid())
        topic_arn = sns_client.create_topic(Name=topic_name)["TopicArn"]

        queue_url = sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        sns_subscription(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

        events_client.create_event_bus(Name=bus_name)
        events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        rs = events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": topic_arn}],
        )

        assert "FailedEntryCount" in rs
        assert "FailedEntries" in rs
        assert rs["FailedEntryCount"] == 0
        assert rs["FailedEntries"] == []

        events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(EVENT_DETAIL),
                }
            ]
        )

        def get_message(queue_url):
            resp = sqs_client.receive_message(QueueUrl=queue_url)
            return resp["Messages"]

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        assert len(messages) == 1

        actual_event = json.loads(messages[0]["Body"]).get("Message")
        self.assert_valid_event(actual_event)
        assert json.loads(actual_event).get("detail") == EVENT_DETAIL

        # clean up
        sns_client.delete_topic(TopicArn=topic_arn)
        self.cleanup(bus_name, rule_name, target_id, queue_url=queue_url)

    def test_put_events_into_event_bus(self, events_client, sqs_client):
        queue_name = "queue-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name_1 = "bus1-{}".format(short_uid())
        bus_name_2 = "bus2-{}".format(short_uid())

        queue_url = sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = self._get_queue_arn(queue_url, sqs_client)

        events_client.create_event_bus(Name=bus_name_1)
        resp = events_client.create_event_bus(Name=bus_name_2)
        events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name_1,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name_1,
            Targets=[{"Id": target_id, "Arn": resp.get("EventBusArn")}],
        )
        events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name_2,
            Targets=[{"Id": target_id, "Arn": queue_arn}],
        )

        events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name_1,
                    "Source": TEST_EVENT_PATTERN["source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(EVENT_DETAIL),
                }
            ]
        )

        def get_message(queue_url):
            resp = sqs_client.receive_message(QueueUrl=queue_url)
            return resp["Messages"]

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        assert len(messages) == 1

        actual_event = json.loads(messages[0]["Body"])
        self.assert_valid_event(actual_event)
        assert actual_event["detail"] == EVENT_DETAIL

        # clean up
        self.cleanup(bus_name_1, rule_name, target_id)
        self.cleanup(bus_name_2)
        sqs_client.delete_queue(QueueUrl=queue_url)

    def test_put_events_with_target_lambda(self, events_client):
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

        events_client.create_event_bus(Name=bus_name)
        events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        rs = events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": func_arn}],
        )

        assert "FailedEntryCount" in rs
        assert "FailedEntries" in rs
        assert rs["FailedEntryCount"] == 0
        assert rs["FailedEntries"] == []

        events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(EVENT_DETAIL),
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
        self.assert_valid_event(actual_event)
        assert actual_event["detail"] == EVENT_DETAIL

        # clean up
        testutil.delete_lambda_function(function_name)
        self.cleanup(bus_name, rule_name, target_id)

    def test_rule_disable(self, events_client):
        rule_name = "rule-{}".format(short_uid())
        events_client.put_rule(Name=rule_name, ScheduleExpression="rate(1 minutes)")

        response = events_client.list_rules()
        assert response["Rules"][0]["State"] == "ENABLED"
        events_client.disable_rule(Name=rule_name)
        response = events_client.list_rules(NamePrefix=rule_name)
        assert response["Rules"][0]["State"] == "DISABLED"

        # clean up
        self.cleanup(rule_name=rule_name)

    def test_scheduled_expression_events(
        self, stepfunctions_client, sns_client, sqs_client, events_client, sns_subscription
    ):
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

        state_machine_arn = stepfunctions_client.create_state_machine(
            name=sm_name, definition=state_machine_definition, roleArn=sm_role_arn
        )["stateMachineArn"]

        topic_arn = sns_client.create_topic(Name=topic_name)["TopicArn"]
        sns_subscription(TopicArn=topic_arn, Protocol="http", Endpoint=endpoint)

        queue_url = sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        fifo_queue_url = sqs_client.create_queue(
            QueueName=fifo_queue_name,
            Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        )["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)
        fifo_queue_arn = aws_stack.sqs_queue_arn(fifo_queue_name)

        event = {"env": "testing"}

        events_client.put_rule(Name=rule_name, ScheduleExpression="rate(1 minutes)")

        events_client.put_targets(
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
            executions = stepfunctions_client.list_executions(stateMachineArn=state_machine_arn)[
                "executions"
            ]
            assert len(executions) >= 1

            # http endpoint got events
            assert len(events) >= 2
            notifications = [
                event["Message"] for event in events if event["Type"] == "Notification"
            ]
            assert len(notifications) >= 1

            # get state machine execution detail
            execution_arn = executions[0]["executionArn"]
            execution_input = stepfunctions_client.describe_execution(executionArn=execution_arn)[
                "input"
            ]

            all_msgs = []
            # get message from queue
            for url in q_urls:
                msgs = sqs_client.receive_message(QueueUrl=url).get("Messages", [])
                assert len(msgs) >= 1
                all_msgs.append(msgs[0])

            return execution_input, notifications[0], all_msgs

        execution_input, notification, msgs_received = retry(
            received, retries=5, sleep=15, q_urls=[queue_url, fifo_queue_url]
        )
        assert json.loads(notification) == event
        assert json.loads(execution_input) == event
        for msg_received in msgs_received:
            assert json.loads(msg_received["Body"]) == event

        # clean up
        proxy.stop()
        target_ids = [topic_target_id, sm_target_id, queue_target_id, fifo_queue_target_id]
        self.cleanup(None, rule_name, target_ids=target_ids, queue_url=queue_url)
        sns_client.delete_topic(TopicArn=topic_arn)
        stepfunctions_client.delete_state_machine(stateMachineArn=state_machine_arn)

    def test_api_destinations(self, events_client):

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

                if headers.get("target_header"):
                    headers_list.append(headers.get("target_header"))

                if "client_id" in event:
                    oauth_data.update(
                        {
                            "client_id": event.get("client_id"),
                            "client_secret": event.get("client_secret"),
                            "header_value": headers.get("oauthheader"),
                            "body_value": event.get("oauthbody"),
                            "path": path,
                        }
                    )

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
        oauth_data = {}

        local_port = get_free_tcp_port()
        proxy = start_proxy(local_port, update_listener=HttpEndpointListener())
        wait_for_port_open(local_port)
        url = f"http://localhost:{local_port}"

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
                    "OAuthHttpParameters": {
                        "BodyParameters": [{"Key": "oauthbody", "Value": "value1"}],
                        "HeaderParameters": [{"Key": "oauthheader", "Value": "value2"}],
                        "QueryStringParameters": [{"Key": "oauthquery", "Value": "value3"}],
                    },
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
            result = events_client.create_api_destination(
                Name=dest_name,
                ConnectionArn=connection_arn,
                InvocationEndpoint=url,
                HttpMethod="POST",
            )

            # create rule and target
            rule_name = "r-%s" % short_uid()
            target_id = "target-{}".format(short_uid())
            pattern = json.dumps({"source": ["source-123"], "detail-type": ["type-123"]})
            events_client.put_rule(Name=rule_name, EventPattern=pattern)
            events_client.put_targets(
                Rule=rule_name,
                Targets=[
                    {
                        "Id": target_id,
                        "Arn": result["ApiDestinationArn"],
                        "Input": '{"target_value":"value"}',
                        "HttpParameters": {
                            "PathParameterValues": ["target_path"],
                            "HeaderParameters": {"target_header": "target_header_value"},
                            "QueryStringParameters": {"target_query": "t_query"},
                        },
                    }
                ],
            )

            entries = [
                {
                    "Source": "source-123",
                    "DetailType": "type-123",
                    "Detail": '{"i": %s}' % 0,
                }
            ]
            events_client.put_events(Entries=entries)

            # clean up
            events_client.delete_connection(Name=connection_name)
            events_client.delete_api_destination(Name=dest_name)
            self.cleanup(rule_name=rule_name, target_ids=target_id)

        # assert that all events have been received in the HTTP server listener

        def check():
            assert len(events) >= len(auth_types)
            assert "key" in paths_list[0] and "value" in paths_list[0]
            assert "target_query" in paths_list[0] and "t_query" in paths_list[0]
            assert "target_path" in paths_list[0]
            assert events[0].get("key") == "value"
            assert events[0].get("target_value") == "value"

            assert oauth_data.get("client_id") == "id"
            assert oauth_data.get("client_secret") == "password"
            assert oauth_data.get("header_value") == "value2"
            assert oauth_data.get("body_value") == "value1"
            assert "oauthquery" in oauth_data.get("path")
            assert "value3" in oauth_data.get("path")

            user_pass = to_str(base64.b64encode(b"user:pass"))
            assert f"Basic {user_pass}" in headers_list
            assert "apikey_secret" in headers_list
            assert bearer in headers_list
            assert "target_header_value" in headers_list

        retry(check, sleep=0.5, retries=5)

        # clean up
        proxy.stop()

    def test_put_events_with_target_firehose(self, events_client, s3_client, firehose_client):
        s3_bucket = "s3-{}".format(short_uid())
        s3_prefix = "testeventdata"
        stream_name = "firehose-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        # create firehose target bucket
        aws_stack.get_or_create_bucket(s3_bucket)

        # create firehose delivery stream to s3
        stream = firehose_client.create_delivery_stream(
            DeliveryStreamName=stream_name,
            S3DestinationConfiguration={
                "RoleARN": aws_stack.iam_resource_arn("firehose"),
                "BucketARN": aws_stack.s3_bucket_arn(s3_bucket),
                "Prefix": s3_prefix,
            },
        )
        stream_arn = stream["DeliveryStreamARN"]

        events_client.create_event_bus(Name=bus_name)
        events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        rs = events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": stream_arn}],
        )

        assert "FailedEntryCount" in rs
        assert "FailedEntries" in rs
        assert rs["FailedEntryCount"] == 0
        assert rs["FailedEntries"] == []

        events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(EVENT_DETAIL),
                }
            ]
        )

        # run tests
        bucket_contents = s3_client.list_objects(Bucket=s3_bucket)["Contents"]
        assert len(bucket_contents) == 1
        key = bucket_contents[0]["Key"]
        s3_object = s3_client.get_object(Bucket=s3_bucket, Key=key)
        actual_event = json.loads(s3_object["Body"].read().decode())
        self.assert_valid_event(actual_event)
        assert actual_event["detail"] == EVENT_DETAIL

        # clean up
        firehose_client.delete_delivery_stream(DeliveryStreamName=stream_name)
        # empty and delete bucket
        s3_client.delete_object(Bucket=s3_bucket, Key=key)
        s3_client.delete_bucket(Bucket=s3_bucket)
        self.cleanup(bus_name, rule_name, target_id)

    def test_put_events_with_target_sqs_new_region(self):
        events_client = aws_stack.create_external_boto_client("events", region_name="eu-west-1")
        queue_name = "queue-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        sqs_client = aws_stack.create_external_boto_client("sqs", region_name="eu-west-1")
        sqs_client.create_queue(QueueName=queue_name)
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        events_client.create_event_bus(Name=bus_name)

        events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": queue_arn}],
        )

        response = events_client.put_events(
            Entries=[
                {
                    "Source": "com.mycompany.myapp",
                    "Detail": '{ "key1": "value1", "key": "value2" }',
                    "Resources": [],
                    "DetailType": "myDetailType",
                }
            ]
        )
        assert "Entries" in response
        assert len(response.get("Entries")) == 1
        assert "EventId" in response.get("Entries")[0]

    def test_put_events_with_target_kinesis(self, events_client, kinesis_client):
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())
        stream_name = "stream-{}".format(short_uid())
        stream_arn = aws_stack.kinesis_stream_arn(stream_name)

        kinesis_client.create_stream(StreamName=stream_name, ShardCount=1)

        events_client.create_event_bus(Name=bus_name)

        events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        put_response = events_client.put_targets(
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

        assert "FailedEntryCount" in put_response
        assert "FailedEntries" in put_response
        assert put_response["FailedEntryCount"] == 0
        assert put_response["FailedEntries"] == []

        def check_stream_status():
            _stream = kinesis_client.describe_stream(StreamName=stream_name)
            assert _stream["StreamDescription"]["StreamStatus"] == "ACTIVE"

        # wait until stream becomes available
        retry(check_stream_status, retries=7, sleep=0.8)

        events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(EVENT_DETAIL),
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

        assert partition_key == TEST_EVENT_PATTERN["detail-type"][0]
        assert data["detail"] == EVENT_DETAIL
        self.assert_valid_event(data)

    def test_put_events_with_input_path(self, events_client, sqs_client):
        queue_name = f"queue-{short_uid()}"
        rule_name = f"rule-{short_uid()}"
        target_id = f"target-{short_uid()}"
        bus_name = f"bus-{short_uid()}"

        queue_url = sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        events_client.create_event_bus(Name=bus_name)
        events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"}],
        )

        events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(EVENT_DETAIL),
                }
            ]
        )

        def get_message(queue_url):
            resp = sqs_client.receive_message(QueueUrl=queue_url)
            return resp.get("Messages")

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        assert len(messages) == 1
        assert json.loads(messages[0].get("Body")) == EVENT_DETAIL

        events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": "dummySource",
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(EVENT_DETAIL),
                }
            ]
        )

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        assert messages is None

        # clean up
        self.cleanup(bus_name, rule_name, target_id, queue_url=queue_url)

    def test_put_events_with_input_path_multiple(self, events_client, sqs_client):
        queue_name = "queue-{}".format(short_uid())
        queue_name_1 = "queue-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        target_id_1 = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        queue_url = sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        queue_url_1 = sqs_client.create_queue(QueueName=queue_name_1)["QueueUrl"]
        queue_arn_1 = aws_stack.sqs_queue_arn(queue_name_1)

        events_client.create_event_bus(Name=bus_name)

        events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        events_client.put_targets(
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

        events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(EVENT_DETAIL),
                }
            ]
        )

        def get_message(queue_url):
            resp = sqs_client.receive_message(QueueUrl=queue_url)
            return resp.get("Messages")

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        assert len(messages) == 1
        assert json.loads(messages[0].get("Body")) == EVENT_DETAIL

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url_1)
        assert len(messages) == 1
        assert json.loads(messages[0].get("Body")).get("detail") == EVENT_DETAIL

        events_client.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": "dummySource",
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(EVENT_DETAIL),
                }
            ]
        )

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        assert messages is None

        # clean up
        self.cleanup(bus_name, rule_name, [target_id, target_id_1], queue_url=queue_url)

    def test_put_event_without_source(self):
        events_client = aws_stack.create_external_boto_client("events", region_name="eu-west-1")

        response = events_client.put_events(Entries=[{"DetailType": "Test", "Detail": "{}"}])
        assert response.get("Entries")

    def test_put_event_without_detail(self):
        events_client = aws_stack.create_external_boto_client("events", region_name="eu-west-1")

        response = events_client.put_events(
            Entries=[
                {
                    "DetailType": "Test",
                }
            ]
        )
        assert response.get("Entries")

    def test_trigger_event_on_ssm_change(self, events_client, sqs_client, ssm_client):
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())

        # create queue
        queue_name = "queue-{}".format(short_uid())
        queue_url = sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        # put rule listening on SSM changes
        ssm_prefix = "/test/local/"
        events_client.put_rule(
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
        events_client.put_targets(
            Rule=rule_name,
            EventBusName=TEST_EVENT_BUS_NAME,
            Targets=[{"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"}],
        )

        # change SSM param to trigger event
        ssm_client.put_parameter(Name=f"{ssm_prefix}/test123", Value="value1", Type="String")

        def assert_message():
            resp = sqs_client.receive_message(QueueUrl=queue_url)
            result = resp.get("Messages")
            body = json.loads(result[0]["Body"])
            assert body == {"name": "/test/local/test123", "operation": "Create"}

        # assert that message has been received
        retry(assert_message, retries=7, sleep=0.3)

        # clean up
        self.cleanup(rule_name=rule_name, target_ids=target_id)

    def test_put_event_with_content_base_rule_in_pattern(self, events_client, sqs_client):
        queue_name = f"queue-{short_uid()}"
        rule_name = f"rule-{short_uid()}"
        target_id = f"target-{short_uid()}"

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

        events_client.create_event_bus(Name=TEST_EVENT_BUS_NAME)
        events_client.put_rule(
            Name=rule_name,
            EventBusName=TEST_EVENT_BUS_NAME,
            EventPattern=json.dumps(pattern),
        )

        events_client.put_targets(
            Rule=rule_name,
            EventBusName=TEST_EVENT_BUS_NAME,
            Targets=[{"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"}],
        )
        events_client.put_events(Entries=[event])

        def get_message(queue_url):
            resp = sqs_client.receive_message(QueueUrl=queue_url)
            return resp.get("Messages")

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        assert len(messages) == 1
        assert json.loads(messages[0].get("Body")) == json.loads(event["Detail"])
        event_details = json.loads(event["Detail"])
        event_details["admins"] = "no"
        event["Detail"] = json.dumps(event_details)

        events_client.put_events(Entries=[event])

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        assert messages is None

        # clean up
        self.cleanup(TEST_EVENT_BUS_NAME, rule_name, target_id, queue_url=queue_url)

    def _get_queue_arn(self, queue_url, sqs_client):
        queue_attrs = sqs_client.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )
        return queue_attrs["Attributes"]["QueueArn"]

    def cleanup(
        self,
        bus_name=None,
        rule_name=None,
        target_ids=None,
        queue_url=None,
        events_client=None,
        sqs_client=None,
    ):
        events_client = events_client or aws_stack.create_external_boto_client("events")
        kwargs = {"EventBusName": bus_name} if bus_name else {}
        if target_ids:
            target_ids = target_ids if isinstance(target_ids, list) else [target_ids]
            events_client.remove_targets(Rule=rule_name, Ids=target_ids, Force=True, **kwargs)
        if rule_name:
            events_client.delete_rule(Name=rule_name, Force=True, **kwargs)
        if bus_name:
            events_client.delete_event_bus(Name=bus_name)
        if queue_url:
            sqs_client = sqs_client or aws_stack.create_external_boto_client("sqs")
            sqs_client.delete_queue(QueueUrl=queue_url)

# -*- coding: utf-8 -*-
import base64
import json
import os
import time
import uuid
from datetime import datetime
from typing import Dict, List, Tuple

import pytest
from botocore.exceptions import ClientError

from localstack import config
from localstack.aws.api.lambda_ import Runtime
from localstack.services.apigateway.helpers import extract_query_string_params
from localstack.services.events.provider import _get_events_tmp_dir
from localstack.services.generic_proxy import ProxyListener
from localstack.services.infra import start_proxy
from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.aws import arns, aws_stack, resources
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
from localstack.utils.sync import poll_condition
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

API_DESTINATION_AUTHS = [
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
            "AuthorizationEndpoint": "replace_this",
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

EVENT_BUS_ROLE = {
    "Statement": {
        "Sid": "",
        "Effect": "Allow",
        "Principal": {"Service": "events.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }
}


@pytest.fixture
def events_allow_event_rule_to_sqs_queue(sqs_client):
    def _allow_event_rule(sqs_queue_url, sqs_queue_arn, event_rule_arn) -> None:
        # allow event rule to write to sqs queue
        sqs_client.set_queue_attributes(
            QueueUrl=sqs_queue_url,
            Attributes={
                "Policy": json.dumps(
                    {
                        "Statement": [
                            {
                                "Sid": "AllowEventsToQueue",
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": sqs_queue_arn,
                                "Condition": {"ArnEquals": {"aws:SourceArn": event_rule_arn}},
                            }
                        ]
                    }
                )
            },
        )

    return _allow_event_rule


@pytest.fixture
def events_put_rule(events_client):
    rules = []

    def _factory(**kwargs):
        if "Name" not in kwargs:
            kwargs["Name"] = f"rule-{short_uid()}"

        resp = events_client.put_rule(**kwargs)
        rules.append((kwargs["Name"], kwargs.get("EventBusName", "default")))
        return resp

    yield _factory

    for rule, event_bus_name in rules:
        targets_response = events_client.list_targets_by_rule(
            Rule=rule, EventBusName=event_bus_name
        )
        if targets := targets_response["Targets"]:
            targets_ids = [target["Id"] for target in targets]
            events_client.remove_targets(Rule=rule, EventBusName=event_bus_name, Ids=targets_ids)
        events_client.delete_rule(Name=rule, EventBusName=event_bus_name)


@pytest.fixture
def events_create_event_bus(events_client):
    event_buses = []

    def _factory(**kwargs):
        if "Name" not in kwargs:
            kwargs["Name"] = f"event-bus-{short_uid()}"
        resp = events_client.create_event_bus(**kwargs)
        event_buses.append(kwargs["Name"])
        return resp

    yield _factory

    for event_bus in event_buses:
        events_client.delete_event_bus(Name=event_bus)


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
        rule_name = f"rule-{short_uid()}"

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
        queue_arn = arns.sqs_queue_arn(queue_name)

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

    def test_put_events_with_target_lambda(
        self, events_client, lambda_client, create_lambda_function, cleanups
    ):
        rule_name = f"rule-{short_uid()}"
        function_name = f"lambda-func-{short_uid()}"
        target_id = f"target-{short_uid()}"
        bus_name = f"bus-{short_uid()}"

        # clean up
        cleanups.append(lambda: lambda_client.delete_function(FunctionName=function_name))
        cleanups.append(lambda: self.cleanup(bus_name, rule_name, target_id))

        rs = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
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
        sm_role_arn = arns.role_arn("sfn_role")
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
        queue_arn = arns.sqs_queue_arn(queue_name)
        fifo_queue_arn = arns.sqs_queue_arn(fifo_queue_name)

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

    @pytest.mark.parametrize("auth", API_DESTINATION_AUTHS)
    def test_api_destinations(self, events_client, auth):
        token = short_uid()
        bearer = f"Bearer {token}"

        class HttpEndpointListener(ProxyListener):
            def forward_request(self, method, path, data, headers):
                event = json.loads(to_str(data))
                data_received.update(event)

                request_split = extract_query_string_params(path)
                paths_list.append(request_split[0])
                query_params_received.update(request_split[1])

                headers_received.update(headers)

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

        data_received = {}
        query_params_received = {}
        paths_list = []
        headers_received = {}
        oauth_data = {}

        local_port = get_free_tcp_port()
        proxy = start_proxy(local_port, update_listener=HttpEndpointListener())
        wait_for_port_open(local_port)
        url = f"http://localhost:{local_port}"

        if auth.get("type") == "OAUTH_CLIENT_CREDENTIALS":
            auth["parameters"]["AuthorizationEndpoint"] = url

        connection_name = f"c-{short_uid()}"
        connection_arn = events_client.create_connection(
            Name=connection_name,
            AuthorizationType=auth.get("type"),
            AuthParameters={
                auth.get("key"): auth.get("parameters"),
                "InvocationHttpParameters": {
                    "BodyParameters": [
                        {
                            "Key": "connection_body_param",
                            "Value": "value",
                            "IsValueSecret": False,
                        },
                    ],
                    "HeaderParameters": [
                        {
                            "Key": "connection_header_param",
                            "Value": "value",
                            "IsValueSecret": False,
                        },
                        {
                            "Key": "overwritten_header",
                            "Value": "original",
                            "IsValueSecret": False,
                        },
                    ],
                    "QueryStringParameters": [
                        {
                            "Key": "connection_query_param",
                            "Value": "value",
                            "IsValueSecret": False,
                        },
                        {
                            "Key": "overwritten_query",
                            "Value": "original",
                            "IsValueSecret": False,
                        },
                    ],
                },
            },
        )["ConnectionArn"]

        # create api destination
        dest_name = f"d-{short_uid()}"
        result = events_client.create_api_destination(
            Name=dest_name,
            ConnectionArn=connection_arn,
            InvocationEndpoint=url,
            HttpMethod="POST",
        )

        # create rule and target
        rule_name = f"r-{short_uid()}"
        target_id = f"target-{short_uid}"
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
                        "HeaderParameters": {
                            "target_header": "target_header_value",
                            "overwritten_header": "changed",
                        },
                        "QueryStringParameters": {
                            "target_query": "t_query",
                            "overwritten_query": "changed",
                        },
                    },
                }
            ],
        )

        entries = [
            {
                "Source": "source-123",
                "DetailType": "type-123",
                "Detail": '{"i": 0}',
            }
        ]
        events_client.put_events(Entries=entries)

        # clean up
        events_client.delete_connection(Name=connection_name)
        events_client.delete_api_destination(Name=dest_name)
        self.cleanup(rule_name=rule_name, target_ids=target_id)

        # assert that all events have been received in the HTTP server listener
        user_pass = to_str(base64.b64encode(b"user:pass"))

        def check():
            # Connection data validation
            assert data_received.get("connection_body_param") == "value"
            assert headers_received.get("Connection_Header_Param") == "value"
            assert query_params_received.get("connection_query_param") == "value"

            # Target parameters validation
            assert "/target_path" in paths_list
            assert data_received.get("target_value") == "value"
            assert headers_received.get("Target_Header") == "target_header_value"
            assert query_params_received.get("target_query") == "t_query"

            # connection/target overwrite test
            assert headers_received.get("Overwritten_Header") == "original"
            assert query_params_received.get("overwritten_query") == "original"

            # Auth validation
            if auth.get("type") == "BASIC":
                assert headers_received.get("Authorization") == f"Basic {user_pass}"
            if auth.get("type") == "API_KEY":
                assert headers_received.get("Api") == "apikey_secret"
            if auth.get("type") == "OAUTH_CLIENT_CREDENTIALS":
                assert headers_received.get("Authorization") == bearer

                # Oauth login validation
                assert oauth_data.get("client_id") == "id"
                assert oauth_data.get("client_secret") == "password"
                assert oauth_data.get("header_value") == "value2"
                assert oauth_data.get("body_value") == "value1"
                assert "oauthquery=value3" in oauth_data.get("path")

        retry(check, sleep=0.5, retries=5)

        # clean up
        proxy.stop()

    def test_create_connection_validations(self, events_client):
        connection_name = "This should fail with two errors 123467890123412341234123412341234"

        with pytest.raises(ClientError) as ctx:
            events_client.create_connection(
                Name=connection_name,
                AuthorizationType="INVALID",
                AuthParameters={"BasicAuthParameters": {"Username": "user", "Password": "pass"}},
            ),

        assert ctx.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
        assert ctx.value.response["Error"]["Code"] == "ValidationException"

        message = ctx.value.response["Error"]["Message"]
        assert "3 validation errors" in message
        assert "must satisfy regular expression pattern" in message
        assert "must have length less than or equal to 64" in message
        assert "must satisfy enum value set: [BASIC, OAUTH_CLIENT_CREDENTIALS, API_KEY]" in message

    def test_put_events_with_target_firehose(self, events_client, s3_client, firehose_client):
        s3_bucket = "s3-{}".format(short_uid())
        s3_prefix = "testeventdata"
        stream_name = "firehose-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        # create firehose target bucket
        resources.get_or_create_bucket(s3_bucket)

        # create firehose delivery stream to s3
        stream = firehose_client.create_delivery_stream(
            DeliveryStreamName=stream_name,
            S3DestinationConfiguration={
                "RoleARN": arns.iam_resource_arn("firehose"),
                "BucketARN": arns.s3_bucket_arn(s3_bucket),
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
        queue_arn = arns.sqs_queue_arn(queue_name)

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
        stream_arn = arns.kinesis_stream_arn(stream_name)

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
        queue_arn = arns.sqs_queue_arn(queue_name)

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
        queue_arn = arns.sqs_queue_arn(queue_name)

        queue_url_1 = sqs_client.create_queue(QueueName=queue_name_1)["QueueUrl"]
        queue_arn_1 = arns.sqs_queue_arn(queue_name_1)

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
        queue_arn = arns.sqs_queue_arn(queue_name)

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
        queue_arn = arns.sqs_queue_arn(queue_name)

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

    @pytest.mark.parametrize(
        "schedule_expression", ["rate(1 minute)", "rate(1 day)", "rate(1 hour)"]
    )
    @pytest.mark.aws_validated
    def test_create_rule_with_one_unit_in_singular_should_succeed(
        self, events_client, schedule_expression
    ):
        rule_name = f"rule-{short_uid()}"

        # rule should be creatable with given expression
        try:
            events_client.put_rule(Name=rule_name, ScheduleExpression=schedule_expression)
        finally:
            self.cleanup(rule_name=rule_name, events_client=events_client)

    @pytest.mark.parametrize(
        "schedule_expression", ["rate(1 minutes)", "rate(1 days)", "rate(1 hours)"]
    )
    @pytest.mark.aws_validated
    @pytest.mark.xfail
    def test_create_rule_with_one_unit_in_plural_should_fail(
        self, events_client, schedule_expression
    ):
        rule_name = f"rule-{short_uid()}"

        # rule should not be creatable with given expression
        with pytest.raises(ClientError):
            events_client.put_rule(Name=rule_name, ScheduleExpression=schedule_expression)

    @pytest.mark.aws_validated
    @pytest.mark.xfail
    def test_verify_rule_event_content(self, events_client, logs_client):
        log_group_name = f"/aws/events/testLogGroup-{short_uid()}"
        rule_name = f"rule-{short_uid()}"
        target_id = f"testRuleId-{short_uid()}"

        logs_client.create_log_group(logGroupName=log_group_name)
        log_groups = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)
        assert len(log_groups["logGroups"]) == 1
        log_group = log_groups["logGroups"][0]
        log_group_arn = log_group["arn"]

        events_client.put_rule(Name=rule_name, ScheduleExpression="rate(1 minute)")
        events_client.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": log_group_arn}])

        def ensure_log_stream_exists():
            streams = logs_client.describe_log_streams(logGroupName=log_group_name)
            return len(streams["logStreams"]) == 1

        poll_condition(condition=ensure_log_stream_exists, timeout=65, interval=5)

        log_streams = logs_client.describe_log_streams(logGroupName=log_group_name)
        log_stream_name = log_streams["logStreams"][0]["logStreamName"]

        log_content = logs_client.get_log_events(
            logGroupName=log_group_name, logStreamName=log_stream_name
        )
        events = log_content["events"]
        assert len(events) == 1
        event = events[0]

        self.assert_valid_event(event["message"])

        self.cleanup(
            rule_name=rule_name,
            target_ids=target_id,
            events_client=events_client,
            logs_client=logs_client,
            log_group_name=log_group_name,
        )

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=lambda: config.LEGACY_S3_PROVIDER, path="$..Messages..Body.detail.object.etag"
    )
    def test_put_events_to_default_eventbus_for_custom_eventbus(
        self,
        events_client,
        events_create_event_bus,
        events_put_rule,
        sqs_client,
        sqs_create_queue,
        sqs_queue_arn,
        create_role,
        create_policy,
        events_allow_event_rule_to_sqs_queue,
        s3_client,
        s3_bucket,
        snapshot,
        iam_client,
    ):
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.resource_name())
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("MD5OfBody"),
                snapshot.transform.jsonpath("$..detail.bucket.name", "bucket-name"),
                snapshot.transform.jsonpath("$..detail.object.key", "key-name"),
                snapshot.transform.jsonpath(
                    "$..detail.object.sequencer", "object-sequencer", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..detail.request-id", "request-id", reference_replacement=False
                ),
                snapshot.transform.jsonpath(
                    "$..detail.requester", "<requester>", reference_replacement=False
                ),
                snapshot.transform.jsonpath("$..detail.source-ip-address", "ip-address"),
            ]
        )
        default_bus_rule_name = f"test-default-bus-rule-{short_uid()}"
        custom_bus_rule_name = f"test-custom-bus-rule-{short_uid()}"
        default_bus_target_id = f"test-target-default-b-{short_uid()}"
        custom_bus_target_id = f"test-target-custom-b-{short_uid()}"
        custom_bus_name = f"test-eventbus-{short_uid()}"

        role = f"test-eventbus-role-{short_uid()}"
        policy_name = f"test-eventbus-role-policy-{short_uid()}"

        s3_client.put_bucket_notification_configuration(
            Bucket=s3_bucket, NotificationConfiguration={"EventBridgeConfiguration": {}}
        )

        queue_url = sqs_create_queue()
        queue_arn = sqs_queue_arn(queue_url)

        custom_event_bus = events_create_event_bus(Name=custom_bus_name)
        snapshot.match("create-custom-event-bus", custom_event_bus)
        custom_event_bus_arn = custom_event_bus["EventBusArn"]

        event_bus_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "events:PutEvents", "Resource": custom_event_bus_arn}
            ],
        }

        role_response = create_role(
            RoleName=role, AssumeRolePolicyDocument=json.dumps(EVENT_BUS_ROLE)
        )
        role_arn = role_response["Role"]["Arn"]
        policy_arn = create_policy(
            PolicyName=policy_name, PolicyDocument=json.dumps(event_bus_policy)
        )["Policy"]["Arn"]
        iam_client.attach_role_policy(RoleName=role, PolicyArn=policy_arn)
        if is_aws_cloud():
            # wait for the policy to be properly attached
            time.sleep(20)

        rule_on_default_bus = events_put_rule(
            Name=default_bus_rule_name,
            EventPattern='{"detail-type":["Object Created"],"source":["aws.s3"]}',
            State="ENABLED",
        )
        snapshot.match("create-rule-1", rule_on_default_bus)

        custom_bus_rule_event_pattern = {
            "detail": {
                "bucket": {"name": [s3_bucket]},
                "object": {"key": [{"prefix": "delivery/"}]},
            },
            "detail-type": ["Object Created"],
            "source": ["aws.s3"],
        }

        rule_on_custom_bus = events_put_rule(
            Name=custom_bus_rule_name,
            EventBusName=custom_bus_name,
            EventPattern=json.dumps(custom_bus_rule_event_pattern),
            State="ENABLED",
        )
        rule_on_custom_bus_arn = rule_on_custom_bus["RuleArn"]
        snapshot.match("create-rule-2", rule_on_custom_bus)

        events_allow_event_rule_to_sqs_queue(
            sqs_queue_url=queue_url, sqs_queue_arn=queue_arn, event_rule_arn=rule_on_custom_bus_arn
        )

        resp = events_client.put_targets(
            Rule=default_bus_rule_name,
            Targets=[
                {"Id": default_bus_target_id, "Arn": custom_event_bus_arn, "RoleArn": role_arn}
            ],
        )
        snapshot.match("put-target-1", resp)

        resp = events_client.put_targets(
            Rule=custom_bus_rule_name,
            EventBusName=custom_bus_name,
            Targets=[{"Id": custom_bus_target_id, "Arn": queue_arn}],
        )
        snapshot.match("put-target-2", resp)

        s3_client.put_object(Bucket=s3_bucket, Key="delivery/test.txt", Body=b"data")

        def get_message():
            recv_msg = sqs_client.receive_message(QueueUrl=queue_url, WaitTimeSeconds=5)
            return recv_msg["Messages"]

        retries = 20 if is_aws_cloud() else 3
        messages = retry(get_message, retries=retries, sleep=0.5)
        assert len(messages) == 1
        snapshot.match("get-events", {"Messages": messages})

        received_event = json.loads(messages[0]["Body"])

        self.assert_valid_event(received_event)

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
        log_group_name=None,
        logs_client=None,
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
        if log_group_name:
            logs_client = logs_client or aws_stack.create_external_boto_client("logs")
            log_streams = logs_client.describe_log_streams(logGroupName=log_group_name)
            for log_stream in log_streams["logStreams"]:
                logs_client.delete_log_stream(
                    logGroupName=log_group_name, logStreamName=log_stream["logStreamName"]
                )
            logs_client.delete_log_group(logGroupName=log_group_name)

import base64
import json
import os
import time
import uuid
from datetime import datetime
from typing import Dict, List, Tuple

import pytest
from botocore.exceptions import ClientError
from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

from localstack import config
from localstack.aws.api.lambda_ import Runtime
from localstack.constants import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME
from localstack.services.events.provider import _get_events_tmp_dir
from localstack.testing.aws.eventbus_utils import allow_event_rule_to_sqs_queue
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws import arns, resources
from localstack.utils.files import load_file
from localstack.utils.strings import long_uid, short_uid, to_str
from localstack.utils.sync import poll_condition, retry
from localstack.utils.testutil import check_expected_lambda_log_events_length
from tests.aws.services.lambda_.test_lambda import TEST_LAMBDA_PYTHON_ECHO

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

    @markers.aws.validated
    def test_put_rule(self, aws_client, snapshot, clean_up):
        rule_name = f"rule-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(rule_name, "<rule-name>"))

        response = aws_client.events.put_rule(
            Name=rule_name, EventPattern=json.dumps(TEST_EVENT_PATTERN)
        )
        snapshot.match("put-rule", response)

        response = aws_client.events.list_rules(NamePrefix=rule_name)
        snapshot.match("list-rules", response)
        rules = response["Rules"]
        assert len(rules) == 1
        assert json.loads(rules[0]["EventPattern"]) == TEST_EVENT_PATTERN

        # clean up
        clean_up(rule_name=rule_name)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "expression",
        [
            "rate(10 seconds)",
            "rate(10 years)",
            "rate(1 minutes)",
            "rate(1 hours)",
            "rate(1 days)",
            "rate(10 minute)",
            "rate(10 hour)",
            "rate(10 day)",
            "rate()",
            "rate(10)",
            "rate(10 minutess)",
            "rate(foo minutes)",
            "rate(0 minutes)",
            "rate(-10 minutes)",
            "rate(10 MINUTES)",
            "rate( 10 minutes )",
            " rate(10 minutes)",
        ],
    )
    def test_put_rule_invalid_rate_schedule_expression(self, expression, aws_client):
        with pytest.raises(ClientError) as e:
            aws_client.events.put_rule(Name=f"rule-{short_uid()}", ScheduleExpression=expression)

        assert e.value.response["Error"] == {
            "Code": "ValidationException",
            "Message": "Parameter ScheduleExpression is not valid.",
        }

    @markers.aws.unknown
    def test_events_written_to_disk_are_timestamp_prefixed_for_chronological_ordering(
        self, aws_client
    ):
        event_type = str(uuid.uuid4())
        event_details_to_publish = list(map(lambda n: f"event {n}", range(10)))

        for detail in event_details_to_publish:
            aws_client.events.put_events(
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

    @markers.aws.validated
    def test_list_tags_for_resource(self, aws_client, clean_up):
        rule_name = "rule-{}".format(short_uid())

        rule = aws_client.events.put_rule(
            Name=rule_name, EventPattern=json.dumps(TEST_EVENT_PATTERN)
        )
        rule_arn = rule["RuleArn"]
        expected = [
            {"Key": "key1", "Value": "value1"},
            {"Key": "key2", "Value": "value2"},
        ]

        # insert two tags, verify both are visible
        aws_client.events.tag_resource(ResourceARN=rule_arn, Tags=expected)
        actual = aws_client.events.list_tags_for_resource(ResourceARN=rule_arn)["Tags"]
        assert actual == expected

        # remove 'key2', verify only 'key1' remains
        expected = [{"Key": "key1", "Value": "value1"}]
        aws_client.events.untag_resource(ResourceARN=rule_arn, TagKeys=["key2"])
        actual = aws_client.events.list_tags_for_resource(ResourceARN=rule_arn)["Tags"]
        assert actual == expected

        # clean up
        clean_up(rule_name=rule_name)

    @markers.aws.validated
    def test_put_events_with_target_sqs(self, aws_client, put_events_with_filter_to_sqs):
        entries = [
            {
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps(EVENT_DETAIL),
            }
        ]
        put_events_with_filter_to_sqs(
            pattern=TEST_EVENT_PATTERN,
            entries_asserts=[(entries, True)],
        )

    @markers.aws.unknown
    def test_put_events_with_values_in_array(self, aws_client, put_events_with_filter_to_sqs):
        pattern = {"detail": {"event": {"data": {"type": ["1", "2"]}}}}
        entries1 = [
            {
                "Source": "test",
                "DetailType": "test",
                "Detail": json.dumps({"event": {"data": {"type": ["3", "1"]}}}),
            }
        ]
        entries2 = [
            {
                "Source": "test",
                "DetailType": "test",
                "Detail": json.dumps({"event": {"data": {"type": ["2"]}}}),
            }
        ]
        entries3 = [
            {
                "Source": "test",
                "DetailType": "test",
                "Detail": json.dumps({"event": {"data": {"type": ["3"]}}}),
            }
        ]
        entries_asserts = [(entries1, True), (entries2, True), (entries3, False)]
        put_events_with_filter_to_sqs(
            pattern=pattern,
            entries_asserts=entries_asserts,
            input_path="$.detail",
        )

    @markers.aws.validated
    def test_put_events_with_nested_event_pattern(self, aws_client, put_events_with_filter_to_sqs):
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
        put_events_with_filter_to_sqs(
            pattern=pattern,
            entries_asserts=entries_asserts,
            input_path="$.detail",
        )

    @markers.aws.unknown
    def test_put_events_with_target_sqs_event_detail_match(
        self, aws_client, put_events_with_filter_to_sqs
    ):
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
        put_events_with_filter_to_sqs(
            pattern={"detail": {"EventType": ["0", "1"]}},
            entries_asserts=entries_asserts,
            input_path="$.detail",
        )

    @pytest.fixture
    def put_events_with_filter_to_sqs(self, aws_client, sqs_get_queue_arn, clean_up):
        def _put_events_with_filter_to_sqs(
            pattern: Dict,
            entries_asserts: List[Tuple[List[Dict], bool]],
            input_path: str = None,
        ):
            queue_name = f"queue-{short_uid()}"
            rule_name = f"rule-{short_uid()}"
            target_id = f"target-{short_uid()}"
            bus_name = f"bus-{short_uid()}"

            sqs_client = aws_client.sqs
            queue_url = sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
            queue_arn = sqs_get_queue_arn(queue_url)
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

            events_client = aws_client.events
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
                clean_up(
                    bus_name=bus_name,
                    rule_name=rule_name,
                    target_ids=target_id,
                    queue_url=queue_url,
                )

        yield _put_events_with_filter_to_sqs

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

    @markers.aws.unknown
    @pytest.mark.parametrize("strategy", ["domain", "path"])
    def test_put_events_with_target_sns(
        self,
        monkeypatch,
        sns_subscription,
        aws_client,
        clean_up,
        strategy,
    ):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", strategy)

        queue_name = "test-%s" % short_uid()
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        topic_name = "topic-{}".format(short_uid())
        topic_arn = aws_client.sns.create_topic(Name=topic_name)["TopicArn"]

        queue_url = aws_client.sqs.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = arns.sqs_queue_arn(queue_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)

        sns_subscription(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

        aws_client.events.create_event_bus(Name=bus_name)
        aws_client.events.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        rs = aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": topic_arn}],
        )

        assert "FailedEntryCount" in rs
        assert "FailedEntries" in rs
        assert rs["FailedEntryCount"] == 0
        assert rs["FailedEntries"] == []

        aws_client.events.put_events(
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
            resp = aws_client.sqs.receive_message(QueueUrl=queue_url)
            return resp["Messages"]

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        assert len(messages) == 1

        actual_event = json.loads(messages[0]["Body"]).get("Message")
        self.assert_valid_event(actual_event)
        assert json.loads(actual_event).get("detail") == EVENT_DETAIL

        # clean up
        aws_client.sns.delete_topic(TopicArn=topic_arn)
        clean_up(bus_name=bus_name, rule_name=rule_name, target_ids=target_id, queue_url=queue_url)

    @markers.aws.unknown
    @pytest.mark.parametrize("strategy", ["domain", "path"])
    def test_put_events_into_event_bus(
        self, monkeypatch, sqs_get_queue_arn, aws_client, clean_up, strategy
    ):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", strategy)

        queue_name = "queue-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name_1 = "bus1-{}".format(short_uid())
        bus_name_2 = "bus2-{}".format(short_uid())

        queue_url = aws_client.sqs.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = sqs_get_queue_arn(queue_url)

        aws_client.events.create_event_bus(Name=bus_name_1)
        resp = aws_client.events.create_event_bus(Name=bus_name_2)

        for bus_name in (
            bus_name_1,
            bus_name_2,
        ):
            aws_client.events.put_rule(
                Name=rule_name,
                EventBusName=bus_name,
                EventPattern=json.dumps(TEST_EVENT_PATTERN),
            )

        aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=bus_name_1,
            Targets=[{"Id": target_id, "Arn": resp.get("EventBusArn")}],
        )
        aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=bus_name_2,
            Targets=[{"Id": target_id, "Arn": queue_arn}],
        )

        aws_client.events.put_events(
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
            resp = aws_client.sqs.receive_message(QueueUrl=queue_url)
            return resp["Messages"]

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        assert len(messages) == 1

        actual_event = json.loads(messages[0]["Body"])
        self.assert_valid_event(actual_event)
        assert actual_event["detail"] == EVENT_DETAIL

        # clean up
        clean_up(bus_name=bus_name_1, rule_name=rule_name, target_ids=target_id)
        clean_up(bus_name=bus_name_2)
        aws_client.sqs.delete_queue(QueueUrl=queue_url)

    @markers.aws.unknown
    def test_put_events_with_target_lambda(
        self, create_lambda_function, cleanups, aws_client, clean_up
    ):
        rule_name = f"rule-{short_uid()}"
        function_name = f"lambda-func-{short_uid()}"
        target_id = f"target-{short_uid()}"
        bus_name = f"bus-{short_uid()}"

        # clean up
        cleanups.append(lambda: aws_client.lambda_.delete_function(FunctionName=function_name))
        cleanups.append(
            lambda: clean_up(bus_name=bus_name, rule_name=rule_name, target_ids=target_id)
        )

        rs = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
        )

        func_arn = rs["CreateFunctionResponse"]["FunctionArn"]

        aws_client.events.create_event_bus(Name=bus_name)
        aws_client.events.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        rs = aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": func_arn}],
        )

        assert "FailedEntryCount" in rs
        assert "FailedEntries" in rs
        assert rs["FailedEntryCount"] == 0
        assert rs["FailedEntries"] == []

        aws_client.events.put_events(
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
            logs_client=aws_client.logs,
        )
        actual_event = events[0]
        self.assert_valid_event(actual_event)
        assert actual_event["detail"] == EVENT_DETAIL

    @markers.aws.validated
    def test_rule_disable(self, aws_client, clean_up):
        rule_name = f"rule-{short_uid()}"
        aws_client.events.put_rule(Name=rule_name, ScheduleExpression="rate(1 minute)")

        response = aws_client.events.list_rules()
        assert response["Rules"][0]["State"] == "ENABLED"
        aws_client.events.disable_rule(Name=rule_name)
        response = aws_client.events.list_rules(NamePrefix=rule_name)
        assert response["Rules"][0]["State"] == "DISABLED"

        # clean up
        clean_up(rule_name=rule_name)

    @markers.aws.unknown
    def test_scheduled_expression_events(
        self,
        sns_create_topic,
        sqs_create_queue,
        sns_subscription,
        httpserver: HTTPServer,
        aws_client,
        clean_up,
    ):
        httpserver.expect_request("").respond_with_data(b"", 200)
        http_endpoint = httpserver.url_for("/")

        topic_name = f"topic-{short_uid()}"
        queue_name = f"queue-{short_uid()}"
        fifo_queue_name = f"queue-{short_uid()}.fifo"
        rule_name = f"rule-{short_uid()}"
        sm_role_arn = arns.role_arn("sfn_role")
        sm_name = f"state-machine-{short_uid()}"
        topic_target_id = f"target-{short_uid()}"
        sm_target_id = f"target-{short_uid()}"
        queue_target_id = f"target-{short_uid()}"
        fifo_queue_target_id = f"target-{short_uid()}"

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

        state_machine_arn = aws_client.stepfunctions.create_state_machine(
            name=sm_name, definition=state_machine_definition, roleArn=sm_role_arn
        )["stateMachineArn"]

        topic_arn = sns_create_topic(Name=topic_name)["TopicArn"]
        subscription = sns_subscription(TopicArn=topic_arn, Protocol="http", Endpoint=http_endpoint)

        assert poll_condition(lambda: len(httpserver.log) >= 1, timeout=5)
        sub_request, _ = httpserver.log[0]
        payload = sub_request.get_json(force=True)
        assert payload["Type"] == "SubscriptionConfirmation"
        token = payload["Token"]
        aws_client.sns.confirm_subscription(TopicArn=topic_arn, Token=token)
        sub_attrs = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"]
        )
        assert sub_attrs["Attributes"]["PendingConfirmation"] == "false"

        queue_url = sqs_create_queue(QueueName=queue_name)
        fifo_queue_url = sqs_create_queue(
            QueueName=fifo_queue_name,
            Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        )

        queue_arn = arns.sqs_queue_arn(queue_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)
        fifo_queue_arn = arns.sqs_queue_arn(
            fifo_queue_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME
        )

        event = {"env": "testing"}
        event_json = json.dumps(event)

        aws_client.events.put_rule(Name=rule_name, ScheduleExpression="rate(1 minute)")

        aws_client.events.put_targets(
            Rule=rule_name,
            Targets=[
                {"Id": topic_target_id, "Arn": topic_arn, "Input": event_json},
                {
                    "Id": sm_target_id,
                    "Arn": state_machine_arn,
                    "Input": event_json,
                },
                {"Id": queue_target_id, "Arn": queue_arn, "Input": event_json},
                {
                    "Id": fifo_queue_target_id,
                    "Arn": fifo_queue_arn,
                    "Input": event_json,
                    "SqsParameters": {"MessageGroupId": "123"},
                },
            ],
        )

        def received(q_urls):
            # state machine got executed
            executions = aws_client.stepfunctions.list_executions(
                stateMachineArn=state_machine_arn
            )["executions"]
            assert len(executions) >= 1

            # http endpoint got events
            assert len(httpserver.log) >= 2
            notifications = [
                sns_event["Message"]
                for request, _ in httpserver.log
                if (
                    (sns_event := request.get_json(force=True))
                    and sns_event["Type"] == "Notification"
                )
            ]
            assert len(notifications) >= 1

            # get state machine execution detail
            execution_arn = executions[0]["executionArn"]
            _execution_input = aws_client.stepfunctions.describe_execution(
                executionArn=execution_arn
            )["input"]

            all_msgs = []
            # get message from queue and fifo_queue
            for url in q_urls:
                msgs = aws_client.sqs.receive_message(QueueUrl=url).get("Messages", [])
                assert len(msgs) >= 1
                all_msgs.append(msgs[0])

            return _execution_input, notifications[0], all_msgs

        execution_input, notification, msgs_received = retry(
            received, retries=5, sleep=15, q_urls=[queue_url, fifo_queue_url]
        )
        assert json.loads(notification) == event
        assert json.loads(execution_input) == event
        for msg_received in msgs_received:
            assert json.loads(msg_received["Body"]) == event

        # clean up
        target_ids = [topic_target_id, sm_target_id, queue_target_id, fifo_queue_target_id]
        clean_up(rule_name=rule_name, target_ids=target_ids, queue_url=queue_url)
        aws_client.stepfunctions.delete_state_machine(stateMachineArn=state_machine_arn)

    @pytest.mark.parametrize("auth", API_DESTINATION_AUTHS)
    @markers.aws.unknown
    def test_api_destinations(self, httpserver: HTTPServer, auth, aws_client, clean_up):
        token = short_uid()
        bearer = f"Bearer {token}"

        def _handler(_request: Request):
            return Response(
                json.dumps(
                    {
                        "access_token": token,
                        "token_type": "Bearer",
                        "expires_in": 86400,
                    }
                ),
                mimetype="application/json",
            )

        httpserver.expect_request("").respond_with_handler(_handler)
        http_endpoint = httpserver.url_for("/")

        if auth.get("type") == "OAUTH_CLIENT_CREDENTIALS":
            auth["parameters"]["AuthorizationEndpoint"] = http_endpoint

        connection_name = f"c-{short_uid()}"
        connection_arn = aws_client.events.create_connection(
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
                            "Key": "connection-header-param",
                            "Value": "value",
                            "IsValueSecret": False,
                        },
                        {
                            "Key": "overwritten-header",
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
        result = aws_client.events.create_api_destination(
            Name=dest_name,
            ConnectionArn=connection_arn,
            InvocationEndpoint=http_endpoint,
            HttpMethod="POST",
        )

        # create rule and target
        rule_name = f"r-{short_uid()}"
        target_id = f"target-{short_uid()}"
        pattern = json.dumps({"source": ["source-123"], "detail-type": ["type-123"]})
        aws_client.events.put_rule(Name=rule_name, EventPattern=pattern)
        aws_client.events.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    "Id": target_id,
                    "Arn": result["ApiDestinationArn"],
                    "Input": '{"target_value":"value"}',
                    "HttpParameters": {
                        "PathParameterValues": ["target_path"],
                        "HeaderParameters": {
                            "target-header": "target_header_value",
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
        aws_client.events.put_events(Entries=entries)

        # clean up
        aws_client.events.delete_connection(Name=connection_name)
        aws_client.events.delete_api_destination(Name=dest_name)
        clean_up(rule_name=rule_name, target_ids=target_id)

        to_recv = 2 if auth["type"] == "OAUTH_CLIENT_CREDENTIALS" else 1
        poll_condition(lambda: len(httpserver.log) >= to_recv, timeout=5)

        event_request, _ = httpserver.log[-1]
        event = event_request.get_json(force=True)
        headers = event_request.headers
        query_args = event_request.args

        # Connection data validation
        assert event["connection_body_param"] == "value"
        assert headers["Connection-Header-Param"] == "value"
        assert query_args["connection_query_param"] == "value"

        # Target parameters validation
        assert "/target_path" in event_request.path
        assert event["target_value"] == "value"
        assert headers["Target-Header"] == "target_header_value"
        assert query_args["target_query"] == "t_query"

        # connection/target overwrite test
        assert headers["Overwritten-Header"] == "original"
        assert query_args["overwritten_query"] == "original"

        # Auth validation
        match auth["type"]:
            case "BASIC":
                user_pass = to_str(base64.b64encode(b"user:pass"))
                assert headers["Authorization"] == f"Basic {user_pass}"
            case "API_KEY":
                assert headers["Api"] == "apikey_secret"

            case "OAUTH_CLIENT_CREDENTIALS":
                assert headers["Authorization"] == bearer

                oauth_request, _ = httpserver.log[0]
                oauth_login = oauth_request.get_json(force=True)
                # Oauth login validation
                assert oauth_login["client_id"] == "id"
                assert oauth_login["client_secret"] == "password"
                assert oauth_login["oauthbody"] == "value1"
                assert oauth_request.headers["oauthheader"] == "value2"
                assert oauth_request.args["oauthquery"] == "value3"

    @markers.aws.unknown
    def test_create_connection_validations(self, aws_client):
        connection_name = "This should fail with two errors 123467890123412341234123412341234"

        with pytest.raises(ClientError) as ctx:
            aws_client.events.create_connection(
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

    @markers.aws.unknown
    def test_put_events_with_target_firehose(self, aws_client, clean_up):
        s3_bucket = "s3-{}".format(short_uid())
        s3_prefix = "testeventdata"
        stream_name = "firehose-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        # create firehose target bucket
        resources.get_or_create_bucket(s3_bucket, s3_client=aws_client.s3)

        # create firehose delivery stream to s3
        stream = aws_client.firehose.create_delivery_stream(
            DeliveryStreamName=stream_name,
            S3DestinationConfiguration={
                "RoleARN": arns.iam_resource_arn("firehose"),
                "BucketARN": arns.s3_bucket_arn(s3_bucket),
                "Prefix": s3_prefix,
            },
        )
        stream_arn = stream["DeliveryStreamARN"]

        aws_client.events.create_event_bus(Name=bus_name)
        aws_client.events.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        rs = aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": stream_arn}],
        )

        assert "FailedEntryCount" in rs
        assert "FailedEntries" in rs
        assert rs["FailedEntryCount"] == 0
        assert rs["FailedEntries"] == []

        aws_client.events.put_events(
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
        bucket_contents = aws_client.s3.list_objects(Bucket=s3_bucket)["Contents"]
        assert len(bucket_contents) == 1
        key = bucket_contents[0]["Key"]
        s3_object = aws_client.s3.get_object(Bucket=s3_bucket, Key=key)
        actual_event = json.loads(s3_object["Body"].read().decode())
        self.assert_valid_event(actual_event)
        assert actual_event["detail"] == EVENT_DETAIL

        # clean up
        aws_client.firehose.delete_delivery_stream(DeliveryStreamName=stream_name)
        # empty and delete bucket
        aws_client.s3.delete_object(Bucket=s3_bucket, Key=key)
        aws_client.s3.delete_bucket(Bucket=s3_bucket)
        clean_up(bus_name=bus_name, rule_name=rule_name, target_ids=target_id)

    @markers.aws.unknown
    def test_put_events_with_target_sqs_new_region(self, aws_client_factory):
        events_client = aws_client_factory(region_name="eu-west-1").events
        queue_name = "queue-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        sqs_client = aws_client_factory(region_name="eu-west-1").sqs
        sqs_client.create_queue(QueueName=queue_name)
        queue_arn = arns.sqs_queue_arn(queue_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)

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

    @markers.aws.unknown
    def test_put_events_with_target_kinesis(self, aws_client):
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())
        stream_name = "stream-{}".format(short_uid())
        stream_arn = arns.kinesis_stream_arn(stream_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)

        aws_client.kinesis.create_stream(StreamName=stream_name, ShardCount=1)

        aws_client.events.create_event_bus(Name=bus_name)

        aws_client.events.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        put_response = aws_client.events.put_targets(
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
            _stream = aws_client.kinesis.describe_stream(StreamName=stream_name)
            assert _stream["StreamDescription"]["StreamStatus"] == "ACTIVE"

        # wait until stream becomes available
        retry(check_stream_status, retries=7, sleep=0.8)

        aws_client.events.put_events(
            Entries=[
                {
                    "EventBusName": bus_name,
                    "Source": TEST_EVENT_PATTERN["source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(EVENT_DETAIL),
                }
            ]
        )

        stream = aws_client.kinesis.describe_stream(StreamName=stream_name)
        shard_id = stream["StreamDescription"]["Shards"][0]["ShardId"]
        shard_iterator = aws_client.kinesis.get_shard_iterator(
            StreamName=stream_name,
            ShardId=shard_id,
            ShardIteratorType="AT_TIMESTAMP",
            Timestamp=datetime(2020, 1, 1),
        )["ShardIterator"]

        record = aws_client.kinesis.get_records(ShardIterator=shard_iterator)["Records"][0]

        partition_key = record["PartitionKey"]
        data = json.loads(record["Data"].decode())

        assert partition_key == TEST_EVENT_PATTERN["detail-type"][0]
        assert data["detail"] == EVENT_DETAIL
        self.assert_valid_event(data)

    @markers.aws.unknown
    def test_put_events_with_input_path(self, aws_client, clean_up):
        queue_name = f"queue-{short_uid()}"
        rule_name = f"rule-{short_uid()}"
        target_id = f"target-{short_uid()}"
        bus_name = f"bus-{short_uid()}"

        queue_url = aws_client.sqs.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = arns.sqs_queue_arn(queue_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)

        aws_client.events.create_event_bus(Name=bus_name)
        aws_client.events.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"}],
        )

        aws_client.events.put_events(
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
            resp = aws_client.sqs.receive_message(QueueUrl=queue_url)
            return resp.get("Messages")

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        assert len(messages) == 1
        assert json.loads(messages[0].get("Body")) == EVENT_DETAIL

        aws_client.events.put_events(
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
        clean_up(bus_name=bus_name, rule_name=rule_name, target_ids=target_id, queue_url=queue_url)

    @markers.aws.unknown
    def test_put_events_with_input_path_multiple(self, aws_client, clean_up):
        queue_name = "queue-{}".format(short_uid())
        queue_name_1 = "queue-{}".format(short_uid())
        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())
        target_id_1 = "target-{}".format(short_uid())
        bus_name = "bus-{}".format(short_uid())

        queue_url = aws_client.sqs.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = arns.sqs_queue_arn(queue_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)

        queue_url_1 = aws_client.sqs.create_queue(QueueName=queue_name_1)["QueueUrl"]
        queue_arn_1 = arns.sqs_queue_arn(queue_name_1, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)

        aws_client.events.create_event_bus(Name=bus_name)

        aws_client.events.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        aws_client.events.put_targets(
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

        aws_client.events.put_events(
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
            resp = aws_client.sqs.receive_message(QueueUrl=queue_url)
            return resp.get("Messages")

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        assert len(messages) == 1
        assert json.loads(messages[0].get("Body")) == EVENT_DETAIL

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url_1)
        assert len(messages) == 1
        assert json.loads(messages[0].get("Body")).get("detail") == EVENT_DETAIL

        aws_client.events.put_events(
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
        clean_up(
            bus_name=bus_name,
            rule_name=rule_name,
            target_ids=[target_id, target_id_1],
            queue_url=queue_url,
        )

    @markers.aws.unknown
    def test_put_event_without_source(self, aws_client_factory):
        events_client = aws_client_factory(region_name="eu-west-1").events

        response = events_client.put_events(Entries=[{"DetailType": "Test", "Detail": "{}"}])
        assert response.get("Entries")

    @markers.aws.unknown
    def test_put_event_without_detail(self, aws_client_factory):
        events_client = aws_client_factory(region_name="eu-west-1").events

        response = events_client.put_events(
            Entries=[
                {
                    "DetailType": "Test",
                }
            ]
        )
        assert response.get("Entries")

    @markers.aws.unknown
    @pytest.mark.parametrize("strategy", ["domain", "path"])
    def test_trigger_event_on_ssm_change(self, monkeypatch, aws_client, clean_up, strategy):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", strategy)

        rule_name = "rule-{}".format(short_uid())
        target_id = "target-{}".format(short_uid())

        # create queue
        queue_name = "queue-{}".format(short_uid())
        queue_url = aws_client.sqs.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = arns.sqs_queue_arn(queue_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)

        # put rule listening on SSM changes
        ssm_prefix = "/test/local/"
        aws_client.events.put_rule(
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
        aws_client.events.put_targets(
            Rule=rule_name,
            Targets=[{"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"}],
        )

        param_suffix = short_uid()

        # change SSM param to trigger event
        aws_client.ssm.put_parameter(
            Name=f"{ssm_prefix}/test-{param_suffix}", Value="value1", Type="String"
        )

        def assert_message():
            resp = aws_client.sqs.receive_message(QueueUrl=queue_url)
            result = resp.get("Messages")
            body = json.loads(result[0]["Body"])
            assert body == {"name": f"/test/local/test-{param_suffix}", "operation": "Create"}

        # assert that message has been received
        retry(assert_message, retries=7, sleep=0.3)

        # clean up
        clean_up(rule_name=rule_name, target_ids=target_id)

    @markers.aws.unknown
    def test_put_event_with_content_base_rule_in_pattern(self, aws_client, clean_up):
        queue_name = f"queue-{short_uid()}"
        rule_name = f"rule-{short_uid()}"
        target_id = f"target-{short_uid()}"

        queue_url = aws_client.sqs.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = arns.sqs_queue_arn(queue_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)

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

        aws_client.events.create_event_bus(Name=TEST_EVENT_BUS_NAME)
        aws_client.events.put_rule(
            Name=rule_name,
            EventBusName=TEST_EVENT_BUS_NAME,
            EventPattern=json.dumps(pattern),
        )

        aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=TEST_EVENT_BUS_NAME,
            Targets=[{"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"}],
        )
        aws_client.events.put_events(Entries=[event])

        def get_message(queue_url):
            resp = aws_client.sqs.receive_message(QueueUrl=queue_url)
            return resp.get("Messages")

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        assert len(messages) == 1
        assert json.loads(messages[0].get("Body")) == json.loads(event["Detail"])
        event_details = json.loads(event["Detail"])
        event_details["admins"] = "no"
        event["Detail"] = json.dumps(event_details)

        aws_client.events.put_events(Entries=[event])

        messages = retry(get_message, retries=3, sleep=1, queue_url=queue_url)
        assert messages is None

        # clean up
        clean_up(
            bus_name=TEST_EVENT_BUS_NAME,
            rule_name=rule_name,
            target_ids=target_id,
            queue_url=queue_url,
        )

    @pytest.mark.parametrize(
        "schedule_expression", ["rate(1 minute)", "rate(1 day)", "rate(1 hour)"]
    )
    @markers.aws.validated
    def test_create_rule_with_one_unit_in_singular_should_succeed(
        self, schedule_expression, aws_client, clean_up
    ):
        rule_name = f"rule-{short_uid()}"

        # rule should be creatable with given expression
        try:
            aws_client.events.put_rule(Name=rule_name, ScheduleExpression=schedule_expression)
        finally:
            clean_up(rule_name=rule_name)

    @markers.aws.validated
    @pytest.mark.xfail
    def test_verify_rule_event_content(self, aws_client, clean_up):
        log_group_name = f"/aws/events/testLogGroup-{short_uid()}"
        rule_name = f"rule-{short_uid()}"
        target_id = f"testRuleId-{short_uid()}"

        aws_client.logs.create_log_group(logGroupName=log_group_name)
        log_groups = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)
        assert len(log_groups["logGroups"]) == 1
        log_group = log_groups["logGroups"][0]
        log_group_arn = log_group["arn"]

        aws_client.events.put_rule(Name=rule_name, ScheduleExpression="rate(1 minute)")
        aws_client.events.put_targets(
            Rule=rule_name, Targets=[{"Id": target_id, "Arn": log_group_arn}]
        )

        def ensure_log_stream_exists():
            streams = aws_client.logs.describe_log_streams(logGroupName=log_group_name)
            return len(streams["logStreams"]) == 1

        poll_condition(condition=ensure_log_stream_exists, timeout=65, interval=5)

        log_streams = aws_client.logs.describe_log_streams(logGroupName=log_group_name)
        log_stream_name = log_streams["logStreams"][0]["logStreamName"]

        log_content = aws_client.logs.get_log_events(
            logGroupName=log_group_name, logStreamName=log_stream_name
        )
        events = log_content["events"]
        assert len(events) == 1
        event = events[0]

        self.assert_valid_event(event["message"])

        clean_up(
            rule_name=rule_name,
            target_ids=target_id,
            log_group_name=log_group_name,
        )

    @markers.aws.validated
    def test_put_events_to_default_eventbus_for_custom_eventbus(
        self,
        events_create_event_bus,
        events_put_rule,
        sqs_create_queue,
        sqs_get_queue_arn,
        create_role,
        create_policy,
        s3_bucket,
        snapshot,
        aws_client,
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

        aws_client.s3.put_bucket_notification_configuration(
            Bucket=s3_bucket, NotificationConfiguration={"EventBridgeConfiguration": {}}
        )

        queue_url = sqs_create_queue()
        queue_arn = sqs_get_queue_arn(queue_url)

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
        aws_client.iam.attach_role_policy(RoleName=role, PolicyArn=policy_arn)
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

        allow_event_rule_to_sqs_queue(
            aws_client=aws_client,
            sqs_queue_url=queue_url,
            sqs_queue_arn=queue_arn,
            event_rule_arn=rule_on_custom_bus_arn,
        )

        resp = aws_client.events.put_targets(
            Rule=default_bus_rule_name,
            Targets=[
                {"Id": default_bus_target_id, "Arn": custom_event_bus_arn, "RoleArn": role_arn}
            ],
        )
        snapshot.match("put-target-1", resp)

        resp = aws_client.events.put_targets(
            Rule=custom_bus_rule_name,
            EventBusName=custom_bus_name,
            Targets=[{"Id": custom_bus_target_id, "Arn": queue_arn}],
        )
        snapshot.match("put-target-2", resp)

        aws_client.s3.put_object(Bucket=s3_bucket, Key="delivery/test.txt", Body=b"data")

        def get_message():
            recv_msg = aws_client.sqs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=5)
            return recv_msg["Messages"]

        retries = 20 if is_aws_cloud() else 3
        messages = retry(get_message, retries=retries, sleep=0.5)
        assert len(messages) == 1
        snapshot.match("get-events", {"Messages": messages})

        received_event = json.loads(messages[0]["Body"])

        self.assert_valid_event(received_event)

    @markers.aws.validated
    def test_put_target_id_validation(
        self, sqs_create_queue, sqs_get_queue_arn, events_put_rule, snapshot, aws_client
    ):
        rule_name = f"rule-{short_uid()}"
        queue_url = sqs_create_queue()
        queue_arn = sqs_get_queue_arn(queue_url)

        events_put_rule(
            Name=rule_name, EventPattern=json.dumps(TEST_EVENT_PATTERN), State="ENABLED"
        )

        target_id = "!@#$@!#$"
        with pytest.raises(ClientError) as e:
            aws_client.events.put_targets(
                Rule=rule_name,
                Targets=[
                    {"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"},
                ],
            )
        snapshot.add_transformer(snapshot.transform.regex(target_id, "invalid-target-id"))
        snapshot.match("error", e.value.response)

        target_id = f"{long_uid()}-{long_uid()}-extra"
        with pytest.raises(ClientError) as e:
            aws_client.events.put_targets(
                Rule=rule_name,
                Targets=[
                    {"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"},
                ],
            )
        snapshot.add_transformer(snapshot.transform.regex(target_id, "second-invalid-target-id"))
        snapshot.match("length_error", e.value.response)

        target_id = f"test-With_valid.Characters-{short_uid()}"
        aws_client.events.put_targets(
            Rule=rule_name,
            Targets=[
                {"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"},
            ],
        )

    @markers.aws.validated
    def test_should_ignore_schedules_for_put_event(
        self, create_lambda_function, cleanups, aws_client
    ):
        """Regression test for https://github.com/localstack/localstack/issues/7847"""
        fn_name = f"test-event-fn-{short_uid()}"
        create_lambda_function(
            func_name=fn_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=Runtime.python3_9,
            client=aws_client.lambda_,
        )

        aws_client.lambda_.add_permission(
            FunctionName=fn_name,
            StatementId="AllowFnInvokeStatement",
            Action="lambda:InvokeFunction",
            Principal="events.amazonaws.com",
        )

        fn_arn = aws_client.lambda_.get_function(FunctionName=fn_name)["Configuration"][
            "FunctionArn"
        ]
        aws_client.events.put_rule(
            Name="ScheduledLambda", ScheduleExpression="rate(1 minute)"
        )  # every minute, can't go lower than that
        cleanups.append(lambda: aws_client.events.delete_rule(Name="ScheduledLambda"))
        aws_client.events.put_targets(
            Rule="ScheduledLambda", Targets=[{"Id": "calllambda1", "Arn": fn_arn}]
        )
        cleanups.append(
            lambda: aws_client.events.remove_targets(Rule="ScheduledLambda", Ids=["calllambda1"])
        )

        aws_client.events.put_events(
            Entries=[
                {
                    "Source": "MySource",
                    "DetailType": "CustomType",
                    "Detail": json.dumps({"message": "manually invoked"}),
                }
            ]
        )

        def check_invocation():
            events_after = aws_client.logs.filter_log_events(logGroupName=f"/aws/lambda/{fn_name}")
            # the custom sent event should NOT trigger the lambda (!)
            assert len([e for e in events_after["events"] if "START" in e["message"]]) >= 1
            assert (
                len([e for e in events_after["events"] if "manually invoked" in e["message"]]) == 0
            )

        retry(check_invocation, sleep=5, retries=15)

    @markers.aws.validated
    def test_put_events_nonexistent_event_bus(
        self,
        aws_client,
        sqs_create_queue,
        sqs_get_queue_arn,
        events_put_rule,
        snapshot,
    ):
        default_bus_rule_name = f"rule-{short_uid()}"
        default_bus_target_id = f"test-target-default-b-{short_uid()}"
        nonexistent_event_bus = f"event-bus-{short_uid()}"

        snapshot.add_transformer(
            [
                snapshot.transform.key_value("MD5OfBody"),  # the event contains a timestamp
                snapshot.transform.key_value("ReceiptHandle"),
                snapshot.transform.regex(nonexistent_event_bus, "<custom-event-bus>"),
            ]
        )
        # create SQS queue + add rules & targets so that we can check the default event bus received the message
        # even if one entry was wrong

        queue_url = sqs_create_queue()
        queue_arn = sqs_get_queue_arn(queue_url)

        rule_on_default_bus = events_put_rule(
            Name=default_bus_rule_name,
            EventPattern=json.dumps({"detail-type": ["CustomType"], "source": ["MySource"]}),
            State="ENABLED",
        )

        allow_event_rule_to_sqs_queue(
            aws_client=aws_client,
            event_rule_arn=rule_on_default_bus["RuleArn"],
            sqs_queue_arn=queue_arn,
            sqs_queue_url=queue_url,
        )

        aws_client.events.put_targets(
            Rule=default_bus_rule_name,
            Targets=[{"Id": default_bus_target_id, "Arn": queue_arn}],
        )

        # create two entries, one with no EventBus specified (so it will target the default one)
        # and one with a nonexistent EventBusName, which should be ignored
        entries = [
            {
                "Source": "MySource",
                "DetailType": "CustomType",
                "Detail": json.dumps({"message": "for the default event bus"}),
            },
            {
                "EventBusName": nonexistent_event_bus,
                "Source": "MySource",
                "DetailType": "CustomType",
                "Detail": json.dumps({"message": "for the custom event bus"}),
            },
        ]
        response = aws_client.events.put_events(Entries=entries)
        snapshot.match("put-events", response)

        def _get_sqs_messages():
            resp = aws_client.sqs.receive_message(
                QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=1
            )
            msgs = resp.get("Messages")
            assert len(msgs) == 1
            aws_client.sqs.delete_message(
                QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"]
            )
            return msgs

        messages = retry(_get_sqs_messages, retries=5, sleep=0.1)
        snapshot.match("get-events", messages)

        # try to get the custom EventBus we passed the Event to
        with pytest.raises(ClientError) as e:
            aws_client.events.describe_event_bus(Name=nonexistent_event_bus)
        snapshot.match("non-existent-bus", e.value.response)

    @markers.aws.validated
    def test_test_event_pattern(self, aws_client, snapshot, account_id, region):
        response = aws_client.events.test_event_pattern(
            Event=json.dumps(
                {
                    "id": "1",
                    "source": "order",
                    "detail-type": "Test",
                    "account": account_id,
                    "region": region,
                    "time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
            ),
            EventPattern=json.dumps(
                {
                    "source": ["order"],
                    "detail-type": ["Test"],
                }
            ),
        )
        snapshot.match("eventbridge-test-event-pattern-response", response)

        # negative test, source is not matched
        response = aws_client.events.test_event_pattern(
            Event=json.dumps(
                {
                    "id": "1",
                    "source": "order",
                    "detail-type": "Test",
                    "account": account_id,
                    "region": region,
                    "time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
            ),
            EventPattern=json.dumps(
                {
                    "source": ["shipment"],
                    "detail-type": ["Test"],
                }
            ),
        )
        snapshot.match("eventbridge-test-event-pattern-response-no-match", response)

    @markers.aws.validated
    def test_put_events_time(
        self,
        aws_client,
        sqs_create_queue,
        sqs_get_queue_arn,
        events_put_rule,
        snapshot,
    ):
        default_bus_rule_name = f"rule-{short_uid()}"
        default_bus_target_id = f"test-target-default-b-{short_uid()}"

        snapshot.add_transformer(
            [
                snapshot.transform.key_value("MD5OfBody"),  # the event contains a timestamp
                snapshot.transform.key_value("ReceiptHandle"),
            ]
        )

        queue_url = sqs_create_queue()
        queue_arn = sqs_get_queue_arn(queue_url)

        rule_on_default_bus = events_put_rule(
            Name=default_bus_rule_name,
            EventPattern=json.dumps({"detail-type": ["CustomType"], "source": ["MySource"]}),
            State="ENABLED",
        )

        allow_event_rule_to_sqs_queue(
            aws_client=aws_client,
            event_rule_arn=rule_on_default_bus["RuleArn"],
            sqs_queue_arn=queue_arn,
            sqs_queue_url=queue_url,
        )

        aws_client.events.put_targets(
            Rule=default_bus_rule_name,
            Targets=[{"Id": default_bus_target_id, "Arn": queue_arn}],
        )

        # create an entry with a defined time
        entries = [
            {
                "Source": "MySource",
                "DetailType": "CustomType",
                "Detail": json.dumps({"message": "for the default event bus"}),
                "Time": datetime(year=2022, day=1, month=1),
            }
        ]
        response = aws_client.events.put_events(Entries=entries)
        snapshot.match("put-events", response)

        def _get_sqs_messages():
            resp = aws_client.sqs.receive_message(
                QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=1
            )
            msgs = resp.get("Messages")
            assert len(msgs) == 1
            aws_client.sqs.delete_message(
                QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"]
            )
            return msgs

        messages = retry(_get_sqs_messages, retries=5, sleep=0.1)
        snapshot.match("get-events", messages)

        message_body = json.loads(messages[0]["Body"])
        assert message_body["time"] == "2022-01-01T00:00:00Z"

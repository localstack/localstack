"""General EventBridge and EventBridgeBus tests.
Test creating and modifying event buses, as well as putting events to custom and the default bus.
"""

import base64
import json
import os
import time
import uuid
from datetime import datetime

import pytest
from botocore.exceptions import ClientError
from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

from localstack import config
from localstack.services.events.provider import _get_events_tmp_dir
from localstack.testing.aws.eventbus_utils import allow_event_rule_to_sqs_queue
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.files import load_file
from localstack.utils.strings import long_uid, short_uid, to_str
from localstack.utils.sync import poll_condition, retry
from tests.aws.services.events.conftest import assert_valid_event, sqs_collect_messages
from tests.aws.services.events.helper_functions import is_v2_provider

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
    @markers.aws.unknown
    @pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
    def test_events_written_to_disk_are_timestamp_prefixed_for_chronological_ordering(
        self, aws_client
    ):
        event_type = str(uuid.uuid4())
        event_details_to_publish = [f"event {n}" for n in range(10)]

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
        sorted_events_written_to_disk = (
            json.loads(str(load_file(os.path.join(events_tmp_dir, filename))))
            for filename in sorted(os.listdir(events_tmp_dir))
        )
        sorted_events = list(
            filter(
                lambda event: event.get("DetailType") == event_type,
                sorted_events_written_to_disk,
            )
        )

        assert [json.loads(event["Detail"]) for event in sorted_events] == event_details_to_publish

    @markers.aws.validated
    @pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
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

    @markers.aws.unknown
    @pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
    def test_put_events_with_values_in_array(self, put_events_with_filter_to_sqs):
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
    @pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
    def test_put_events_with_nested_event_pattern(self, put_events_with_filter_to_sqs):
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
    @pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
    def test_scheduled_expression_events(
        self,
        sns_create_topic,
        sqs_create_queue,
        sns_subscription,
        httpserver: HTTPServer,
        aws_client,
        account_id,
        region_name,
        clean_up,
    ):
        httpserver.expect_request("").respond_with_data(b"", 200)
        http_endpoint = httpserver.url_for("/")

        topic_name = f"topic-{short_uid()}"
        queue_name = f"queue-{short_uid()}"
        fifo_queue_name = f"queue-{short_uid()}.fifo"
        rule_name = f"rule-{short_uid()}"
        sm_role_arn = arns.iam_role_arn("sfn_role", account_id=account_id)
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

        queue_arn = arns.sqs_queue_arn(queue_name, account_id, region_name)
        fifo_queue_arn = arns.sqs_queue_arn(fifo_queue_name, account_id, region_name)

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

    @markers.aws.unknown
    @pytest.mark.parametrize("auth", API_DESTINATION_AUTHS)
    @pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
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
    @pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
    def test_create_connection_validations(self, aws_client):
        connection_name = "This should fail with two errors 123467890123412341234123412341234"

        with pytest.raises(ClientError) as ctx:
            (
                aws_client.events.create_connection(
                    Name=connection_name,
                    AuthorizationType="INVALID",
                    AuthParameters={
                        "BasicAuthParameters": {"Username": "user", "Password": "pass"}
                    },
                ),
            )

        assert ctx.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
        assert ctx.value.response["Error"]["Code"] == "ValidationException"

        message = ctx.value.response["Error"]["Message"]
        assert "3 validation errors" in message
        assert "must satisfy regular expression pattern" in message
        assert "must have length less than or equal to 64" in message
        assert "must satisfy enum value set: [BASIC, OAUTH_CLIENT_CREDENTIALS, API_KEY]" in message

    @markers.aws.unknown
    @pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
    def test_put_event_without_source(self, aws_client_factory):
        events_client = aws_client_factory(region_name="eu-west-1").events

        response = events_client.put_events(Entries=[{"DetailType": "Test", "Detail": "{}"}])
        assert response.get("Entries")

    @markers.aws.unknown
    @pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
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

    @markers.aws.validated
    @pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
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
    @pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
    def test_event_pattern(self, aws_client, snapshot, account_id, region_name):
        response = aws_client.events.test_event_pattern(
            Event=json.dumps(
                {
                    "id": "1",
                    "source": "order",
                    "detail-type": "Test",
                    "account": account_id,
                    "region": region_name,
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
                    "region": region_name,
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
    @pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
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


class TestEventsEventBus:
    @markers.aws.validated
    def test_create_list_describe_delete_custom_event_bus(self, aws_client, snapshot):
        events = aws_client.events
        bus_name = "test-bus"

        response = events.create_event_bus(Name=bus_name)
        snapshot.match("create-custom-event-bus", response)

        response = events.list_event_buses()
        snapshot.match("list-event-buses-create", response)

        response = events.describe_event_bus(Name=bus_name)
        snapshot.match("describe-custom-event-bus", response)

        response = events.delete_event_bus(Name=bus_name)
        snapshot.match("delete-custom-event-bus", response)

        response = events.list_event_buses()
        snapshot.match("list-event-buses-delete", response)

    @markers.aws.validated
    def test_list_event_buses_with_prefix(self, aws_client, cleanups, snapshot):
        events = aws_client.events
        bus_name = "test-bus"
        bus_name_not_match = "no-prefix-match"

        events.create_event_bus(Name=bus_name)
        cleanups.append(lambda: events.delete_event_bus(Name=bus_name))
        events.create_event_bus(Name=bus_name_not_match)
        cleanups.append(lambda: events.delete_event_bus(Name=bus_name_not_match))

        response = events.list_event_buses(NamePrefix=bus_name)
        snapshot.match("list-event-buses-prefix-complete-name", response)

        response = events.list_event_buses(NamePrefix=bus_name.split("-")[0])
        snapshot.match("list-event-buses-prefix", response)

    @markers.aws.validated
    def test_list_event_buses_with_limit(self, create_event_bus, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.jsonpath("$..NextToken", "next_token"))
        events = aws_client.events
        bus_name_prefix = "test-bus"
        count = 6

        for i in range(count):
            bus_name = f"{bus_name_prefix}-{i}"
            create_event_bus(bus_name)

        response = events.list_event_buses(Limit=int(count / 2))
        snapshot.match("list-event-buses-limit", response)

        response = events.list_event_buses(
            Limit=int(count / 2) + 2, NextToken=response["NextToken"]
        )
        snapshot.match("list-event-buses-limit-next-token", response)

    @markers.aws.unknown
    @pytest.mark.parametrize("strategy", ["standard", "domain", "path"])
    @pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
    def test_put_events_into_event_bus(
        self,
        monkeypatch,
        sqs_get_queue_arn,
        aws_client,
        clean_up,
        strategy,
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

        messages = sqs_collect_messages(aws_client, queue_url, min_events=1, retries=3)
        assert len(messages) == 1

        actual_event = json.loads(messages[0]["Body"])
        assert_valid_event(actual_event)
        assert actual_event["detail"] == EVENT_DETAIL

        # clean up
        clean_up(bus_name=bus_name_1, rule_name=rule_name, target_ids=target_id)
        clean_up(bus_name=bus_name_2)
        aws_client.sqs.delete_queue(QueueUrl=queue_url)

    @markers.aws.validated
    @pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
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

        retries = 20 if is_aws_cloud() else 3
        messages = sqs_collect_messages(
            aws_client, queue_url, min_events=1, retries=retries, wait_time=5
        )
        assert len(messages) == 1
        snapshot.match("get-events", {"Messages": messages})

        received_event = json.loads(messages[0]["Body"])

        assert_valid_event(received_event)

    @markers.aws.validated
    @pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
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

        messages = retry(_get_sqs_messages, retries=10, sleep=0.1)
        snapshot.match("get-events", messages)

        # try to get the custom EventBus we passed the Event to
        with pytest.raises(ClientError) as e:
            aws_client.events.describe_event_bus(Name=nonexistent_event_bus)
        snapshot.match("non-existent-bus", e.value.response)

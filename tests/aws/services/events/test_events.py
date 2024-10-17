"""General EventBridge and EventBridgeBus tests.
Test creating and modifying event buses, as well as putting events to custom and the default bus.
"""

import base64
import json
import os
import time
import uuid

import pytest
from botocore.exceptions import ClientError
from localstack_snapshot.snapshots.transformer import SortingTransformer
from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

from localstack import config
from localstack.services.events.v1.provider import _get_events_tmp_dir
from localstack.testing.aws.eventbus_utils import allow_event_rule_to_sqs_queue
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.files import load_file
from localstack.utils.strings import long_uid, short_uid, to_str
from localstack.utils.sync import poll_condition, retry
from tests.aws.services.events.helper_functions import (
    assert_valid_event,
    is_old_provider,
    is_v2_provider,
    sqs_collect_messages,
)

EVENT_DETAIL = {"command": "update-account", "payload": {"acc_id": "0a787ecb-4015", "sf_id": "baz"}}

TEST_EVENT_PATTERN = {
    "source": ["core.update-account-command"],
    "detail-type": ["core.update-account-command"],
    "detail": {"command": ["update-account"]},
}

TEST_EVENT_PATTERN_NO_DETAIL = {
    "source": ["core.update-account-command"],
    "detail-type": ["core.update-account-command"],
}

TEST_EVENT_PATTERN_NO_SOURCE = {
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
    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_put_events_without_source(self, snapshot, aws_client):
        entries = [
            {
                "DetailType": TEST_EVENT_PATTERN_NO_SOURCE["detail-type"][0],
                "Detail": json.dumps(EVENT_DETAIL),
            },
        ]
        response = aws_client.events.put_events(Entries=entries)
        snapshot.match("put-events", response)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_put_event_without_detail(self, snapshot, aws_client):
        entries = [
            {
                "Source": TEST_EVENT_PATTERN_NO_DETAIL["source"][0],
                "DetailType": TEST_EVENT_PATTERN_NO_DETAIL["detail-type"][0],
            },
        ]
        response = aws_client.events.put_events(Entries=entries)
        snapshot.match("put-events", response)

    @markers.aws.validated
    def test_put_events_time(self, put_events_with_filter_to_sqs, snapshot):
        entries1 = [
            {
                "Source": TEST_EVENT_PATTERN_NO_DETAIL["source"][0],
                "DetailType": TEST_EVENT_PATTERN_NO_DETAIL["detail-type"][0],
                "Detail": json.dumps({"message": "short time"}),
                "Time": "2022-01-01",
            },
        ]
        entries2 = [
            {
                "Source": TEST_EVENT_PATTERN_NO_DETAIL["source"][0],
                "DetailType": TEST_EVENT_PATTERN_NO_DETAIL["detail-type"][0],
                "Detail": json.dumps({"message": "new time"}),
                "Time": "01-01-2022T00:00:00Z",
            },
        ]
        entries3 = [
            {
                "Source": TEST_EVENT_PATTERN_NO_DETAIL["source"][0],
                "DetailType": TEST_EVENT_PATTERN_NO_DETAIL["detail-type"][0],
                "Detail": json.dumps({"message": "long time"}),
                "Time": "2022-01-01 00:00:00Z",
            },
        ]
        entries_asserts = [(entries1, True), (entries2, True), (entries3, True)]
        messages = put_events_with_filter_to_sqs(
            pattern=TEST_EVENT_PATTERN_NO_DETAIL,
            entries_asserts=entries_asserts,
        )

        snapshot.add_transformer(
            [
                snapshot.transform.key_value("MD5OfBody"),
                snapshot.transform.key_value("ReceiptHandle"),
            ]
        )
        snapshot.match("messages", messages)

        # check for correct time strings in the messages
        for message in messages:
            message_body = json.loads(message["Body"])
            assert message_body["time"] == "2022-01-01T00:00:00Z"

    @markers.aws.validated
    @pytest.mark.parametrize("bus_name", ["custom", "default"])
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_put_events_exceed_limit_ten_entries(
        self, bus_name, events_create_event_bus, aws_client, snapshot
    ):
        if bus_name == "custom":
            bus_name = f"test-bus-{short_uid()}"
            events_create_event_bus(Name=bus_name)
        entries = []
        for i in range(11):
            entries.append(
                {
                    "Source": TEST_EVENT_PATTERN["source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(EVENT_DETAIL),
                    "EventBusName": bus_name,
                }
            )
        with pytest.raises(ClientError) as e:
            aws_client.events.put_events(Entries=entries)

        snapshot.add_transformer(snapshot.transform.regex(bus_name, "<bus-name>"))
        snapshot.match("put-events-exceed-limit-error", e.value.response)

    @markers.aws.only_localstack
    # tests for legacy v1 provider delete once v1 provider is removed
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

    @markers.aws.only_localstack
    # tests for legacy v1 provider delete once v1 provider is removed, v2 covered in separate tests
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
        sm_role_arn = arns.iam_role_arn("sfn_role", account_id=account_id, region_name=region_name)
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

    @markers.aws.only_localstack
    # tests for legacy v1 provider delete once v1 provider is removed, v2 covered in separate tests
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

    @markers.aws.only_localstack
    # tests for legacy v1 provider delete once v1 provider is removed, v2 covered in separate tests
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


class TestEventBus:
    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    @pytest.mark.parametrize("regions", [["us-east-1"], ["us-east-1", "us-west-1", "eu-central-1"]])
    def test_create_list_describe_delete_custom_event_buses(
        self, aws_client_factory, regions, snapshot
    ):
        bus_name = f"test-bus-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(bus_name, "<bus-name>"))

        for region in regions:
            # overwriting randomized region https://docs.localstack.cloud/contributing/multi-account-region-testing/
            # requires manually adding region replacement for snapshot
            snapshot.add_transformer(snapshot.transform.regex(region, "<region>"))
            events = aws_client_factory(region_name=region).events

            response = events.create_event_bus(Name=bus_name)
            snapshot.match(f"create-custom-event-bus-{region}", response)

            response = events.list_event_buses(NamePrefix=bus_name)
            snapshot.match(f"list-event-buses-after-create-{region}", response)

            response = events.describe_event_bus(Name=bus_name)
            snapshot.match(f"describe-custom-event-bus-{region}", response)

        # multiple event buses with same name in multiple regions before deleting them
        for region in regions:
            events = aws_client_factory(region_name=region).events

            response = events.delete_event_bus(Name=bus_name)
            snapshot.match(f"delete-custom-event-bus-{region}", response)

            response = events.list_event_buses(NamePrefix=bus_name)
            snapshot.match(f"list-event-buses-after-delete-{region}", response)

    @markers.aws.validated
    def test_create_multiple_event_buses_same_name(
        self, events_create_event_bus, aws_client, snapshot
    ):
        bus_name = f"test-bus-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(bus_name, "<bus-name>"))
        events_create_event_bus(Name=bus_name)

        with pytest.raises(aws_client.events.exceptions.ResourceAlreadyExistsException) as e:
            events_create_event_bus(Name=bus_name)
        snapshot.match("create-multiple-event-buses-same-name", e)

    @markers.aws.validated
    def test_describe_delete_not_existing_event_bus(self, aws_client, snapshot):
        bus_name = f"this-bus-does-not-exist-1234567890-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(bus_name, "<bus-name>"))

        with pytest.raises(aws_client.events.exceptions.ResourceNotFoundException) as e:
            aws_client.events.describe_event_bus(Name=bus_name)
        snapshot.match("describe-not-existing-event-bus-error", e)

        aws_client.events.delete_event_bus(Name=bus_name)
        snapshot.match("delete-not-existing-event-bus", e)

    @markers.aws.validated
    def test_delete_default_event_bus(self, aws_client, snapshot):
        with pytest.raises(aws_client.events.exceptions.ClientError) as e:
            aws_client.events.delete_event_bus(Name="default")
        snapshot.match("delete-default-event-bus-error", e)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_list_event_buses_with_prefix(self, events_create_event_bus, aws_client, snapshot):
        events = aws_client.events
        bus_name = f"unique-prefix-1234567890-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(bus_name, "<bus-name>"))

        bus_name_not_match = "no-prefix-match"
        snapshot.add_transformer(snapshot.transform.regex(bus_name_not_match, "<bus-name>"))

        events_create_event_bus(Name=bus_name)
        events_create_event_bus(Name=bus_name_not_match)

        response = events.list_event_buses(NamePrefix=bus_name)
        snapshot.match("list-event-buses-prefix-complete-name", response)

        response = events.list_event_buses(NamePrefix=bus_name.split("-")[0])
        snapshot.match("list-event-buses-prefix", response)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_list_event_buses_with_limit(self, events_create_event_bus, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.jsonpath("$..NextToken", "next_token"))
        events = aws_client.events
        bus_name_prefix = f"test-bus-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(bus_name_prefix, "<bus-name-prefix>"))
        count = 6

        for i in range(count):
            bus_name = f"{bus_name_prefix}-{i}"
            events_create_event_bus(Name=bus_name)

        response = events.list_event_buses(Limit=int(count / 2), NamePrefix=bus_name_prefix)
        snapshot.match("list-event-buses-limit", response)

        response = events.list_event_buses(
            Limit=int(count / 2) + 2, NextToken=response["NextToken"], NamePrefix=bus_name_prefix
        )
        snapshot.match("list-event-buses-limit-next-token", response)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    @pytest.mark.parametrize("bus_name", ["custom", "default"])
    def test_put_permission(
        self,
        bus_name,
        events_create_event_bus,
        aws_client,
        account_id,
        secondary_account_id,
        snapshot,
    ):
        if bus_name == "custom":
            bus_name = f"test-bus-{short_uid()}"
            events_create_event_bus(Name=bus_name)
        if bus_name == "default":
            try:
                aws_client.events.remove_permission(
                    EventBusName=bus_name, RemoveAllPermissions=True
                )  # error if no permission is present
            except Exception:
                pass

        snapshot.add_transformer(
            [
                snapshot.transform.regex(bus_name, "<bus-name>"),
                snapshot.transform.regex(account_id, "<account-id>"),
                snapshot.transform.regex(secondary_account_id, "<secondary-account-id>"),
                SortingTransformer("Statement", lambda o: o["Sid"]),
                snapshot.transform.key_value("Sid"),
            ]
        )

        statement_id_primary = f"statement-1-{short_uid()}"
        response = aws_client.events.put_permission(
            EventBusName=bus_name,
            Action="events:PutEvents",
            Principal=account_id,
            StatementId=statement_id_primary,
        )
        snapshot.match("put-permission", response)

        statement_id_primary = f"statement-2-{short_uid()}"
        aws_client.events.put_permission(
            EventBusName=bus_name,
            Action="events:PutEvents",
            Principal=account_id,
            StatementId=statement_id_primary,
        )

        statement_id_secondary = f"statement-3-{short_uid()}"
        aws_client.events.put_permission(
            EventBusName=bus_name,
            Action="events:PutEvents",
            Principal=secondary_account_id,
            StatementId=statement_id_secondary,
        )

        response = aws_client.events.describe_event_bus(Name=bus_name)
        snapshot.match("describe-event-bus-put-permission-multiple-principals", response)

        # allow all principals to put events
        statement_id = f"statement-4-{short_uid()}"
        # only events:PutEvents is allowed for actions
        # only a single access policy is allowed per event bus
        aws_client.events.put_permission(
            EventBusName=bus_name,
            Action="events:PutEvents",
            Principal="*",  # required if condition is present
            StatementId=statement_id,
            # Condition={"Type": "StringEquals", "Key": "aws:PrincipalOrgID", "Value": "org id"},
        )

        # put permission just replaces the existing permission
        aws_client.events.put_permission(
            EventBusName=bus_name,
            Action="events:PutEvents",
            Principal="*",
            StatementId=statement_id,
        )

        response = aws_client.events.describe_event_bus(Name=bus_name)
        snapshot.match("describe-event-bus-put-permission", response)

        # allow with policy document
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": f"statement-5-{short_uid()}",
                    "Effect": "Allow",
                    "Principal": {"Service": "events.amazonaws.com"},
                    "Action": "events:ListRules",
                    "Resource": "*",
                }
            ],
        }
        response = aws_client.events.put_permission(
            EventBusName=bus_name,
            Policy=json.dumps(policy),
        )
        snapshot.match("put-permission-policy", response)

        response = aws_client.events.describe_event_bus(Name=bus_name)
        snapshot.match("describe-event-bus-put-permission-policy", response)

        try:
            aws_client.events.remove_permission(EventBusName=bus_name, RemoveAllPermissions=True)
        except Exception:
            pass

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_put_permission_non_existing_event_bus(self, aws_client, snapshot):
        non_exist_bus_name = f"non-existing-bus-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(non_exist_bus_name, "<bus-name>"))

        with pytest.raises(ClientError) as e:
            aws_client.events.put_permission(
                EventBusName=non_exist_bus_name,
                Action="events:PutEvents",
                Principal="*",
                StatementId="statement-id",
            )
        snapshot.match("remove-permission-non-existing-sid-error", e)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    @pytest.mark.parametrize("bus_name", ["custom", "default"])
    def test_remove_permission(
        self,
        bus_name,
        events_create_event_bus,
        aws_client,
        account_id,
        secondary_account_id,
        snapshot,
    ):
        if bus_name == "custom":
            bus_name = f"test-bus-{short_uid()}"
            events_create_event_bus(Name=bus_name)
        if bus_name == "default":
            try:
                aws_client.events.remove_permission(
                    EventBusName=bus_name, RemoveAllPermissions=True
                )  # error if no permission is present
            except Exception:
                pass

        snapshot.add_transformer(
            [
                snapshot.transform.regex(bus_name, "<bus-name>"),
                snapshot.transform.regex(account_id, "<account-id>"),
                snapshot.transform.regex(secondary_account_id, "<secondary-account-id>"),
                SortingTransformer("Statement", lambda o: o["Sid"]),
                snapshot.transform.key_value("Sid"),
            ]
        )

        statement_id_primary = f"statement-1-{short_uid()}"
        aws_client.events.put_permission(
            EventBusName=bus_name,
            Action="events:PutEvents",
            Principal=account_id,
            StatementId=statement_id_primary,
        )

        statement_id_secondary = f"statement-2-{short_uid()}"
        aws_client.events.put_permission(
            EventBusName=bus_name,
            Action="events:PutEvents",
            Principal=secondary_account_id,
            StatementId=statement_id_secondary,
        )

        response_remove_permission = aws_client.events.remove_permission(
            EventBusName=bus_name, StatementId=statement_id_primary, RemoveAllPermissions=False
        )
        snapshot.match("remove-permission", response_remove_permission)

        response = aws_client.events.describe_event_bus(Name=bus_name)
        snapshot.match("describe-event-bus-remove-permission", response)

        response_remove_all = aws_client.events.remove_permission(
            EventBusName=bus_name, RemoveAllPermissions=True
        )
        snapshot.match("remove-permission-all", response_remove_all)

        response = aws_client.events.describe_event_bus(Name=bus_name)
        snapshot.match("describe-event-bus-remove-permission-all", response)

        try:
            aws_client.events.remove_permission(EventBusName=bus_name, RemoveAllPermissions=True)
        except Exception:
            pass

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    @pytest.mark.parametrize("bus_name", ["custom", "default"])
    @pytest.mark.parametrize("policy_exists", [True, False])
    def test_remove_permission_non_existing_sid(
        self, aws_client, bus_name, policy_exists, events_create_event_bus, account_id, snapshot
    ):
        if bus_name == "custom":
            bus_name = f"test-bus-{short_uid()}"
            events_create_event_bus(Name=bus_name)
        if bus_name == "default":
            try:
                aws_client.events.remove_permission(
                    EventBusName=bus_name, RemoveAllPermissions=True
                )  # error if no permission is present
            except Exception:
                pass

        if policy_exists:
            aws_client.events.put_permission(
                EventBusName=bus_name,
                Action="events:PutEvents",
                Principal=account_id,
                StatementId=f"statement-{short_uid()}",
            )

        with pytest.raises(ClientError) as e:
            aws_client.events.remove_permission(
                EventBusName=bus_name, StatementId="non-existing-sid"
            )
        snapshot.match("remove-permission-non-existing-sid-error", e)

    @markers.aws.validated
    # TODO move to test targets
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    @pytest.mark.parametrize("strategy", ["standard", "domain", "path"])
    def test_put_events_bus_to_bus(
        self,
        strategy,
        monkeypatch,
        sqs_as_events_target,
        events_create_event_bus,
        events_put_rule,
        aws_client,
        snapshot,
    ):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", strategy)

        bus_name_one = "bus1-{}".format(short_uid())
        bus_name_two = "bus2-{}".format(short_uid())

        events_create_event_bus(Name=bus_name_one)
        event_bus_2_arn = events_create_event_bus(Name=bus_name_two)["EventBusArn"]

        # Create permission for event bus in primary region to send events to event bus in secondary region

        role_name_bus_one_to_bus_two = f"event-bus-one-to-two-role-{short_uid()}"
        assume_role_policy_document_bus_one_to_bus_two = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "events.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

        role_arn_bus_one_to_bus_two = aws_client.iam.create_role(
            RoleName=role_name_bus_one_to_bus_two,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document_bus_one_to_bus_two),
        )["Role"]["Arn"]

        policy_name_bus_one_to_bus_two = f"event-bus-one-to-two-policy-{short_uid()}"
        policy_document_bus_one_to_bus_two = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Action": "events:PutEvents",
                    "Resource": "arn:aws:events:*:*:event-bus/*",
                }
            ],
        }

        aws_client.iam.put_role_policy(
            RoleName=role_name_bus_one_to_bus_two,
            PolicyName=policy_name_bus_one_to_bus_two,
            PolicyDocument=json.dumps(policy_document_bus_one_to_bus_two),
        )

        if is_aws_cloud():
            time.sleep(10)

        # Rule and target bus 1 to bus 2
        rule_name_bus_one = f"rule-{short_uid()}"
        events_put_rule(
            Name=rule_name_bus_one,
            EventBusName=bus_name_one,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        target_id_bus_one_to_bus_two = f"target-{short_uid()}"
        aws_client.events.put_targets(
            Rule=rule_name_bus_one,
            EventBusName=bus_name_one,
            Targets=[
                {
                    "Id": target_id_bus_one_to_bus_two,
                    "Arn": event_bus_2_arn,
                    "RoleArn": role_arn_bus_one_to_bus_two,
                }
            ],
        )

        # Create sqs target
        queue_url, queue_arn = sqs_as_events_target()

        # Rule and target bus 2 to sqs
        rule_name_bus_two = f"rule-{short_uid()}"
        events_put_rule(
            Name=rule_name_bus_two,
            EventBusName=bus_name_two,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        target_id_bus_two_to_sqs = f"target-{short_uid()}"
        aws_client.events.put_targets(
            Rule=rule_name_bus_two,
            EventBusName=bus_name_two,
            Targets=[{"Id": target_id_bus_two_to_sqs, "Arn": queue_arn}],
        )

        aws_client.events.put_events(
            Entries=[
                {
                    "EventBusName": bus_name_one,
                    "Source": TEST_EVENT_PATTERN["source"][0],
                    "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                    "Detail": json.dumps(EVENT_DETAIL),
                }
            ]
        )

        messages = sqs_collect_messages(aws_client, queue_url, expected_events_count=1, retries=3)

        snapshot.add_transformer(
            [
                snapshot.transform.key_value("ReceiptHandle", reference_replacement=False),
                snapshot.transform.key_value("MD5OfBody", reference_replacement=False),
            ]
        )
        snapshot.match("messages", messages)

    @markers.aws.validated
    # TODO simplify and use sqs as target
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
            aws_client, queue_url, expected_events_count=1, retries=retries, wait_time=5
        )
        assert len(messages) == 1
        snapshot.match("get-events", {"Messages": messages})

        received_event = json.loads(messages[0]["Body"])

        assert_valid_event(received_event)

    @markers.aws.validated  # TODO fix condition for this test, only succeeds if run on its own
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

        entries = [
            {
                "Source": "MySource",
                "DetailType": "CustomType",
                "Detail": json.dumps({"message": "for the default event bus"}),
            },
            {
                "EventBusName": nonexistent_event_bus,  # nonexistent EventBusName, message should be ignored
                "Source": "MySource",
                "DetailType": "CustomType",
                "Detail": json.dumps({"message": "for the custom event bus"}),
            },
        ]
        response = aws_client.events.put_events(Entries=entries)
        snapshot.match("put-events", response)

        def _get_sqs_messages():  # TODO cleanup use exiting fixture
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

        with pytest.raises(ClientError) as e:
            aws_client.events.describe_event_bus(Name=nonexistent_event_bus)
        snapshot.match("non-existent-bus-error", e.value.response)


class TestEventRule:
    @markers.aws.validated
    @pytest.mark.parametrize("bus_name", ["custom", "default"])
    def test_put_list_with_prefix_describe_delete_rule(
        self, bus_name, events_create_event_bus, events_put_rule, aws_client, snapshot
    ):
        if bus_name == "custom":
            bus_name = f"bus-{short_uid()}"
            snapshot.add_transformer(snapshot.transform.regex(bus_name, "<bus-name>"))
            events_create_event_bus(Name=bus_name)

        rule_name = f"test-rule-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(rule_name, "<rule-name>"))
        response = events_put_rule(
            Name=rule_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
            EventBusName=bus_name,
        )
        snapshot.match("put-rule", response)

        # NamePrefix required for default bus against AWS
        response = aws_client.events.list_rules(NamePrefix=rule_name, EventBusName=bus_name)
        snapshot.match("list-rules", response)

        response = aws_client.events.describe_rule(Name=rule_name, EventBusName=bus_name)
        snapshot.match("describe-rule", response)

        response = aws_client.events.delete_rule(Name=rule_name, EventBusName=bus_name)
        snapshot.match("delete-rule", response)

        response = aws_client.events.list_rules(NamePrefix=rule_name, EventBusName=bus_name)
        snapshot.match("list-rules-after-delete", response)

    @markers.aws.validated
    def test_put_multiple_rules_with_same_name(
        self, events_create_event_bus, events_put_rule, aws_client, snapshot
    ):
        event_bus_name = f"bus-{short_uid()}"
        events_create_event_bus(Name=event_bus_name)
        snapshot.add_transformer(snapshot.transform.regex(event_bus_name, "<bus-name>"))

        rule_name = f"test-rule-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(rule_name, "<rule-name>"))

        response = events_put_rule(
            Name=rule_name,
            EventBusName=event_bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        snapshot.match("put-rule", response)

        # put_rule updates the rule if it already exists
        response = events_put_rule(
            Name=rule_name,
            EventBusName=event_bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        snapshot.match("re-put-rule", response)

        response = aws_client.events.list_rules(EventBusName=event_bus_name)
        snapshot.match("list-rules", response)

    @markers.aws.validated
    def test_list_rule_with_limit(
        self, events_create_event_bus, events_put_rule, aws_client, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.jsonpath("$..NextToken", "next_token"))

        event_bus_name = f"bus-{short_uid()}"
        events_create_event_bus(Name=event_bus_name)
        snapshot.add_transformer(snapshot.transform.regex(event_bus_name, "<bus-name>"))

        rule_name_prefix = f"test-rule-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(rule_name_prefix, "<rule-name-prefix>"))
        count = 6

        for i in range(count):
            rule_name = f"{rule_name_prefix}-{i}"
            events_put_rule(
                Name=rule_name,
                EventBusName=event_bus_name,
                EventPattern=json.dumps(TEST_EVENT_PATTERN),
            )

        response = aws_client.events.list_rules(Limit=int(count / 2), EventBusName=event_bus_name)
        snapshot.match("list-rules-limit", response)

        response = aws_client.events.list_rules(
            Limit=int(count / 2) + 2, NextToken=response["NextToken"], EventBusName=event_bus_name
        )
        snapshot.match("list-rules-limit-next-token", response)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_describe_nonexistent_rule(self, aws_client, snapshot):
        rule_name = f"this-rule-does-not-exist-1234567890-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(rule_name, "<rule-name>"))

        with pytest.raises(aws_client.events.exceptions.ResourceNotFoundException) as e:
            aws_client.events.describe_rule(Name=rule_name)
        snapshot.match("describe-not-existing-rule-error", e)

    @markers.aws.validated
    @pytest.mark.parametrize("bus_name", ["custom", "default"])
    def test_disable_re_enable_rule(
        self, events_create_event_bus, events_put_rule, aws_client, snapshot, bus_name
    ):
        if bus_name == "custom":
            bus_name = f"bus-{short_uid()}"
            snapshot.add_transformer(snapshot.transform.regex(bus_name, "<bus-name>"))
            events_create_event_bus(Name=bus_name)

        rule_name = f"test-rule-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(rule_name, "<rule-name>"))
        events_put_rule(
            Name=rule_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
            EventBusName=bus_name,
        )

        response = aws_client.events.disable_rule(Name=rule_name, EventBusName=bus_name)
        snapshot.match("disable-rule", response)

        response = aws_client.events.describe_rule(Name=rule_name, EventBusName=bus_name)
        snapshot.match("describe-rule-disabled", response)

        response = aws_client.events.enable_rule(Name=rule_name, EventBusName=bus_name)
        snapshot.match("enable-rule", response)

        response = aws_client.events.describe_rule(Name=rule_name, EventBusName=bus_name)
        snapshot.match("describe-rule-enabled", response)

    @markers.aws.validated
    def test_delete_rule_with_targets(
        self, events_put_rule, sqs_create_queue, sqs_get_queue_arn, aws_client, snapshot
    ):
        rule_name = f"test-rule-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(rule_name, "<rule-name>"))
        events_put_rule(
            Name=rule_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        target_id = f"test-target-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(target_id, "<target-id>"))

        queue_url = sqs_create_queue()
        queue_arn = sqs_get_queue_arn(queue_url)
        snapshot.add_transformer(snapshot.transform.regex(queue_arn, "<queue-arn>"))

        aws_client.events.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    "Id": target_id,
                    "Arn": queue_arn,
                }
            ],
        )

        with pytest.raises(aws_client.events.exceptions.ClientError) as e:
            aws_client.events.delete_rule(Name=rule_name)
        snapshot.match("delete-rule-with-targets-error", e)

    @markers.aws.validated
    def test_update_rule_with_targets(
        self, events_put_rule, sqs_create_queue, sqs_get_queue_arn, aws_client, snapshot
    ):
        rule_name = f"test-rule-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(rule_name, "<rule-name>"))
        events_put_rule(
            Name=rule_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )

        target_id = f"test-target-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(target_id, "<target-id>"))

        queue_url = sqs_create_queue()
        queue_arn = sqs_get_queue_arn(queue_url)
        snapshot.add_transformer(snapshot.transform.regex(queue_arn, "<queue-arn>"))

        aws_client.events.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    "Id": target_id,
                    "Arn": queue_arn,
                }
            ],
        )

        response = aws_client.events.list_targets_by_rule(Rule=rule_name)
        snapshot.match("list-targets", response)

        response = events_put_rule(
            Name=rule_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        snapshot.match("update-rule", response)

        response = aws_client.events.list_targets_by_rule(Rule=rule_name)
        snapshot.match("list-targets-after-update", response)


class TestEventPattern:
    @markers.aws.validated
    def test_put_events_pattern_with_values_in_array(self, put_events_with_filter_to_sqs, snapshot):
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
        messages = put_events_with_filter_to_sqs(
            pattern=pattern,
            entries_asserts=entries_asserts,
            input_path="$.detail",
        )

        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("MD5OfBody"),
                snapshot.transform.key_value("ReceiptHandle"),
            ]
        )
        snapshot.match("messages", messages)

    @markers.aws.validated
    def test_put_events_pattern_nested(self, put_events_with_filter_to_sqs, snapshot):
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
        messages = put_events_with_filter_to_sqs(
            pattern=pattern,
            entries_asserts=entries_asserts,
            input_path="$.detail",
        )

        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("MD5OfBody"),
                snapshot.transform.key_value("ReceiptHandle"),
            ]
        )
        snapshot.match("messages", messages)


class TestEventTarget:
    @markers.aws.validated
    @pytest.mark.parametrize("bus_name", ["custom", "default"])
    def test_put_list_remove_target(
        self,
        bus_name,
        events_create_event_bus,
        events_put_rule,
        sqs_create_queue,
        sqs_get_queue_arn,
        aws_client,
        snapshot,
    ):
        kwargs = {}
        if bus_name == "custom":
            bus_name = f"bus-{short_uid()}"
            snapshot.add_transformer(snapshot.transform.regex(bus_name, "<bus-name>"))
            events_create_event_bus(Name=bus_name)
            kwargs["EventBusName"] = bus_name  # required for custom event bus, optional for default

        rule_name = f"test-rule-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(rule_name, "<rule-name>"))
        events_put_rule(
            Name=rule_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
            EventBusName=bus_name,
        )

        queue_url = sqs_create_queue()
        queue_arn = sqs_get_queue_arn(queue_url)
        snapshot.add_transformer(snapshot.transform.regex(queue_arn, "<queue-arn>"))
        target_id = f"test-target-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(target_id, "<target-id>"))
        response = aws_client.events.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    "Id": target_id,
                    "Arn": queue_arn,
                }
            ],
            **kwargs,
        )
        snapshot.match("put-target", response)

        response = aws_client.events.list_targets_by_rule(Rule=rule_name, **kwargs)
        snapshot.match("list-targets", response)

        response = aws_client.events.remove_targets(Rule=rule_name, Ids=[target_id], **kwargs)
        snapshot.match("remove-target", response)

        response = aws_client.events.list_targets_by_rule(Rule=rule_name, **kwargs)
        snapshot.match("list-targets-after-delete", response)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_add_exceed_fife_targets_per_rule(
        self, events_put_rule, sqs_create_queue, sqs_get_queue_arn, aws_client, snapshot
    ):
        rule_name = f"test-rule-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(rule_name, "<rule-name>"))
        events_put_rule(
            Name=rule_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        queue_url = sqs_create_queue()
        queue_arn = sqs_get_queue_arn(queue_url)
        snapshot.add_transformer(snapshot.transform.regex(queue_arn, "<queue-arn>"))

        targets = [{"Id": f"test-target-{i}", "Arn": queue_arn} for i in range(7)]
        snapshot.add_transformer(snapshot.transform.regex("test-target-", "<target-id>"))

        with pytest.raises(aws_client.events.exceptions.LimitExceededException) as error:
            aws_client.events.put_targets(Rule=rule_name, Targets=targets)
        snapshot.match("put-targets-client-error", error)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_list_target_by_rule_limit(
        self, events_put_rule, sqs_create_queue, sqs_get_queue_arn, aws_client, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.jsonpath("$..NextToken", "next_token"))
        rule_name = f"test-rule-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(rule_name, "<rule-name>"))
        events_put_rule(
            Name=rule_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        queue_url = sqs_create_queue()
        queue_arn = sqs_get_queue_arn(queue_url)
        snapshot.add_transformer(snapshot.transform.regex(queue_arn, "<queue-arn>"))

        targets = [{"Id": f"test-target-{i}", "Arn": queue_arn} for i in range(5)]
        snapshot.add_transformer(snapshot.transform.regex("test-target-", "<target-id>"))
        aws_client.events.put_targets(Rule=rule_name, Targets=targets)

        response = aws_client.events.list_targets_by_rule(Rule=rule_name, Limit=3)
        snapshot.match("list-targets-limit", response)

        response = aws_client.events.list_targets_by_rule(
            Rule=rule_name, NextToken=response["NextToken"]
        )
        snapshot.match("list-targets-limit-next-token", response)

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
        snapshot.match("put-targets-invalid-id-error", e.value.response)

        target_id = f"{long_uid()}-{long_uid()}-extra"
        with pytest.raises(ClientError) as e:
            aws_client.events.put_targets(
                Rule=rule_name,
                Targets=[
                    {"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"},
                ],
            )
        snapshot.add_transformer(snapshot.transform.regex(target_id, "second-invalid-target-id"))
        snapshot.match("put-targets-length-error", e.value.response)

        target_id = f"test-With_valid.Characters-{short_uid()}"
        aws_client.events.put_targets(
            Rule=rule_name,
            Targets=[
                {"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"},
            ],
        )

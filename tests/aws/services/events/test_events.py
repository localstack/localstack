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
from localstack.testing.snapshots.transformer_utility import TransformerUtility
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
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_put_event_without_detail_type(self, snapshot, aws_client):
        entries = [
            {
                "Source": "some.source",
                "Detail": json.dumps(EVENT_DETAIL),
                "DetailType": "",
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
    @pytest.mark.skipif(
        is_v2_provider(), reason="Whitebox test for v1 provider only, completely irrelevant for v2"
    )
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

    @markers.aws.validated
    @pytest.mark.skip(
        reason="V2 provider does not support this feature yet and it also fails in V1 now"
    )
    def test_create_connection_validations(self, aws_client, snapshot):
        connection_name = "This should fail with two errors 123467890123412341234123412341234"

        with pytest.raises(ClientError) as e:
            (
                aws_client.events.create_connection(
                    Name=connection_name,
                    AuthorizationType="INVALID",
                    AuthParameters={
                        "BasicAuthParameters": {"Username": "user", "Password": "pass"}
                    },
                ),
            )
        snapshot.match("create_connection_exc", e.value.response)

    @markers.aws.validated
    def test_put_events_response_entries_order(
        self, events_put_rule, create_sqs_events_target, aws_client, snapshot, clean_up
    ):
        """Test that put_events response contains each EventId only once, even with multiple targets."""

        queue_url_1, queue_arn_1 = create_sqs_events_target()
        queue_url_2, queue_arn_2 = create_sqs_events_target()

        rule_name = f"test-rule-{short_uid()}"

        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("EventId", reference_replacement=False),
                snapshot.transform.key_value("detail", reference_replacement=False),
                snapshot.transform.regex(queue_arn_1, "<queue-1-arn>"),
                snapshot.transform.regex(queue_arn_2, "<queue-2-arn>"),
                snapshot.transform.regex(rule_name, "<rule-name>"),
                *snapshot.transform.sqs_api(),
                *snapshot.transform.sns_api(),
            ]
        )

        events_put_rule(
            Name=rule_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN_NO_DETAIL),
        )

        def check_rule_active():
            rule = aws_client.events.describe_rule(Name=rule_name)
            assert rule["State"] == "ENABLED"

        retry(check_rule_active, retries=10, sleep=1)

        target_id_1 = f"test-target-1-{short_uid()}"
        target_id_2 = f"test-target-2-{short_uid()}"
        target_response = aws_client.events.put_targets(
            Rule=rule_name,
            Targets=[
                {"Id": target_id_1, "Arn": queue_arn_1},
                {"Id": target_id_2, "Arn": queue_arn_2},
            ],
        )

        assert (
            target_response["FailedEntryCount"] == 0
        ), f"Failed to add targets: {target_response.get('FailedEntries', [])}"

        # Use the test constants for the event
        test_event = {
            "Source": TEST_EVENT_PATTERN_NO_DETAIL["source"][0],
            "DetailType": TEST_EVENT_PATTERN_NO_DETAIL["detail-type"][0],
            "Detail": json.dumps(EVENT_DETAIL),
        }

        event_response = aws_client.events.put_events(Entries=[test_event])

        snapshot.match("put-events-response", event_response)

        assert len(event_response["Entries"]) == 1
        event_id = event_response["Entries"][0]["EventId"]
        assert event_id, "EventId not found in response"

        def verify_message_content(message, original_event_id):
            """Verify the message content matches what we sent."""
            body = json.loads(message["Body"])

            assert (
                body["source"] == TEST_EVENT_PATTERN_NO_DETAIL["source"][0]
            ), f"Unexpected source: {body['source']}"
            assert (
                body["detail-type"] == TEST_EVENT_PATTERN_NO_DETAIL["detail-type"][0]
            ), f"Unexpected detail-type: {body['detail-type']}"

            detail = body["detail"]  # detail is already parsed as dict
            assert isinstance(detail, dict), f"Detail should be a dict, got {type(detail)}"
            assert detail == EVENT_DETAIL, f"Unexpected detail content: {detail}"

            assert (
                body["id"] == original_event_id
            ), f"Event ID mismatch. Expected {original_event_id}, got {body['id']}"

            return body

        try:
            messages_1 = sqs_collect_messages(
                aws_client, queue_url_1, expected_events_count=1, retries=30, wait_time=5
            )
            messages_2 = sqs_collect_messages(
                aws_client, queue_url_2, expected_events_count=1, retries=30, wait_time=5
            )
        except Exception as e:
            raise Exception(f"Failed to collect messages: {str(e)}")

        assert len(messages_1) == 1, f"Expected 1 message in queue 1, got {len(messages_1)}"
        assert len(messages_2) == 1, f"Expected 1 message in queue 2, got {len(messages_2)}"

        verify_message_content(messages_1[0], event_id)
        verify_message_content(messages_2[0], event_id)

        snapshot.match(
            "sqs-messages", {"queue1_messages": messages_1, "queue2_messages": messages_2}
        )

    @markers.aws.validated
    def test_put_events_with_target_delivery_failure(
        self, events_put_rule, sqs_create_queue, sqs_get_queue_arn, aws_client, snapshot, clean_up
    ):
        """Test that put_events returns successful EventId even when target delivery fails due to non-existent queue."""
        # Create a queue and get its ARN
        queue_url = sqs_create_queue()
        queue_arn = sqs_get_queue_arn(queue_url)

        # Delete the queue to simulate a failure scenario
        aws_client.sqs.delete_queue(QueueUrl=queue_url)

        rule_name = f"test-rule-{short_uid()}"

        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("EventId"),
                snapshot.transform.regex(queue_arn, "<queue-arn>"),
                snapshot.transform.regex(rule_name, "<rule-name>"),
                *snapshot.transform.sqs_api(),
            ]
        )

        events_put_rule(
            Name=rule_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN_NO_DETAIL),
        )

        target_id = f"test-target-{short_uid()}"
        aws_client.events.put_targets(
            Rule=rule_name,
            Targets=[
                {"Id": target_id, "Arn": queue_arn},
            ],
        )

        test_event = {
            "Source": TEST_EVENT_PATTERN_NO_DETAIL["source"][0],
            "DetailType": TEST_EVENT_PATTERN_NO_DETAIL["detail-type"][0],
            "Detail": json.dumps(EVENT_DETAIL),
        }

        response = aws_client.events.put_events(Entries=[test_event])
        snapshot.match("put-events-response", response)

        assert len(response["Entries"]) == 1
        assert "EventId" in response["Entries"][0]
        assert response["FailedEntryCount"] == 0

        new_queue_url = sqs_create_queue()
        messages = aws_client.sqs.receive_message(
            QueueUrl=new_queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=1
        ).get("Messages", [])

        assert len(messages) == 0, "No messages should be delivered when queue doesn't exist"


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
        create_sqs_events_target,
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
        queue_url, queue_arn = create_sqs_events_target()

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


API_DESTINATION_AUTH_PARAMS = [
    {
        "AuthorizationType": "BASIC",
        "AuthParameters": {
            "BasicAuthParameters": {"Username": "user", "Password": "pass"},
        },
    },
    {
        "AuthorizationType": "API_KEY",
        "AuthParameters": {
            "ApiKeyAuthParameters": {"ApiKeyName": "ApiKey", "ApiKeyValue": "secret"},
        },
    },
    {
        "AuthorizationType": "OAUTH_CLIENT_CREDENTIALS",
        "AuthParameters": {
            "OAuthParameters": {
                "AuthorizationEndpoint": "https://example.com/oauth",
                "ClientParameters": {"ClientID": "client_id", "ClientSecret": "client_secret"},
                "HttpMethod": "POST",
            }
        },
    },
]


class TestEventBridgeConnections:
    @pytest.fixture
    def connection_snapshots(self, snapshot, connection_name):
        """Common snapshot transformers for connection tests."""
        return TransformerUtility.eventbridge_connection(snapshot, connection_name)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_create_connection(
        self, aws_client, connection_snapshots, create_connection, connection_name
    ):
        response = create_connection(
            "API_KEY",
            {
                "ApiKeyAuthParameters": {"ApiKeyName": "ApiKey", "ApiKeyValue": "secret"},
                "InvocationHttpParameters": {},
            },
        )
        connection_snapshots.match("create-connection", response)

        describe_response = aws_client.events.describe_connection(Name=connection_name)
        connection_snapshots.match("describe-connection", describe_response)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    @pytest.mark.parametrize("auth_params", API_DESTINATION_AUTH_PARAMS)
    def test_create_connection_with_auth(
        self, aws_client, connection_snapshots, create_connection, auth_params, connection_name
    ):
        response = create_connection(
            auth_params["AuthorizationType"],
            auth_params["AuthParameters"],
        )
        connection_snapshots.match("create-connection-auth", response)

        describe_response = aws_client.events.describe_connection(Name=connection_name)
        connection_snapshots.match("describe-connection-auth", describe_response)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_list_connections(
        self, aws_client, connection_snapshots, create_connection, connection_name
    ):
        create_connection(
            "BASIC",
            {
                "BasicAuthParameters": {"Username": "user", "Password": "pass"},
                "InvocationHttpParameters": {},
            },
        )

        response = aws_client.events.list_connections(NamePrefix=connection_name)
        connection_snapshots.match("list-connections", response)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_delete_connection(
        self, aws_client, connection_snapshots, create_connection, connection_name
    ):
        create_connection(
            "API_KEY",
            {
                "ApiKeyAuthParameters": {"ApiKeyName": "ApiKey", "ApiKeyValue": "secret"},
                "InvocationHttpParameters": {},
            },
        )

        delete_response = aws_client.events.delete_connection(Name=connection_name)
        connection_snapshots.match("delete-connection", delete_response)

        with pytest.raises(aws_client.events.exceptions.ResourceNotFoundException) as exc:
            aws_client.events.describe_connection(Name=connection_name)
        assert f"Connection '{connection_name}' does not exist" in str(exc.value)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_create_connection_invalid_parameters(
        self, aws_client, connection_snapshots, connection_name
    ):
        with pytest.raises(ClientError) as e:
            aws_client.events.create_connection(
                Name=connection_name,
                AuthorizationType="INVALID_AUTH_TYPE",
                AuthParameters={},
            )
        connection_snapshots.match("create-connection-invalid-auth-error", e.value.response)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_update_connection(
        self, aws_client, connection_snapshots, create_connection, connection_name
    ):
        create_response = create_connection(
            "BASIC",
            {
                "BasicAuthParameters": {"Username": "user", "Password": "pass"},
                "InvocationHttpParameters": {},
            },
        )
        connection_snapshots.match("create-connection", create_response)

        update_response = aws_client.events.update_connection(
            Name=connection_name,
            AuthorizationType="BASIC",
            AuthParameters={
                "BasicAuthParameters": {"Username": "new_user", "Password": "new_pass"},
                "InvocationHttpParameters": {},
            },
        )
        connection_snapshots.match("update-connection", update_response)

        describe_response = aws_client.events.describe_connection(Name=connection_name)
        connection_snapshots.match("describe-updated-connection", describe_response)

    @markers.aws.validated
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_create_connection_name_validation(
        self, aws_client, connection_snapshots, connection_name
    ):
        invalid_name = "Invalid Name With Spaces!"

        with pytest.raises(ClientError) as e:
            aws_client.events.create_connection(
                Name=invalid_name,
                AuthorizationType="API_KEY",
                AuthParameters={
                    "ApiKeyAuthParameters": {"ApiKeyName": "ApiKey", "ApiKeyValue": "secret"},
                    "InvocationHttpParameters": {},
                },
            )
        connection_snapshots.match("create-connection-invalid-name-error", e.value.response)


API_DESTINATION_AUTHS = [
    {
        "type": "BASIC",
        "key": "BasicAuthParameters",
        "parameters": {"Username": "user", "Password": "pass"},
    },
    {
        "type": "API_KEY",
        "key": "ApiKeyAuthParameters",
        "parameters": {"ApiKeyName": "ApiKey", "ApiKeyValue": "secret"},
    },
    {
        "type": "OAUTH_CLIENT_CREDENTIALS",
        "key": "OAuthParameters",
        "parameters": {
            "ClientParameters": {"ClientID": "id", "ClientSecret": "password"},
            "AuthorizationEndpoint": "https://example.com/oauth",
            "HttpMethod": "POST",
            "OAuthHttpParameters": {
                "BodyParameters": [{"Key": "oauthbody", "Value": "value1", "IsValueSecret": False}],
                "HeaderParameters": [
                    {"Key": "oauthheader", "Value": "value2", "IsValueSecret": False}
                ],
                "QueryStringParameters": [
                    {"Key": "oauthquery", "Value": "value3", "IsValueSecret": False}
                ],
            },
        },
    },
]


class TestEventBridgeApiDestinations:
    @pytest.fixture
    def api_destination_snapshots(self, snapshot, destination_name):
        """Common snapshot transformers for API destination tests."""
        return TransformerUtility.eventbridge_api_destination(snapshot, destination_name)

    @markers.aws.validated
    @pytest.mark.parametrize("auth", API_DESTINATION_AUTHS)
    @pytest.mark.skipif(
        is_old_provider(),
        reason="V1 provider does not support this feature",
    )
    def test_api_destinations(
        self,
        aws_client,
        api_destination_snapshots,
        create_connection,
        create_api_destination,
        connection_name,
        destination_name,
        auth,
    ):
        connection_response = create_connection(auth)
        connection_arn = connection_response["ConnectionArn"]

        response = create_api_destination(
            ConnectionArn=connection_arn,
            HttpMethod="POST",
            InvocationEndpoint="https://example.com/api",
            Description="Test API destination",
        )
        api_destination_snapshots.match("create-api-destination", response)

        describe_response = aws_client.events.describe_api_destination(Name=destination_name)
        api_destination_snapshots.match("describe-api-destination", describe_response)

        list_response = aws_client.events.list_api_destinations(NamePrefix=destination_name)
        api_destination_snapshots.match("list-api-destinations", list_response)

        update_response = aws_client.events.update_api_destination(
            Name=destination_name,
            ConnectionArn=connection_arn,
            HttpMethod="PUT",
            InvocationEndpoint="https://example.com/api/v2",
            Description="Updated API destination",
        )
        api_destination_snapshots.match("update-api-destination", update_response)

        describe_updated_response = aws_client.events.describe_api_destination(
            Name=destination_name
        )
        api_destination_snapshots.match(
            "describe-updated-api-destination", describe_updated_response
        )

        delete_response = aws_client.events.delete_api_destination(Name=destination_name)
        api_destination_snapshots.match("delete-api-destination", delete_response)

        with pytest.raises(aws_client.events.exceptions.ResourceNotFoundException) as exc_info:
            aws_client.events.describe_api_destination(Name=destination_name)
        api_destination_snapshots.match(
            "describe-api-destination-not-found-error", exc_info.value.response
        )

    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="V1 provider does not support this feature")
    def test_create_api_destination_invalid_parameters(
        self, aws_client, api_destination_snapshots, connection_name, destination_name
    ):
        with pytest.raises(ClientError) as e:
            aws_client.events.create_api_destination(
                Name=destination_name,
                ConnectionArn="invalid-connection-arn",
                HttpMethod="INVALID_METHOD",
                InvocationEndpoint="invalid-endpoint",
            )
        api_destination_snapshots.match(
            "create-api-destination-invalid-parameters-error", e.value.response
        )

    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="V1 provider does not support this feature")
    def test_create_api_destination_name_validation(
        self, aws_client, api_destination_snapshots, create_connection, connection_name
    ):
        invalid_name = "Invalid Name With Spaces!"

        connection_response = create_connection(API_DESTINATION_AUTHS[0])
        connection_arn = connection_response["ConnectionArn"]

        with pytest.raises(ClientError) as e:
            aws_client.events.create_api_destination(
                Name=invalid_name,
                ConnectionArn=connection_arn,
                HttpMethod="POST",
                InvocationEndpoint="https://example.com/api",
            )
        api_destination_snapshots.match(
            "create-api-destination-invalid-name-error", e.value.response
        )

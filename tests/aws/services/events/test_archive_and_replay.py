import json

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.services.events.test_events import TEST_EVENT_PATTERN, TEST_EVENT_PATTERN_NO_DETAIL


class TestArchive:
    @markers.aws.validated
    @pytest.mark.parametrize("event_bus_type", ["default", "custom"])
    def test_create_list_describe_update_delete_archive(
        self, event_bus_type, region_name, account_id, events_create_event_bus, aws_client, snapshot
    ):
        if event_bus_type == "default":
            event_bus_name = "default"
            event_source_arn = f"arn:aws:events:{region_name}:{account_id}:event-bus/default"
        if event_bus_type == "custom":
            event_bus_name = f"test-bus-{short_uid()}"
            response = events_create_event_bus(Name=event_bus_name)
            event_source_arn = response["EventBusArn"]

        archive_name = f"test-archive.{short_uid()}"
        response_create_archive = aws_client.events.create_archive(
            ArchiveName=archive_name,
            EventSourceArn=event_source_arn,  # ARN of the source event bus
            Description="description of the archive",
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
            RetentionDays=1,
        )

        snapshot.add_transformer(
            [
                snapshot.transform.regex(event_bus_name, "<event-bus-name>"),
                snapshot.transform.regex(archive_name, "<archive-name>"),
            ]
        )

        snapshot.match("create_archive", response_create_archive)

        response_list_archives = aws_client.events.list_archives()
        snapshot.match("list_archives", response_list_archives)

        response_describe_archive = aws_client.events.describe_archive(ArchiveName=archive_name)
        snapshot.match("describe_archive", response_describe_archive)

        response_update_archive = aws_client.events.update_archive(
            ArchiveName=archive_name,
            Description="updated description of the archive",
            EventPattern=json.dumps(TEST_EVENT_PATTERN_NO_DETAIL),
            RetentionDays=2,
        )
        snapshot.match("update_archive", response_update_archive)

        response_delete_archive = aws_client.events.delete_archive(ArchiveName=archive_name)
        snapshot.match("delete_archive", response_delete_archive)

    @markers.aws.validated
    def test_create_archive_error_unknown_event_bus(self, aws_client, snapshot):
        not_existing_event_bus_name = f"doesnotexist-{short_uid()}"
        non_existing_event_bus_arn = (
            f"arn:aws:events:us-east-1:123456789012:event-bus/{not_existing_event_bus_name}"
        )
        with pytest.raises(Exception) as error:
            aws_client.events.create_archive(
                ArchiveName="test-archive",
                EventSourceArn=non_existing_event_bus_arn,
                Description="description of the archive",
                EventPattern=json.dumps(TEST_EVENT_PATTERN),
                RetentionDays=1,
            )

        snapshot.add_transformer(
            [snapshot.transform.regex(not_existing_event_bus_name, "<event-bus-name>")]
        )
        snapshot.match("create_archive_error_unknown_event_bus", error)

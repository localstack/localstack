import json

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.aws.services.events.test_events import (
    EVENT_DETAIL,
    TEST_EVENT_PATTERN,
    TEST_EVENT_PATTERN_NO_DETAIL,
)


class TestArchive:
    @markers.aws.validated
    @pytest.mark.parametrize("event_bus_type", ["default", "custom"])
    def test_create_list_describe_update_delete_archive(
        self,
        event_bus_type,
        region_name,
        account_id,
        events_create_event_bus,
        events_create_archive,
        aws_client,
        snapshot,
    ):
        if event_bus_type == "default":
            event_bus_name = "default"
            event_source_arn = f"arn:aws:events:{region_name}:{account_id}:event-bus/default"
        if event_bus_type == "custom":
            event_bus_name = f"test-bus-{short_uid()}"
            response = events_create_event_bus(Name=event_bus_name)
            event_source_arn = response["EventBusArn"]

        archive_name = f"test-archive-{short_uid()}"
        response_create_archive = events_create_archive(
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

        snapshot.match("create-archive", response_create_archive)

        response_list_archives = aws_client.events.list_archives()
        snapshot.match("list-archives", response_list_archives)

        response_describe_archive = aws_client.events.describe_archive(ArchiveName=archive_name)
        snapshot.match("describe-archive", response_describe_archive)

        response_update_archive = aws_client.events.update_archive(
            ArchiveName=archive_name,
            Description="updated description of the archive",
            EventPattern=json.dumps(TEST_EVENT_PATTERN_NO_DETAIL),
            RetentionDays=2,
        )
        snapshot.match("update-archive", response_update_archive)

        response_delete_archive = aws_client.events.delete_archive(ArchiveName=archive_name)
        snapshot.match("delete-archive", response_delete_archive)

    @markers.aws.validated
    @pytest.mark.parametrize("event_bus_type", ["default", "custom"])
    def test_list_archive_with_name_prefix(
        self,
        event_bus_type,
        region_name,
        account_id,
        events_create_event_bus,
        events_create_archive,
        aws_client,
        snapshot,
    ):
        if event_bus_type == "default":
            event_bus_name = "default"
            event_source_arn = f"arn:aws:events:{region_name}:{account_id}:event-bus/default"
        if event_bus_type == "custom":
            event_bus_name = f"test-bus-{short_uid()}"
            response = events_create_event_bus(Name=event_bus_name)
            event_source_arn = response["EventBusArn"]

        archive_name_prefix = "test-archive"
        archive_name = f"{archive_name_prefix}-{short_uid()}"
        events_create_archive(
            ArchiveName=archive_name,
            EventSourceArn=event_source_arn,
            Description="description of the archive",
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
            RetentionDays=1,
        )

        response_list_archives_prefix = aws_client.events.list_archives(
            NamePrefix=archive_name_prefix
        )

        snapshot.add_transformer(
            [
                snapshot.transform.regex(event_bus_name, "<event-bus-name>"),
                snapshot.transform.regex(archive_name, "<archive-name>"),
            ]
        )
        snapshot.match("list-archives-with-name-prefix", response_list_archives_prefix)

        response_list_archives_full_name = aws_client.events.list_archives(NamePrefix=archive_name)
        snapshot.match("list-archives-with-full-name", response_list_archives_full_name)

        response_list_not_existing_archive = aws_client.events.list_archives(
            NamePrefix="doesnotexist"
        )
        snapshot.match("list-archives-not-existing-archive", response_list_not_existing_archive)

    @markers.aws.validated
    @pytest.mark.parametrize("event_bus_type", ["default", "custom"])
    def test_list_archive_with_source_arn(
        self,
        event_bus_type,
        region_name,
        account_id,
        events_create_event_bus,
        events_create_archive,
        aws_client,
        snapshot,
    ):
        if event_bus_type == "default":
            event_bus_name = "default"
            event_source_arn = f"arn:aws:events:{region_name}:{account_id}:event-bus/default"
        if event_bus_type == "custom":
            event_bus_name = f"test-bus-{short_uid()}"
            response = events_create_event_bus(Name=event_bus_name)
            event_source_arn = response["EventBusArn"]

        archive_name = f"test-archive-{short_uid()}"
        events_create_archive(
            ArchiveName=archive_name,
            EventSourceArn=event_source_arn,
            Description="description of the archive",
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
            RetentionDays=1,
        )

        response_list_archives_source_arn = aws_client.events.list_archives(
            EventSourceArn=event_source_arn
        )

        snapshot.add_transformer(
            [
                snapshot.transform.regex(event_bus_name, "<event-bus-name>"),
                snapshot.transform.regex(archive_name, "<archive-name>"),
            ]
        )
        snapshot.match("list-archives-with-source-arn", response_list_archives_source_arn)

    @markers.aws.validated
    @pytest.mark.parametrize("event_bus_type", ["default", "custom"])
    def test_list_archive_state_enabled(
        self,
        event_bus_type,
        region_name,
        account_id,
        events_create_event_bus,
        events_create_archive,
        aws_client,
        snapshot,
    ):
        if event_bus_type == "default":
            event_bus_name = "default"
            event_source_arn = f"arn:aws:events:{region_name}:{account_id}:event-bus/default"
        if event_bus_type == "custom":
            event_bus_name = f"test-bus-{short_uid()}"
            response = events_create_event_bus(Name=event_bus_name)
            event_source_arn = response["EventBusArn"]

        archive_name = f"test-archive-{short_uid()}"
        events_create_archive(
            ArchiveName=archive_name,
            EventSourceArn=event_source_arn,
            Description="description of the archive",
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
            RetentionDays=1,
        )

        response_list_archives = aws_client.events.list_archives(State="ENABLED")
        snapshot.add_transformer(
            [
                snapshot.transform.regex(event_bus_name, "<event-bus-name>"),
                snapshot.transform.regex(archive_name, "<archive-name>"),
            ]
        )
        snapshot.match("list-archives-state-enabled", response_list_archives)

    @markers.aws.validated
    # the archive seams to persist events also after deletion of the archive
    # and restores them if recreated for the same event source arn
    @pytest.mark.parametrize("event_bus_type", ["default", "custom"])
    @pytest.mark.parametrize("archive_pattern_match", [True, False])
    def test_list_archive_with_events(
        self,
        event_bus_type,
        archive_pattern_match,
        region_name,
        account_id,
        events_create_event_bus,
        events_create_archive,
        aws_client,
        put_events_with_filter_to_sqs,
        snapshot,
    ):
        if event_bus_type == "default":
            event_bus_name = "default"
            event_source_arn = f"arn:aws:events:{region_name}:{account_id}:event-bus/default"
        if event_bus_type == "custom":
            event_bus_name = f"test-bus-{short_uid()}"
            response = events_create_event_bus(Name=event_bus_name)
            event_source_arn = response["EventBusArn"]

        archive_name = f"test-archive-{short_uid()}"
        if archive_pattern_match:
            events_create_archive(
                ArchiveName=archive_name,
                EventSourceArn=event_source_arn,
                Description="description of the archive",
                EventPattern=json.dumps(TEST_EVENT_PATTERN),
                RetentionDays=1,
            )
        else:
            events_create_archive(
                ArchiveName=archive_name,
                EventSourceArn=event_source_arn,
                Description="description of the archive",
                RetentionDays=1,
            )

        num_events = 10

        entries = []
        for _ in range(num_events):
            entry = {
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps(EVENT_DETAIL),
            }
            entries.append(entry)

        put_events_with_filter_to_sqs(
            pattern=TEST_EVENT_PATTERN,
            entries_asserts=[(entries, True)],
            event_bus_name=event_bus_name,
        )

        def wait_for_archive_event_count():
            response = aws_client.events.describe_archive(ArchiveName=archive_name)
            event_count = response["EventCount"]
            assert event_count == num_events

        retry(
            wait_for_archive_event_count, retries=35, sleep=10
        )  # events are batched and sent to the archive, this mostly takes at least 5 minutes on AWS

        snapshot.add_transformer(
            [
                snapshot.transform.regex(event_bus_name, "<event-bus-name>"),
                snapshot.transform.regex(archive_name, "<archive-name>"),
            ]
        )
        response_list_archives = aws_client.events.list_archives()
        snapshot.match("list-archives", response_list_archives)

        response_describe_archive = aws_client.events.describe_archive(ArchiveName=archive_name)
        snapshot.match("describe-archive", response_describe_archive)

    # Tests Errors
    @markers.aws.validated
    @pytest.mark.parametrize("event_bus_type", ["default", "custom"])
    def test_create_archive_error_duplicate(
        self,
        event_bus_type,
        events_create_event_bus,
        region_name,
        account_id,
        events_create_archive,
        aws_client,
        snapshot,
    ):
        if event_bus_type == "default":
            event_bus_name = "default"
            event_source_arn = f"arn:aws:events:{region_name}:{account_id}:event-bus/default"
        if event_bus_type == "custom":
            event_bus_name = f"test-bus-{short_uid()}"
            response = events_create_event_bus(Name=event_bus_name)
            event_source_arn = response["EventBusArn"]

        archive_name = f"test-archive-{short_uid()}"
        events_create_archive(
            ArchiveName=archive_name,
            EventSourceArn=event_source_arn,
            Description="description of the archive",
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
            RetentionDays=1,
        )
        with pytest.raises(Exception) as error:
            aws_client.events.create_archive(
                ArchiveName=archive_name,
                EventSourceArn=event_source_arn,
                Description="description of the archive",
                EventPattern=json.dumps(TEST_EVENT_PATTERN),
                RetentionDays=1,
            )

        snapshot.add_transformer([snapshot.transform.regex(archive_name, "<archive-name>")])
        snapshot.match("create-archive-duplicate-error", error)

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
        snapshot.match("create-archive-unknown-event-bus-error", error)

    @markers.aws.validated
    def test_describe_archive_error_unknown_archive(self, aws_client, snapshot):
        not_existing_archive_name = f"doesnotexist-{short_uid()}"
        with pytest.raises(Exception) as error:
            aws_client.events.describe_archive(ArchiveName=not_existing_archive_name)

        snapshot.add_transformer(
            [snapshot.transform.regex(not_existing_archive_name, "<archive-name>")]
        )
        snapshot.match("describe-archive-unknown-archive-error", error)

    @markers.aws.validated
    def test_list_archive_error_unknown_source_arn(
        self, region_name, account_id, aws_client, snapshot
    ):
        not_existing_event_bus_name = f"doesnotexist-{short_uid()}"
        non_existing_event_bus_arn = (
            f"arn:aws:events:{region_name}:{account_id}:event-bus/{not_existing_event_bus_name}"
        )
        with pytest.raises(Exception) as error:
            aws_client.events.list_archives(EventSourceArn=non_existing_event_bus_arn)

        snapshot.add_transformer(
            [snapshot.transform.regex(not_existing_event_bus_name, "<event-bus-name>")]
        )
        snapshot.match("list-archives-unknown-event-bus-error", error)

    @markers.aws.validated
    def test_update_archive_error_unknown_archive(self, aws_client, snapshot):
        not_existing_archive_name = f"doesnotexist-{short_uid()}"
        with pytest.raises(Exception) as error:
            aws_client.events.update_archive(ArchiveName=not_existing_archive_name)

        snapshot.add_transformer(
            [snapshot.transform.regex(not_existing_archive_name, "<archive-name>")]
        )
        snapshot.match("update-archive-unknown-archive-error", error)

    @markers.aws.validated
    def test_delete_archive_error_unknown_archive(self, aws_client, snapshot):
        not_existing_archive_name = f"doesnotexist-{short_uid()}"
        with pytest.raises(Exception) as error:
            aws_client.events.delete_archive(ArchiveName=not_existing_archive_name)

        snapshot.add_transformer(
            [snapshot.transform.regex(not_existing_archive_name, "<archive-name>")]
        )
        snapshot.match("delete-archive-unknown-archive-error", error)

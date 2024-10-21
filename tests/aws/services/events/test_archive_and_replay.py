import json
from datetime import datetime, timedelta, timezone

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.aws.services.events.helper_functions import (
    is_old_provider,
    sqs_collect_messages,
    wait_for_replay_in_state,
)
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
        events_create_default_or_custom_event_bus,
        events_create_archive,
        aws_client,
        snapshot,
    ):
        event_bus_name, event_bus_arn = events_create_default_or_custom_event_bus(event_bus_type)

        archive_name = f"test-archive-{short_uid()}"
        response_create_archive = events_create_archive(
            ArchiveName=archive_name,
            EventSourceArn=event_bus_arn,  # ARN of the source event bus
            Description="description of the archive",
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
            RetentionDays=1,
        )
        # TODO list rule created for archive

        snapshot.add_transformer(
            [
                snapshot.transform.regex(event_bus_name, "<event-bus-name>"),
                snapshot.transform.regex(archive_name, "<archive-name>"),
            ]
        )

        snapshot.match("create-archive", response_create_archive)

        response_list_archives = aws_client.events.list_archives(NamePrefix=archive_name)
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

        response_delete_archive = aws_client.events.delete_archive(
            ArchiveName=archive_name
        )  # TODO test delete archive with active replay
        snapshot.match("delete-archive", response_delete_archive)

    @markers.aws.validated
    @pytest.mark.parametrize("event_bus_type", ["default", "custom"])
    def test_list_archive_with_name_prefix(
        self,
        event_bus_type,
        events_create_default_or_custom_event_bus,
        events_create_archive,
        aws_client,
        snapshot,
    ):
        event_bus_name, event_bus_arn = events_create_default_or_custom_event_bus(event_bus_type)

        archive_name_prefix = "test-archive"
        archive_name = f"{archive_name_prefix}-{short_uid()}"
        events_create_archive(
            ArchiveName=archive_name,
            EventSourceArn=event_bus_arn,
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
        events_create_default_or_custom_event_bus,
        events_create_archive,
        aws_client,
        snapshot,
    ):
        event_bus_name, event_bus_arn = events_create_default_or_custom_event_bus(event_bus_type)

        archive_name = f"test-archive-{short_uid()}"
        events_create_archive(
            ArchiveName=archive_name,
            EventSourceArn=event_bus_arn,
            Description="description of the archive",
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
            RetentionDays=1,
        )

        response_list_archives_source_arn = aws_client.events.list_archives(
            EventSourceArn=event_bus_arn
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
        events_create_default_or_custom_event_bus,
        events_create_archive,
        aws_client,
        snapshot,
    ):
        event_bus_name, event_bus_arn = events_create_default_or_custom_event_bus(event_bus_type)

        archive_name = f"test-archive-{short_uid()}"
        events_create_archive(
            ArchiveName=archive_name,
            EventSourceArn=event_bus_arn,
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
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
    # TODO test with input path and input transformer
    @pytest.mark.parametrize("event_bus_type", ["default", "custom"])
    @pytest.mark.parametrize("archive_pattern_match", [True, False])
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..SizeBytes"]
    )  # TODO currently not possible to accurately predict the size of the archive
    def test_list_archive_with_events(
        self,
        event_bus_type,
        archive_pattern_match,
        events_create_default_or_custom_event_bus,
        events_create_archive,
        aws_client,
        put_events_with_filter_to_sqs,
        snapshot,
    ):
        event_bus_name, event_bus_arn = events_create_default_or_custom_event_bus(event_bus_type)

        archive_name = f"test-archive-{short_uid()}"
        if archive_pattern_match:
            events_create_archive(
                ArchiveName=archive_name,
                EventSourceArn=event_bus_arn,
                Description="description of the archive",
                EventPattern=json.dumps(TEST_EVENT_PATTERN),
                RetentionDays=1,
            )
        else:
            events_create_archive(
                ArchiveName=archive_name,
                EventSourceArn=event_bus_arn,
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

        response_list_archives = aws_client.events.list_archives(NamePrefix=archive_name)
        snapshot.match("list-archives", response_list_archives)

        response_describe_archive = aws_client.events.describe_archive(ArchiveName=archive_name)
        snapshot.match("describe-archive", response_describe_archive)

    # Tests Errors
    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
    @pytest.mark.parametrize("event_bus_type", ["default", "custom"])
    def test_create_archive_error_duplicate(
        self,
        event_bus_type,
        events_create_default_or_custom_event_bus,
        events_create_archive,
        aws_client,
        snapshot,
    ):
        _, event_bus_arn = events_create_default_or_custom_event_bus(event_bus_type)

        archive_name = f"test-archive-{short_uid()}"
        events_create_archive(
            ArchiveName=archive_name,
            EventSourceArn=event_bus_arn,
            Description="description of the archive",
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
            RetentionDays=1,
        )
        with pytest.raises(Exception) as error:
            aws_client.events.create_archive(
                ArchiveName=archive_name,
                EventSourceArn=event_bus_arn,
                Description="description of the archive",
                EventPattern=json.dumps(TEST_EVENT_PATTERN),
                RetentionDays=1,
            )

        snapshot.add_transformer([snapshot.transform.regex(archive_name, "<archive-name>")])
        snapshot.match("create-archive-duplicate-error", error)

    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
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
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
    def test_describe_archive_error_unknown_archive(self, aws_client, snapshot):
        not_existing_archive_name = f"doesnotexist-{short_uid()}"
        with pytest.raises(Exception) as error:
            aws_client.events.describe_archive(ArchiveName=not_existing_archive_name)

        snapshot.add_transformer(
            [snapshot.transform.regex(not_existing_archive_name, "<archive-name>")]
        )
        snapshot.match("describe-archive-unknown-archive-error", error)

    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
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
    @pytest.mark.skip(reason="not possible to test with localstack")
    def test_update_archive_error_unknown_archive(self, aws_client, snapshot):
        not_existing_archive_name = f"doesnotexist-{short_uid()}"
        with pytest.raises(Exception) as error:
            aws_client.events.update_archive(ArchiveName=not_existing_archive_name)

        snapshot.add_transformer(
            [snapshot.transform.regex(not_existing_archive_name, "<archive-name>")]
        )
        snapshot.match("update-archive-unknown-archive-error", error)

    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
    def test_delete_archive_error_unknown_archive(self, aws_client, snapshot):
        not_existing_archive_name = f"doesnotexist-{short_uid()}"
        with pytest.raises(Exception) as error:
            aws_client.events.delete_archive(ArchiveName=not_existing_archive_name)

        snapshot.add_transformer(
            [snapshot.transform.regex(not_existing_archive_name, "<archive-name>")]
        )
        snapshot.match("delete-archive-unknown-archive-error", error)


class TestReplay:
    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
    @pytest.mark.parametrize("event_bus_type", ["default", "custom"])
    @pytest.mark.skip_snapshot_verify(paths=["$..State"])
    def test_start_list_describe_canceled_replay(
        self,
        event_bus_type,
        events_create_default_or_custom_event_bus,
        events_put_rule,
        sqs_as_events_target,
        put_event_to_archive,
        aws_client,
        snapshot,
    ):
        event_start_time = datetime.now(timezone.utc)
        event_end_time = event_start_time + timedelta(minutes=1)

        # setup event bus
        event_bus_name, event_bus_arn = events_create_default_or_custom_event_bus(event_bus_type)

        # setup rule
        rule_name = f"test-rule-{short_uid()}"
        response = events_put_rule(
            Name=rule_name,
            EventBusName=event_bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        rule_arn = response["RuleArn"]

        # setup sqs target
        queue_url, queue_arn = sqs_as_events_target()
        target_id = f"target-{short_uid()}"
        aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=event_bus_name,
            Targets=[
                {"Id": target_id, "Arn": queue_arn},
            ],
        )

        # put events to archive
        num_events = 3
        entries = []
        for _ in range(num_events):
            entry = {
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps(EVENT_DETAIL),
                "EventBusName": event_bus_name,
            }
            entries.append(entry)

        archive_name = f"test-archive-{short_uid()}"
        archive_arn = put_event_to_archive(
            archive_name,
            TEST_EVENT_PATTERN,
            event_bus_name,
            event_bus_arn,
            entries,
        )["ArchiveArn"]
        sqs_collect_messages(
            aws_client, queue_url, expected_events_count=num_events, wait_time=5, retries=12
        )  # reset queue for replay

        # start replay
        replay_name = f"test-replay-{short_uid()}"
        response_start_replay = aws_client.events.start_replay(
            ReplayName=replay_name,
            Description="description of the replay",
            EventSourceArn=archive_arn,
            EventStartTime=event_start_time,
            EventEndTime=event_end_time,
            Destination={
                "Arn": event_bus_arn,
                "FilterArns": [
                    rule_arn,
                ],
            },
        )

        snapshot.add_transformer(
            [
                snapshot.transform.regex(event_bus_name, "<event-bus-name>"),
                snapshot.transform.regex(rule_name, "<rule-name>"),
                snapshot.transform.regex(archive_name, "<archive-name>"),
                snapshot.transform.regex(replay_name, "<replay-name>"),
                snapshot.transform.key_value("ReceiptHandle", reference_replacement=False),
                snapshot.transform.key_value("MD5OfBody", reference_replacement=False),
                snapshot.transform.key_value("ReplayName", reference_replacement=False),
            ]
        )
        snapshot.match("start-replay", response_start_replay)

        # replaying an archive mostly takes at least 5 minutes on AWS
        wait_for_replay_in_state(aws_client, replay_name, "COMPLETED", retries=35, sleep=10)

        # fetch messages from sqs
        messages_replay = sqs_collect_messages(
            aws_client, queue_url, num_events, wait_time=5, retries=12
        )

        snapshot.match("replay-messages", messages_replay)

        response_list_replays = aws_client.events.list_replays(NamePrefix=replay_name)
        snapshot.match("list-replays", response_list_replays)

        response_describe_replay = aws_client.events.describe_replay(ReplayName=replay_name)
        snapshot.match("describe-replay", response_describe_replay)

        replay_canceled_name = f"test-replay-canceled-{short_uid()}"
        aws_client.events.start_replay(
            ReplayName=replay_canceled_name,
            Description="description of the replay",
            EventSourceArn=archive_arn,
            EventStartTime=event_start_time,
            EventEndTime=event_end_time,
            Destination={
                "Arn": event_bus_arn,
                "FilterArns": [
                    rule_arn,
                ],
            },
        )

        response_cancel_replay = aws_client.events.cancel_replay(ReplayName=replay_canceled_name)
        snapshot.add_transformer(
            snapshot.transform.regex(replay_canceled_name, "<replay-canceled-name>")
        )
        snapshot.match("cancel-replay", response_cancel_replay)

        response_describe_replay_canceled = aws_client.events.describe_replay(
            ReplayName=replay_canceled_name
        )
        snapshot.match("describe-replay-canceled", response_describe_replay_canceled)

    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
    def test_list_replays_with_prefix(
        self, events_create_archive, events_create_event_bus, aws_client, snapshot
    ):
        event_start_time = datetime.now(timezone.utc)
        event_end_time = event_start_time + timedelta(minutes=1)

        event_bus_name = f"test-bus-{short_uid()}"
        event_bus_arn = events_create_event_bus(Name=event_bus_name)["EventBusArn"]
        archive_arn = events_create_archive(
            EventSourceArn=event_bus_arn,
            RetentionDays=1,
        )["ArchiveArn"]

        replay_name_prefix = (
            short_uid()  # prefix must be unique since replays are stored 90 days
        )
        replay_name = f"{replay_name_prefix}-test-replay"
        aws_client.events.start_replay(
            ReplayName=replay_name,
            EventSourceArn=archive_arn,
            EventStartTime=event_start_time,
            EventEndTime=event_end_time,
            Destination={
                "Arn": event_bus_arn,
            },
        )

        wait_for_replay_in_state(aws_client, replay_name, "COMPLETED", retries=35, sleep=10)

        replay_name_second = f"{short_uid()}-this-replay-should-not-be-listed"
        aws_client.events.start_replay(
            ReplayName=replay_name_second,
            EventSourceArn=archive_arn,
            EventStartTime=event_start_time,
            EventEndTime=event_end_time,
            Destination={
                "Arn": event_bus_arn,
            },
        )

        response_list_replays_full_name = aws_client.events.list_replays(NamePrefix=replay_name)

        snapshot.add_transformer(
            [
                snapshot.transform.regex(replay_name_prefix, "<replay-name-prefix>"),
                snapshot.transform.regex(archive_arn, "<archive-arn>"),
            ]
        )
        snapshot.match("list-replays-with-full-name", response_list_replays_full_name)

        response_list_replays_prefix = aws_client.events.list_replays(NamePrefix=replay_name_prefix)
        snapshot.match("list-replays-with-prefix", response_list_replays_prefix)

    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
    def test_list_replays_with_event_source_arn(
        self, events_create_event_bus, events_create_archive, aws_client, snapshot
    ):
        event_start_time = datetime.now(timezone.utc)
        event_end_time = event_start_time + timedelta(minutes=1)

        event_bus_name = f"test-bus-{short_uid()}"
        event_bus_arn = events_create_event_bus(Name=event_bus_name)["EventBusArn"]
        archive_arn = events_create_archive(
            EventSourceArn=event_bus_arn,
            RetentionDays=1,
        )["ArchiveArn"]

        replay_name = f"test-replay-{short_uid()}"
        aws_client.events.start_replay(
            ReplayName=replay_name,
            EventSourceArn=archive_arn,
            EventStartTime=event_start_time,
            EventEndTime=event_end_time,
            Destination={
                "Arn": event_bus_arn,
            },
        )

        wait_for_replay_in_state(aws_client, replay_name, "COMPLETED", retries=35, sleep=10)

        response_list_replays = aws_client.events.list_replays(EventSourceArn=archive_arn)

        snapshot.add_transformer(
            [
                snapshot.transform.regex(replay_name, "<replay-name>"),
                snapshot.transform.regex(archive_arn, "<archive-arn>"),
            ]
        )
        snapshot.match("list-replays-with-event-source-arn", response_list_replays)

    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
    def test_list_replay_with_limit(
        self, events_create_event_bus, events_create_archive, aws_client, snapshot
    ):
        event_start_time = datetime.now(timezone.utc)
        event_end_time = event_start_time + timedelta(minutes=1)

        event_bus_name = f"test-bus-{short_uid()}"
        event_bus_arn = events_create_event_bus(Name=event_bus_name)["EventBusArn"]

        archive_name = f"test-archive-{short_uid()}"
        archive_arn = events_create_archive(
            ArchiveName=archive_name,
            EventSourceArn=event_bus_arn,
            RetentionDays=1,
        )["ArchiveArn"]

        replay_name_prefix = short_uid()

        num_replays = 6
        for i in range(num_replays):
            replay_name = f"{replay_name_prefix}-test-replay-{i}"
            aws_client.events.start_replay(
                ReplayName=replay_name,
                Description="description of the replay",
                EventSourceArn=archive_arn,
                EventStartTime=event_start_time,
                EventEndTime=event_end_time,
                Destination={
                    "Arn": event_bus_arn,
                },
            )
            wait_for_replay_in_state(aws_client, replay_name, "COMPLETED", retries=35, sleep=10)

        response = aws_client.events.list_replays(
            Limit=int(num_replays / 2), NamePrefix=replay_name_prefix
        )
        snapshot.add_transformer(
            [
                snapshot.transform.regex(replay_name_prefix, "<replay-name-prefix>"),
                snapshot.transform.regex(archive_name, "<archive-name>"),
                snapshot.transform.jsonpath("$..NextToken", "next_token"),
            ]
        )
        snapshot.match("list-replays-with-limit", response)

        response = aws_client.events.list_replays(
            Limit=int(num_replays / 2) + 2,
            NextToken=response["NextToken"],
            NamePrefix=replay_name_prefix,
        )
        snapshot.match("list-replays-with-limit-next-token", response)

    # Tests Errors
    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
    def test_start_replay_error_unknown_event_bus(
        self,
        events_create_archive,
        region_name,
        account_id,
        events_create_event_bus,
        aws_client,
        snapshot,
    ):
        archive_arn = events_create_archive(
            RetentionDays=1,
        )["ArchiveArn"]

        not_existing_event_bus_name = f"doesnotexist-{short_uid()}"
        not_existing_event_bus_arn = (
            f"arn:aws:events:{region_name}:{account_id}:event-bus/{not_existing_event_bus_name}"
        )

        start_time = datetime.now(timezone.utc) - timedelta(minutes=1)
        end_time = datetime.now(timezone.utc)

        replay_name = f"test-replay-{short_uid()}"
        with pytest.raises(Exception) as error:
            aws_client.events.start_replay(
                ReplayName=replay_name,
                Description="description of the replay",
                EventSourceArn=archive_arn,
                EventStartTime=start_time,
                EventEndTime=end_time,
                Destination={
                    "Arn": not_existing_event_bus_arn,
                },  # the destination must be the exact same event bus the archive is created for
            )

        snapshot.add_transformer(
            [snapshot.transform.regex(not_existing_event_bus_name, "<event-bus-name>")]
        )
        snapshot.match("start-replay-unknown-event-bus-error", error)

        event_bus_arn = events_create_event_bus(Name=not_existing_event_bus_name)["EventBusArn"]

        with pytest.raises(Exception) as error:
            aws_client.events.start_replay(
                ReplayName=replay_name,
                Description="description of the replay",
                EventSourceArn=archive_arn,
                EventStartTime=start_time,
                EventEndTime=end_time,
                Destination={
                    "Arn": event_bus_arn,
                },  # the destination must be the exact same event bus the archive is created for
            )

        snapshot.match("start-replay-wrong-event-bus-error", error)

    @markers.aws.validated
    def test_start_replay_error_unknown_archive(
        self, aws_client, region_name, account_id, snapshot
    ):
        not_existing_archive_name = f"doesnotexist-{short_uid()}"
        start_time = datetime.now(timezone.utc) - timedelta(minutes=1)
        end_time = datetime.now(timezone.utc)
        with pytest.raises(Exception) as error:
            aws_client.events.start_replay(
                ReplayName="test-replay",
                Description="description of the replay",
                EventSourceArn=f"arn:aws:events:{region_name}:{account_id}:archive/{not_existing_archive_name}",
                EventStartTime=start_time,
                EventEndTime=end_time,
                Destination={
                    "Arn": f"arn:aws:events:{region_name}:{account_id}:event-bus/default",
                },
            )

        snapshot.add_transformer(
            [snapshot.transform.regex(not_existing_archive_name, "<archive-name>")]
        )
        snapshot.match("start-replay-unknown-archive-error", error)

    @markers.aws.validated
    def test_start_replay_error_duplicate_name_same_archive(
        self, events_create_archive, aws_client, snapshot
    ):
        event_bus_name = f"test-bus-{short_uid()}"
        event_bus_arn = aws_client.events.create_event_bus(Name=event_bus_name)["EventBusArn"]

        archive_arn = events_create_archive(EventSourceArn=event_bus_arn, RetentionDays=1)[
            "ArchiveArn"
        ]

        replay_name = f"test-replay-{short_uid()}"
        start_time = datetime.now(timezone.utc) - timedelta(minutes=1)
        end_time = datetime.now(timezone.utc)
        aws_client.events.start_replay(
            ReplayName=replay_name,
            Description="description of the replay",
            EventSourceArn=archive_arn,
            EventStartTime=start_time,
            EventEndTime=end_time,
            Destination={
                "Arn": event_bus_arn,
            },
        )

        with pytest.raises(Exception) as error:
            aws_client.events.start_replay(
                ReplayName=replay_name,
                Description="description of the replay",
                EventSourceArn=archive_arn,
                EventStartTime=start_time,
                EventEndTime=end_time,
                Destination={
                    "Arn": event_bus_arn,
                },
            )

        snapshot.add_transformer([snapshot.transform.regex(replay_name, "<replay-name>")])
        snapshot.match("start-replay-duplicate-error", error)

    @markers.aws.validated
    def test_start_replay_error_duplicate_different_archive(
        self, events_create_archive, aws_client, snapshot
    ):
        event_bus_name_one = f"test-bus-{short_uid()}"
        event_bus_arn_one = aws_client.events.create_event_bus(Name=event_bus_name_one)[
            "EventBusArn"
        ]
        archive_arn_one = events_create_archive(EventSourceArn=event_bus_arn_one, RetentionDays=1)[
            "ArchiveArn"
        ]
        event_bus_name_two = f"test-bus-{short_uid()}"
        event_bus_arn_two = aws_client.events.create_event_bus(Name=event_bus_name_two)[
            "EventBusArn"
        ]
        archive_arn_two = events_create_archive(EventSourceArn=event_bus_arn_two, RetentionDays=1)[
            "ArchiveArn"
        ]

        start_time = datetime.now(timezone.utc) - timedelta(minutes=1)
        end_time = datetime.now(timezone.utc)

        replay_name = f"test-replay-{short_uid()}"
        aws_client.events.start_replay(
            ReplayName=replay_name,
            Description="description of the replay",
            EventSourceArn=archive_arn_one,
            EventStartTime=start_time,
            EventEndTime=end_time,
            Destination={
                "Arn": event_bus_arn_one,
            },
        )

        with pytest.raises(Exception) as error:
            aws_client.events.start_replay(
                ReplayName=replay_name,
                Description="description of the replay",
                EventSourceArn=archive_arn_two,
                EventStartTime=start_time,
                EventEndTime=end_time,
                Destination={
                    "Arn": event_bus_arn_two,
                },
            )

        snapshot.add_transformer([snapshot.transform.regex(replay_name, "<replay-name>")])
        snapshot.match("start-replay-duplicate-error", error)

    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
    @pytest.mark.parametrize("negative_time_delta_seconds", [0, 10])
    def test_start_replay_error_invalid_end_time(
        self, negative_time_delta_seconds, events_create_archive, aws_client, snapshot
    ):
        event_bus_name = f"test-bus-{short_uid()}"
        event_bus_arn = aws_client.events.create_event_bus(Name=event_bus_name)["EventBusArn"]

        response = events_create_archive()
        archive_arn = response["ArchiveArn"]

        start_time = datetime.now(timezone.utc)
        end_time = start_time.replace(microsecond=0) - timedelta(
            seconds=negative_time_delta_seconds
        )

        replay_name = f"test-replay-{short_uid()}"
        with pytest.raises(Exception) as error:
            aws_client.events.start_replay(
                ReplayName=replay_name,
                Description="description of the replay",
                EventSourceArn=archive_arn,
                EventStartTime=start_time,
                EventEndTime=end_time,
                Destination={
                    "Arn": event_bus_arn,
                },
            )

        snapshot.match("start-replay-invalid-end-time-error", error)

    @markers.aws.validated
    @pytest.mark.skip(reason="currently no concurrency for replays in localstack")
    def tests_concurrency_error_too_many_active_replays(
        self, events_create_event_bus, events_create_archive, aws_client, snapshot
    ):
        event_bus_name = f"test-bus-{short_uid()}"
        event_bus_arn = events_create_event_bus(Name=event_bus_name)["EventBusArn"]

        archive_name = f"test-archive-{short_uid()}"
        archive_arn = events_create_archive(
            ArchiveName=archive_name,
            EventSourceArn=event_bus_arn,
            RetentionDays=1,
        )["ArchiveArn"]

        replay_name_prefix = short_uid()
        start_time = datetime.now(timezone.utc) - timedelta(minutes=1)
        end_time = datetime.now(timezone.utc)

        num_replays = 10
        for i in range(num_replays):
            replay_name = f"{replay_name_prefix}-test-replay-{i}"
            aws_client.events.start_replay(
                ReplayName=replay_name,
                Description="description of the replay",
                EventSourceArn=archive_arn,
                EventStartTime=start_time,
                EventEndTime=end_time,
                Destination={
                    "Arn": event_bus_arn,
                },
            )

        # only 10 replays are allowed to be in state STARTING or RUNNING at the same time
        with pytest.raises(Exception) as error:
            replay_name = f"{replay_name_prefix}-test-replay-{num_replays}"
            aws_client.events.start_replay(
                ReplayName=replay_name,
                Description="description of the replay",
                EventSourceArn=archive_arn,
                EventStartTime=start_time,
                EventEndTime=end_time,
                Destination={
                    "Arn": event_bus_arn,
                },
            )

        snapshot.add_transformer(
            [
                snapshot.transform.regex(replay_name_prefix, "<replay-name-prefix>"),
                snapshot.transform.regex(archive_name, "<archive-name>"),
                snapshot.transform.jsonpath("$..NextToken", "next_token"),
            ]
        )
        snapshot.match("list-replays-with-limit", error)

    @markers.aws.validated
    def test_describe_replay_error_unknown_replay(self, aws_client, snapshot):
        not_existing_replay_name = f"doesnotexist-{short_uid()}"
        with pytest.raises(Exception) as error:
            aws_client.events.describe_replay(ReplayName=not_existing_replay_name)

        snapshot.add_transformer(
            [snapshot.transform.regex(not_existing_replay_name, "<replay-name>")]
        )
        snapshot.match("describe-replay-unknown-replay-error", error)

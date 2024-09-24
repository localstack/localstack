import json
import os
from datetime import datetime, timedelta, timezone

from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.sync import retry


def is_v2_provider():
    return os.environ.get("PROVIDER_OVERRIDE_EVENTS") == "v2" and not is_aws_cloud()


def is_old_provider():
    return (
        "PROVIDER_OVERRIDE_EVENTS" not in os.environ
        or os.environ.get("PROVIDER_OVERRIDE_EVENTS") != "v2"
    )


def events_time_string_to_timestamp(time_string: str) -> datetime:
    time_string_format = "%Y-%m-%dT%H:%M:%SZ"
    return datetime.strptime(time_string, time_string_format)


def get_cron_expression(delta_minutes: int) -> tuple[str, datetime]:
    """Get a exact cron expression for a future time in UTC from now rounded to the next full minute + delta_minutes."""
    now = datetime.now(timezone.utc)
    future_time = now + timedelta(minutes=delta_minutes)

    # Round to the next full minute
    future_time += timedelta(minutes=1)
    future_time = future_time.replace(second=0, microsecond=0)

    cron_string = (
        f"cron({future_time.minute} {future_time.hour} {future_time.day} {future_time.month} ? *)"
    )

    return cron_string, future_time


def put_entries_assert_results_sqs(
    events_client, sqs_client, queue_url: str, entries: list[dict], should_match: bool
):
    """
    Put events to the event bus, receives the messages resulting from the event in the sqs queue and deletes them out of the queue.
    If should_match is True, the content of the messages is asserted to be the same as the events put to the event bus.

    :param events_client: boto3.client("events")
    :param sqs_client: boto3.client("sqs")
    :param queue_url: URL of the sqs queue
    :param entries: List of entries to put to the event bus, each entry must
                    be a dict that contains the keys: "Source", "DetailType", "Detail"
    :param should_match:

    :return: Messages from the queue if should_match is True, otherwise None
    """
    response = events_client.put_events(Entries=entries)
    assert not response.get("FailedEntryCount")

    def get_message(queue_url):
        resp = sqs_client.receive_message(
            QueueUrl=queue_url, WaitTimeSeconds=5, MaxNumberOfMessages=1
        )
        messages = resp.get("Messages")
        if messages:
            for message in messages:
                receipt_handle = message["ReceiptHandle"]
                sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
        if should_match:
            assert len(messages) == 1
        return messages

    messages = retry(get_message, retries=5, queue_url=queue_url)

    if should_match:
        actual_event = json.loads(messages[0]["Body"])
        if isinstance(actual_event, dict) and "detail" in actual_event:
            assert_valid_event(actual_event)
        return messages
    else:
        assert not messages
        return None


def assert_valid_event(event):
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


def sqs_collect_messages(
    aws_client,
    queue_url: str,
    expected_events_count: int,
    wait_time: int = 1,
    retries: int = 3,
) -> list[dict]:
    """
    Polls the given queue for the given amount of time and extracts and flattens from the received messages all
    events (messages that have a "Records" field in their body, and where the records can be json-deserialized).

    :param queue_url: the queue URL to listen from
    :param expected_events_count: the minimum number of events to receive to wait for
    :param wait_time: the number of seconds to wait between retries
    :param retries: the number of retries before raising an assert error
    :return: a list with the deserialized records from the SQS messages
    """

    events = []

    def collect_events() -> None:
        _response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_time
        )
        messages = _response.get("Messages", [])

        for m in messages:
            events.append(m)
            aws_client.sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])

        assert len(events) >= expected_events_count

    retry(collect_events, retries=retries, sleep=0.01)

    return events


def wait_for_replay_in_state(
    aws_client, replay_name: str, expected_state: str, retries: int = 10, sleep: int = 10
) -> bool:
    def _wait_for_state():
        response = aws_client.events.describe_replay(ReplayName=replay_name)
        state = response["State"]
        assert state == expected_state

    return retry(_wait_for_state, retries, sleep)

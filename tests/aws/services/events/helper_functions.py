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


def sqs_collect_messages(
    aws_client,
    queue_url: str,
    min_events: int,
    wait_time: int = 1,
    retries: int = 3,
) -> list[dict]:
    """
    Polls the given queue for the given amount of time and extracts and flattens from the received messages all
    events (messages that have a "Records" field in their body, and where the records can be json-deserialized).

    :param queue_url: the queue URL to listen from
    :param min_events: the minimum number of events to receive to wait for
    :param wait_time: the number of seconds to wait between retries
    :param retries: the number of retries before raising an assert error
    :return: a list with the deserialized records from the SQS messages
    """

    events = []

    def collect_events() -> None:
        _response = aws_client.sqs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=wait_time)
        messages = _response.get("Messages", [])

        for m in messages:
            events.append(m)
            aws_client.sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])

        assert len(events) >= min_events

    retry(collect_events, retries=retries, sleep=0.01)

    return events


def events_connection_wait_for_deleted(aws_client, connection_name: str) -> None:
    def _wait_for_deleted():
        try:
            aws_client.events.describe_connection(Name=connection_name)
        except aws_client.events.exceptions.ResourceNotFoundException:
            return
        raise AssertionError(f"Connection {connection_name} was not deleted")

    retry(_wait_for_deleted, retries=3, sleep=1)

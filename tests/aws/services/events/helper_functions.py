import os
from datetime import datetime, timedelta, timezone

from localstack.testing.aws.util import is_aws_cloud


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
    now = datetime.now(timezone.utc)
    future_time = now + timedelta(minutes=delta_minutes)

    # Round to the next full minute
    future_time += timedelta(minutes=1)
    future_time = future_time.replace(second=0, microsecond=0)

    cron_string = (
        f"cron({future_time.minute} {future_time.hour} {future_time.day} {future_time.month} ? *)"
    )

    return cron_string, future_time

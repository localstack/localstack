import os
from datetime import datetime

from localstack.testing.aws.util import is_aws_cloud


def is_v2_provider():
    return os.environ.get("PROVIDER_OVERRIDE_EVENTS") == "v2" and not is_aws_cloud()


def events_time_string_to_timestamp(time_string: str) -> int:
    time_string_format = "%Y-%m-%dT%H:%M:%SZ"
    return datetime.strptime(time_string, time_string_format)

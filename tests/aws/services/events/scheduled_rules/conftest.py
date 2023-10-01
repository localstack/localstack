from datetime import timedelta

import pytest
import requests

from localstack.config import get_edge_url
from localstack.testing.aws.util import is_aws_cloud


# @pytest.fixture(autouse=True)
def _speed_up_localstack_scheduler(monkeypatch):
    # this hack speeds up the test on localstack, triggering the rule in 5 seconds rather than 1 minute
    from localstack.services.events import scheduler

    monkeypatch.setattr(scheduler, "parse_rate_expression", lambda e: timedelta(seconds=5))


@pytest.fixture
def trigger_scheduled_rule():
    def _trigger(rule_arn: str):
        if is_aws_cloud():
            return

        url = get_edge_url() + f"/_aws/events/rules/{rule_arn}/trigger"
        response = requests.get(url)
        if not response.ok:
            raise ValueError(
                f"Error triggering rule {rule_arn}: {response.status_code},{response.text}"
            )

    return _trigger

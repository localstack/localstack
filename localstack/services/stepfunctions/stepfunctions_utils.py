import logging
import os
from typing import Dict

from localstack.utils.aws import aws_stack
from localstack.utils.common import retry

LOG = logging.getLogger(__name__)


def await_sfn_execution_result(execution_arn: str, timeout_secs: int = 60) -> Dict:
    """Wait until the given SFN execution ARN is no longer in RUNNING status, then return execution result."""

    client = aws_stack.connect_to_service("stepfunctions")

    def _get_result():
        result = client.describe_execution(executionArn=execution_arn)
        assert result["status"] != "RUNNING"
        return result

    return retry(_get_result, sleep=2, retries=timeout_secs / 2)


def is_old_provider():
    return (
        os.environ.get("TEST_TARGET") != "AWS_CLOUD"
        and os.environ.get("PROVIDER_OVERRIDE_STEPFUNCTIONS") != "v2"
    )


def is_new_provider():
    return not is_old_provider()

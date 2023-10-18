import logging
from typing import Dict

from localstack.aws.connect import connect_to
from localstack.utils.aws.arns import parse_arn
from localstack.utils.common import retry

LOG = logging.getLogger(__name__)


def await_sfn_execution_result(execution_arn: str, timeout_secs: int = 60) -> Dict:
    """Wait until the given SFN execution ARN is no longer in RUNNING status, then return execution result."""

    arn_data = parse_arn(execution_arn)

    client = connect_to(
        aws_access_key_id=arn_data["account"], region_name=arn_data["region"]
    ).stepfunctions

    def _get_result():
        result = client.describe_execution(executionArn=execution_arn)
        assert result["status"] != "RUNNING"
        return result

    return retry(_get_result, sleep=2, retries=timeout_secs / 2)

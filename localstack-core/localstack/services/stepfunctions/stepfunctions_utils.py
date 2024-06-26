import base64
import logging
from typing import Dict

from localstack.aws.api.stepfunctions import ValidationException
from localstack.aws.connect import connect_to
from localstack.utils.aws.arns import parse_arn
from localstack.utils.common import retry
from localstack.utils.strings import to_bytes, to_str

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


def get_next_page_token_from_arn(resource_arn: str) -> str:
    return to_str(base64.b64encode(to_bytes(resource_arn)))


_DEFAULT_SFN_MAX_RESULTS: int = 100


def validate_and_prepare_pagination_params(
    max_results: int = 100,
    next_token: str = None,
    next_token_length_limit: int = 1024,
    max_results_upper_limit: int = 1000,
) -> tuple[int, str]:
    validation_errors = []

    match max_results:
        case None | 0:
            max_results = _DEFAULT_SFN_MAX_RESULTS
        case int() if max_results > max_results_upper_limit:
            validation_errors.append(
                f"Value '{max_results}' at 'maxResults' failed to satisfy constraint: "
                f"Member must have value less than or equal to {max_results_upper_limit}"
            )

    match next_token:
        case str() if len(next_token) > next_token_length_limit:
            validation_errors.append(
                f"Value '{next_token}' at 'nextToken' failed to satisfy constraint: "
                f"Member must have length less than or equal to {next_token_length_limit}"
            )

    if validation_errors:
        errors_message = "; ".join(validation_errors)
        message = f"{len(validation_errors)} validation {'errors' if len(validation_errors) > 1 else 'error'} detected: {errors_message}"
        raise ValidationException(message)

    return max_results, next_token

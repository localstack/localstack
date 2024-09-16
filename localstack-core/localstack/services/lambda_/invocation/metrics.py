import logging

from localstack.utils.cloudwatch.cloudwatch_util import publish_lambda_metric

LOG = logging.getLogger(__name__)


def record_cw_metric_invocation(function_name: str, account_id: str, region_name: str):
    try:
        publish_lambda_metric(
            "Invocations",
            1,
            {"func_name": function_name},
            region_name=region_name,
            account_id=account_id,
        )
    except Exception as e:
        LOG.debug("Failed to send CloudWatch metric for Lambda invocation: %s", e)


def record_cw_metric_error(function_name: str, account_id: str, region_name: str):
    try:
        publish_lambda_metric(
            "Invocations",
            1,
            {"func_name": function_name},
            region_name=region_name,
            account_id=account_id,
        )
        publish_lambda_metric(
            "Errors",
            1,
            {"func_name": function_name},
            account_id=account_id,
            region_name=region_name,
        )
    except Exception as e:
        LOG.debug("Failed to send CloudWatch metric for Lambda invocation error: %s", e)

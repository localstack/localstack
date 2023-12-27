import logging

from localstack.utils.cloudwatch.cloudwatch_util import publish_lambda_metric

LOG = logging.getLogger(__name__)


def record_cw_metric_invocation(function_name: str, region_name: str, function_arn: str):
    try:
        publish_lambda_metric(
            "Invocations",
            1,
            {"func_name": function_name, "func_arn": function_arn},
            region_name=region_name,
        )
    except Exception as e:
        LOG.debug("Failed to send CloudWatch metric for Lambda invocation: %s", e)


def record_cw_metric_error(function_name: str, region_name: str, function_arn: str):
    try:
        publish_lambda_metric(
            "Invocations",
            1,
            {"func_name": function_name, "func_arn": function_arn},
            region_name=region_name,
        )
        publish_lambda_metric(
            "Errors",
            1,
            {"func_name": function_name, "func_arn": function_arn},
            region_name=region_name,
        )
    except Exception as e:
        LOG.debug("Failed to send CloudWatch metric for Lambda invocation error: %s", e)

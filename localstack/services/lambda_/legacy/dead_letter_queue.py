"""Dead letter queue utils for old Lambda provider extracted from localstack/utils/aws/dead_letter_queue.py"""

from typing import Dict

from localstack.services.lambda_.legacy.aws_models import LambdaFunction
from localstack.utils.aws.dead_letter_queue import _send_to_dead_letter_queue


def lambda_error_to_dead_letter_queue(func_details: LambdaFunction, event: Dict, error):
    dlq_arn = (func_details.dead_letter_config or {}).get("TargetArn")
    source_arn = func_details.id
    _send_to_dead_letter_queue(source_arn, dlq_arn, event, error)

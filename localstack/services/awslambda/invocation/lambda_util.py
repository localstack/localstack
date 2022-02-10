from typing import Optional

from localstack.utils.aws import aws_stack


def qualified_lambda_arn(
    function_name: str, qualifier: Optional[str], account: str, region: str
) -> str:
    partition = aws_stack.get_partition(region)
    qualifier = qualifier or "$LATEST"
    return f"arn:{partition}:lambda:{region}:{account}:function:{function_name}:{qualifier}"

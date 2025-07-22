from localstack.aws.api.lambda_ import Arn
from localstack.services.lambda_.lambda_debug_mode.ldm_types import UnknownLambdaArnFormat


def to_qualified_lambda_function_arn(lambda_arn: Arn) -> Arn:
    """
    Returns the $LATEST qualified version of a structurally unqualified version of a lambda Arn iff this
    is detected to be structurally unqualified. Otherwise, it returns the given string.
    Example:
          - arn:aws:lambda:eu-central-1:000000000000:function:functionname:$LATEST ->
              unchanged

          - arn:aws:lambda:eu-central-1:000000000000:function:functionname ->
              arn:aws:lambda:eu-central-1:000000000000:function:functionname:$LATEST

          - arn:aws:lambda:eu-central-1:000000000000:function:functionname: ->
              exception UnknownLambdaArnFormat

          - arn:aws:lambda:eu-central-1:000000000000:function ->
              exception UnknownLambdaArnFormat
    """
    # TODO: consider adding arn syntax validation at this depth.

    if not lambda_arn:
        return lambda_arn
    lambda_arn_parts = lambda_arn.split(":")
    lambda_arn_parts_len = len(lambda_arn_parts)

    # The arn is qualified and with a non-empy qualifier.
    is_qualified = lambda_arn_parts_len == 8
    if is_qualified and lambda_arn_parts[-1]:
        return lambda_arn

    # Unknown lambda arn format.
    is_unqualified = lambda_arn_parts_len == 7
    if not is_unqualified:
        raise UnknownLambdaArnFormat(unknown_lambda_arn=lambda_arn)

    # Structure-wise, the arn is missing the qualifier.
    qualifier = "$LATEST"
    arn_tail = f":{qualifier}" if is_unqualified else qualifier
    qualified_lambda_arn = lambda_arn + arn_tail
    return qualified_lambda_arn

class LDMException(Exception): ...


class UnknownLambdaArnFormat(LDMException):
    unknown_lambda_arn: str

    def __init__(self, unknown_lambda_arn: str):
        self.unknown_lambda_arn = unknown_lambda_arn

    def __str__(self):
        return f"UnknownLambdaArnFormat: '{self.unknown_lambda_arn}'"

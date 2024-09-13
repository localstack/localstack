class LambdaDebugModeConfigException(Exception): ...


class UnknownLambdaArnFormat(LambdaDebugModeConfigException):
    unknown_lambda_arn: str

    def __init__(self, unknown_lambda_arn: str):
        self.unknown_lambda_arn = unknown_lambda_arn

    def __str__(self):
        return f"UnknownLambdaArnFormat: '{self.unknown_lambda_arn}'"


class PortAlreadyInUse(LambdaDebugModeConfigException):
    port_number: int

    def __init__(self, port_number: int):
        self.port_number = port_number

    def __str__(self):
        return f"PortAlreadyInUse: '{self.port_number}'"


class DuplicateLambdaDebugConfig(LambdaDebugModeConfigException):
    lambda_arn_debug_config_first: str
    lambda_arn_debug_config_second: str

    def __init__(self, lambda_arn_debug_config_first: str, lambda_arn_debug_config_second: str):
        self.lambda_arn_debug_config_first = lambda_arn_debug_config_first
        self.lambda_arn_debug_config_second = lambda_arn_debug_config_second

    def __str__(self):
        return (
            f"DuplicateLambdaDebugConfig: Lambda debug configuration in '{self.lambda_arn_debug_config_first}' "
            f"is redefined in '{self.lambda_arn_debug_config_second}'"
        )

from typing import Optional

from localstack.aws.api.lambda_ import Arn
from localstack.utils.lambda_debug_mode.lambda_debug_mode_session import LambdaDebugModeSession

# Specifies the fault timeout value in seconds to be used by time restricted workflows when
# Debug Mode is enabled. The value is set to one hour to ensure eventual termination of
# long-running processes.
DEFAULT_LAMBDA_DEBUG_MODE_TIMEOUT_SECONDS: int = 3_600


def is_lambda_debug_mode() -> bool:
    return LambdaDebugModeSession.get().is_lambda_debug_mode()


def lambda_debug_port_for(lambda_arn: Arn) -> Optional[int]:
    if not is_lambda_debug_mode():
        return None
    debug_configuration = LambdaDebugModeSession.get().debug_config_for(lambda_arn=lambda_arn)
    if debug_configuration is None:
        return None
    return debug_configuration.debug_port


def is_lambda_debug_timeout_enabled_for(lambda_arn: Arn) -> bool:
    if not is_lambda_debug_mode():
        return False
    debug_configuration = LambdaDebugModeSession.get().debug_config_for(lambda_arn=lambda_arn)
    if debug_configuration is None:
        return False
    return not debug_configuration.enforce_timeouts

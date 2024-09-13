from typing import Optional

from localstack.aws.api.lambda_ import Arn
from localstack.utils.lambda_debug_mode.config.config import LambdaDebugModeConfig
from localstack.utils.lambda_debug_mode.lambda_debug_mode_session import LambdaDebugModeSession

# Specifies the fault timeout value in seconds to be used by time restricted workflows when
# Debug Mode is enabled. The value is set to one hour to ensure eventual termination of
# long-running processes.
DEFAULT_LAMBDA_DEBUG_MODE_TIMEOUT_SECONDS: int = 3_600

# TODO: CHANGES IN THIS FILE DEPEND ON OPEN CHANGES FOR CONCURRENCY CONTROL AND HOT RELOADING


def is_lambda_debug_mode() -> bool:
    return LambdaDebugModeSession.get().is_lambda_debug_mode()


def lambda_debug_port_for(lambda_arn: Arn) -> Optional[int]:
    if not is_lambda_debug_mode():
        return None
    lambda_debug_mode_config: LambdaDebugModeConfig = (
        LambdaDebugModeSession.get().lambda_debug_mode_config()
    )
    if lambda_debug_mode_config is None:
        return None
    return lambda_debug_mode_config.lambda_debug_client_port_for(lambda_arn=lambda_arn)


def is_lambda_debug_timeout_enabled_for(lambda_arn: Arn) -> bool:
    if not is_lambda_debug_mode():
        return False
    lambda_debug_mode_config: LambdaDebugModeConfig = (
        LambdaDebugModeSession.get().lambda_debug_mode_config()
    )
    if lambda_debug_mode_config is None:
        return False
    # TODO: see above.
    return lambda_debug_mode_config.lambda_is_enforce_timeouts_for(lambda_arn=lambda_arn)

from typing import Final

from localstack.config import DEBUG_MODE

# Specifies the fault timeout value in seconds to be used by time restricted workflows when
# Debug Mode is enabled. The value is set to one hour to ensure eventual termination of
# long-running processes.
DEFAULT_DEBUG_MODE_TIMEOUT_SECONDS: Final[int] = 3_600


def is_debug_mode() -> bool:
    # Returns the state of debug mode. True if enabled, False otherwise.
    return DEBUG_MODE

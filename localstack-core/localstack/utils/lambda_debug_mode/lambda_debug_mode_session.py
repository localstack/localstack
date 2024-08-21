import logging
from typing import Optional

from localstack.aws.api.lambda_ import Arn
from localstack.config import LAMBDA_DEBUG_MODE, LAMBDA_DEBUG_MODE_CONFIG_PATH
from localstack.utils.lambda_debug_mode.lambda_debug_mode_config import (
    LambdaDebugConfig,
    LambdaDebugModeConfig,
    load_lambda_debug_mode_config,
)

LOG = logging.getLogger(__name__)


class _LambdaDebugModeSession:
    _instance = None
    _is_lambda_debug_mode: bool
    _config: Optional[LambdaDebugModeConfig]

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(_LambdaDebugModeSession, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        self._is_lambda_debug_mode = bool(LAMBDA_DEBUG_MODE)
        self._configuration = self._load_lambda_debug_mode_config()

    def _load_lambda_debug_mode_config(self) -> Optional[LambdaDebugModeConfig]:
        file_path = LAMBDA_DEBUG_MODE_CONFIG_PATH
        if not self._is_lambda_debug_mode or file_path is None:
            return None

        yaml_configuration_string = None
        try:
            with open(file_path, "r") as df:
                yaml_configuration_string = df.read()
        except FileNotFoundError:
            LOG.error(f"Error: The file lambda debug config " f"file '{file_path}' was not found.")
        except IsADirectoryError:
            LOG.error(
                f"Error: Expected a lambda debug config file "
                f"but found a directory at '{file_path}'."
            )
        except PermissionError:
            LOG.error(
                f"Error: Permission denied while trying to read "
                f"the lambda debug config file '{file_path}'."
            )
        except Exception as ex:
            LOG.error(
                f"Error: An unexpected error occurred while reading "
                f"lambda debug config '{file_path}': '{ex}'"
            )
        if not yaml_configuration_string:
            return None

        config = load_lambda_debug_mode_config(yaml_configuration_string)
        return config

    def is_lambda_debug_mode(self) -> bool:
        return self._is_lambda_debug_mode

    def debug_config_for(self, lambda_arn: Arn) -> Optional[LambdaDebugConfig]:
        return self._configuration.functions.get(lambda_arn) if self._configuration else None


lambda_debug_mode_session = _LambdaDebugModeSession()

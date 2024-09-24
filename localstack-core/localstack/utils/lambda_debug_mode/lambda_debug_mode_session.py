from __future__ import annotations

import logging
from typing import Optional

from localstack.aws.api.lambda_ import Arn
from localstack.config import LAMBDA_DEBUG_MODE, LAMBDA_DEBUG_MODE_CONFIG_PATH
from localstack.utils.lambda_debug_mode.lambda_debug_mode_config import (
    LambdaDebugConfig,
    LambdaDebugModeConfig,
    load_lambda_debug_mode_config,
)
from localstack.utils.objects import singleton_factory

LOG = logging.getLogger(__name__)


class LambdaDebugModeSession:
    _is_lambda_debug_mode: bool
    _config: Optional[LambdaDebugModeConfig]

    def __init__(self):
        self._is_lambda_debug_mode = bool(LAMBDA_DEBUG_MODE)
        self._configuration = self._load_lambda_debug_mode_config()

    @staticmethod
    @singleton_factory
    def get() -> LambdaDebugModeSession:
        """Returns a singleton instance of the Lambda Debug Mode session."""
        return LambdaDebugModeSession()

    def _load_lambda_debug_mode_config(self) -> Optional[LambdaDebugModeConfig]:
        file_path = LAMBDA_DEBUG_MODE_CONFIG_PATH
        if not self._is_lambda_debug_mode or file_path is None:
            return None

        yaml_configuration_string = None
        try:
            with open(file_path, "r") as df:
                yaml_configuration_string = df.read()
        except FileNotFoundError:
            LOG.error("Error: The file lambda debug config " "file '%s' was not found.", file_path)
        except IsADirectoryError:
            LOG.error(
                "Error: Expected a lambda debug config file " "but found a directory at '%s'.",
                file_path,
            )
        except PermissionError:
            LOG.error(
                "Error: Permission denied while trying to read "
                "the lambda debug config file '%s'.",
                file_path,
            )
        except Exception as ex:
            LOG.error(
                "Error: An unexpected error occurred while reading "
                "lambda debug config '%s': '%s'",
                file_path,
                ex,
            )
        if not yaml_configuration_string:
            return None

        config = load_lambda_debug_mode_config(yaml_configuration_string)
        return config

    def is_lambda_debug_mode(self) -> bool:
        return self._is_lambda_debug_mode

    def debug_config_for(self, lambda_arn: Arn) -> Optional[LambdaDebugConfig]:
        return self._configuration.functions.get(lambda_arn) if self._configuration else None

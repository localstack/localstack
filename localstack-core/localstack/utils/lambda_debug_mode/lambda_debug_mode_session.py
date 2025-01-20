from __future__ import annotations

import logging
import os
import time
from threading import Event, Thread
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

    _configuration_file_path: Optional[str]
    _watch_thread: Optional[Thread]
    _initialised_event: Optional[Event]
    _stop_event: Optional[Event]
    _config: Optional[LambdaDebugModeConfig]

    def __init__(self):
        self._is_lambda_debug_mode = bool(LAMBDA_DEBUG_MODE)

        # Disabled Lambda Debug Mode state initialisation.
        self._configuration_file_path = None
        self._watch_thread = None
        self._initialised_event = None
        self._stop_event = None
        self._config = None

        # Lambda Debug Mode is not enabled: leave as disabled state and return.
        if not self._is_lambda_debug_mode:
            return

        # Lambda Debug Mode is enabled.
        # Instantiate the configuration requirements if a configuration file is given.
        self._configuration_file_path = LAMBDA_DEBUG_MODE_CONFIG_PATH
        if not self._configuration_file_path:
            return

        # A configuration file path is given: initialised the resources to load and watch the file.

        # Signal and block on first loading to ensure this is enforced from the very first
        # invocation, as this module is not loaded at startup. The LambdaDebugModeConfigWatch
        # thread will then take care of updating the configuration periodically and asynchronously.
        # This may somewhat slow down the first upstream thread loading this module, but not
        # future calls. On the other hand, avoiding this mechanism means that first Lambda calls
        # occur with no Debug configuration.
        self._initialised_event = Event()

        # Signals when a shutdown signal from the application is registered.
        self._stop_event = Event()

        self._watch_thread = Thread(
            target=self._watch_logic, args=(), daemon=True, name="LambdaDebugModeConfigWatch"
        )
        self._watch_thread.start()

    @staticmethod
    @singleton_factory
    def get() -> LambdaDebugModeSession:
        """Returns a singleton instance of the Lambda Debug Mode session."""
        return LambdaDebugModeSession()

    def ensure_running(self) -> None:
        # Nothing to start.
        if self._watch_thread is None or self._watch_thread.is_alive():
            return
        try:
            self._watch_thread.start()
        except Exception as exception:
            exception_str = str(exception)
            # The thread was already restarted by another process.
            if (
                isinstance(exception, RuntimeError)
                and exception_str
                and "threads can only be started once" in exception_str
            ):
                return
            LOG.error(
                "Lambda Debug Mode could not restart the "
                "hot reloading of the configuration file, '%s'",
                exception_str,
            )

    def signal_stop(self) -> None:
        stop_event = self._stop_event
        if stop_event is not None:
            stop_event.set()

    def _load_lambda_debug_mode_config(self):
        yaml_configuration_string = None
        try:
            with open(self._configuration_file_path, "r") as df:
                yaml_configuration_string = df.read()
        except FileNotFoundError:
            LOG.error(
                "Error: The file lambda debug config file '%s' was not found.",
                self._configuration_file_path,
            )
        except IsADirectoryError:
            LOG.error(
                "Error: Expected a lambda debug config file but found a directory at '%s'.",
                self._configuration_file_path,
            )
        except PermissionError:
            LOG.error(
                "Error: Permission denied while trying to read the lambda debug config file '%s'.",
                self._configuration_file_path,
            )
        except Exception as ex:
            LOG.error(
                "Error: An unexpected error occurred while reading lambda debug config '%s': '%s'",
                self._configuration_file_path,
                ex,
            )
        if not yaml_configuration_string:
            return None

        self._config = load_lambda_debug_mode_config(yaml_configuration_string)
        if self._config is not None:
            LOG.info("Lambda Debug Mode is now enforcing the latest configuration.")
        else:
            LOG.warning(
                "Lambda Debug Mode could not load the latest configuration due to an error, "
                "check logs for more details."
            )

    def _config_file_epoch_last_modified_or_now(self) -> int:
        try:
            modified_time = os.path.getmtime(self._configuration_file_path)
            return int(modified_time)
        except Exception as e:
            LOG.warning("Lambda Debug Mode could not access the configuration file: %s", e)
            epoch_now = int(time.time())
            return epoch_now

    def _watch_logic(self) -> None:
        # TODO: consider relying on system calls (watchdog lib for cross-platform support)
        #  instead of monitoring last modified dates.
        # Run the first load and signal as initialised.
        epoch_last_loaded: int = self._config_file_epoch_last_modified_or_now()
        self._load_lambda_debug_mode_config()
        self._initialised_event.set()

        # Monitor for file changes whilst the application is running.
        while not self._stop_event.is_set():
            time.sleep(1)
            epoch_last_modified = self._config_file_epoch_last_modified_or_now()
            if epoch_last_modified > epoch_last_loaded:
                epoch_last_loaded = epoch_last_modified
                self._load_lambda_debug_mode_config()

    def _get_initialised_config(self) -> Optional[LambdaDebugModeConfig]:
        # Check the session is not initialising, and if so then wait for initialisation to finish.
        # Note: the initialisation event is otherwise left set since after first initialisation has terminated.
        if self._initialised_event is not None:
            self._initialised_event.wait()
        return self._config

    def is_lambda_debug_mode(self) -> bool:
        return self._is_lambda_debug_mode

    def debug_config_for(self, lambda_arn: Arn) -> Optional[LambdaDebugConfig]:
        config = self._get_initialised_config()
        return config.functions.get(lambda_arn) if config else None

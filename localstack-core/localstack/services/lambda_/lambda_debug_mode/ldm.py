from __future__ import annotations

import logging
import os
import threading
import time
from threading import Event, RLock, Thread
from typing import Callable, Dict, Final, Optional

from localstack.aws.api.lambda_ import (
    Arn,
    FunctionVersion,
    ResourceNotFoundException,
    TooManyRequestsException,
)
from localstack.config import LAMBDA_DEBUG_MODE, LAMBDA_DEBUG_MODE_CONFIG_PATH
from localstack.services.lambda_.invocation.execution_environment import (
    ExecutionEnvironment,
    InvalidStatusException,
    RuntimeStatus,
)
from localstack.services.lambda_.lambda_debug_mode.ldm_config_file import parse_ldm_config
from localstack.services.lambda_.provider_utils import get_function_version
from localstack.utils.aws.arns import parse_arn
from localstack.utils.objects import singleton_factory
from localstack.utils.strings import long_uid

LOG = logging.getLogger(__name__)

# Specifies the default timeout value in seconds to be used by time restricted workflows
# when Debug Mode is enabled. The value is set to one hour to ensure eventual termination
# of long-running processes.
DEFAULT_LAMBDA_DEBUG_MODE_TIMEOUT_SECONDS: int = 3_600
LDM_ENV_VAR_DEBUG_PORT: str = "LDM_DEBUG_PORT"


class LambdaFunctionDebugConfig:
    qualified_lambda_arn: Final[Arn]
    port: Final[int]
    enforce_timeouts: Final[bool]
    user_agent: Final[Optional[str]]

    def __init__(
        self,
        qualified_lambda_arn: Arn,
        port: int,
        enforce_timeouts: bool = False,
        user_agent: Optional[str] = None,
    ):
        self.qualified_lambda_arn = qualified_lambda_arn
        self.port = port
        self.enforce_timeouts = enforce_timeouts
        self.user_agent = user_agent


class DebugEnabledExecutionEnvironment(ExecutionEnvironment):
    _lambda_function_debug_config: Final[LambdaFunctionDebugConfig]

    def __init__(
        self,
        function_version: FunctionVersion,
        lambda_function_debug_config: LambdaFunctionDebugConfig,
        on_timeout: Callable[[str, str], None],
    ):
        super().__init__(
            function_version=function_version,
            version_manager_id=f"debug-enable-{long_uid()}",
            initialization_type="provisioned-concurrency",
            on_timeout=on_timeout,
        )
        self._lambda_function_debug_config = lambda_function_debug_config

    def get_environment_variables(self) -> Dict[str, str]:
        environment_variables = super().get_environment_variables()
        environment_variables[LDM_ENV_VAR_DEBUG_PORT] = str(self._lambda_function_debug_config.port)
        if not self._lambda_function_debug_config.enforce_timeouts:
            environment_variables["AWS_LAMBDA_FUNCTION_TIMEOUT"] = str(
                DEFAULT_LAMBDA_DEBUG_MODE_TIMEOUT_SECONDS
            )
        return environment_variables

    def _get_startup_timeout_seconds(self) -> int:
        return DEFAULT_LAMBDA_DEBUG_MODE_TIMEOUT_SECONDS


class LambdaDebugTarget:
    _mutex: Final[RLock]
    _lambda_qualified_arn: Final[str]
    lambda_function_debug_config: Final[LambdaFunctionDebugConfig]
    _debug_execution_environment: Optional[DebugEnabledExecutionEnvironment]

    def __init__(self, lambda_function_debug_config: LambdaFunctionDebugConfig):
        self._mutex = RLock()
        self._lambda_qualified_arn = lambda_function_debug_config.qualified_lambda_arn
        self.lambda_function_debug_config = lambda_function_debug_config
        self._debug_execution_environment = None

    def start_debug_enabled_execution_environment(self):
        # Attempt to create the debug environment now if the function exists.
        with self._mutex:
            if self._debug_execution_environment is not None:
                return
            self.stop_debug_enabled_execution_environment()

            try:
                lambda_parsed_arn = parse_arn(self._lambda_qualified_arn)
                lambda_account_id = lambda_parsed_arn["account"]
                lambda_region_name = lambda_parsed_arn["region"]
                _, lambda_function_name, lambda_function_qualifier = lambda_parsed_arn[
                    "resource"
                ].split(":")
                function_version = get_function_version(
                    function_name=lambda_function_name,
                    qualifier=lambda_function_qualifier,
                    account_id=lambda_account_id,
                    region=lambda_region_name,
                )
            except ResourceNotFoundException:
                # The lambda function has not being created yet.
                return

            self._debug_execution_environment = DebugEnabledExecutionEnvironment(
                function_version=function_version,
                lambda_function_debug_config=self.lambda_function_debug_config,
                on_timeout=self._on_execution_environment_timeout,
            )
            # FIXME: this log should take place after RuntimeStatus.READY, however the debug-enabled
            #        docker container will not notify LS about it starting up until the user has
            #        connected a debug client. Future work should resolve this notification issue.
            LOG.info(
                "LDM is ready for debugger connections for '%s' on port %i.",
                self.lambda_function_debug_config.qualified_lambda_arn,
                self.lambda_function_debug_config.port,
            )
            self._debug_execution_environment.start()
            if self._debug_execution_environment.status != RuntimeStatus.READY:
                LOG.error(
                    "LDM could not create a debug environment for '%s'", self._lambda_qualified_arn
                )
                self._debug_execution_environment = None

    def stop_debug_enabled_execution_environment(self):
        with self._mutex:
            if environment := self._debug_execution_environment:
                environment.stop()
            self._debug_execution_environment = None

    def get_execution_environment(self) -> DebugEnabledExecutionEnvironment:
        # TODO: add support for concurrent invokes, such as invoke object queuing, new container spinup
        with self._mutex:
            # TODO: move this start-up logic to lambda function creation.
            self.start_debug_enabled_execution_environment()
            try:
                self._debug_execution_environment.reserve()
                return self._debug_execution_environment
            except InvalidStatusException:
                LOG.warning(
                    "Concurrent lambda invocations disabled for '%s' by Lambda Debug Mode",
                    self._lambda_qualified_arn,
                )
                raise TooManyRequestsException(
                    "Rate Exceeded.",
                    Reason="SingleLeaseEnforcement",
                    Type="User",
                )

    def _on_execution_environment_timeout(
        self, version_manager_id: str, environment_id: str
    ) -> None:
        # This function is run by the ExecutionEnvironment when the
        # release of on-demand container times-out whilst waiting for
        # invokes. However, DebugEnabledExecutionEnvironment are
        # provisioned-concurrency ExecutionEnvironments.
        LOG.warning(
            "Lambda Debug Mode function '%s' timed out ('%s', '%s')",
            self._lambda_qualified_arn,
            version_manager_id,
            environment_id,
        )
        self.stop_debug_enabled_execution_environment()


class LDMConfigFileWatch:
    _mutex: Final[RLock]
    _stop_event: Final[Event]
    _watch_thread: Final[Thread]

    def __init__(self):
        self._mutex = RLock()
        self._stop_event = Event()
        self._watch_thread = Thread(
            target=self._watch_logic, args=(), daemon=True, name="LDMConfigFileWatch"
        )

    def start(self):
        with self._mutex:
            self._stop_event.clear()
            if not self._watch_thread.is_alive():
                self._watch_thread.start()

    def stop(self):
        with self._mutex:
            self._stop_event.set()

    def _watch_logic(self) -> None:
        if not LAMBDA_DEBUG_MODE_CONFIG_PATH:
            LOG.info("LDM: no definitions for LAMBDA_DEBUG_MODE_CONFIG_PATH")
            return

        # TODO: consider relying on system calls (watchdog lib for cross-platform support)
        #  instead of monitoring last modified dates.
        # Run the first load and signal as initialised.
        epoch_last_loaded: int = self._config_file_epoch_last_modified_or_now()
        self._update_ldm_from_ldm_config_file()

        # Monitor for file changes whilst the application is running.
        while not self._stop_event.is_set():
            time.sleep(1)
            epoch_last_modified = self._config_file_epoch_last_modified_or_now()
            if epoch_last_modified > epoch_last_loaded:
                epoch_last_loaded = epoch_last_modified
                self._update_ldm_from_ldm_config_file()

    @staticmethod
    def _update_ldm_from_ldm_config_file() -> None:
        yaml_configuration_string = None
        try:
            with open(LAMBDA_DEBUG_MODE_CONFIG_PATH, "r") as df:
                yaml_configuration_string = df.read()
        except FileNotFoundError:
            LOG.error(
                "LDM: The file lambda debug config file '%s' was not found.",
                LAMBDA_DEBUG_MODE_CONFIG_PATH,
            )
        except IsADirectoryError:
            LOG.error(
                "LDM: Expected a lambda debug config file but found a directory at '%s'.",
                LAMBDA_DEBUG_MODE_CONFIG_PATH,
            )
        except PermissionError:
            LOG.error(
                "LDM: Permission denied while trying to read the lambda debug config file '%s'.",
                LAMBDA_DEBUG_MODE_CONFIG_PATH,
            )
        except Exception as ex:
            LOG.error(
                "LDM: An unexpected error occurred while reading lambda debug config '%s': '%s'",
                LAMBDA_DEBUG_MODE_CONFIG_PATH,
                ex,
            )

        if not yaml_configuration_string:
            return

        config = parse_ldm_config(yaml_configuration_string)
        if config is not None:
            LDM.remove_all_configurations()
            for qualified_lambda_arn, ldm_config in config.functions.items():
                LDM.add_configuration(
                    config=LambdaFunctionDebugConfig(
                        qualified_lambda_arn=qualified_lambda_arn,
                        port=ldm_config.debug_port,
                        enforce_timeouts=ldm_config.enforce_timeouts,
                    )
                )
                LDM.enable_configuration(qualified_lambda_arn=qualified_lambda_arn)
            LOG.info(
                "LDM is now enforcing the latest configuration from the LDM configuration file"
            )
        else:
            LOG.warning(
                "LDM could not load the latest Lambda debug mode configuration "
                "due to an error; check logs for more details."
            )

    @staticmethod
    def _config_file_epoch_last_modified_or_now() -> int:
        try:
            modified_time = os.path.getmtime(LAMBDA_DEBUG_MODE_CONFIG_PATH)
            return int(modified_time)
        except Exception as e:
            LOG.warning("LDM could not access the configuration file: %s", e)
            epoch_now = int(time.time())
            return epoch_now


class LambdaDebugMode:
    _mutex: Final[RLock]
    _is_enabled: bool
    _debug_targets: Final[dict[str, LambdaDebugTarget]]
    _config_file_watch: Final[Optional[LDMConfigFileWatch]]

    def __init__(self):
        self._mutex = RLock()
        self._is_enabled = bool(LAMBDA_DEBUG_MODE)
        self._debug_targets = dict()
        self._config_file_watch = LDMConfigFileWatch() if LAMBDA_DEBUG_MODE_CONFIG_PATH else None
        if self._is_enabled:
            self.start_debug_mode()

    @staticmethod
    @singleton_factory
    def get() -> LambdaDebugMode:
        """Returns a singleton instance of the Lambda Debug Mode session."""
        return LambdaDebugMode()

    def start_debug_mode(self) -> None:
        with self._mutex:
            self._is_enabled = True
            if self._config_file_watch:
                self._config_file_watch.start()

    def stop_debug_mode(self) -> None:
        with self._mutex:
            self._is_enabled = False
            if self._config_file_watch:
                self._config_file_watch.stop()
            self.remove_all_configurations()

    def is_enabled(self) -> bool:
        return self._is_enabled

    def add_configuration(self, config: LambdaFunctionDebugConfig) -> None:
        with self._mutex:
            if not self._is_enabled:
                return

            arn = config.qualified_lambda_arn
            if existing_target := self._debug_targets.get(arn):
                existing_target.stop_debug_enabled_execution_environment()

            target = LambdaDebugTarget(lambda_function_debug_config=config)
            self._debug_targets[arn] = target

    def enable_configuration(self, qualified_lambda_arn: Arn) -> None:
        with self._mutex:
            if not self._is_enabled:
                return

            if target := self._debug_targets.get(qualified_lambda_arn):
                threading.Thread(
                    target=target.start_debug_enabled_execution_environment,
                    args=(),
                    name=f"LambdaDebugTarget-start_debug_enabled_execution_environment-{qualified_lambda_arn}",
                    daemon=True,
                ).start()

    def remove_configuration(self, qualified_lambda_arn: Arn) -> None:
        with self._mutex:
            if not self._is_enabled:
                return

            if target := self._debug_targets.pop(qualified_lambda_arn, None):
                target.stop_debug_enabled_execution_environment()

    def remove_all_configurations(self) -> None:
        with self._mutex:
            for target in self._debug_targets.values():
                target.stop_debug_enabled_execution_environment()
            self._debug_targets.clear()

    def get_execution_environment(
        self, qualified_lambda_arn: Arn, user_agent: Optional[str]
    ) -> Optional[DebugEnabledExecutionEnvironment]:
        if not self._is_enabled:
            return None

        if target := self._debug_targets.get(qualified_lambda_arn):
            target_user_agent = target.lambda_function_debug_config.user_agent
            if target_user_agent is None or target_user_agent == user_agent:
                return target.get_execution_environment()
        return None


LDM: Final[LambdaDebugMode] = LambdaDebugMode.get()

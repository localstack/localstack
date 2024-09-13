from __future__ import annotations

import logging
from typing import Optional

from pydantic import BaseModel, Field, ValidationError

from localstack.aws.api.lambda_ import Arn
from localstack.utils.lambda_debug_mode.config.config import (
    LambdaDebugModeConfig,
)
from localstack.utils.lambda_debug_mode.config.exceptions import (
    DuplicateLambdaDebugConfig,
    LambdaDebugModeConfigException,
    PortAlreadyInUse,
    UnknownLambdaArnFormat,
)
from localstack.utils.lambda_debug_mode.config.version import DEFAULT_VERSION, Version

LOG = logging.getLogger(__name__)


class LambdaDebugConfigData(BaseModel):
    debug_port: Optional[int] = Field(None, alias="debug-port")
    enforce_timeouts: bool = Field(False, alias="enforce-timeouts")


class LambdaDebugModeConfigData(BaseModel):
    # Version of the configuration file.
    version: Version = Field(DEFAULT_VERSION, alias="version")
    # Bindings of Lambda function Arn and the respective debugging configuration.
    functions: dict[Arn, LambdaDebugConfigData]


class LambdaDebugModeConfigV0(LambdaDebugModeConfig):
    _config: Optional[LambdaDebugModeConfigData]

    def __init__(self, config: LambdaDebugModeConfigData):
        self._config = config

    @classmethod
    def from_yaml(cls, yaml_string: str):
        config: Optional[LambdaDebugModeConfigData] = load_lambda_debug_mode_config(yaml_string)
        return cls(config=config)

    def _get_lambda_debug_config_for(self, lambda_arn: Arn) -> Optional[LambdaDebugConfigData]:
        config = self._config
        if config is None:
            return None
        lambda_debug_config = config.functions.get(lambda_arn)
        return lambda_debug_config

    def lambda_is_enforce_timeouts_for(self, lambda_arn: Arn) -> bool:
        lambda_debug_config: Optional[LambdaDebugConfigData] = self._get_lambda_debug_config_for(
            lambda_arn=lambda_arn
        )
        if lambda_debug_config is None:
            return False
        return not lambda_debug_config.enforce_timeouts

    def _debug_port_for(self, lambda_arn: Arn) -> Optional[int]:
        lambda_debug_config: Optional[LambdaDebugConfigData] = self._get_lambda_debug_config_for(
            lambda_arn=lambda_arn
        )
        if lambda_debug_config is None:
            return None
        return lambda_debug_config.debug_port

    def lambda_debug_client_port_for(self, lambda_arn: Arn) -> Optional[int]:
        return self._debug_port_for(lambda_arn=lambda_arn)

    def lambda_debugger_port_for(self, lambda_arn: Arn) -> Optional[int]:
        return self._debug_port_for(lambda_arn=lambda_arn)


class _LambdaDebugModeConfigPostProcessingState:
    version: Version
    ports_used: set[int]

    def __init__(self, version: Version):
        self.version = version
        self.ports_used = set()


def post_process_lambda_debug_mode_config(config: LambdaDebugModeConfigData) -> None:
    _post_process_lambda_debug_mode_config(
        post_processing_state=_LambdaDebugModeConfigPostProcessingState(version=config.version),
        config=config,
    )


def _post_process_lambda_debug_mode_config(
    post_processing_state: _LambdaDebugModeConfigPostProcessingState,
    config: LambdaDebugModeConfigData,
) -> None:
    config_functions = config.functions
    lambda_arns = list(config_functions.keys())
    for lambda_arn in lambda_arns:
        qualified_lambda_arn = _to_qualified_lambda_function_arn(lambda_arn)
        if lambda_arn != qualified_lambda_arn:
            if qualified_lambda_arn in config_functions:
                raise DuplicateLambdaDebugConfig(
                    lambda_arn_debug_config_first=lambda_arn,
                    lambda_arn_debug_config_second=qualified_lambda_arn,
                )
            config_functions[qualified_lambda_arn] = config_functions.pop(lambda_arn)

    for lambda_arn, lambda_debug_config in config_functions.items():
        _post_process_lambda_debug_config(
            post_processing_state=post_processing_state, lambda_debug_config=lambda_debug_config
        )


def _to_qualified_lambda_function_arn(lambda_arn: Arn) -> Arn:
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


def _post_process_lambda_debug_config(
    post_processing_state: _LambdaDebugModeConfigPostProcessingState,
    lambda_debug_config: LambdaDebugConfigData,
) -> None:
    debug_port: Optional[int] = lambda_debug_config.debug_port
    if debug_port is None:
        return
    if debug_port in post_processing_state.ports_used:
        raise PortAlreadyInUse(port_number=debug_port)
    post_processing_state.ports_used.add(debug_port)


def load_lambda_debug_mode_config(raw_config: dict) -> Optional[LambdaDebugModeConfigData]:
    # Attempt to build the LambdaDebugModeConfig object from the yaml object.
    try:
        config = LambdaDebugModeConfigData(**raw_config)
    except ValidationError as validation_error:
        validation_errors = validation_error.errors() or list()
        error_messages = [
            f"When parsing '{err.get('loc', '')}': {err.get('msg', str(err))}"
            for err in validation_errors
        ]
        LOG.error(
            "Unable to parse lambda debug mode configuration file due to errors: %s",
            error_messages,
        )
        return None

    # Attempt to post_process the configuration.
    try:
        post_process_lambda_debug_mode_config(config)
    except LambdaDebugModeConfigException as lambda_debug_mode_error:
        LOG.error(
            "Invalid lambda debug mode configuration due to: %s",
            lambda_debug_mode_error,
        )
        config = None

    return config

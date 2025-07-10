from __future__ import annotations

import logging
from typing import Optional

import yaml
from pydantic import BaseModel, Field, ValidationError
from yaml import Loader, MappingNode, MarkedYAMLError, SafeLoader

from localstack.aws.api.lambda_ import Arn
from localstack.services.lambda_.lambda_debug_mode.ldm_types import LDMException
from localstack.services.lambda_.lambda_debug_mode.ldm_utils import to_qualified_lambda_function_arn

LOG = logging.getLogger(__name__)


class PortAlreadyInUse(LDMException):
    port_number: int

    def __init__(self, port_number: int):
        self.port_number = port_number

    def __str__(self):
        return f"PortAlreadyInUse: '{self.port_number}'"


class DuplicateLDMConfig(LDMException):
    lambda_arn_debug_config_first: str
    lambda_arn_debug_config_second: str

    def __init__(self, lambda_arn_debug_config_first: str, lambda_arn_debug_config_second: str):
        self.lambda_arn_debug_config_first = lambda_arn_debug_config_first
        self.lambda_arn_debug_config_second = lambda_arn_debug_config_second

    def __str__(self):
        return (
            f"DuplicateLDMConfig: Lambda debug configuration in '{self.lambda_arn_debug_config_first}' "
            f"is redefined in '{self.lambda_arn_debug_config_second}'"
        )


class LambdaFunctionConfig(BaseModel):
    debug_port: Optional[int] = Field(None, alias="debug-port")
    enforce_timeouts: bool = Field(False, alias="enforce-timeouts")


class LDMConfigFile(BaseModel):
    # Bindings of Lambda function Arn and the respective debugging configuration.
    functions: dict[Arn, LambdaFunctionConfig]


class _LDMConfigPostProcessingState:
    ports_used: set[int]

    def __init__(self):
        self.ports_used = set()


class _SafeLoaderWithDuplicateCheck(SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self.add_constructor(
            yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
            self._construct_mappings_with_duplicate_check,
        )

    @staticmethod
    def _construct_mappings_with_duplicate_check(
        loader: Loader, node: MappingNode, deep=False
    ) -> dict:
        # Constructs yaml bindings, whilst checking for duplicate mapping key definitions, raising a
        # MarkedYAMLError when one is found.
        mapping = dict()
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in mapping:
                # Create a MarkedYAMLError to indicate the duplicate key issue
                raise MarkedYAMLError(
                    context="while constructing a mapping",
                    context_mark=node.start_mark,
                    problem=f"found duplicate key: {key}",
                    problem_mark=key_node.start_mark,
                )
            value = loader.construct_object(value_node, deep=deep)
            mapping[key] = value
        return mapping


def _from_yaml_string(yaml_string: str) -> Optional[LDMConfigFile]:
    try:
        data = yaml.load(yaml_string, _SafeLoaderWithDuplicateCheck)
    except yaml.YAMLError as yaml_error:
        LOG.error(
            "Could not parse yaml LDM configuration file due to: %s",
            yaml_error,
        )
        data = None
    if not data:
        return None
    config = LDMConfigFile(**data)
    return config


def _post_process_ldm_config_file(
    ldm_config: LDMConfigFile,
    post_processing_state: Optional[_LDMConfigPostProcessingState] = None,
) -> None:
    post_processing_state = post_processing_state or _LDMConfigPostProcessingState()
    lambda_function_configs = ldm_config.functions
    lambda_arns = list(lambda_function_configs.keys())
    for lambda_arn in lambda_arns:
        qualified_lambda_arn = to_qualified_lambda_function_arn(lambda_arn)
        if lambda_arn != qualified_lambda_arn:
            if qualified_lambda_arn in lambda_function_configs:
                raise DuplicateLDMConfig(
                    lambda_arn_debug_config_first=lambda_arn,
                    lambda_arn_debug_config_second=qualified_lambda_arn,
                )
            lambda_function_configs[qualified_lambda_arn] = lambda_function_configs.pop(lambda_arn)

    for lambda_function_config in lambda_function_configs.values():
        _post_process_lambda_function_config(
            post_processing_state=post_processing_state,
            lambda_function_config=lambda_function_config,
        )


def _post_process_lambda_function_config(
    post_processing_state: _LDMConfigPostProcessingState,
    lambda_function_config: LambdaFunctionConfig,
) -> None:
    debug_port: Optional[int] = lambda_function_config.debug_port
    if debug_port is None:
        return
    if debug_port in post_processing_state.ports_used:
        raise PortAlreadyInUse(port_number=debug_port)
    post_processing_state.ports_used.add(debug_port)


def parse_ldm_config(yaml_string: str) -> Optional[LDMConfigFile]:
    # Attempt to parse the yaml string.
    try:
        yaml_data = yaml.load(yaml_string, _SafeLoaderWithDuplicateCheck)
    except yaml.YAMLError as yaml_error:
        LOG.error(
            "Could not parse yaml LDM configuration file due to: %s",
            yaml_error,
        )
        yaml_data = None
    if not yaml_data:
        return None

    # Attempt to build the LDMConfig object from the yaml object.
    try:
        config = LDMConfigFile(**yaml_data)
    except ValidationError as validation_error:
        validation_errors = validation_error.errors() or list()
        error_messages = [
            f"When parsing '{err.get('loc', '')}': {err.get('msg', str(err))}"
            for err in validation_errors
        ]
        LOG.error(
            "Unable to parse LDM configuration file due to errors: %s",
            error_messages,
        )
        return None

    # Attempt to post_process the configuration.
    try:
        _post_process_ldm_config_file(config)
    except LDMException as ldm_error:
        LOG.error(
            "Invalid LDM configuration due to: %s",
            ldm_error,
        )
        config = None

    return config

import logging
from typing import Optional

import yaml
from yaml import Loader, MappingNode, MarkedYAMLError, SafeLoader

from localstack.utils.lambda_debug_mode.config.config import LambdaDebugModeConfig
from localstack.utils.lambda_debug_mode.config.config_v0 import LambdaDebugModeConfigV0
from localstack.utils.lambda_debug_mode.config.version import (
    DEFAULT_VERSION,
    validate_version_string,
)

LOG = logging.getLogger(__name__)


class _SafeLoaderWithDuplicateCheck(SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self.add_constructor(
            yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
            self._construct_mappings_with_duplicate_check,
        )

    @staticmethod
    def _construct_mappings_with_duplicate_check(loader: Loader, node: MappingNode, deep=False):
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


def load_lambda_debug_mode_config(yaml_string: str) -> Optional[LambdaDebugModeConfig]:
    try:
        data = yaml.load(yaml_string, _SafeLoaderWithDuplicateCheck)
    except yaml.YAMLError as yaml_error:
        LOG.error(
            "Could not parse yaml lambda debug mode configuration file due to: %s",
            yaml_error,
        )
        data = None
    if not data or not isinstance(data, dict):
        return None

    if "version" in data:
        version_string: str = data["version"]
        validate_version_string(version_string=version_string)
    else:
        version_string: str = DEFAULT_VERSION
        data["version"] = version_string
        LOG.info(
            "Lambda Debug Mode is defaulting configuration file to version '%s'; it is recommended to declare the desired version in the configuration file",
            version_string,
        )

    if version_string.startswith("0."):
        return LambdaDebugModeConfigV0.from_raw(raw_config=data)
    else:
        # This never occurs as the if block should be exhaustive. If so, log the incident and apply not config.
        LOG.error("Lambda Debug Mode cannot build configuration with version '%s'.", version_string)
        return None

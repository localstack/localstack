# A simple module to track deprecations over time / versions, and some simple functions guiding affected users.
import logging
import os
from dataclasses import dataclass
from typing import Callable, List, Optional

from localstack.utils.analytics import log

LOG = logging.getLogger(__name__)


@dataclass
class EnvVarDeprecation:
    """
    Simple class defining a deprecation of an environment variable config.
    It helps keeping track of deprecations over time.
    """

    env_var: str
    deprecation_version: str
    deprecation_path: str = None

    @property
    def is_affected(self) -> bool:
        """
        Checks whether an environment is affected.
        :return: true if the environment is affected / is using a deprecated config
        """
        return os.environ.get(self.env_var) is not None


# List of deprecations
DEPRECATIONS = [
    # Since 0.11.3 - HTTP / HTTPS multiplexing
    EnvVarDeprecation(
        "USE_SSL",
        "0.11.3",
        "Each endpoint now supports multiplexing HTTP/HTTPS traffic over the same port. Please remove this environment variable.",  # noqa
    ),
    # Since 0.12.8 - PORT_UI was removed
    EnvVarDeprecation(
        "PORT_WEB_UI",
        "0.12.8",
        "PORT_WEB_UI has been removed, and is not available anymore. Please remove this environment variable.",
    ),
    # Since 0.12.7 - Full multi-region support
    EnvVarDeprecation(
        "USE_SINGLE_REGION",
        "0.12.7",
        "LocalStack now has full multi-region support. Please remove this environment variable.",
    ),
    EnvVarDeprecation(
        "DEFAULT_REGION",
        "0.12.7",
        "LocalStack now has full multi-region support. Please remove this environment variable.",
    ),
    # Since 1.0.0 - New Persistence and file system
    EnvVarDeprecation(
        "DATA_DIR",
        "1.0.0",
        "Please use PERSISTENCE instead. The state will be stored in your LocalStack volume in the state/ directory.",
    ),
    EnvVarDeprecation("HOST_TMP_FOLDER", "1.0.0", "Please remove this environment variable."),
    EnvVarDeprecation(
        "LEGACY_DIRECTORIES",
        "1.0.0",
        "Please migrate to the new filesystem layout (introduced with v1.0).",
    ),
    EnvVarDeprecation(
        "TMPDIR", "1.0.0", "Please migrate to the new filesystem layout (introduced with v1.0)."
    ),
    EnvVarDeprecation(
        "PERSISTENCE_SINGLE_FILE",
        "1.0.0",
        "The legacy persistence mechanism is not supported anymore, please migrate to the advanced persistence mechanism of LocalStack Pro.",  # noqa
    ),
    # Since 1.0.0 - New ASF Gateway
    EnvVarDeprecation(
        "LEGACY_EDGE_PROXY",
        "1.0.0",
        "Please migrate to the new HTTP gateway by removing this environment variable.",
    ),
    # Since 1.1.0 - Kinesalite removed with 1.3, only kinesis-mock is used as kinesis provider / backend
    EnvVarDeprecation(
        "KINESIS_PROVIDER",
        "1.1.0",
        "Only a single provider is supported for kinesis. Please remove this environment variable.",
    ),
    # Since 1.1.0 - Init dir has been deprecated in favor of pluggable init hooks
    EnvVarDeprecation(
        "LEGACY_INIT_DIR",
        "1.1.0",
        "Please use the pluggable initialization hooks in /etc/localhost/init/<stage>.d instead.",
    ),
    EnvVarDeprecation(
        "INIT_SCRIPTS_PATH",
        "1.1.0",
        "Please use the pluggable initialization hooks in /etc/localhost/init/<stage>.d instead.",
    ),
    # Since 1.3.0 - Synchronous events break AWS parity
    EnvVarDeprecation(
        "SYNCHRONOUS_SNS_EVENTS",
        "1.3.0",
        "This configuration breaks parity with AWS. Please remove this environment variable.",
    ),
    EnvVarDeprecation(
        "SYNCHRONOUS_SQS_EVENTS",
        "1.3.0",
        "This configuration breaks parity with AWS. Please remove this environment variable.",
    ),
    EnvVarDeprecation(
        "SYNCHRONOUS_API_GATEWAY_EVENTS",
        "1.3.0",
        "This configuration breaks parity with AWS. Please remove this environment variable.",
    ),
    EnvVarDeprecation(
        "SYNCHRONOUS_KINESIS_EVENTS",
        "1.3.0",
        "This configuration breaks with parity AWS. Please remove this environment variable.",
    ),
    EnvVarDeprecation(
        "SYNCHRONOUS_DYNAMODB_EVENTS",
        "1.3.0",
        "This configuration breaks with parity AWS. Please remove this environment variable.",
    ),
    # Since 1.3.0 - All non-pre-seeded infra is downloaded asynchronously
    EnvVarDeprecation(
        "SKIP_INFRA_DOWNLOADS",
        "1.3.0",
        "Infra downloads are triggered on-demand now. Please remove this environment variable.",
    ),
    # Since 1.3.0 - Mocking for unimplemented operations will be removed
    EnvVarDeprecation(
        "MOCK_UNIMPLEMENTED",
        "1.3.0",
        "This feature will not be suppored in the future. Please remove this environment variable.",
    ),
]


def collect_affected_deprecations(
    deprecations: Optional[List[EnvVarDeprecation]] = None,
) -> List[EnvVarDeprecation]:
    """
    Collects all deprecations which are used in the OS environ.
    :param deprecations: List of deprecations to check. Uses DEPRECATIONS list by default.
    :return: List of deprecations which are used in the current environment
    """
    if deprecations is None:
        deprecations = DEPRECATIONS
    return [deprecation for deprecation in deprecations if deprecation.is_affected]


def log_env_warning(deprecations: List[EnvVarDeprecation]) -> None:
    """
    Logs warnings for the given deprecations.
    :param deprecations: list of affected deprecations to show a warning for
    """
    """
    Logs a warning if a given environment variable is set (no matter the value).
    :param env_var: to check
    :param deprecation_version: version with which the env variable has been deprecated
    """
    if deprecations:
        env_vars = []

        # Print warnings for the env vars and collect them (for the analytics event)
        for deprecation in deprecations:
            LOG.warning(
                "%s is deprecated (since %s) and will be removed in upcoming releases of LocalStack! %s",
                deprecation.env_var,
                deprecation.deprecation_version,
                deprecation.deprecation_path,
            )
            env_vars.append(deprecation.env_var)

        # Log an event if deprecated env vars are used
        log.event(event="deprecated_env_usage", payload={"deprecated_env_vars": env_vars})


def log_deprecation_warnings(deprecations: Optional[List[EnvVarDeprecation]] = None) -> None:
    affected_deprecations = collect_affected_deprecations(deprecations)
    log_env_warning(affected_deprecations)


def deprecated_endpoint(
    endpoint: Callable, previous_path: str, deprecation_version: str, new_path: str
) -> Callable:
    """
    Wrapper function which logs a warning (and a deprecation path) whenever a deprecated URL is invoked by a router.

    :param endpoint: to wrap (log a warning whenever it is invoked)
    :param previous_path: route path it is triggered by
    :param deprecation_version: version of LocalStack with which this endpoint is deprecated
    :param new_path: new route path which should be used instead
    :return: wrapped function which can be registered for a route
    """

    def deprecated_wrapper(*args, **kwargs):
        LOG.warning(
            "%s is deprecated (since %s) and will be removed in upcoming releases of LocalStack! Use %s instead.",
            previous_path,
            deprecation_version,
            new_path,
        )
        return endpoint(*args, **kwargs)

    return deprecated_wrapper

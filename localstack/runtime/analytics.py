import logging
import os

from localstack.runtime import hooks
from localstack.utils.analytics import log

LOG = logging.getLogger(__name__)

TRACKED_ENV_VAR = [
    "DEBUG",
    "DISABLE_CORS_CHECK",
    "DISABLE_CORS_HEADERS",
    "EAGER_SERVICE_LOADING",
    "EDGE_PORT",
    "HOSTNAME",
    "HOSTNAME_EXTERNAL",
    "HOSTNAME_FROM_LAMBDA",
    "LAMBDA_EXECUTOR",
    "LAMBDA_RUNTIME_EXECUTOR",
    "LAMBDA_REMOTE_DOCKER",
    "LAMBDA_PREBUILD_IMAGES",
    "LEGACY_DIRECTORIES",
    "LEGACY_EDGE_PROXY",
    "LS_LOG",
    "PERSISTENCE",
    "OPENSEARCH_ENDPOINT_STRATEGY",
    "SQS_ENDPOINT_STRATEGY",
]

PRESENCE_ENV_VAR = ["LAMBDA_FALLBACK_URL", "LAMBDA_FORWARD_URL"]


@hooks.on_infra_start()
def _publish_config_as_analytics_event():
    from localstack.deprecations import DEPRECATIONS

    env_vars = list(TRACKED_ENV_VAR)

    for key, value in os.environ.items():
        if key.startswith("PROVIDER_OVERRIDE_"):
            env_vars.append(key)

    env_vars = {key: os.getenv(key) for key in env_vars}

    deprecated_env_vars = [dep.env_var for dep in DEPRECATIONS if dep.env_var not in env_vars]
    presence_env_vars = list(set(PRESENCE_ENV_VAR + deprecated_env_vars))
    present_env_vars = {env_var: 1 for env_var in presence_env_vars if os.getenv(env_var)}

    log.event("config", env_vars=env_vars, set_vars=present_env_vars)

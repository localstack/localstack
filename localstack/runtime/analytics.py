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
    env_vars = list(TRACKED_ENV_VAR)

    for key, value in os.environ.items():
        if key.startswith("PROVIDER_OVERRIDE_"):
            env_vars.append(key)

    env_vars = {key: os.getenv(key) for key in env_vars}
    present_env_vars = {env_var: 1 for env_var in PRESENCE_ENV_VAR if os.getenv(env_var)}

    log.event("config", env_vars=env_vars, set_vars=present_env_vars)

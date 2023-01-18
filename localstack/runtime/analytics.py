import logging
import os

from localstack.runtime import hooks
from localstack.utils.analytics import log

LOG = logging.getLogger(__name__)

TRACKED_ENV_VAR = [
    "PROVIDER_OVERRIDE_S3",
    "LAMBDA_RUNTIME_EXECUTOR",
    "DEBUG",
    "DISABLE_CORS_CHECK",
    "DISABLE_CORS_HEADERS",
    "EAGER_SERVICE_LOADING",
    "EDGE_PORT",
    "HOSTNAME",
    "HOSTNAME_EXTERNAL",
    "HOSTNAME_FROM_LAMBDA",
    "LEGACY_DIRECTORIES",
    "LEGACY_EDGE_PROXY",
    "LS_LOG",
    "PERSISTENCE",
    "OPENSEARCH_ENDPOINT_STRATEGY",
    "SQS_ENDPOINT_STRATEGY",
]


@hooks.on_infra_start()
def _publish_config_as_analytics_event():
    env_vars = {key: os.getenv(key) for key in TRACKED_ENV_VAR}

    log.event("config", env_vars=env_vars)

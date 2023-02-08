import logging
import os

from localstack.runtime import hooks
from localstack.utils.analytics import log

LOG = logging.getLogger(__name__)

TRACKED_ENV_VAR = [
    "DEBUG",
    "DEFAULT_REGION",
    "DISABLE_CORS_CHECK",
    "DISABLE_CORS_HEADERS",
    "EAGER_SERVICE_LOADING",
    "EDGE_PORT",
    "ENFORCE_IAM",
    "HOSTNAME",
    "HOSTNAME_EXTERNAL",
    "HOSTNAME_FROM_LAMBDA",
    "IAM_SOFT_MODE",
    "KINESIS_PROVIDER",
    "KMS_PROVIDER",
    "LAMBDA_DOWNLOAD_AWS_LAYERS",
    "LAMBDA_EXECUTOR",
    "LAMBDA_PREBUILD_IMAGES",
    "LAMBDA_REMOTE_DOCKER",
    "LAMBDA_RUNTIME_EXECUTOR",
    "LEGACY_DIRECTORIES",
    "LEGACY_EDGE_PROXY",
    "LS_LOG",
    "MOCK_UNIMPLEMENTED",
    "OPENSEARCH_ENDPOINT_STRATEGY",
    "PERSISTENCE",
    "PERSISTENCE_SINGLE_FILE",
    "PERSIST_ALL",
    "PORT_WEB_UI",
    "RDS_MYSQL_DOCKER",
    "REQUIRE_PRO",
    "SKIP_INFRA_DOWNLOADS",
    "SQS_ENDPOINT_STRATEGY",
    "USE_SINGLE_REGION",
    "USE_SSL",
]

PRESENCE_ENV_VAR = [
    "DATA_DIR",
    "EDGE_FORWARD_URL",
    "HOST_TMP_FOLDER",
    "INIT_SCRIPTS_PATH",
    "LAMBDA_FALLBACK_URL",
    "LAMBDA_FORWARD_URL",
    "LEGACY_DIRECTORIES",
    "LEGACY_INIT_DIR",
    "S3_DIR",
    "TMPDIR",
]


@hooks.on_infra_start()
def _publish_config_as_analytics_event():
    env_vars = list(TRACKED_ENV_VAR)

    for key, value in os.environ.items():
        if key.startswith("PROVIDER_OVERRIDE_"):
            env_vars.append(key)
        elif key.startswith("SYNCHRONOUS_") and key.endswith("_EVENTS"):
            env_vars.append(key)

    env_vars = {key: os.getenv(key) for key in env_vars}
    present_env_vars = {env_var: 1 for env_var in PRESENCE_ENV_VAR if os.getenv(env_var)}

    log.event("config", env_vars=env_vars, set_vars=present_env_vars)

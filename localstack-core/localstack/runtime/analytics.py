import logging
import os

from localstack import config
from localstack.runtime import hooks
from localstack.utils.analytics import log

LOG = logging.getLogger(__name__)

TRACKED_ENV_VAR = [
    "ACTIVATE_PRO",
    "ALLOW_NONSTANDARD_REGIONS",
    "BEDROCK_PREWARM",
    "CLOUDFRONT_LAMBDA_EDGE",
    "CONTAINER_RUNTIME",
    "DEBUG",
    "DEFAULT_REGION",  # Not functional; deprecated in 0.12.7, removed in 3.0.0
    "DEFAULT_BEDROCK_MODEL",
    "DISABLE_CORS_CHECK",
    "DISABLE_CORS_HEADERS",
    "DMS_SERVERLESS_DEPROVISIONING_DELAY",
    "DMS_SERVERLESS_STATUS_CHANGE_WAITING_TIME",
    "DNS_ADDRESS",
    "DYNAMODB_ERROR_PROBABILITY",
    "DYNAMODB_IN_MEMORY",
    "DYNAMODB_REMOVE_EXPIRED_ITEMS",
    "EAGER_SERVICE_LOADING",
    "EC2_VM_MANAGER",
    "ECS_TASK_EXECUTOR",
    "EDGE_PORT",
    "ENABLE_REPLICATOR",
    "ENFORCE_IAM",
    "ES_CUSTOM_BACKEND",  # deprecated in 0.14.0, removed in 3.0.0
    "ES_MULTI_CLUSTER",  # deprecated in 0.14.0, removed in 3.0.0
    "ES_ENDPOINT_STRATEGY",  # deprecated in 0.14.0, removed in 3.0.0
    "EVENT_RULE_ENGINE",
    "IAM_SOFT_MODE",
    "KINESIS_PROVIDER",  # Not functional; deprecated in 2.0.0, removed in 3.0.0
    "KINESIS_ERROR_PROBABILITY",
    "KMS_PROVIDER",  # defunct since 1.4.0
    "LAMBDA_DEBUG_MODE",
    "LAMBDA_DOWNLOAD_AWS_LAYERS",
    "LAMBDA_EXECUTOR",  # Not functional; deprecated in 2.0.0, removed in 3.0.0
    "LAMBDA_STAY_OPEN_MODE",  # Not functional; deprecated in 2.0.0, removed in 3.0.0
    "LAMBDA_REMOTE_DOCKER",  # Not functional; deprecated in 2.0.0, removed in 3.0.0
    "LAMBDA_CODE_EXTRACT_TIME",  # Not functional; deprecated in 2.0.0, removed in 3.0.0
    "LAMBDA_CONTAINER_REGISTRY",  # Not functional; deprecated in 2.0.0, removed in 3.0.0
    "LAMBDA_FALLBACK_URL",  # Not functional; deprecated in 2.0.0, removed in 3.0.0
    "LAMBDA_FORWARD_URL",  # Not functional; deprecated in 2.0.0, removed in 3.0.0
    "LAMBDA_XRAY_INIT",  # Not functional; deprecated in 2.0.0, removed in 3.0.0
    "LAMBDA_PREBUILD_IMAGES",
    "LAMBDA_RUNTIME_EXECUTOR",
    "LAMBDA_RUNTIME_ENVIRONMENT_TIMEOUT",
    "LEGACY_EDGE_PROXY",  # Not functional; deprecated in 1.0.0, removed in 2.0.0
    "LS_LOG",
    "MOCK_UNIMPLEMENTED",  # Not functional; deprecated in 1.3.0, removed in 3.0.0
    "OPENSEARCH_ENDPOINT_STRATEGY",
    "PERSISTENCE",
    "PERSISTENCE_SINGLE_FILE",
    "PERSIST_ALL",  # defunct since 2.3.2
    "PORT_WEB_UI",
    "RDS_MYSQL_DOCKER",
    "REQUIRE_PRO",
    "SERVICES",
    "STRICT_SERVICE_LOADING",
    "SKIP_INFRA_DOWNLOADS",
    "SQS_ENDPOINT_STRATEGY",
    "USE_SINGLE_REGION",  # Not functional; deprecated in 0.12.7, removed in 3.0.0
    "USE_SSL",
]

PRESENCE_ENV_VAR = [
    "DATA_DIR",
    "EDGE_FORWARD_URL",  # Not functional; deprecated in 1.4.0, removed in 3.0.0
    "GATEWAY_LISTEN",
    "HOSTNAME",
    "HOSTNAME_EXTERNAL",
    "HOSTNAME_FROM_LAMBDA",
    "HOST_TMP_FOLDER",  # Not functional; deprecated in 1.0.0, removed in 2.0.0
    "INIT_SCRIPTS_PATH",  # Not functional; deprecated in 1.1.0, removed in 2.0.0
    "LAMBDA_DEBUG_MODE_CONFIG_PATH",
    "LEGACY_DIRECTORIES",  # Not functional; deprecated in 1.1.0, removed in 2.0.0
    "LEGACY_INIT_DIR",  # Not functional; deprecated in 1.1.0, removed in 2.0.0
    "LOCALSTACK_HOST",
    "LOCALSTACK_HOSTNAME",
    "OUTBOUND_HTTP_PROXY",
    "OUTBOUND_HTTPS_PROXY",
    "S3_DIR",
    "SFN_MOCK_CONFIG",
    "TMPDIR",
]


@hooks.on_infra_start()
def _publish_config_as_analytics_event():
    env_vars = list(TRACKED_ENV_VAR)

    for key, value in os.environ.items():
        if key.startswith("PROVIDER_OVERRIDE_"):
            env_vars.append(key)
        elif key.startswith("SYNCHRONOUS_") and key.endswith("_EVENTS"):
            # these config variables have been removed with 3.0.0
            env_vars.append(key)

    env_vars = {key: os.getenv(key) for key in env_vars}
    present_env_vars = {env_var: 1 for env_var in PRESENCE_ENV_VAR if os.getenv(env_var)}

    log.event("config", env_vars=env_vars, set_vars=present_env_vars)


class LocalstackContainerInfo:
    def get_image_variant(self) -> str:
        for f in os.listdir("/usr/lib/localstack"):
            if f.startswith(".") and f.endswith("-version"):
                return f[1:-8]
        return "unknown"

    def has_docker_socket(self) -> bool:
        return os.path.exists("/run/docker.sock")

    def to_dict(self):
        return {
            "variant": self.get_image_variant(),
            "has_docker_socket": self.has_docker_socket(),
        }


@hooks.on_infra_start()
def _publish_container_info():
    if not config.is_in_docker:
        return

    try:
        log.event("container_info", payload=LocalstackContainerInfo().to_dict())
    except Exception as e:
        if config.DEBUG_ANALYTICS:
            LOG.debug("error gathering container information: %s", e)

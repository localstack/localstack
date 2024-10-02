"""Definition of Plux extension points (i.e., hooks) for Lambda."""

from localstack.runtime.hooks import hook_spec

HOOKS_LAMBDA_START_DOCKER_EXECUTOR = "localstack.hooks.lambda_start_docker_executor"
HOOKS_LAMBDA_PREPARE_DOCKER_EXECUTOR = "localstack.hooks.lambda_prepare_docker_executors"
HOOKS_LAMBDA_INJECT_LAYER_FETCHER = "localstack.hooks.lambda_inject_layer_fetcher"
HOOKS_LAMBDA_PREBUILD_ENVIRONMENT_IMAGE = "localstack.hooks.lambda_prebuild_environment_image"
HOOKS_LAMBDA_CREATE_EVENT_SOURCE_POLLER = "localstack.hooks.lambda_create_event_source_poller"
HOOKS_LAMBDA_SET_EVENT_SOURCE_CONFIG_DEFAULTS = (
    "localstack.hooks.lambda_set_event_source_config_defaults"
)


start_docker_executor = hook_spec(HOOKS_LAMBDA_START_DOCKER_EXECUTOR)
prepare_docker_executor = hook_spec(HOOKS_LAMBDA_PREPARE_DOCKER_EXECUTOR)
inject_layer_fetcher = hook_spec(HOOKS_LAMBDA_INJECT_LAYER_FETCHER)
prebuild_environment_image = hook_spec(HOOKS_LAMBDA_PREBUILD_ENVIRONMENT_IMAGE)
create_event_source_poller = hook_spec(HOOKS_LAMBDA_CREATE_EVENT_SOURCE_POLLER)
set_event_source_config_defaults = hook_spec(HOOKS_LAMBDA_SET_EVENT_SOURCE_CONFIG_DEFAULTS)

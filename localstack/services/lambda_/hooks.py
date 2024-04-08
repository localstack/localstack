"""Definition of Plux extension points (i.e., hooks) for Lambda."""

from localstack.runtime.hooks import hook_spec

HOOKS_LAMBDA_START_DOCKER_EXECUTOR = "localstack.hooks.lambda_start_docker_executor"
HOOKS_LAMBDA_PREPARE_DOCKER_EXECUTOR = "localstack.hooks.lambda_prepare_docker_executors"
HOOKS_LAMBDA_INJECT_LAYER_FETCHER = "localstack.hooks.lambda_inject_layer_fetcher"
HOOKS_LAMBDA_PREBUILD_ENVIRONMENT_IMAGE = "localstack.hooks.lambda_prebuild_environment_image"

start_docker_executor = hook_spec(HOOKS_LAMBDA_START_DOCKER_EXECUTOR)
prepare_docker_executor = hook_spec(HOOKS_LAMBDA_PREPARE_DOCKER_EXECUTOR)
inject_layer_fetcher = hook_spec(HOOKS_LAMBDA_INJECT_LAYER_FETCHER)
prebuild_environment_image = hook_spec(HOOKS_LAMBDA_PREBUILD_ENVIRONMENT_IMAGE)

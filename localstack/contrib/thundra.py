import json
import logging
import os
from typing import Optional, Union

from localstack import config
from localstack.services import install
from localstack.services.awslambda.lambda_executors import (
    AdditionalInvocationOptions,
    InvocationContext,
    InvocationResult,
    LambdaExecutorPlugin,
    is_java_lambda,
    is_nodejs_runtime,
)
from localstack.services.awslambda.lambda_utils import (
    LAMBDA_RUNTIME_JAVA8,
    LAMBDA_RUNTIME_JAVA8_AL2,
    LAMBDA_RUNTIME_JAVA11,
    LAMBDA_RUNTIME_NODEJS12X,
    LAMBDA_RUNTIME_NODEJS14X,
    LAMBDA_RUNTIME_NODEJS16X,
    LAMBDA_RUNTIME_PYTHON36,
    LAMBDA_RUNTIME_PYTHON37,
    LAMBDA_RUNTIME_PYTHON38,
    get_executor_mode,
    is_python_runtime,
)
from localstack.utils import common

# logger
LOG = logging.getLogger(__name__)

# Global constants
THUNDRA_APIKEY_ENV_VAR_NAME = "THUNDRA_APIKEY"
THUNDRA_AGENT_LAMBDA_HANDLER_ENV_VAR_NAME = "THUNDRA_AGENT_LAMBDA_HANDLER"
THUNDRA_AGENT_LOG_DISABLE_ENV_VAR_NAME = "THUNDRA_AGENT_LAMBDA_LOG_DISABLE"
THUNDRA_APIKEY = os.getenv(THUNDRA_APIKEY_ENV_VAR_NAME)

# Java related constants
THUNDRA_JAVA_AGENT_INITIALIZED = False
THUNDRA_JAVA_AGENT_REMOTE_URL: Optional[str] = None
THUNDRA_JAVA_AGENT_LOCAL_PATH: Optional[str] = None

# Node related constants
THUNDRA_NODE_AGENT_INITIALIZED = False
THUNDRA_NODE_AGENT_VERSION: Optional[str] = None
THUNDRA_NODE_AGENT_LOCAL_PATH: Optional[str] = None
THUNDRA_NODE_AGENT_LOCAL_PATH_ON_HOST: Optional[str] = None

# Python related constants
THUNDRA_PYTHON_AGENT_INITIALIZED = False
THUNDRA_PYTHON_AGENT_VERSION: Optional[str] = None
THUNDRA_PYTHON_AGENT_LOCAL_PATH: Optional[str] = None
THUNDRA_PYTHON_AGENT_LOCAL_PATH_ON_HOST: Optional[str] = None


################
# COMMON
################


def _get_apikey(env_vars):
    thundra_apikey = env_vars.get(THUNDRA_APIKEY_ENV_VAR_NAME)

    # If Thundra API key is specified for the function through env vars, use it
    if not thundra_apikey:
        # Otherwise, try to get it from Localstack env vars
        thundra_apikey = THUNDRA_APIKEY

    return thundra_apikey


################
# JAVA AGENT
################


def _ensure_java_agent_initialized():
    global THUNDRA_JAVA_AGENT_INITIALIZED
    if not THUNDRA_JAVA_AGENT_INITIALIZED:
        _init_java_agent_configs()
        _install_java_agent()
        THUNDRA_JAVA_AGENT_INITIALIZED = True


def _get_latest_java_agent_version(metadata_url):
    try:
        import xml.etree.ElementTree as et

        import requests

        response = requests.get(metadata_url)
        xml = et.fromstring(response.content)
        latest_version = xml.find("./versioning/latest").text

        return latest_version
    except Exception as e:
        print("Unable to get latest version of Thundra Java agent: %s" % e)
        return "LATEST"


def _init_java_agent_configs():
    global THUNDRA_JAVA_AGENT_REMOTE_URL
    global THUNDRA_JAVA_AGENT_LOCAL_PATH

    metadata_url = (
        "https://repo.thundra.io/service/local/repositories/thundra-releases/content/"
        + "io/thundra/agent/thundra-agent-lambda-bootstrap/maven-metadata.xml"
    )
    latest_version = _get_latest_java_agent_version(metadata_url)
    version = os.getenv("THUNDRA_AGENT_JAVA_VERSION", latest_version)
    jar_name = "thundra-agent-%s.jar" % version

    THUNDRA_JAVA_AGENT_REMOTE_URL = (
        "https://repo.thundra.io/service/local/artifact/maven/redirect?"
        + "r=thundra-releases&g=io.thundra.agent&a=thundra-agent-lambda-bootstrap&v={v}"
    ).format(v=version)
    THUNDRA_JAVA_AGENT_LOCAL_PATH = "%s/%s" % (config.dirs.tmp, jar_name)


def _install_java_agent():
    # Install Thundra Java agent JAR file
    if not os.path.exists(THUNDRA_JAVA_AGENT_LOCAL_PATH):
        install.log_install_msg("Thundra Java agent", verbatim=True)
        install.download(THUNDRA_JAVA_AGENT_REMOTE_URL, THUNDRA_JAVA_AGENT_LOCAL_PATH)


def _is_java8_lambda(func_details):
    runtime = getattr(func_details, "runtime", func_details)
    return runtime == LAMBDA_RUNTIME_JAVA8 or runtime == LAMBDA_RUNTIME_JAVA8_AL2


def _is_java_lambda_with_support_version(lambda_details):
    runtime = getattr(lambda_details, "runtime", lambda_details)
    return runtime in [LAMBDA_RUNTIME_JAVA8, LAMBDA_RUNTIME_JAVA8_AL2, LAMBDA_RUNTIME_JAVA11]


def _prepare_invocation_for_java_lambda(context: InvocationContext) -> AdditionalInvocationOptions:
    # Download and initialize Java agent
    _ensure_java_agent_initialized()

    # If agent could not be initialized, skip here
    if not THUNDRA_JAVA_AGENT_INITIALIZED:
        return None

    result = AdditionalInvocationOptions()
    environment = context.environment
    agent_flag = "-javaagent:{agent_path}"

    # Inject Thundra agent path into "JAVA_TOOL_OPTIONS" env var,
    # so it will be automatically loaded on JVM startup
    java_tool_opts = environment.get("JAVA_TOOL_OPTIONS", "")
    if agent_flag not in java_tool_opts:
        java_tool_opts += f" {agent_flag}"
    result.env_updates["JAVA_TOOL_OPTIONS"] = java_tool_opts.strip()

    # Disable CDS (Class Data Sharing),
    # because "-javaagent" cannot be enabled when CDS is enabled on JDK 8.
    # CDS can only be disabled by "_JAVA_OPTIONS" env var,
    # because by default it is enabled ("-Xshare:on")
    # on Lambci by command line parameters and
    # "_JAVA_OPTIONS" has precedence over command line parameters
    # but "JAVA_TOOL_OPTIONS" is not.
    if _is_java8_lambda(context.lambda_function):
        java_opts = environment.get("_JAVA_OPTIONS", "")
        java_opts += " -Xshare:off"
        result.env_updates["_JAVA_OPTIONS"] = java_opts.strip()

    # If log disable is not configured explicitly, set it to false to enable log capturing by default
    log_disabled = environment.get(THUNDRA_AGENT_LOG_DISABLE_ENV_VAR_NAME)
    if not log_disabled:
        result.env_updates[THUNDRA_AGENT_LOG_DISABLE_ENV_VAR_NAME] = "false"

    # Make sure API key is contained in environment
    result.env_updates[THUNDRA_APIKEY_ENV_VAR_NAME] = _get_apikey(environment)

    # Note: The code below doesn't seem to be required, as LAMBDA_EXECUTOR=local also picks up $JAVA_TOOL_OPTIONS
    # if context.lambda_command:
    #     result.updated_command = context.lambda_command.replace(
    #         "java ", f"java {agent_flag} ", 1
    #     )
    # construct agent file path mapping
    result.files_to_add["agent_path"] = THUNDRA_JAVA_AGENT_LOCAL_PATH

    return result


################
# NODE AGENT
################


def _ensure_node_agent_initialized():
    global THUNDRA_NODE_AGENT_INITIALIZED
    if not THUNDRA_NODE_AGENT_INITIALIZED:
        if _init_node_agent_configs() and _install_node_agent():
            THUNDRA_NODE_AGENT_INITIALIZED = True


def _get_latest_node_agent_version():
    try:
        return common.run("npm view @thundra/core version".split())
    except Exception as e:
        print("Unable to get latest version of Thundra Node agent: %s" % e)
        return None


def _init_node_agent_configs() -> bool:
    global THUNDRA_NODE_AGENT_VERSION
    global THUNDRA_NODE_AGENT_LOCAL_PATH
    global THUNDRA_NODE_AGENT_LOCAL_PATH_ON_HOST

    latest_version = _get_latest_node_agent_version()
    version = os.getenv("THUNDRA_AGENT_NODE_VERSION", latest_version)
    if not version:
        return False

    THUNDRA_NODE_AGENT_VERSION = version.strip()
    THUNDRA_NODE_AGENT_LOCAL_PATH = "%s/thundra/node/%s/" % (
        config.dirs.tmp,
        THUNDRA_NODE_AGENT_VERSION,
    )
    THUNDRA_NODE_AGENT_LOCAL_PATH_ON_HOST = "%s/thundra/node/%s/" % (
        config.dirs.functions,
        THUNDRA_NODE_AGENT_VERSION,
    )

    return True


def _install_node_agent() -> bool:
    # Install Thundra Node agent NPM package
    if not os.path.exists(THUNDRA_NODE_AGENT_LOCAL_PATH):
        install.log_install_msg("Thundra Node agent", verbatim=True)
        try:
            install_thundra_cmd = "npm install --prefix %s @thundra/core@%s --no-save" % (
                THUNDRA_NODE_AGENT_LOCAL_PATH,
                THUNDRA_NODE_AGENT_VERSION,
            )
            common.run(install_thundra_cmd.split())
        except Exception as e:
            print("Unable to install Thundra Node agent: %s" % e)
            return False
    return True


def _is_node_lambda_with_support_version(func_details):
    runtime = getattr(func_details, "runtime", func_details)
    return runtime in [
        LAMBDA_RUNTIME_NODEJS12X,
        LAMBDA_RUNTIME_NODEJS14X,
        LAMBDA_RUNTIME_NODEJS16X,
    ]


def _prepare_invocation_for_node_lambda(context: InvocationContext) -> AdditionalInvocationOptions:
    # Download and initialize Node agent
    _ensure_node_agent_initialized()

    # If agent could not be initialized, skip here
    if not THUNDRA_NODE_AGENT_INITIALIZED:
        return None

    result = AdditionalInvocationOptions()

    # Make sure API key is contained in environment
    result.env_updates[THUNDRA_APIKEY_ENV_VAR_NAME] = _get_apikey(context.environment)

    # Switch handler to Thundra and pass original handler to Thundra through environment variable
    result.env_updates[THUNDRA_AGENT_LAMBDA_HANDLER_ENV_VAR_NAME] = context.handler
    result.updated_handler = "/opt/nodejs/node_modules/@thundra/core/dist/handler.wrapper"

    # If log disable is not configured explicitly, set it to false to enable log capturing by default
    log_disabled = context.environment.get(THUNDRA_AGENT_LOG_DISABLE_ENV_VAR_NAME)
    if not log_disabled:
        result.env_updates[THUNDRA_AGENT_LOG_DISABLE_ENV_VAR_NAME] = "false"

    # Map Thundra agent path into container so it will be accessible by Lambda function Node environment
    agent_path_mapping = (
        "-v %s/node_modules/:/opt/nodejs/node_modules/" % THUNDRA_NODE_AGENT_LOCAL_PATH_ON_HOST
    )

    if context.docker_flags:
        context.docker_flags = f"{context.docker_flags} {agent_path_mapping}"
    else:
        context.docker_flags = agent_path_mapping

    return result


################
# PYTHON AGENT
################


def _ensure_python_agent_initialized():
    global THUNDRA_PYTHON_AGENT_INITIALIZED
    if not THUNDRA_PYTHON_AGENT_INITIALIZED:
        if _init_python_agent_configs() and _install_python_agent():
            THUNDRA_PYTHON_AGENT_INITIALIZED = True


def _get_latest_python_agent_version():
    try:
        from distutils.version import StrictVersion

        import requests

        response = requests.get("https://pypi.org/pypi/thundra/json")
        data = json.loads(response.content.decode())
        versions = sorted(list(data["releases"].keys()), key=StrictVersion, reverse=True)
        return versions[0]
    except Exception as e:
        print("Unable to get latest version of Thundra Python agent: %s" % e)
        return None


def _init_python_agent_configs() -> bool:
    global THUNDRA_PYTHON_AGENT_VERSION
    global THUNDRA_PYTHON_AGENT_LOCAL_PATH
    global THUNDRA_PYTHON_AGENT_LOCAL_PATH_ON_HOST

    latest_version = _get_latest_python_agent_version()
    version = os.getenv("THUNDRA_AGENT_PYTHON_VERSION", latest_version)
    if not version:
        return False

    THUNDRA_PYTHON_AGENT_VERSION = version.strip()
    THUNDRA_PYTHON_AGENT_LOCAL_PATH = "%s/thundra/python/%s/" % (
        config.dirs.tmp,
        THUNDRA_PYTHON_AGENT_VERSION,
    )
    THUNDRA_PYTHON_AGENT_LOCAL_PATH_ON_HOST = "%s/thundra/python/%s/" % (
        config.dirs.functions,
        THUNDRA_PYTHON_AGENT_VERSION,
    )

    return True


def _install_python_agent() -> bool:
    # Install Thundra Python agent PIP package
    if not os.path.exists(THUNDRA_PYTHON_AGENT_LOCAL_PATH):
        install.log_install_msg("Thundra Python agent", verbatim=True)
        try:
            install_thundra_cmd = "pip install --target=%s thundra==%s --no-warn-conflicts" % (
                THUNDRA_PYTHON_AGENT_LOCAL_PATH,
                THUNDRA_PYTHON_AGENT_VERSION,
            )
            common.run(install_thundra_cmd.split())
        except Exception as e:
            print("Unable to install Thundra Python agent: %s" % e)
            return False
    return True


def _is_python_lambda_with_support_version(func_details):
    runtime = getattr(func_details, "runtime", func_details)
    return runtime in [
        LAMBDA_RUNTIME_PYTHON36,
        LAMBDA_RUNTIME_PYTHON37,
        LAMBDA_RUNTIME_PYTHON38,
    ]


def _prepare_invocation_for_python_lambda(
    context: InvocationContext,
) -> AdditionalInvocationOptions:
    # Download and initialize Python agent
    _ensure_python_agent_initialized()

    # If agent could not be initialized, skip here
    if not THUNDRA_PYTHON_AGENT_INITIALIZED:
        return None

    result = AdditionalInvocationOptions()

    # Make sure API key is contained in environment
    result.env_updates[THUNDRA_APIKEY_ENV_VAR_NAME] = _get_apikey(context.environment)

    # Switch handler to Thundra and pass original handler to Thundra through environment variable
    result.env_updates[THUNDRA_AGENT_LAMBDA_HANDLER_ENV_VAR_NAME] = context.handler
    result.updated_handler = "thundra.handler.wrapper"

    # If log disable is not configured explicitly, set it to false to enable log capturing by default
    log_disabled = context.environment.get(THUNDRA_AGENT_LOG_DISABLE_ENV_VAR_NAME)
    if not log_disabled:
        result.env_updates[THUNDRA_AGENT_LOG_DISABLE_ENV_VAR_NAME] = "false"

    # Map Thundra agent path into container so it will be accessible by Lambda function Python environment
    agent_path_mapping = "-v %s/:/opt/python/" % THUNDRA_PYTHON_AGENT_LOCAL_PATH_ON_HOST

    if context.docker_flags:
        context.docker_flags = f"{context.docker_flags} {agent_path_mapping}"
    else:
        context.docker_flags = agent_path_mapping

    return result


################
# THUNDRA PLUGIN
################


class LambdaExecutorPluginThundra(LambdaExecutorPlugin):
    def should_apply(self, context: InvocationContext) -> bool:
        # Local executor is not supported yet
        if "local" in get_executor_mode():
            return False

        # Plugin can only be applied if LAMBDA_REMOTE_DOCKER=0
        if "docker" in get_executor_mode() and config.LAMBDA_REMOTE_DOCKER:
            return False

        # Plugin can only applied if API key is configured
        thundra_apikey = _get_apikey(context.environment)
        if not thundra_apikey:
            return False

        # Plugin can be applied for Java Lambdas with supported versions
        if _is_java_lambda_with_support_version(context.lambda_function.runtime):
            return True

        # Plugin can be applied for Node Lambdas with supported versions
        if _is_node_lambda_with_support_version(context.lambda_function.runtime):
            return True

        # Plugin can be applied for Python Lambdas with supported versions
        if _is_python_lambda_with_support_version(context.lambda_function.runtime):
            return True

        # Not applicable for Thundra plugin
        return False

    def prepare_invocation(
        self, context: InvocationContext
    ) -> Optional[Union[AdditionalInvocationOptions, InvocationResult]]:
        if is_java_lambda(context.lambda_function):
            return _prepare_invocation_for_java_lambda(context)
        elif is_nodejs_runtime(context.lambda_function):
            return _prepare_invocation_for_node_lambda(context)
        elif is_python_runtime(context.lambda_function):
            return _prepare_invocation_for_python_lambda(context)
        return None

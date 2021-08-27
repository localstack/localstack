import logging
import os
from typing import Optional

from localstack import config
from localstack.services import install
from localstack.services.awslambda.lambda_executors import (
    AdditionalInvocationOptions,
    InvocationContext,
    LambdaExecutorPlugin,
    is_java_lambda,
)
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_JAVA8


def get_latest_java_agent_version(metadata_url):
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


# logger
LOG = logging.getLogger(__name__)

# Global constants
THUNDRA_APIKEY_ENV_VAR_NAME = "THUNDRA_APIKEY"
THUNDRA_AGENT_LOG_DISABLE_VAR_NAME = "THUNDRA_AGENT_LAMBDA_LOG_DISABLE"
THUNDRA_APIKEY = os.getenv(THUNDRA_APIKEY_ENV_VAR_NAME)

# Java related constants
THUNDRA_JAVA_AGENT_INITIALIZED = False
THUNDRA_JAVA_AGENT_REMOTE_URL = None
THUNDRA_JAVA_AGENT_LOCAL_PATH = None


def _get_apikey(env_vars):
    thundra_apikey = env_vars.get(THUNDRA_APIKEY_ENV_VAR_NAME)

    # If Thundra API key is specified for the function through env vars, use it
    if not thundra_apikey:
        # Otherwise, try to get it from Localstack env vars
        thundra_apikey = THUNDRA_APIKEY

    return thundra_apikey


#############
# JAVA AGENT
#############


def _ensure_java_agent_initialized():
    global THUNDRA_JAVA_AGENT_INITIALIZED
    if not THUNDRA_JAVA_AGENT_INITIALIZED:
        _init_java_agent_configs()
        _install_java_agent()
        THUNDRA_JAVA_AGENT_INITIALIZED = True


def _init_java_agent_configs():
    global THUNDRA_JAVA_AGENT_REMOTE_URL
    global THUNDRA_JAVA_AGENT_LOCAL_PATH

    metadata_url = (
        "https://repo.thundra.io/service/local/repositories/thundra-releases/content/"
        + "io/thundra/agent/thundra-agent-lambda-bootstrap/maven-metadata.xml"
    )
    latest_version = get_latest_java_agent_version(metadata_url)
    version = os.getenv("THUNDRA_AGENT_JAVA_VERSION", latest_version)
    jar_name = "thundra-agent-%s.jar" % version

    THUNDRA_JAVA_AGENT_REMOTE_URL = (
        "https://repo.thundra.io/service/local/artifact/maven/redirect?"
        + "r=thundra-releases&g=io.thundra.agent&a=thundra-agent-lambda-bootstrap&v={v}"
    ).format(v=version)
    THUNDRA_JAVA_AGENT_LOCAL_PATH = "%s/%s" % (config.TMP_FOLDER, jar_name)


def _install_java_agent():
    # install Thundra Java agent JAR file
    if not os.path.exists(THUNDRA_JAVA_AGENT_LOCAL_PATH):
        install.log_install_msg("Thundra Java agent", verbatim=True)
        install.download(THUNDRA_JAVA_AGENT_REMOTE_URL, THUNDRA_JAVA_AGENT_LOCAL_PATH)


def _is_java8_lambda(func_details):
    runtime = getattr(func_details, "runtime", func_details)
    return runtime == LAMBDA_RUNTIME_JAVA8


class LambdaExecutorPluginThundra(LambdaExecutorPlugin):
    def initialize(self):
        # If Thundra API key is initialized, init at startup
        if THUNDRA_APIKEY:
            _ensure_java_agent_initialized()

    def should_apply(self, context: InvocationContext) -> bool:
        # plugin currently only applied for Java Lambdas, if LAMBDA_REMOTE_DOCKER=0, and if API key is configured
        if not is_java_lambda(context.lambda_function.runtime):
            return False
        if "docker" in config.LAMBDA_EXECUTOR and config.LAMBDA_REMOTE_DOCKER:
            return False
        thundra_apikey = _get_apikey(context.environment)
        if not thundra_apikey:
            return False
        return True

    def prepare_invocation(
        self, context: InvocationContext
    ) -> Optional[AdditionalInvocationOptions]:
        # download and initialize Java agent
        _ensure_java_agent_initialized()

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
        log_disabled = environment.get(THUNDRA_AGENT_LOG_DISABLE_VAR_NAME)
        if not log_disabled:
            result.env_updates[THUNDRA_AGENT_LOG_DISABLE_VAR_NAME] = "false"

        # make sure API key is contained in environment
        result.env_updates[THUNDRA_APIKEY_ENV_VAR_NAME] = _get_apikey(environment)

        # Note: The code below doesn't seem to be required, as LAMBDA_EXECUTOR=local also picks up $JAVA_TOOL_OPTIONS
        # if context.lambda_command:
        #     result.updated_command = context.lambda_command.replace(
        #         "java ", f"java {agent_flag} ", 1
        #     )
        # construct agent file path mapping
        result.files_to_add["agent_path"] = THUNDRA_JAVA_AGENT_LOCAL_PATH

        return result

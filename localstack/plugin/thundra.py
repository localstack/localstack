import logging
import os

from localstack import config
from localstack.services import install
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
THUNDRA_APIKEY = os.getenv(THUNDRA_APIKEY_ENV_VAR_NAME)

# Java related constants
THUNDRA_JAVA_AGENT_INITIALIZED = False
THUNDRA_JAVA_AGENT_REMOTE_URL = None
THUNDRA_JAVA_AGENT_LOCAL_PATH = None
THUNDRA_JAVA_AGENT_CONTAINER_SOURCE_PATH = None
THUNDRA_JAVA_AGENT_CONTAINER_TARGET_PATH = None


def init():
    """
    Initialized Thundra plugin at startup
    """

    # If Thundra API key is initialized, init at startup
    if THUNDRA_APIKEY:
        _ensure_java_agent_initialized()


def _get_apikey(env_vars):
    thundra_apikey = env_vars.get(THUNDRA_APIKEY_ENV_VAR_NAME)

    # If Thundra API key is specified for the function through env vars, use it
    if not thundra_apikey:
        # Otherwise, try to get it from Localstack env vars
        thundra_apikey = THUNDRA_APIKEY

    return thundra_apikey


########################################################################################################################
# JAVA AGENT
########################################################################################################################


def _ensure_java_agent_initialized():
    global THUNDRA_JAVA_AGENT_INITIALIZED
    if not THUNDRA_JAVA_AGENT_INITIALIZED:
        _init_java_agent_configs()
        _install_java_agent()
        THUNDRA_JAVA_AGENT_INITIALIZED = True


def _init_java_agent_configs():
    global THUNDRA_JAVA_AGENT_REMOTE_URL
    global THUNDRA_JAVA_AGENT_LOCAL_PATH
    global THUNDRA_JAVA_AGENT_CONTAINER_SOURCE_PATH
    global THUNDRA_JAVA_AGENT_CONTAINER_TARGET_PATH

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

    THUNDRA_JAVA_AGENT_CONTAINER_SOURCE_PATH = "%s/%s" % (config.HOST_TMP_FOLDER, jar_name)
    THUNDRA_JAVA_AGENT_CONTAINER_TARGET_PATH = "/tmp/thundra-agent.jar"


def _install_java_agent():
    # install Thundra Java agent JAR file
    if not os.path.exists(THUNDRA_JAVA_AGENT_LOCAL_PATH):
        install.log_install_msg("Thundra Java agent", verbatim=True)
        install.download(THUNDRA_JAVA_AGENT_REMOTE_URL, THUNDRA_JAVA_AGENT_LOCAL_PATH)


def _is_java8_lambda(func_details):
    runtime = getattr(func_details, "runtime", func_details)
    return runtime == LAMBDA_RUNTIME_JAVA8


def inject_java_agent_for_local(func_details, java_opts):
    """
    Injects Thundra Java agent if it is available and configured when Lambda is executed on Local

    :param func_details: the function details
    :param java_opts: existing options to be passed as VM arguments to the local JVM process
    :return: the additional options to be passed as VM arguments to the local JVM process
    """

    thundra_apikey = _get_apikey(func_details.envvars)
    if not thundra_apikey:
        return None

    _ensure_java_agent_initialized()

    if not THUNDRA_JAVA_AGENT_LOCAL_PATH:
        return None

    func_details.envvars[THUNDRA_APIKEY_ENV_VAR_NAME] = thundra_apikey

    return "-javaagent:" + THUNDRA_JAVA_AGENT_LOCAL_PATH


def inject_java_agent_for_container(func_details, environment, docker_flags):
    """
    Injects Thundra Java agent if it is available and configured when Lambda is executed in container (Docker)

    :param func_details: the function details
    :param environment: the function environment variables
    :param docker_flags: existing Docker flags to be to "docker run" command
    :return: the additional Docker flags to be passed to "docker run" command
    """

    thundra_apikey = _get_apikey(environment)
    if not thundra_apikey:
        return None

    _ensure_java_agent_initialized()

    if not THUNDRA_JAVA_AGENT_CONTAINER_SOURCE_PATH:
        return None

    if config.LAMBDA_REMOTE_DOCKER:
        LOG.info(
            "Not enabling Thundra agent, as Docker file mounting is disabled due to LAMBDA_REMOTE_DOCKER=1"
        )
        return None

    environment[THUNDRA_APIKEY_ENV_VAR_NAME] = thundra_apikey

    # Inject Thundra agent path into "JAVA_TOOL_OPTIONS" env var,
    # so it will be automatically loaded on JVM startup
    java_tool_opts = environment.get("JAVA_TOOL_OPTIONS", "")
    java_tool_opts += " -javaagent:" + THUNDRA_JAVA_AGENT_CONTAINER_TARGET_PATH
    environment["JAVA_TOOL_OPTIONS"] = java_tool_opts.strip()

    # Disable CDS (Class Data Sharing),
    # because "-javaagent" cannot be enabled when CDS is enabled on JDK 8.
    # CDS can only be disabled by "_JAVA_OPTIONS" env var,
    # because by default it is enabled ("-Xshare:on")
    # on Lambci by command line parameters and
    # "_JAVA_OPTIONS" has precedence over command line parameters
    # but "JAVA_TOOL_OPTIONS" is not.
    if _is_java8_lambda(func_details):
        java_opts = environment.get("_JAVA_OPTIONS", "")
        java_opts += " -Xshare:off"
        environment["_JAVA_OPTIONS"] = java_opts.strip()

    # Mount Thundra agent jar into container file system
    return "-v %s:%s" % (
        THUNDRA_JAVA_AGENT_CONTAINER_SOURCE_PATH,
        THUNDRA_JAVA_AGENT_CONTAINER_TARGET_PATH,
    )


########################################################################################################################

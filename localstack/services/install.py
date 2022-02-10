#!/usr/bin/env python
import functools
import glob
import logging
import os
import platform
import re
import shutil
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Tuple

import requests
from plugin import Plugin, PluginManager

from localstack import config
from localstack.config import dirs, has_docker
from localstack.constants import (
    DEFAULT_SERVICE_PORTS,
    DYNAMODB_JAR_URL,
    ELASTICMQ_JAR_URL,
    ELASTICSEARCH_DEFAULT_VERSION,
    ELASTICSEARCH_DELETE_MODULES,
    ELASTICSEARCH_PLUGIN_LIST,
    KMS_URL_PATTERN,
    LOCALSTACK_MAVEN_VERSION,
    MODULE_MAIN_PATH,
    OPENSEARCH_DEFAULT_VERSION,
    STS_JAR_URL,
)
from localstack.runtime import hooks
from localstack.utils.common import (
    chmod_r,
    download,
    file_exists_not_empty,
    get_arch,
    is_windows,
    load_file,
    mkdir,
    new_tmp_file,
    parallelize,
    replace_in_file,
    retry,
    rm_rf,
    run,
    safe_run,
    save_file,
    untar,
    unzip,
)
from localstack.utils.docker_utils import DOCKER_CLIENT

LOG = logging.getLogger(__name__)

INSTALL_DIR_NPM = "%s/node_modules" % MODULE_MAIN_PATH  # FIXME: migrate to infra
INSTALL_DIR_DDB = "%s/dynamodb" % dirs.static_libs
INSTALL_DIR_KCL = "%s/amazon-kinesis-client" % dirs.static_libs
INSTALL_DIR_STEPFUNCTIONS = "%s/stepfunctions" % dirs.static_libs
INSTALL_DIR_KMS = "%s/kms" % dirs.static_libs
INSTALL_DIR_ELASTICMQ = "%s/elasticmq" % dirs.static_libs
INSTALL_DIR_KINESIS_MOCK = os.path.join(dirs.static_libs, "kinesis-mock")
INSTALL_PATH_LOCALSTACK_FAT_JAR = "%s/localstack-utils-fat.jar" % dirs.static_libs
INSTALL_PATH_DDB_JAR = os.path.join(INSTALL_DIR_DDB, "DynamoDBLocal.jar")
INSTALL_PATH_KCL_JAR = os.path.join(INSTALL_DIR_KCL, "aws-java-sdk-sts.jar")
INSTALL_PATH_STEPFUNCTIONS_JAR = os.path.join(INSTALL_DIR_STEPFUNCTIONS, "StepFunctionsLocal.jar")
INSTALL_PATH_KMS_BINARY_PATTERN = os.path.join(INSTALL_DIR_KMS, "local-kms.<arch>.bin")
INSTALL_PATH_ELASTICMQ_JAR = os.path.join(INSTALL_DIR_ELASTICMQ, "elasticmq-server.jar")
INSTALL_PATH_KINESALITE_CLI = os.path.join(INSTALL_DIR_NPM, "kinesalite", "cli.js")
URL_LOCALSTACK_FAT_JAR = (
    "https://repo1.maven.org/maven2/"
    + "cloud/localstack/localstack-utils/{v}/localstack-utils-{v}-fat.jar"
).format(v=LOCALSTACK_MAVEN_VERSION)

MARKER_FILE_LIGHT_VERSION = "%s/.light-version" % dirs.static_libs
IMAGE_NAME_SFN_LOCAL = "amazon/aws-stepfunctions-local:1.7.9"
ARTIFACTS_REPO = "https://github.com/localstack/localstack-artifacts"
SFN_PATCH_URL_PREFIX = (
    f"{ARTIFACTS_REPO}/raw/2958554c8aeadff0e8f5d0e35f6e520d834854ea/stepfunctions-local-patch"
)
SFN_PATCH_CLASS1 = "com/amazonaws/stepfunctions/local/runtime/Config.class"
SFN_PATCH_CLASS2 = (
    "com/amazonaws/stepfunctions/local/runtime/executors/task/LambdaTaskStateExecutor.class"
)
SFN_PATCH_CLASS_STARTER = "cloud/localstack/StepFunctionsStarter.class"
SFN_PATCH_CLASS_REGION = "cloud/localstack/RegionAspect.class"
SFN_PATCH_CLASS_ASYNC2SERVICEAPI = "cloud/localstack/Async2ServiceApi.class"
SFN_PATCH_CLASS_DESCRIBEEXECUTIONPARSED = "cloud/localstack/DescribeExecutionParsed.class"
SFN_PATCH_FILE_METAINF = "META-INF/aop.xml"

SFN_AWS_SDK_URL_PREFIX = (
    f"{ARTIFACTS_REPO}/raw/a4adc8f4da9c7ec0d93b50ca5b73dd14df791c0e/stepfunctions-internal-awssdk"
)
SFN_AWS_SDK_LAMBDA_ZIP_FILE = f"{SFN_AWS_SDK_URL_PREFIX}/awssdk.zip"

# additional JAR libs required for multi-region and persistence (PRO only) support
MAVEN_REPO = "https://repo1.maven.org/maven2"
URL_ASPECTJRT = f"{MAVEN_REPO}/org/aspectj/aspectjrt/1.9.7/aspectjrt-1.9.7.jar"
URL_ASPECTJWEAVER = f"{MAVEN_REPO}/org/aspectj/aspectjweaver/1.9.7/aspectjweaver-1.9.7.jar"
JAR_URLS = [URL_ASPECTJRT, URL_ASPECTJWEAVER]

# kinesis-mock version
KINESIS_MOCK_VERSION = os.environ.get("KINESIS_MOCK_VERSION") or "0.2.2"
KINESIS_MOCK_RELEASE_URL = (
    "https://api.github.com/repos/etspaceman/kinesis-mock/releases/tags/" + KINESIS_MOCK_VERSION
)

# debugpy module
DEBUGPY_MODULE = "debugpy"
DEBUGPY_DEPENDENCIES = ["gcc", "python3-dev", "musl-dev"]

# Target version for javac, to ensure compatibility with earlier JREs
JAVAC_TARGET_VERSION = "1.8"

# SQS backend implementation provider - either "moto" or "elasticmq"
SQS_BACKEND_IMPL = os.environ.get("SQS_PROVIDER") or "moto"

# GO Lambda runtime
GO_RUNTIME_VERSION = "0.4.0"
GO_RUNTIME_DOWNLOAD_URL_TEMPLATE = "https://github.com/localstack/awslamba-go-runtime/releases/download/v{version}/awslamba-go-runtime-{version}-{os}-{arch}.tar.gz"
GO_INSTALL_FOLDER = os.path.join(config.dirs.var_libs, "awslamba-go-runtime")
GO_LAMBDA_RUNTIME = os.path.join(GO_INSTALL_FOLDER, "aws-lambda-mock")
GO_LAMBDA_MOCKSERVER = os.path.join(GO_INSTALL_FOLDER, "mockserver")

# Terraform (used for tests)
TERRAFORM_VERSION = "1.1.3"
TERRAFORM_URL_TEMPLATE = (
    "https://releases.hashicorp.com/terraform/{version}/terraform_{version}_{os}_{arch}.zip"
)
TERRAFORM_BIN = os.path.join(dirs.static_libs, f"terraform-{TERRAFORM_VERSION}", "terraform")

# Java Test Jar Download (used for tests)
TEST_LAMBDA_JAVA = os.path.join(config.dirs.var_libs, "localstack-utils-tests.jar")
MAVEN_BASE_URL = "https://repo.maven.apache.org/maven2"
TEST_LAMBDA_JAR_URL = "{url}/cloud/localstack/{name}/{version}/{name}-{version}-tests.jar".format(
    version=LOCALSTACK_MAVEN_VERSION, url=MAVEN_BASE_URL, name="localstack-utils"
)

OS_INSTALL_LOCKS = {}


def get_elasticsearch_install_version(version: str) -> str:
    from localstack.services.opensearch import versions

    if config.SKIP_INFRA_DOWNLOADS:
        return ELASTICSEARCH_DEFAULT_VERSION

    return versions.get_install_version(version)


def get_elasticsearch_install_dir(version: str) -> str:
    if version == get_elasticsearch_install_version(
        ELASTICSEARCH_DEFAULT_VERSION
    ) and not os.path.exists(MARKER_FILE_LIGHT_VERSION):
        # install the default version into a subfolder of the code base
        install_dir = os.path.join(dirs.static_libs, "elasticsearch")
    else:
        # put all other versions into the TMP_FOLDER
        install_dir = os.path.join(config.dirs.var_libs, "elasticsearch", version)

    return install_dir


def install_elasticsearch(version=None):
    # locally import to avoid having a dependency on ASF when starting the CLI
    from localstack.aws.api.opensearch import EngineType
    from localstack.services.opensearch import versions

    if not version:
        version = ELASTICSEARCH_DEFAULT_VERSION

    version = get_elasticsearch_install_version(version)
    install_dir = get_elasticsearch_install_dir(version)
    installed_executable = os.path.join(install_dir, "bin", "elasticsearch")
    if not os.path.exists(installed_executable):
        log_install_msg("Elasticsearch (%s)" % version)
        es_url = versions.get_download_url(version, EngineType.Elasticsearch)
        install_dir_parent = os.path.dirname(install_dir)
        mkdir(install_dir_parent)
        # download and extract archive
        tmp_archive = os.path.join(config.dirs.tmp, "localstack.%s" % os.path.basename(es_url))
        download_and_extract_with_retry(es_url, tmp_archive, install_dir_parent)
        elasticsearch_dir = glob.glob(os.path.join(install_dir_parent, "elasticsearch*"))
        if not elasticsearch_dir:
            raise Exception("Unable to find Elasticsearch folder in %s" % install_dir_parent)
        shutil.move(elasticsearch_dir[0], install_dir)

        for dir_name in ("data", "logs", "modules", "plugins", "config/scripts"):
            dir_path = os.path.join(install_dir, dir_name)
            mkdir(dir_path)
            chmod_r(dir_path, 0o777)

        # install default plugins
        for plugin in ELASTICSEARCH_PLUGIN_LIST:
            plugin_binary = os.path.join(install_dir, "bin", "elasticsearch-plugin")
            plugin_dir = os.path.join(install_dir, "plugins", plugin)
            if not os.path.exists(plugin_dir):
                LOG.info("Installing Elasticsearch plugin %s", plugin)

                def try_install():
                    output = safe_run([plugin_binary, "install", "-b", plugin])
                    LOG.debug("Plugin installation output: %s", output)

                # We're occasionally seeing javax.net.ssl.SSLHandshakeException -> add download retries
                download_attempts = 3
                try:
                    retry(try_install, retries=download_attempts - 1, sleep=2)
                except Exception:
                    LOG.warning(
                        "Unable to download Elasticsearch plugin '%s' after %s attempts",
                        plugin,
                        download_attempts,
                    )
                    if not os.environ.get("IGNORE_ES_DOWNLOAD_ERRORS"):
                        raise

    # delete some plugins to free up space
    for plugin in ELASTICSEARCH_DELETE_MODULES:
        module_dir = os.path.join(install_dir, "modules", plugin)
        rm_rf(module_dir)

    # disable x-pack-ml plugin (not working on Alpine)
    xpack_dir = os.path.join(install_dir, "modules", "x-pack-ml", "platform")
    rm_rf(xpack_dir)

    # patch JVM options file - replace hardcoded heap size settings
    jvm_options_file = os.path.join(install_dir, "config", "jvm.options")
    if os.path.exists(jvm_options_file):
        jvm_options = load_file(jvm_options_file)
        jvm_options_replaced = re.sub(
            r"(^-Xm[sx][a-zA-Z0-9\.]+$)", r"# \1", jvm_options, flags=re.MULTILINE
        )
        if jvm_options != jvm_options_replaced:
            save_file(jvm_options_file, jvm_options_replaced)


def get_opensearch_install_version(version: str) -> str:
    from localstack.services.opensearch import versions

    if config.SKIP_INFRA_DOWNLOADS:
        version = OPENSEARCH_DEFAULT_VERSION

    return versions.get_install_version(version)


def get_opensearch_install_dir(version: str) -> str:
    return os.path.join(config.dirs.var_libs, "opensearch", version)


def install_opensearch(version=None):
    # locally import to avoid having a dependency on ASF when starting the CLI
    from localstack.aws.api.opensearch import EngineType
    from localstack.services.opensearch import versions

    if not version:
        version = OPENSEARCH_DEFAULT_VERSION

    version = get_opensearch_install_version(version)
    install_dir = get_opensearch_install_dir(version)
    installed_executable = os.path.join(install_dir, "bin", "opensearch")
    if not os.path.exists(installed_executable):
        with OS_INSTALL_LOCKS.setdefault(version, threading.Lock()):
            if not os.path.exists(installed_executable):
                log_install_msg("OpenSearch (%s)" % version)
                opensearch_url = versions.get_download_url(version, EngineType.OpenSearch)
                install_dir_parent = os.path.dirname(install_dir)
                mkdir(install_dir_parent)
                # download and extract archive
                tmp_archive = os.path.join(
                    config.dirs.tmp, f"localstack.{os.path.basename(opensearch_url)}"
                )
                download_and_extract_with_retry(opensearch_url, tmp_archive, install_dir_parent)
                opensearch_dir = glob.glob(os.path.join(install_dir_parent, "opensearch*"))
                if not opensearch_dir:
                    raise Exception("Unable to find OpenSearch folder in %s" % install_dir_parent)
                shutil.move(opensearch_dir[0], install_dir)

                for dir_name in ("data", "logs", "modules", "plugins", "config/scripts"):
                    dir_path = os.path.join(install_dir, dir_name)
                    mkdir(dir_path)
                    chmod_r(dir_path, 0o777)

    # patch JVM options file - replace hardcoded heap size settings
    jvm_options_file = os.path.join(install_dir, "config", "jvm.options")
    if os.path.exists(jvm_options_file):
        jvm_options = load_file(jvm_options_file)
        jvm_options_replaced = re.sub(
            r"(^-Xm[sx][a-zA-Z0-9\.]+$)", r"# \1", jvm_options, flags=re.MULTILINE
        )
        if jvm_options != jvm_options_replaced:
            save_file(jvm_options_file, jvm_options_replaced)


def install_sqs_provider():
    if SQS_BACKEND_IMPL == "elasticmq":
        install_elasticmq()


def install_elasticmq():
    # TODO remove this function if we stop using ElasticMQ entirely
    if not os.path.exists(INSTALL_PATH_ELASTICMQ_JAR):
        log_install_msg("ElasticMQ")
        mkdir(INSTALL_DIR_ELASTICMQ)
        # download archive
        tmp_archive = os.path.join(config.dirs.tmp, "elasticmq-server.jar")
        if not os.path.exists(tmp_archive):
            download(ELASTICMQ_JAR_URL, tmp_archive)
        shutil.copy(tmp_archive, INSTALL_DIR_ELASTICMQ)


def install_kinesis():
    if config.KINESIS_PROVIDER == "kinesalite":
        install_kinesalite()
        return
    if config.KINESIS_PROVIDER == "kinesis-mock":
        is_installed, bin_path = get_is_kinesis_mock_installed()
        if not is_installed:
            install_kinesis_mock(bin_path)
        return
    raise ValueError("unknown kinesis provider %s" % config.KINESIS_PROVIDER)


def _apply_patches_kinesalite():
    files = [
        "%s/kinesalite/validations/decreaseStreamRetentionPeriod.js",
        "%s/kinesalite/validations/increaseStreamRetentionPeriod.js",
    ]
    for file_path in files:
        file_path = file_path % INSTALL_DIR_NPM
        replace_in_file("lessThanOrEqual: 168", "lessThanOrEqual: 8760", file_path)


def install_kinesalite():
    if not os.path.exists(INSTALL_PATH_KINESALITE_CLI):
        log_install_msg("Kinesis")
        run('cd "%s" && npm install' % MODULE_MAIN_PATH)
        _apply_patches_kinesalite()


def get_is_kinesis_mock_installed() -> Tuple[bool, str]:
    """
    Checks the host system to see if kinesis mock is installed and where.
    :returns: True if kinesis mock is installed (False otherwise) and the expected installation path
    """
    bin_file_path = kinesis_mock_install_path()
    if os.path.exists(bin_file_path):
        LOG.debug("kinesis-mock found at %s", bin_file_path)
        return True, bin_file_path
    return False, bin_file_path


def kinesis_mock_install_path() -> str:
    machine = platform.machine().lower()
    system = platform.system().lower()
    version = platform.version().lower()
    is_probably_m1 = system == "darwin" and ("arm64" in version or "arm32" in version)

    LOG.debug("getting kinesis-mock for %s %s", system, machine)
    if config.is_env_true("KINESIS_MOCK_FORCE_JAVA"):
        # sometimes the static binaries may have problems, and we want to fal back to Java
        bin_file = "kinesis-mock.jar"
    elif (machine == "x86_64" or machine == "amd64") and not is_probably_m1:
        if system == "windows":
            bin_file = "kinesis-mock-mostly-static.exe"
        elif system == "linux":
            bin_file = "kinesis-mock-linux-amd64-static"
        elif system == "darwin":
            bin_file = "kinesis-mock-macos-amd64-dynamic"
        else:
            bin_file = "kinesis-mock.jar"
    else:
        bin_file = "kinesis-mock.jar"

    bin_file_path = os.path.join(INSTALL_DIR_KINESIS_MOCK, bin_file)
    return bin_file_path


def install_kinesis_mock(bin_file_path: str = None):
    response = requests.get(KINESIS_MOCK_RELEASE_URL)
    if not response.ok:
        raise ValueError(
            "Could not get list of releases from %s: %s" % (KINESIS_MOCK_RELEASE_URL, response.text)
        )

    bin_file_path = bin_file_path or kinesis_mock_install_path()
    github_release = response.json()
    download_url = None
    bin_file_name = os.path.basename(bin_file_path)
    for asset in github_release.get("assets", []):
        # find the correct binary in the release
        if asset["name"] == bin_file_name:
            download_url = asset["browser_download_url"]
            break
    if download_url is None:
        raise ValueError(
            "could not find required binary %s in release %s"
            % (bin_file_name, KINESIS_MOCK_RELEASE_URL)
        )

    mkdir(INSTALL_DIR_KINESIS_MOCK)
    LOG.info("downloading kinesis-mock binary from %s", download_url)
    download(download_url, bin_file_path)
    chmod_r(bin_file_path, 0o777)


def install_local_kms():
    local_arch = f"{platform.system().lower()}-{get_arch()}"
    binary_path = INSTALL_PATH_KMS_BINARY_PATTERN.replace("<arch>", local_arch)
    if not os.path.exists(binary_path):
        log_install_msg("KMS")
        mkdir(INSTALL_DIR_KMS)
        kms_url = KMS_URL_PATTERN.replace("<arch>", local_arch)
        download(kms_url, binary_path)
        chmod_r(binary_path, 0o777)


def install_stepfunctions_local():
    if not os.path.exists(INSTALL_PATH_STEPFUNCTIONS_JAR):
        # pull the JAR file from the Docker image, which is more up-to-date than the downloadable JAR file
        if not has_docker():
            # TODO: works only when a docker socket is available -> add a fallback if running without Docker?
            LOG.warning("Docker not available - skipping installation of StepFunctions dependency")
            return
        log_install_msg("Step Functions")
        mkdir(INSTALL_DIR_STEPFUNCTIONS)
        DOCKER_CLIENT.pull_image(IMAGE_NAME_SFN_LOCAL)
        docker_name = "tmp-ls-sfn"
        DOCKER_CLIENT.run_container(
            IMAGE_NAME_SFN_LOCAL,
            remove=True,
            entrypoint="",
            name=docker_name,
            detach=True,
            command=["sleep", "15"],
        )
        time.sleep(5)
        DOCKER_CLIENT.copy_from_container(
            docker_name, local_path=dirs.static_libs, container_path="/home/stepfunctionslocal/"
        )

        path = Path(f"{dirs.static_libs}/stepfunctionslocal/")
        for file in path.glob("*.jar"):
            file.rename(Path(INSTALL_DIR_STEPFUNCTIONS) / file.name)
        rm_rf("%s/stepfunctionslocal" % dirs.static_libs)

    classes = [
        SFN_PATCH_CLASS1,
        SFN_PATCH_CLASS2,
        SFN_PATCH_CLASS_REGION,
        SFN_PATCH_CLASS_STARTER,
        SFN_PATCH_CLASS_ASYNC2SERVICEAPI,
        SFN_PATCH_CLASS_DESCRIBEEXECUTIONPARSED,
        SFN_PATCH_FILE_METAINF,
    ]
    for patch_class in classes:
        patch_url = f"{SFN_PATCH_URL_PREFIX}/{patch_class}"
        add_file_to_jar(patch_class, patch_url, target_jar=INSTALL_PATH_STEPFUNCTIONS_JAR)

    # special case for Manifest file - extract first, replace content, then update in JAR file
    manifest_file = os.path.join(INSTALL_DIR_STEPFUNCTIONS, "META-INF", "MANIFEST.MF")
    if not os.path.exists(manifest_file):
        content = run(["unzip", "-p", INSTALL_PATH_STEPFUNCTIONS_JAR, "META-INF/MANIFEST.MF"])
        content = re.sub(
            "Main-Class: .+", "Main-Class: cloud.localstack.StepFunctionsStarter", content
        )
        classpath = " ".join([os.path.basename(jar) for jar in JAR_URLS])
        content = re.sub(r"Class-Path: \. ", f"Class-Path: {classpath} . ", content)
        save_file(manifest_file, content)
        run(
            ["zip", INSTALL_PATH_STEPFUNCTIONS_JAR, "META-INF/MANIFEST.MF"],
            cwd=INSTALL_DIR_STEPFUNCTIONS,
        )

    # download additional jar libs
    for jar_url in JAR_URLS:
        target = os.path.join(INSTALL_DIR_STEPFUNCTIONS, os.path.basename(jar_url))
        if not file_exists_not_empty(target):
            download(jar_url, target)

    # download aws-sdk lambda handler
    target = os.path.join(INSTALL_DIR_STEPFUNCTIONS, "localstack-internal-awssdk", "awssdk.zip")
    if not file_exists_not_empty(target):
        download(SFN_AWS_SDK_LAMBDA_ZIP_FILE, target)


def add_file_to_jar(class_file, class_url, target_jar, base_dir=None):
    base_dir = base_dir or os.path.dirname(target_jar)
    patch_class_file = os.path.join(base_dir, class_file)
    if not os.path.exists(patch_class_file):
        download(class_url, patch_class_file)
        run(["zip", target_jar, class_file], cwd=base_dir)


def install_dynamodb_local():
    if not os.path.exists(INSTALL_PATH_DDB_JAR):
        log_install_msg("DynamoDB")
        # download and extract archive
        tmp_archive = os.path.join(tempfile.gettempdir(), "localstack.ddb.zip")
        download_and_extract_with_retry(DYNAMODB_JAR_URL, tmp_archive, INSTALL_DIR_DDB)

    # fix logging configuration for DynamoDBLocal
    log4j2_config = """<Configuration status="WARN">
      <Appenders>
        <Console name="Console" target="SYSTEM_OUT">
          <PatternLayout pattern="%d{HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n"/>
        </Console>
      </Appenders>
      <Loggers>
        <Root level="WARN"><AppenderRef ref="Console"/></Root>
      </Loggers>
    </Configuration>"""
    log4j2_file = os.path.join(INSTALL_DIR_DDB, "log4j2.xml")
    save_file(log4j2_file, log4j2_config)
    run('cd "%s" && zip -u DynamoDBLocal.jar log4j2.xml || true' % INSTALL_DIR_DDB)


def install_amazon_kinesis_client_libs():
    # install KCL/STS JAR files
    if not os.path.exists(INSTALL_PATH_KCL_JAR):
        mkdir(INSTALL_DIR_KCL)
        tmp_archive = os.path.join(tempfile.gettempdir(), "aws-java-sdk-sts.jar")
        if not os.path.exists(tmp_archive):
            download(STS_JAR_URL, tmp_archive)
        shutil.copy(tmp_archive, INSTALL_DIR_KCL)
    # Compile Java files
    from localstack.utils.kinesis import kclipy_helper

    classpath = kclipy_helper.get_kcl_classpath()

    if is_windows():
        classpath = re.sub(r":([^\\])", r";\1", classpath)
    java_files = "%s/utils/kinesis/java/cloud/localstack/*.java" % MODULE_MAIN_PATH
    class_files = "%s/utils/kinesis/java/cloud/localstack/*.class" % MODULE_MAIN_PATH
    if not glob.glob(class_files):
        run(
            'javac -source %s -target %s -cp "%s" %s'
            % (JAVAC_TARGET_VERSION, JAVAC_TARGET_VERSION, classpath, java_files)
        )


def install_lambda_java_libs():
    # install LocalStack "fat" JAR file (contains all dependencies)
    if not os.path.exists(INSTALL_PATH_LOCALSTACK_FAT_JAR):
        log_install_msg("LocalStack Java libraries", verbatim=True)
        download(URL_LOCALSTACK_FAT_JAR, INSTALL_PATH_LOCALSTACK_FAT_JAR)


def install_lambda_java_testlibs():
    # Download the LocalStack Utils Test jar file from the maven repo
    if not os.path.exists(TEST_LAMBDA_JAVA):
        mkdir(os.path.dirname(TEST_LAMBDA_JAVA))
        download(TEST_LAMBDA_JAR_URL, TEST_LAMBDA_JAVA)


def install_go_lambda_runtime():
    if os.path.isfile(GO_LAMBDA_RUNTIME):
        return

    log_install_msg("Installing golang runtime")

    system = platform.system().lower()
    arch = get_arch()

    if system not in ["linux"]:
        raise ValueError("unsupported os %s for awslambda-go-runtime" % system)
    if arch not in ["amd64", "arm64"]:
        raise ValueError("unsupported arch %s for awslambda-go-runtime" % arch)

    url = GO_RUNTIME_DOWNLOAD_URL_TEMPLATE.format(
        version=GO_RUNTIME_VERSION,
        os=system,
        arch=arch,
    )

    download_and_extract(url, GO_INSTALL_FOLDER)

    st = os.stat(GO_LAMBDA_RUNTIME)
    os.chmod(GO_LAMBDA_RUNTIME, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    st = os.stat(GO_LAMBDA_MOCKSERVER)
    os.chmod(GO_LAMBDA_MOCKSERVER, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def install_cloudformation_libs():
    from localstack.services.cloudformation import deployment_utils

    # trigger download of CF module file
    deployment_utils.get_cfn_response_mod_file()


def install_terraform() -> str:
    if os.path.isfile(TERRAFORM_BIN):
        return TERRAFORM_BIN

    log_install_msg(f"Installing terraform {TERRAFORM_VERSION}")

    system = platform.system().lower()
    arch = get_arch()

    url = TERRAFORM_URL_TEMPLATE.format(version=TERRAFORM_VERSION, os=system, arch=arch)

    download_and_extract(url, os.path.dirname(TERRAFORM_BIN))
    chmod_r(TERRAFORM_BIN, 0o777)

    return TERRAFORM_BIN


def get_terraform_binary() -> str:
    if not os.path.isfile(TERRAFORM_BIN):
        install_terraform()

    return TERRAFORM_BIN


def install_component(name):
    installer = installers.get(name)
    if installer:
        installer()


def install_components(names):
    parallelize(install_component, names)
    install_lambda_java_libs()


def install_all_components():
    # install dependencies - make sure that install_components(..) is called before hooks.install below!
    install_components(DEFAULT_SERVICE_PORTS.keys())
    hooks.install.run()


def install_debugpy_and_dependencies():
    try:
        import debugpy

        assert debugpy
        logging.debug("Debugpy module already Installed")
    except ModuleNotFoundError:
        logging.debug("Installing Debugpy module")
        import pip

        if hasattr(pip, "main"):
            pip.main(["install", DEBUGPY_MODULE])
        else:
            pip._internal.main(["install", DEBUGPY_MODULE])


# -----------------
# HELPER FUNCTIONS
# -----------------


def log_install_msg(component, verbatim=False):
    component = component if verbatim else "local %s server" % component
    LOG.info("Downloading and installing %s. This may take some time.", component)


def download_and_extract(archive_url, target_dir, retries=0, sleep=3, tmp_archive=None):
    mkdir(target_dir)

    if tmp_archive:
        _, ext = os.path.splitext(tmp_archive)
    else:
        _, ext = os.path.splitext(archive_url)

    tmp_archive = tmp_archive or new_tmp_file()
    if not os.path.exists(tmp_archive) or os.path.getsize(tmp_archive) <= 0:
        # create temporary placeholder file, to avoid duplicate parallel downloads
        save_file(tmp_archive, "")
        for i in range(retries + 1):
            try:
                download(archive_url, tmp_archive)
                break
            except Exception:
                time.sleep(sleep)

    if ext == ".zip":
        unzip(tmp_archive, target_dir)
    elif ext == ".gz" or ext == ".bz2":
        untar(tmp_archive, target_dir)
    else:
        raise Exception("Unsupported archive format: %s" % ext)


def download_and_extract_with_retry(archive_url, tmp_archive, target_dir):
    try:
        download_and_extract(archive_url, target_dir, tmp_archive=tmp_archive)
    except Exception as e:
        # try deleting and re-downloading the zip file
        LOG.info("Unable to extract file, re-downloading ZIP archive %s: %s", tmp_archive, e)
        rm_rf(tmp_archive)
        download_and_extract(archive_url, target_dir, tmp_archive=tmp_archive)


# kept here for backwards compatibility (installed on "make init" - TODO should be removed)
installers = {
    "cloudformation": install_cloudformation_libs,
    "dynamodb": install_dynamodb_local,
    "kinesis": install_kinesis,
    "kms": install_local_kms,
    "sqs": install_sqs_provider,
    "stepfunctions": install_stepfunctions_local,
}

Installer = Tuple[str, Callable]


class InstallerRepository(Plugin):
    namespace = "localstack.installer"

    def get_installer(self) -> List[Installer]:
        raise NotImplementedError


class CommunityInstallerRepository(InstallerRepository):
    name = "community"

    def get_installer(self) -> List[Installer]:
        return [
            ("awslamba-go-runtime", install_go_lambda_runtime),
            ("cloudformation-libs", install_cloudformation_libs),
            ("dynamodb-local", install_dynamodb_local),
            ("elasticmq", install_elasticmq),
            ("elasticsearch", install_elasticsearch),
            ("opensearch", install_opensearch),
            ("kinesalite", install_kinesalite),
            ("kinesis-client-libs", install_amazon_kinesis_client_libs),
            ("kinesis-mock", install_kinesis_mock),
            ("lambda-java-libs", install_lambda_java_libs),
            ("local-kms", install_local_kms),
            ("stepfunctions-local", install_stepfunctions_local),
            ("terraform", install_terraform),
        ]


class InstallerManager:
    def __init__(self):
        self.repositories: PluginManager[InstallerRepository] = PluginManager(
            InstallerRepository.namespace
        )

    @functools.lru_cache()
    def get_installers(self) -> Dict[str, Callable]:
        installer: List[Installer] = []

        for repo in self.repositories.load_all():
            installer.extend(repo.get_installer())

        return dict(installer)

    def install(self, package: str, *args, **kwargs):
        installer = self.get_installers().get(package)

        if not installer:
            raise ValueError("no installer for package %s" % package)

        return installer(*args, **kwargs)


def main():
    if len(sys.argv) > 1:
        # set test API key so pro install hooks are called
        os.environ["LOCALSTACK_API_KEY"] = os.environ.get("LOCALSTACK_API_KEY") or "test"
        if sys.argv[1] == "libs":
            print("Initializing installation.")
            logging.basicConfig(level=logging.INFO)
            logging.getLogger("requests").setLevel(logging.WARNING)
            install_all_components()
        if sys.argv[1] in ("libs", "testlibs"):
            # Install additional libraries for testing
            install_amazon_kinesis_client_libs()
            install_lambda_java_testlibs()
        print("Done.")


if __name__ == "__main__":
    main()

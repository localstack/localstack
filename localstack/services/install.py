#!/usr/bin/env python
import functools
import glob
import json
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
from abc import ABC
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Tuple, Union

import requests
import semver
from plugin import Plugin, PluginManager

from localstack import config
from localstack.config import dirs
from localstack.constants import (
    DEFAULT_SERVICE_PORTS,
    ELASTICMQ_JAR_URL,
    ELASTICSEARCH_DEFAULT_VERSION,
    ELASTICSEARCH_DELETE_MODULES,
    ELASTICSEARCH_PLUGIN_LIST,
    KMS_URL_PATTERN,
    LOCALSTACK_MAVEN_VERSION,
    MAVEN_REPO_URL,
    OPENSEARCH_DEFAULT_VERSION,
    OPENSEARCH_PLUGIN_LIST,
)
from localstack.runtime import hooks
from localstack.utils.archives import untar, unzip
from localstack.utils.files import (
    chmod_r,
    file_exists_not_empty,
    load_file,
    mkdir,
    new_tmp_file,
    replace_in_file,
    rm_rf,
    save_file,
)
from localstack.utils.functions import run_safe
from localstack.utils.http import download
from localstack.utils.platform import get_arch, is_mac_os
from localstack.utils.run import run
from localstack.utils.sync import retry
from localstack.utils.threads import parallelize

LOG = logging.getLogger(__name__)

# TODO: install paths should become parameterizable to allow lpm to chose static_libs or var_libs
INSTALL_DIR_NPM = "%s/node_modules" % dirs.static_libs
INSTALL_DIR_DDB = "%s/dynamodb" % dirs.static_libs
INSTALL_DIR_KCL = "%s/amazon-kinesis-client" % dirs.static_libs
INSTALL_DIR_STEPFUNCTIONS = "%s/stepfunctions" % dirs.static_libs
INSTALL_DIR_KMS = "%s/kms" % dirs.static_libs
INSTALL_DIR_ELASTICMQ = "%s/elasticmq" % dirs.var_libs
INSTALL_DIR_KINESIS_MOCK = os.path.join(dirs.static_libs, "kinesis-mock")
INSTALL_PATH_LOCALSTACK_FAT_JAR = "%s/localstack-utils-fat.jar" % dirs.static_libs
INSTALL_PATH_DDB_JAR = os.path.join(INSTALL_DIR_DDB, "DynamoDBLocal.jar")
INSTALL_PATH_KCL_JAR = os.path.join(INSTALL_DIR_KCL, "aws-java-sdk-sts.jar")
INSTALL_PATH_STEPFUNCTIONS_JAR = os.path.join(INSTALL_DIR_STEPFUNCTIONS, "StepFunctionsLocal.jar")
INSTALL_PATH_KMS_BINARY_PATTERN = os.path.join(INSTALL_DIR_KMS, "local-kms.<arch>.bin")
INSTALL_PATH_ELASTICMQ_JAR = os.path.join(INSTALL_DIR_ELASTICMQ, "elasticmq-server.jar")
INSTALL_PATH_KINESALITE_CLI = os.path.join(INSTALL_DIR_NPM, "kinesalite", "cli.js")

URL_LOCALSTACK_FAT_JAR = (
    "{mvn_repo}/cloud/localstack/localstack-utils/{ver}/localstack-utils-{ver}-fat.jar"
).format(ver=LOCALSTACK_MAVEN_VERSION, mvn_repo=MAVEN_REPO_URL)

MARKER_FILE_LIGHT_VERSION = f"{dirs.static_libs}/.light-version"
IMAGE_NAME_SFN_LOCAL = "amazon/aws-stepfunctions-local:1.7.9"
ARTIFACTS_REPO = "https://github.com/localstack/localstack-artifacts"
SFN_PATCH_URL_PREFIX = (
    f"{ARTIFACTS_REPO}/raw/ac84739adc87ff4b5553478f6849134bcd259672/stepfunctions-local-patch"
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

SFN_IMAGE = "amazon/aws-stepfunctions-local"
SFN_IMAGE_LAYER_DIGEST = "sha256:e7b256bdbc9d58c20436970e8a56bd03581b891a784b00fea7385faff897b777"
"""
Digest of the Docker layer which adds the StepFunctionsLocal JAR files to the Docker image.
This digest pin defines the version of StepFunctionsLocal used in LocalStack.

The Docker image layer digest can be determined by:
- Use regclient: regctl image manifest amazon/aws-stepfunctions-local:1.7.9 --platform local
- Inspect the manifest in the Docker registry manually:
  - Get the auth bearer token (see download code).
  - Download the manifest (/v2/<image/name>/manifests/<tag>) with the bearer token
  - Follow any platform link
  - Extract the layer digest
Since the JAR files are platform-independent, you can use the layer digest of any platform's image.
"""

SFN_AWS_SDK_URL_PREFIX = (
    f"{ARTIFACTS_REPO}/raw/a4adc8f4da9c7ec0d93b50ca5b73dd14df791c0e/stepfunctions-internal-awssdk"
)
SFN_AWS_SDK_LAMBDA_ZIP_FILE = f"{SFN_AWS_SDK_URL_PREFIX}/awssdk.zip"


# additional JAR libs required for multi-region and persistence (PRO only) support
URL_ASPECTJRT = f"{MAVEN_REPO_URL}/org/aspectj/aspectjrt/1.9.7/aspectjrt-1.9.7.jar"
URL_ASPECTJWEAVER = f"{MAVEN_REPO_URL}/org/aspectj/aspectjweaver/1.9.7/aspectjweaver-1.9.7.jar"
JAR_URLS = [URL_ASPECTJRT, URL_ASPECTJWEAVER]

# kinesis-mock version
KINESIS_MOCK_VERSION = os.environ.get("KINESIS_MOCK_VERSION") or "0.2.5"
KINESIS_MOCK_RELEASE_URL = (
    "https://api.github.com/repos/etspaceman/kinesis-mock/releases/tags/" + KINESIS_MOCK_VERSION
)

# kinesalite version (npm dependency)
KINESALITE_VERSION = os.environ.get("KINESALITE_VERSION") or "3.3.3"

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
TEST_LAMBDA_JAR_URL = "{url}/cloud/localstack/{name}/{version}/{name}-{version}-tests.jar".format(
    version=LOCALSTACK_MAVEN_VERSION, url=MAVEN_REPO_URL, name="localstack-utils"
)

LAMBDA_RUNTIME_INIT_URL = "https://github.com/localstack/lambda-runtime-init/releases/download/v0.1.1-pre/aws-lambda-rie-{arch}"
LAMBDA_RUNTIME_INIT_PATH = os.path.join(config.dirs.static_libs, "aws-lambda-rie")

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
        log_install_msg(f"Elasticsearch ({version})")
        es_url = versions.get_download_url(version, EngineType.Elasticsearch)
        install_dir_parent = os.path.dirname(install_dir)
        mkdir(install_dir_parent)
        # download and extract archive
        tmp_archive = os.path.join(config.dirs.cache, f"localstack.{os.path.basename(es_url)}")
        download_and_extract_with_retry(es_url, tmp_archive, install_dir_parent)
        elasticsearch_dir = glob.glob(os.path.join(install_dir_parent, "elasticsearch*"))
        if not elasticsearch_dir:
            raise Exception(f"Unable to find Elasticsearch folder in {install_dir_parent}")
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
                    output = run([plugin_binary, "install", "-b", plugin])
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
            r"(^-Xm[sx][a-zA-Z0-9.]+$)", r"# \1", jvm_options, flags=re.MULTILINE
        )
        if jvm_options != jvm_options_replaced:
            save_file(jvm_options_file, jvm_options_replaced)

    # patch JVM options file - replace hardcoded heap size settings
    jvm_options_file = os.path.join(install_dir, "config", "jvm.options")
    if os.path.exists(jvm_options_file):
        jvm_options = load_file(jvm_options_file)
        jvm_options_replaced = re.sub(
            r"(^-Xm[sx][a-zA-Z0-9.]+$)", r"# \1", jvm_options, flags=re.MULTILINE
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
        tmp_archive = os.path.join(config.dirs.cache, "elasticmq-server.jar")
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
    raise ValueError(f"Unknown Kinesis provider {config.KINESIS_PROVIDER}")


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
        run(["npm", "install", "--prefix", dirs.static_libs, f"kinesalite@{KINESALITE_VERSION}"])
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
            f"Could not get list of releases from {KINESIS_MOCK_RELEASE_URL}: {response.text}"
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
            f"Could not find required binary {bin_file_name} in release {KINESIS_MOCK_RELEASE_URL}"
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
    """
    The StepFunctionsLocal JAR files are downloaded using the artifacts in DockerHub (because AWS only provides an
    HTTP link to the most recent version). Installers are executed when building Docker, this means they _cannot_ use
    the Docker socket. Therefore, this installer downloads a pinned Docker Layer Digest (i.e. only the data for a single
    Docker build step which adds the JAR files of the desired version to a Docker image) using plain HTTP requests.
    """
    if not os.path.exists(INSTALL_PATH_STEPFUNCTIONS_JAR):

        target_path = dirs.static_libs

        # Download layer that contains the necessary jars
        def download_stepfunctions_jar(image, image_digest, target_path):
            registry_base = "https://registry-1.docker.io"
            auth_base = "https://auth.docker.io"
            auth_service = "registry.docker.io"
            token_request = requests.get(
                f"{auth_base}/token?service={auth_service}&scope=repository:{image}:pull"
            )
            token = json.loads(token_request.content.decode("utf-8"))["token"]
            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get(
                headers=headers,
                url=f"{registry_base}/v2/{image}/blobs/{image_digest}",
            )
            temp_path = new_tmp_file()
            with open(temp_path, "wb") as f:
                f.write(response.content)
            untar(temp_path, target_path)

        download_stepfunctions_jar(SFN_IMAGE, SFN_IMAGE_LAYER_DIGEST, target_path)
        mkdir(INSTALL_DIR_STEPFUNCTIONS)
        path = Path(f"{target_path}/home/stepfunctionslocal")
        for file in path.glob("*.jar"):
            file.rename(Path(INSTALL_DIR_STEPFUNCTIONS) / file.name)
        rm_rf(f"{target_path}/home")

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

    # add additional classpath entries to JAR manifest file
    classpath = " ".join([os.path.basename(jar) for jar in JAR_URLS])
    update_jar_manifest(
        "StepFunctionsLocal.jar",
        INSTALL_DIR_STEPFUNCTIONS,
        "Class-Path: . ",
        f"Class-Path: {classpath} . ",
    )
    update_jar_manifest(
        "StepFunctionsLocal.jar",
        INSTALL_DIR_STEPFUNCTIONS,
        re.compile(r"Main-Class: com\.amazonaws.+"),
        "Main-Class: cloud.localstack.StepFunctionsStarter",
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


def update_jar_manifest(
    jar_file_name: str, parent_dir: str, search: Union[str, re.Pattern], replace: str
):
    manifest_file_path = "META-INF/MANIFEST.MF"
    jar_path = os.path.join(parent_dir, jar_file_name)
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_manifest_file = os.path.join(tmp_dir, manifest_file_path)
        run(["unzip", "-o", jar_path, manifest_file_path], cwd=tmp_dir)
        manifest = load_file(tmp_manifest_file)

    # return if the search pattern does not match (for idempotence, to avoid file permission issues further below)
    if isinstance(search, re.Pattern):
        if not search.search(manifest):
            return
        manifest = search.sub(replace, manifest, 1)
    else:
        if search not in manifest:
            return
        manifest = manifest.replace(search, replace, 1)

    manifest_file = os.path.join(parent_dir, manifest_file_path)
    save_file(manifest_file, manifest)
    run(["zip", jar_file_name, manifest_file_path], cwd=parent_dir)


def upgrade_jar_file(base_dir: str, file_glob: str, maven_asset: str):
    """
    Upgrade the matching Java JAR file in a local directory with the given Maven asset
    :param base_dir: base directory to search the JAR file to replace in
    :param file_glob: glob pattern for the JAR file to replace
    :param maven_asset: name of Maven asset to download, in the form "<qualified_name>:<version>"
    """

    local_path = os.path.join(base_dir, file_glob)
    parent_dir = os.path.dirname(local_path)
    maven_asset = maven_asset.replace(":", "/")
    parts = maven_asset.split("/")
    maven_asset_url = f"{MAVEN_REPO_URL}/{maven_asset}/{parts[-2]}-{parts[-1]}.jar"
    target_file = os.path.join(parent_dir, os.path.basename(maven_asset_url))
    if os.path.exists(target_file):
        # avoid re-downloading the newer JAR version if it already exists locally
        return
    matches = glob.glob(local_path)
    if not matches:
        return
    for match in matches:
        os.remove(match)
    download(maven_asset_url, target_file)


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
        raise ValueError(f"Unsupported os {system} for awslambda-go-runtime")
    if arch not in ["amd64", "arm64"]:
        raise ValueError(f"Unsupported arch {arch} for awslambda-go-runtime")

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


def install_lambda_runtime():
    if os.path.isfile(LAMBDA_RUNTIME_INIT_PATH):
        return
    log_install_msg("Installing lambda runtime")
    arch = get_arch()
    arch = "x86_64" if arch == "amd64" else arch
    download_url = LAMBDA_RUNTIME_INIT_URL.format(arch=arch)
    download(download_url, LAMBDA_RUNTIME_INIT_PATH)
    st = os.stat(LAMBDA_RUNTIME_INIT_PATH)
    os.chmod(LAMBDA_RUNTIME_INIT_PATH, mode=st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


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
    component = component if verbatim else f"local {component} server"
    LOG.info("Downloading and installing %s. This may take some time.", component)


def download_and_extract(archive_url, target_dir, retries=0, sleep=3, tmp_archive=None):
    mkdir(target_dir)

    _, ext = os.path.splitext(tmp_archive or archive_url)

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
    elif ext in [".bz2", ".gz", ".tgz"]:
        untar(tmp_archive, target_dir)
    else:
        raise Exception(f"Unsupported archive format: {ext}")


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
    # WIP, this function was removed due to the installer refactoring
    # "dynamodb": install_dynamodb_local,
    "kinesis": install_kinesis,
    "kms": install_local_kms,
    "lambda": install_lambda_runtime,
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
            ("awslambda-runtime", install_lambda_runtime),
            ("cloudformation-libs", install_cloudformation_libs),
            ("dynamodb-local", DynamoDBLocalPackage()),
            ("elasticmq", install_elasticmq),
            ("elasticsearch", install_elasticsearch),
            ("opensearch", OpenSearchPackage()),
            ("kinesalite", install_kinesalite),
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


class NoSuchInstallTargetException(Exception):
    pass


class NoSuchVersionException(Exception):
    pass


class InstallTarget(Enum):
    # TODO explicitly state that the order is important here! It defines the lookup priority
    VAR_LIBS = config.dirs.var_libs
    STATIC_LIBS = config.dirs.static_libs


class PackageInstaller(ABC):
    def install(self, target: InstallTarget):
        """
        The method that is called to execute all steps necessary to install the specified version of a package
        into the specified target
        """
        if not target:
            target = InstallTarget.VAR_LIBS
        if not self.is_installed():
            self._install(target)

    def is_installed(self) -> bool:
        return self.get_installed_dir() is not None

    def get_installed_dir(self) -> str:
        for target in InstallTarget:
            directory = self._get_install_dir(target)
            if directory and os.path.exists(directory):
                return directory

    def get_executables_path(self) -> str | None:
        """
        The method that returns a path under which the necessary executables have been installed. It must consider all
        locations specified in InstallTarget. It will return the first path that matches the lookup.
        If no path is returned, no installation was found.
        """
        directory = self.get_installed_dir()
        if directory:
            return self._build_executables_path(directory)

    def _get_install_dir(self, target: InstallTarget):
        raise NotImplementedError()

    def _build_executables_path(self, install_dir: str):
        raise NotImplementedError()

    def _install(self, target: InstallTarget):
        raise NotImplementedError()


class Package(ABC):
    def __init__(self, default_version: str):
        self.default_version = default_version

    def get_executables_path(self, version: str | None = None) -> str | None:
        return self.get_installer(version).get_executables_path()

    def get_installed_dir(self, version: str) -> str | None:
        return self.get_installer(version).get_installed_dir()

    def get_installer(self, version: str | None = None) -> PackageInstaller:
        if not version:
            version = self.default_version
        return self._get_installer(version)

    def get_versions(self) -> List[str]:
        raise NotImplementedError()

    def _get_installer(self, version):
        raise NotImplementedError()


class OpenSearchPackage(Package):
    def __init__(self, default_version: str = OPENSEARCH_DEFAULT_VERSION):
        super().__init__(default_version)

    def _get_installer(self, version: str | None = None) -> PackageInstaller:
        # TODO check if the version is allowed, otherwise raise Exception
        return OpenSearchPackageInstaller(version)

    def get_versions(self) -> List[str]:
        # TODO implement
        raise NotImplementedError()


class OpenSearchPackageInstaller(PackageInstaller):
    def __init__(self, version: str):
        self.version = version

    def _install(self, target: InstallTarget):
        # TODO fix install directory (should be /var/lib/localstack/opensearch/1.1/...)
        # locally import to avoid having a dependency on ASF when starting the CLI
        from localstack.aws.api.opensearch import EngineType
        from localstack.services.opensearch import versions

        version = self._get_opensearch_install_version()
        install_dir = self._get_install_dir(target)
        if not os.path.exists(install_dir):
            with OS_INSTALL_LOCKS.setdefault(version, threading.Lock()):
                if not os.path.exists(install_dir):
                    log_install_msg(f"OpenSearch ({version})")
                    opensearch_url = versions.get_download_url(version, EngineType.OpenSearch)
                    install_dir_parent = os.path.dirname(install_dir)
                    mkdir(install_dir_parent)
                    # download and extract archive
                    tmp_archive = os.path.join(
                        config.dirs.cache, f"localstack.{os.path.basename(opensearch_url)}"
                    )
                    print(f"DEBUG: installing opensearch to path {install_dir_parent}")
                    download_and_extract_with_retry(opensearch_url, tmp_archive, install_dir_parent)
                    opensearch_dir = glob.glob(os.path.join(install_dir_parent, "opensearch*"))
                    if not opensearch_dir:
                        raise Exception(f"Unable to find OpenSearch folder in {install_dir_parent}")
                    shutil.move(opensearch_dir[0], install_dir)

                    for dir_name in ("data", "logs", "modules", "plugins", "config/scripts"):
                        dir_path = os.path.join(install_dir, dir_name)
                        mkdir(dir_path)
                        chmod_r(dir_path, 0o777)

                    # install default plugins for opensearch 1.1+
                    # https://forum.opensearch.org/t/ingest-attachment-cannot-be-installed/6494/12
                    parsed_version = semver.VersionInfo.parse(version)
                    if parsed_version >= "1.1.0":
                        for plugin in OPENSEARCH_PLUGIN_LIST:
                            plugin_binary = os.path.join(install_dir, "bin", "opensearch-plugin")
                            plugin_dir = os.path.join(install_dir, "plugins", plugin)
                            if not os.path.exists(plugin_dir):
                                LOG.info("Installing OpenSearch plugin %s", plugin)

                                def try_install():
                                    output = run([plugin_binary, "install", "-b", plugin])
                                    LOG.debug("Plugin installation output: %s", output)

                                # We're occasionally seeing javax.net.ssl.SSLHandshakeException -> add download retries
                                download_attempts = 3
                                try:
                                    retry(try_install, retries=download_attempts - 1, sleep=2)
                                except Exception:
                                    LOG.warning(
                                        "Unable to download OpenSearch plugin '%s' after %s attempts",
                                        plugin,
                                        download_attempts,
                                    )
                                    if not os.environ.get("IGNORE_OS_DOWNLOAD_ERRORS"):
                                        raise

    def _get_install_dir(self, target: InstallTarget) -> str:
        return os.path.join(target.value, "opensearch", self.version)

    def _build_executables_path(self, install_dir: str) -> str | None:
        return os.path.join(install_dir, "bin", "opensearch")

    def _get_opensearch_install_version(self) -> str:
        from localstack.services.opensearch import versions

        if config.SKIP_INFRA_DOWNLOADS:
            self.version = OPENSEARCH_DEFAULT_VERSION

        return versions.get_install_version(self.version)


class DynamoDBLocalPackage(Package):
    def __init__(self, default_version: str = "latest"):
        super().__init__(default_version)

    def _get_installer(self, version: str | None = None) -> PackageInstaller:
        return DynamoDBLocalPackageInstaller(version)

    def get_versions(self) -> List[str]:
        return [self.default_version]


class DynamoDBLocalPackageInstaller(PackageInstaller):
    # patches for DynamoDB Local
    DDB_PATCH_URL_PREFIX = (
        f"{ARTIFACTS_REPO}/raw/388cd73f45bfd3bcf7ad40aa35499093061c7962/dynamodb-local-patch"
    )
    DDB_AGENT_JAR_URL = f"{DDB_PATCH_URL_PREFIX}/target/ddb-local-loader-0.1.jar"

    LIBSQLITE_AARCH64_URL = f"{MAVEN_REPO_URL}/io/github/ganadist/sqlite4java/libsqlite4java-osx-aarch64/1.0.392/libsqlite4java-osx-aarch64-1.0.392.dylib"
    DYNAMODB_JAR_URL = "https://s3-us-west-2.amazonaws.com/dynamodb-local/dynamodb_local_latest.zip"
    JAVASSIST_JAR_URL = (
        f"{MAVEN_REPO_URL}/org/javassist/javassist/3.28.0-GA/javassist-3.28.0-GA.jar"
    )

    def __init__(self, version: str):
        self.version = version

    def _get_install_dir(self, target: InstallTarget):
        return os.path.join(target.value, "dynamodb", self.version)

    def _build_executables_path(self, install_dir: str):
        return os.path.join(install_dir, "DynamoDBLocal.jar")

    def _install(self, target: InstallTarget):
        # download and extract archive
        tmp_archive = os.path.join(tempfile.gettempdir(), "localstack.ddb.zip")
        install_dir = self._get_install_dir(target)
        download_and_extract_with_retry(self.DYNAMODB_JAR_URL, tmp_archive, install_dir)

        # download additional libs for Mac M1 (for local dev mode)
        ddb_local_lib_dir = os.path.join(install_dir, "DynamoDBLocal_lib")
        if is_mac_os() and get_arch() == "arm64":
            target_path = os.path.join(ddb_local_lib_dir, "libsqlite4java-osx-aarch64.dylib")
            if not file_exists_not_empty(target_path):
                download(self.LIBSQLITE_AARCH64_URL, target_path)

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
        log4j2_file = os.path.join(install_dir, "log4j2.xml")
        run_safe(lambda: save_file(log4j2_file, log4j2_config))
        run_safe(lambda: run(["zip", "-u", "DynamoDBLocal.jar", "log4j2.xml"], cwd=install_dir))

        ddb_agent_jar_path = os.path.join(install_dir, "ddb-local-loader-0.1.jar")
        javassit_jar_path = os.path.join(install_dir, "javassist.jar")
        # download agent JAR
        if not os.path.exists(ddb_agent_jar_path):
            download(self.DDB_AGENT_JAR_URL, ddb_agent_jar_path)
        if not os.path.exists(javassit_jar_path):
            download(self.JAVASSIST_JAR_URL, javassit_jar_path)

        upgrade_jar_file(ddb_local_lib_dir, "slf4j-ext-*.jar", "org/slf4j/slf4j-ext:1.8.0-beta4")

        # ensure that javassist.jar is in the manifest classpath
        update_jar_manifest(
            "DynamoDBLocal.jar", install_dir, "Class-Path: .", "Class-Path: javassist.jar ."
        )


def main():
    if len(sys.argv) > 1:
        config.dirs.mkdirs()

        # set test API key so pro install hooks are called
        os.environ["LOCALSTACK_API_KEY"] = os.environ.get("LOCALSTACK_API_KEY") or "test"
        if sys.argv[1] == "libs":
            print("Initializing installation.")
            logging.basicConfig(level=logging.INFO)
            logging.getLogger("requests").setLevel(logging.WARNING)
            install_all_components()
        if sys.argv[1] in ("libs", "testlibs"):
            # Install additional libraries for testing
            install_lambda_java_testlibs()
        print("Done.")


if __name__ == "__main__":
    main()

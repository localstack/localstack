#!/usr/bin/env python
import glob
import logging
import os
import platform
import re
import shutil
import stat
import sys
import tempfile
import time
import zipfile
from pathlib import Path

import requests

from localstack import config
from localstack.config import is_env_true
from localstack.constants import (
    DEFAULT_SERVICE_PORTS,
    DYNAMODB_JAR_URL,
    DYNAMODB_JAR_URL_ALPINE,
    ELASTICMQ_JAR_URL,
    ELASTICSEARCH_DEFAULT_VERSION,
    ELASTICSEARCH_DELETE_MODULES,
    ELASTICSEARCH_PLUGIN_LIST,
    ELASTICSEARCH_URLS,
    INSTALL_DIR_INFRA,
    KMS_URL_PATTERN,
    LOCALSTACK_INFRA_PROCESS,
    LOCALSTACK_MAVEN_VERSION,
    MODULE_MAIN_PATH,
    STS_JAR_URL,
)
from localstack.utils import bootstrap
from localstack.utils.common import (
    chmod_r,
    download,
    get_arch,
    is_alpine,
    is_windows,
    load_file,
    mkdir,
    new_tmp_file,
    parallelize,
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

INSTALL_DIR_NPM = "%s/node_modules" % MODULE_MAIN_PATH
INSTALL_DIR_DDB = "%s/dynamodb" % INSTALL_DIR_INFRA
INSTALL_DIR_KCL = "%s/amazon-kinesis-client" % INSTALL_DIR_INFRA
INSTALL_DIR_STEPFUNCTIONS = "%s/stepfunctions" % INSTALL_DIR_INFRA
INSTALL_DIR_KMS = "%s/kms" % INSTALL_DIR_INFRA
INSTALL_DIR_ELASTICMQ = "%s/elasticmq" % INSTALL_DIR_INFRA
INSTALL_PATH_LOCALSTACK_FAT_JAR = "%s/localstack-utils-fat.jar" % INSTALL_DIR_INFRA
INSTALL_PATH_DDB_JAR = os.path.join(INSTALL_DIR_DDB, "DynamoDBLocal.jar")
INSTALL_PATH_KCL_JAR = os.path.join(INSTALL_DIR_KCL, "aws-java-sdk-sts.jar")
INSTALL_PATH_STEPFUNCTIONS_JAR = os.path.join(INSTALL_DIR_STEPFUNCTIONS, "StepFunctionsLocal.jar")
INSTALL_PATH_KMS_BINARY_PATTERN = os.path.join(INSTALL_DIR_KMS, "local-kms.<arch>.bin")
INSTALL_PATH_ELASTICMQ_JAR = os.path.join(INSTALL_DIR_ELASTICMQ, "elasticmq-server.jar")
INSTALL_PATH_KINESALITE_CLI = os.path.join(INSTALL_DIR_NPM, "kinesalite", "cli.js")
INSTALL_PATH_KINESIS_MOCK = os.path.join(INSTALL_DIR_INFRA, "kinesis-mock")
URL_LOCALSTACK_FAT_JAR = (
    "https://repo1.maven.org/maven2/"
    + "cloud/localstack/localstack-utils/{v}/localstack-utils-{v}-fat.jar"
).format(v=LOCALSTACK_MAVEN_VERSION)

MARKER_FILE_LIGHT_VERSION = "%s/.light-version" % INSTALL_DIR_INFRA
IMAGE_NAME_SFN_LOCAL = "amazon/aws-stepfunctions-local"
ARTIFACTS_REPO = "https://github.com/localstack/localstack-artifacts"
SFN_PATCH_CLASS1 = "com/amazonaws/stepfunctions/local/runtime/Config.class"
SFN_PATCH_CLASS2 = (
    "com/amazonaws/stepfunctions/local/runtime/executors/task/LambdaTaskStateExecutor.class"
)
SFN_PATCH_CLASS_URL1 = "%s/raw/master/stepfunctions-local-patch/%s" % (
    ARTIFACTS_REPO,
    SFN_PATCH_CLASS1,
)
SFN_PATCH_CLASS_URL2 = "%s/raw/master/stepfunctions-local-patch/%s" % (
    ARTIFACTS_REPO,
    SFN_PATCH_CLASS2,
)

# kinesis-mock version
KINESIS_MOCK_VERSION = os.environ.get("KINESIS_MOCK_VERSION") or "0.2.0"
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
GO_RUNTIME_DOWNLOAD_URL = (
    "https://github.com/localstack/awslamba-go-runtime/releases/download/first/runtime.zip"
)
GO_INSTALL_FOLDER = config.TMP_FOLDER + "/runtime"
GO_LAMBDA_RUNTIME = GO_INSTALL_FOLDER + "/aws-lambda-mock"
GO_LAMBDA_MOCKSERVER = GO_INSTALL_FOLDER + "/mockserver"
GO_ZIP_NAME = "runtime.zip"


GLIBC_KEY_URL = "https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub"
GLIBC_KEY = "/etc/apk/keys/sgerrand.rsa.pub"
GLIBC_VERSION = "2.32-r0"
GLIBC_FILE = "glibc-%s.apk" % GLIBC_VERSION
GLIBC_URL = "https://github.com/sgerrand/alpine-pkg-glibc/releases/download/%s/%s" % (
    GLIBC_VERSION,
    GLIBC_FILE,
)
GLIBC_PATH = config.TMP_FOLDER + "/" + GLIBC_FILE
CA_CERTIFICATES = "ca-certificates"


def get_elasticsearch_install_version(version=None):
    if config.SKIP_INFRA_DOWNLOADS:
        return ELASTICSEARCH_DEFAULT_VERSION
    return version or ELASTICSEARCH_DEFAULT_VERSION


def get_elasticsearch_install_dir(version=None):
    version = get_elasticsearch_install_version(version)
    if version == ELASTICSEARCH_DEFAULT_VERSION and not os.path.exists(MARKER_FILE_LIGHT_VERSION):
        # install the default version into a subfolder of the code base
        install_dir = os.path.join(INSTALL_DIR_INFRA, "elasticsearch")
    else:
        install_dir = os.path.join(config.TMP_FOLDER, "elasticsearch", version)
    return install_dir


def install_elasticsearch(version=None):
    version = get_elasticsearch_install_version(version)
    install_dir = get_elasticsearch_install_dir(version)
    installed_executable = os.path.join(install_dir, "bin", "elasticsearch")
    if not os.path.exists(installed_executable):
        log_install_msg("Elasticsearch (%s)" % version)
        es_url = ELASTICSEARCH_URLS.get(version)
        if not es_url:
            raise Exception('Unable to find download URL for Elasticsearch version "%s"' % version)
        install_dir_parent = os.path.dirname(install_dir)
        mkdir(install_dir_parent)
        # download and extract archive
        tmp_archive = os.path.join(config.TMP_FOLDER, "localstack.%s" % os.path.basename(es_url))
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
            if is_alpine():
                # https://github.com/pires/docker-elasticsearch/issues/56
                os.environ["ES_TMPDIR"] = "/tmp"
            plugin_binary = os.path.join(install_dir, "bin", "elasticsearch-plugin")
            plugin_dir = os.path.join(install_dir, "plugins", plugin)
            if not os.path.exists(plugin_dir):
                LOG.info("Installing Elasticsearch plugin %s" % plugin)

                def try_install():
                    safe_run([plugin_binary, "install", "-b", plugin])

                # We're occasionally seeing javax.net.ssl.SSLHandshakeException -> add download retries
                download_attempts = 3
                try:
                    retry(try_install, retries=download_attempts - 1, sleep=2)
                except Exception:
                    LOG.warning(
                        "Unable to download Elasticsearch plugin '%s' after %s attempts"
                        % (plugin, download_attempts)
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


def install_elasticmq():
    if SQS_BACKEND_IMPL != "elasticmq":
        return
    # TODO remove this function if we stop using ElasticMQ entirely
    if not os.path.exists(INSTALL_PATH_ELASTICMQ_JAR):
        log_install_msg("ElasticMQ")
        mkdir(INSTALL_DIR_ELASTICMQ)
        # download archive
        tmp_archive = os.path.join(config.TMP_FOLDER, "elasticmq-server.jar")
        if not os.path.exists(tmp_archive):
            download(ELASTICMQ_JAR_URL, tmp_archive)
        shutil.copy(tmp_archive, INSTALL_DIR_ELASTICMQ)


def install_kinesis():
    if config.KINESIS_PROVIDER == "kinesalite":
        return install_kinesalite()
    elif config.KINESIS_PROVIDER == "kinesis-mock":
        return install_kinesis_mock()
    else:
        raise ValueError("unknown kinesis provider %s" % config.KINESIS_PROVIDER)


def install_kinesalite():
    if not os.path.exists(INSTALL_PATH_KINESALITE_CLI):
        log_install_msg("Kinesis")
        run('cd "%s" && npm install' % MODULE_MAIN_PATH)


def install_kinesis_mock():
    target_dir = INSTALL_PATH_KINESIS_MOCK

    machine = platform.machine().lower()
    system = platform.system().lower()
    version = platform.version().lower()

    is_probably_m1 = system == "darwin" and ("arm64" in version or "arm32" in version)

    LOG.debug("getting kinesis-mock for %s %s", system, machine)

    if is_env_true("KINESIS_MOCK_FORCE_JAVA"):
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

    bin_file_path = os.path.join(target_dir, bin_file)
    if os.path.exists(bin_file_path):
        LOG.debug("kinesis-mock found at %s", bin_file_path)
        return bin_file_path

    response = requests.get(KINESIS_MOCK_RELEASE_URL)
    if not response.ok:
        raise ValueError(
            "Could not get list of releases from %s: %s" % (KINESIS_MOCK_RELEASE_URL, response.text)
        )

    github_release = response.json()
    download_url = None
    for asset in github_release.get("assets", []):
        # find the correct binary in the release
        if asset["name"] == bin_file:
            download_url = asset["browser_download_url"]
            break

    if download_url is None:
        raise ValueError(
            "could not find required binary %s in release %s" % (bin_file, KINESIS_MOCK_RELEASE_URL)
        )

    mkdir(target_dir)
    LOG.info("downloading kinesis-mock binary from %s", download_url)
    download(download_url, bin_file_path)
    chmod_r(bin_file_path, 0o777)
    return bin_file_path


def install_local_kms():
    local_arch = get_arch()
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
        # TODO: works only when running on the host, outside of Docker -> add a fallback if running in Docker?
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
            docker_name, local_path=INSTALL_DIR_INFRA, container_path="/home/stepfunctionslocal/"
        )

        path = Path(f"{INSTALL_DIR_INFRA}/stepfunctionslocal/")
        for file in path.glob("*.jar"):
            file.rename(Path(INSTALL_DIR_STEPFUNCTIONS) / file.name)
        rm_rf("%s/stepfunctionslocal" % INSTALL_DIR_INFRA)
    # apply patches
    for patch_class, patch_url in (
        (SFN_PATCH_CLASS1, SFN_PATCH_CLASS_URL1),
        (SFN_PATCH_CLASS2, SFN_PATCH_CLASS_URL2),
    ):
        patch_class_file = os.path.join(INSTALL_DIR_STEPFUNCTIONS, patch_class)
        if not os.path.exists(patch_class_file):
            download(patch_url, patch_class_file)
            cmd = 'cd "%s"; zip %s %s' % (
                INSTALL_DIR_STEPFUNCTIONS,
                INSTALL_PATH_STEPFUNCTIONS_JAR,
                patch_class,
            )
            run(cmd)


def install_dynamodb_local():
    if not os.path.exists(INSTALL_PATH_DDB_JAR):
        log_install_msg("DynamoDB")
        # download and extract archive
        is_in_alpine = is_alpine()
        tmp_archive = os.path.join(tempfile.gettempdir(), "localstack.ddb.zip")
        dynamodb_url = DYNAMODB_JAR_URL_ALPINE if is_in_alpine else DYNAMODB_JAR_URL
        download_and_extract_with_retry(dynamodb_url, tmp_archive, INSTALL_DIR_DDB)

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


def install_go_lambda_runtime():
    install_glibc_for_alpine()

    if not os.path.isfile(GO_LAMBDA_RUNTIME):
        log_install_msg("Installing golang runtime")
        file_location = os.path.join(config.TMP_FOLDER, GO_ZIP_NAME)
        download(GO_RUNTIME_DOWNLOAD_URL, file_location)

        if not zipfile.is_zipfile(file_location):
            raise ValueError("Downloaded file is not zip ")

        zipfile.ZipFile(file_location).extractall(config.TMP_FOLDER)
        st = os.stat(GO_LAMBDA_RUNTIME)
        os.chmod(GO_LAMBDA_RUNTIME, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        st = os.stat(GO_LAMBDA_MOCKSERVER)
        os.chmod(GO_LAMBDA_MOCKSERVER, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def install_glibc_for_alpine():
    try:
        run("apk info glibc")
        return
    except Exception:
        pass

    log_install_msg("Installing glibc")
    try:
        try:
            run("apk add %s" % CA_CERTIFICATES)
        except Exception:
            raise Exception("ca-certificates not installed")

        download(GLIBC_KEY_URL, GLIBC_KEY)
        download(GLIBC_URL, GLIBC_PATH)

        run("apk add %s" % GLIBC_PATH)

    except Exception as e:
        log_install_msg("glibc installation failed: " + str(e))


def install_cloudformation_libs():
    from localstack.services.cloudformation import deployment_utils

    # trigger download of CF module file
    deployment_utils.get_cfn_response_mod_file()


def install_component(name):
    installers = {
        "cloudformation": install_cloudformation_libs,
        "dynamodb": install_dynamodb_local,
        "kinesis": install_kinesis,
        "kms": install_local_kms,
        "sqs": install_elasticmq,
        "stepfunctions": install_stepfunctions_local,
    }
    installer = installers.get(name)
    if installer:
        installer()


def install_components(names):
    parallelize(install_component, names)
    install_lambda_java_libs()


def install_all_components():
    # load plugins
    os.environ[LOCALSTACK_INFRA_PROCESS] = "1"
    bootstrap.load_plugins()
    # install all components
    install_components(DEFAULT_SERVICE_PORTS.keys())


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
    LOG.info("Downloading and installing %s. This may take some time." % component)


def download_and_extract(archive_url, target_dir, retries=0, sleep=3, tmp_archive=None):
    mkdir(target_dir)

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

    _, ext = os.path.splitext(tmp_archive)
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
        LOG.info("Unable to extract file, re-downloading ZIP archive %s: %s" % (tmp_archive, e))
        rm_rf(tmp_archive)
        download_and_extract(archive_url, target_dir, tmp_archive=tmp_archive)


def main():
    if len(sys.argv) > 1:
        os.environ["LOCALSTACK_API_KEY"] = os.environ.get("LOCALSTACK_API_KEY") or "test"
        if sys.argv[1] == "libs":
            print("Initializing installation.")
            logging.basicConfig(level=logging.INFO)
            logging.getLogger("requests").setLevel(logging.WARNING)
            install_all_components()
        if sys.argv[1] in ("libs", "testlibs"):
            # Install additional libraries for testing
            install_amazon_kinesis_client_libs()
        print("Done.")


if __name__ == "__main__":
    main()

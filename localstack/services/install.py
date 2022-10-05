#!/usr/bin/env python
import functools
import glob
import logging
import os
import re
import sys
import tempfile
import time
from typing import Callable, Dict, List, Tuple, Union

from plugin import Plugin, PluginManager

from localstack import config
from localstack.config import dirs
from localstack.constants import DEFAULT_SERVICE_PORTS, LOCALSTACK_MAVEN_VERSION, MAVEN_REPO_URL
from localstack.runtime import hooks
from localstack.utils.archives import untar, unzip
from localstack.utils.files import load_file, mkdir, new_tmp_file, rm_rf, save_file
from localstack.utils.http import download
from localstack.utils.run import run
from localstack.utils.threads import parallelize

LOG = logging.getLogger(__name__)

# TODO: install paths should become parameterizable to allow lpm to chose static_libs or var_libs
INSTALL_DIR_NPM = "%s/node_modules" % dirs.static_libs
INSTALL_DIR_DDB = "%s/dynamodb" % dirs.static_libs
INSTALL_DIR_KCL = "%s/amazon-kinesis-client" % dirs.static_libs
INSTALL_DIR_ELASTICMQ = "%s/elasticmq" % dirs.var_libs
INSTALL_PATH_DDB_JAR = os.path.join(INSTALL_DIR_DDB, "DynamoDBLocal.jar")
INSTALL_PATH_KCL_JAR = os.path.join(INSTALL_DIR_KCL, "aws-java-sdk-sts.jar")
INSTALL_PATH_ELASTICMQ_JAR = os.path.join(INSTALL_DIR_ELASTICMQ, "elasticmq-server.jar")

ARTIFACTS_REPO = "https://github.com/localstack/localstack-artifacts"

# additional JAR libs required for multi-region and persistence (PRO only) support
URL_ASPECTJRT = f"{MAVEN_REPO_URL}/org/aspectj/aspectjrt/1.9.7/aspectjrt-1.9.7.jar"
URL_ASPECTJWEAVER = f"{MAVEN_REPO_URL}/org/aspectj/aspectjweaver/1.9.7/aspectjweaver-1.9.7.jar"
JAR_URLS = [URL_ASPECTJRT, URL_ASPECTJWEAVER]


# debugpy module
DEBUGPY_MODULE = "debugpy"
DEBUGPY_DEPENDENCIES = ["gcc", "python3-dev", "musl-dev"]

# Target version for javac, to ensure compatibility with earlier JREs
JAVAC_TARGET_VERSION = "1.8"

# SQS backend implementation provider - either "moto" or "elasticmq"
SQS_BACKEND_IMPL = os.environ.get("SQS_PROVIDER") or "moto"


# Java Test Jar Download (used for tests)
TEST_LAMBDA_JAVA = os.path.join(config.dirs.var_libs, "localstack-utils-tests.jar")
TEST_LAMBDA_JAR_URL = "{url}/cloud/localstack/{name}/{version}/{name}-{version}-tests.jar".format(
    version=LOCALSTACK_MAVEN_VERSION, url=MAVEN_REPO_URL, name="localstack-utils"
)


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


def install_lambda_java_testlibs():
    # Download the LocalStack Utils Test jar file from the maven repo
    if not os.path.exists(TEST_LAMBDA_JAVA):
        mkdir(os.path.dirname(TEST_LAMBDA_JAVA))
        download(TEST_LAMBDA_JAR_URL, TEST_LAMBDA_JAVA)


def install_cloudformation_libs():
    from localstack.services.cloudformation import deployment_utils

    # trigger download of CF module file
    deployment_utils.get_cfn_response_mod_file()


def install_component(name):
    from localstack.services.awslambda.packages import awslambda_runtime_package
    from localstack.services.cloudformation.packages import cloudformation_package
    from localstack.services.dynamodb.packages import dynamodblocal_package
    from localstack.services.kinesis.packages import kinesismock_package
    from localstack.services.kms.packages import kms_local_package
    from localstack.services.sqs.legacy.packages import elasticmq_package
    from localstack.services.stepfunctions.packages import stepfunctions_local_package

    installers = {
        "cloudformation": cloudformation_package.install,
        "dynamodb": dynamodblocal_package.install,
        "kinesis": kinesismock_package.install,
        "kms": kms_local_package.install,
        "lambda": awslambda_runtime_package.install,
        "sqs": elasticmq_package.install,
        "stepfunctions": stepfunctions_local_package.install,
    }

    installer = installers.get(name)
    if installer:
        installer()


def install_components(names):
    parallelize(install_component, names)

    # TODO: subject to removal, migrated from old code
    from localstack.services.awslambda.packages import lambda_java_libs_package

    lambda_java_libs_package.install()


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


def extract(source_archive, target):
    _, ext = os.path.splitext(source_archive)
    if ext == ".zip":
        unzip(source_archive, target)
    elif ext in [".bz2", ".gz", ".tgz"]:
        untar(source_archive, target)
    else:
        raise Exception(f"Unsupported archive format: {ext}")


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
    extract(tmp_archive, target_dir)


def download_and_extract_with_retry(archive_url, tmp_archive, target_dir):
    try:
        download_and_extract(archive_url, target_dir, tmp_archive=tmp_archive)
    except Exception as e:
        # try deleting and re-downloading the zip file
        LOG.info("Unable to extract file, re-downloading ZIP archive %s: %s", tmp_archive, e)
        rm_rf(tmp_archive)
        download_and_extract(archive_url, target_dir, tmp_archive=tmp_archive)


Installer = Tuple[str, Callable]


class InstallerRepository(Plugin):
    # TODO the installer repositories should be migrated (downwards compatible) to use the packages / package installers
    namespace = "localstack.installer"

    def get_installer(self) -> List[Installer]:
        raise NotImplementedError


class CommunityInstallerRepository(InstallerRepository):
    name = "community"

    def get_installer(self) -> List[Installer]:
        from localstack.packages.postgres import PostgresqlPackage
        from localstack.packages.terraform import terraform_package
        from localstack.services.awslambda.packages import (
            awslambda_go_runtime_package,
            awslambda_runtime_package,
            lambda_java_libs_package,
        )
        from localstack.services.cloudformation.packages import cloudformation_package
        from localstack.services.dynamodb.packages import dynamodblocal_package
        from localstack.services.kinesis.packages import kinesalite_package, kinesismock_package
        from localstack.services.kms.packages import kms_local_package
        from localstack.services.opensearch.packages import (
            elasticsearch_package,
            opensearch_package,
        )
        from localstack.services.sqs.legacy.packages import elasticmq_package
        from localstack.services.stepfunctions.packages import stepfunctions_local_package

        return [
            ("awslambda-go-runtime", awslambda_go_runtime_package),
            ("awslambda-runtime", awslambda_runtime_package),
            ("cloudformation-libs", cloudformation_package),
            ("dynamodb-local", dynamodblocal_package),
            ("elasticmq", elasticmq_package),
            ("elasticsearch", elasticsearch_package),
            ("opensearch", opensearch_package),
            ("kinesalite", kinesalite_package),
            ("kinesis-mock", kinesismock_package),
            ("lambda-java-libs", lambda_java_libs_package),
            ("local-kms", kms_local_package),
            ("postgresql", PostgresqlPackage()),
            ("stepfunctions-local", stepfunctions_local_package),
            ("terraform", terraform_package),
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
    # TODO this main should be removed (together with the make init target in the Makefile)
    #      once the installer refactoring is done
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

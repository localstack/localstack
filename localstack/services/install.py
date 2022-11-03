import glob
import logging
import os
import re
import tempfile
from typing import Union

import time

from localstack.config import dirs
from localstack.constants import MAVEN_REPO_URL
from localstack.utils.archives import untar, unzip
from localstack.utils.files import load_file, mkdir, new_tmp_file, rm_rf, save_file
from localstack.utils.http import download
from localstack.utils.run import run

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

# Target version for javac, to ensure compatibility with earlier JREs
JAVAC_TARGET_VERSION = "1.8"

# SQS backend implementation provider - either "moto" or "elasticmq"
SQS_BACKEND_IMPL = os.environ.get("SQS_PROVIDER") or "moto"


# BEGIN OF SECTION

# remove this whole section once its absence doesn't cause any problems anymore
INSTALL_DIR_STEPFUNCTIONS = "%s/stepfunctions" % dirs.static_libs
INSTALL_PATH_STEPFUNCTIONS_JAR = os.path.join(INSTALL_DIR_STEPFUNCTIONS, "StepFunctionsLocal.jar")
IMAGE_NAME_SFN_LOCAL = "amazon/aws-stepfunctions-local:1.7.9"
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

SFN_AWS_SDK_URL_PREFIX = (
    f"{ARTIFACTS_REPO}/raw/a4adc8f4da9c7ec0d93b50ca5b73dd14df791c0e/stepfunctions-internal-awssdk"
)
SFN_AWS_SDK_LAMBDA_ZIP_FILE = f"{SFN_AWS_SDK_URL_PREFIX}/awssdk.zip"


# END OF SECTION


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

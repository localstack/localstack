import json
import os
import re
from pathlib import Path
from typing import List

import requests

from localstack.constants import ARTIFACTS_REPO, MAVEN_REPO_URL
from localstack.packages import InstallTarget, Package, PackageInstaller
from localstack.packages.core import ExecutableInstaller
from localstack.packages.java import JavaInstallerMixin
from localstack.utils.archives import add_file_to_jar, untar, update_jar_manifest
from localstack.utils.files import file_exists_not_empty, mkdir, new_tmp_file, rm_rf
from localstack.utils.http import download

# additional JAR libs required for multi-region and persistence (PRO only) support
URL_ASPECTJRT = f"{MAVEN_REPO_URL}/org/aspectj/aspectjrt/1.9.7/aspectjrt-1.9.7.jar"
URL_ASPECTJWEAVER = f"{MAVEN_REPO_URL}/org/aspectj/aspectjweaver/1.9.7/aspectjweaver-1.9.7.jar"
JAR_URLS = [URL_ASPECTJRT, URL_ASPECTJWEAVER]

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

SFN_AWS_SDK_URL_PREFIX = (
    f"{ARTIFACTS_REPO}/raw/6f56dd5b9c405d4356367ffb22d2f52cc8efa57a/stepfunctions-internal-awssdk"
)
SFN_AWS_SDK_LAMBDA_ZIP_FILE = f"{SFN_AWS_SDK_URL_PREFIX}/awssdk.zip"

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


class StepFunctionsLocalPackage(Package):
    """
    NOTE: Do NOT update the version here! (It will also have no effect)

    We are currently stuck on 1.7.9 since later versions introduced the generic aws-sdk Task,
    which introduced additional 300MB+ to the jar file since it includes all AWS Java SDK libs.

    This is blocked until our custom stepfunctions implementation is mature enough to replace it.
    """

    def __init__(self):
        super().__init__("StepFunctionsLocal", "1.7.9")

    def get_versions(self) -> List[str]:
        return ["1.7.9"]

    def _get_installer(self, version: str) -> PackageInstaller:
        return StepFunctionsLocalPackageInstaller("stepfunctions-local", version)


class StepFunctionsLocalPackageInstaller(JavaInstallerMixin, ExecutableInstaller):
    def _get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, "StepFunctionsLocal.jar")

    def _install(self, target: InstallTarget) -> None:
        """
        The StepFunctionsLocal JAR files are downloaded using the artifacts in DockerHub (because AWS only provides an
        HTTP link to the most recent version). Installers are executed when building Docker, this means they _cannot_ use
        the Docker socket. Therefore, this installer downloads a pinned Docker Layer Digest (i.e. only the data for a single
        Docker build step which adds the JAR files of the desired version to a Docker image) using plain HTTP requests.
        """
        install_dir = self._get_install_dir(target)
        install_destination = self._get_install_marker_path(install_dir)
        if not os.path.exists(install_destination):
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

            download_stepfunctions_jar(SFN_IMAGE, SFN_IMAGE_LAYER_DIGEST, target.value)
            mkdir(install_dir)
            path = Path(f"{target.value}/home/stepfunctionslocal")
            for file in path.glob("*.jar"):
                file.rename(Path(install_dir) / file.name)
            rm_rf(f"{target.value}/home")

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
            add_file_to_jar(patch_class, patch_url, target_jar=install_destination)

        # add additional classpath entries to JAR manifest file
        classpath = " ".join([os.path.basename(jar) for jar in JAR_URLS])
        update_jar_manifest(
            "StepFunctionsLocal.jar",
            install_dir,
            "Class-Path: . ",
            f"Class-Path: {classpath} . ",
        )
        update_jar_manifest(
            "StepFunctionsLocal.jar",
            install_dir,
            re.compile(r"Main-Class: com\.amazonaws.+"),
            "Main-Class: cloud.localstack.StepFunctionsStarter",
        )

        # download additional jar libs
        for jar_url in JAR_URLS:
            jar_target = os.path.join(install_dir, os.path.basename(jar_url))
            if not file_exists_not_empty(jar_target):
                download(jar_url, jar_target)

        # download aws-sdk lambda handler
        target = os.path.join(install_dir, "localstack-internal-awssdk", "awssdk.zip")
        if not file_exists_not_empty(target):
            download(SFN_AWS_SDK_LAMBDA_ZIP_FILE, target)


stepfunctions_local_package = StepFunctionsLocalPackage()

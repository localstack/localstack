from typing import List

from localstack.constants import LOCALSTACK_MAVEN_VERSION, MAVEN_REPO_URL
from localstack.packages import DownloadInstaller, Package, PackageInstaller

# Java Test Jar Download (used for tests)
TEST_LAMBDA_JAR_URL_TEMPLATE = "{url}/cloud/localstack/{name}/{version}/{name}-{version}-tests.jar"


class LambdaJavaTestlibsPackage(Package):
    def __init__(self):
        super().__init__("JavaLambdaTestlibs", "latest")

    def get_versions(self) -> List[str]:
        return ["latest"]

    def _get_installer(self, version: str) -> PackageInstaller:
        return LambdaJavaTestlibsPackageInstaller("lambda-java-testlibs", version)


class LambdaJavaTestlibsPackageInstaller(DownloadInstaller):
    def _get_download_url(self) -> str:
        return TEST_LAMBDA_JAR_URL_TEMPLATE.format(
            version=LOCALSTACK_MAVEN_VERSION, url=MAVEN_REPO_URL, name="localstack-utils"
        )


lambda_java_testlibs_package = LambdaJavaTestlibsPackage()

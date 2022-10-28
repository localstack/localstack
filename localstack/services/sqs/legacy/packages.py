import os
from typing import List

from localstack.packages import InstallTarget, Package, PackageInstaller
from localstack.services.install import log_install_msg
from localstack.utils.files import mkdir
from localstack.utils.http import download

ELASTICMQ_JAR_URL = (
    "https://s3-eu-west-1.amazonaws.com/softwaremill-public/elasticmq-server-1.1.0.jar"
)


class ElasticMQPackage(Package):
    def __init__(self):
        super().__init__("ElasticMQ", "1.1.0")

    def get_versions(self) -> List[str]:
        return ["1.1.0"]

    def _get_installer(self, version: str) -> PackageInstaller:
        return ElasticMQPackageInstaller()


class ElasticMQPackageInstaller(PackageInstaller):
    def __init__(self):
        super().__init__("elasticmq", "1.1.0")

    def _get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, "elasticmq-server.jar")

    def _install(self, target: InstallTarget) -> None:
        log_install_msg("ElasticMQ")
        install_dir = self._get_install_dir(target)
        mkdir(install_dir)
        download(ELASTICMQ_JAR_URL, self._get_install_marker_path(self._get_install_dir(target)))


elasticmq_package = ElasticMQPackage()

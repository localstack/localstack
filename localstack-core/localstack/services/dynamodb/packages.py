import os
from typing import List

from localstack import config
from localstack.constants import ARTIFACTS_REPO, MAVEN_REPO_URL
from localstack.packages import InstallTarget, Package, PackageInstaller
from localstack.packages.java import java_package
from localstack.utils.archives import (
    download_and_extract_with_retry,
    update_jar_manifest,
    upgrade_jar_file,
)
from localstack.utils.files import rm_rf, save_file
from localstack.utils.functions import run_safe
from localstack.utils.http import download
from localstack.utils.run import run

DDB_AGENT_JAR_URL = f"{ARTIFACTS_REPO}/raw/388cd73f45bfd3bcf7ad40aa35499093061c7962/dynamodb-local-patch/target/ddb-local-loader-0.1.jar"
JAVASSIST_JAR_URL = f"{MAVEN_REPO_URL}/org/javassist/javassist/3.30.2-GA/javassist-3.30.2-GA.jar"

DDBLOCAL_URL = "https://d1ni2b6xgvw0s0.cloudfront.net/v2.x/dynamodb_local_latest.zip"


class DynamoDBLocalPackage(Package):
    def __init__(self):
        super().__init__(name="DynamoDBLocal", default_version="2")

    def _get_installer(self, _) -> PackageInstaller:
        return DynamoDBLocalPackageInstaller()

    def get_versions(self) -> List[str]:
        return ["2"]


class DynamoDBLocalPackageInstaller(PackageInstaller):
    def __init__(self):
        super().__init__("dynamodb-local", "2")

        # DDBLocal v2 requires JRE 17+
        # See: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.DownloadingAndRunning.html
        self.java_version = "21"

    def _prepare_installation(self, target: InstallTarget) -> None:
        java_package.get_installer(self.java_version).install(target)

    def get_java_env_vars(self) -> dict[str, str]:
        java_home = java_package.get_installer(self.java_version).get_java_home()
        path = f"{java_home}/bin:{os.environ['PATH']}"

        return {
            "JAVA_HOME": java_home,
            "PATH": path,
        }

    def _install(self, target: InstallTarget):
        # download and extract archive
        tmp_archive = os.path.join(config.dirs.cache, f"DynamoDBLocal-{self.version}.zip")
        install_dir = self._get_install_dir(target)

        download_and_extract_with_retry(DDBLOCAL_URL, tmp_archive, install_dir)
        rm_rf(tmp_archive)

        # Use custom log formatting
        log4j2_config = """<?xml version="1.0" encoding="UTF-8"?>
        <Configuration status="WARN">
          <Appenders>
            <Console name="Console" target="SYSTEM_OUT">
              <PatternLayout pattern="%d{HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n"/>
            </Console>
          </Appenders>
          <Loggers>
            <Root level="WARN">
              <AppenderRef ref="Console"/>
            </Root>
          </Loggers>
        </Configuration>"""
        log4j2_file = os.path.join(install_dir, "log4j2.xml")
        run_safe(lambda: save_file(log4j2_file, log4j2_config))
        run_safe(lambda: run(["zip", "-u", "DynamoDBLocal.jar", "log4j2.xml"], cwd=install_dir))

        # Add patch that enables 20+ GSIs
        ddb_agent_jar_path = self.get_ddb_agent_jar_path()
        if not os.path.exists(ddb_agent_jar_path):
            download(DDB_AGENT_JAR_URL, ddb_agent_jar_path)

        javassit_jar_path = os.path.join(install_dir, "javassist.jar")
        if not os.path.exists(javassit_jar_path):
            download(JAVASSIST_JAR_URL, javassit_jar_path)

        # Add javassist in the manifest classpath
        update_jar_manifest(
            "DynamoDBLocal.jar", install_dir, "Class-Path: .", "Class-Path: javassist.jar ."
        )

        ddb_local_lib_dir = os.path.join(install_dir, "DynamoDBLocal_lib")
        upgrade_jar_file(ddb_local_lib_dir, "slf4j-ext-*.jar", "org/slf4j/slf4j-ext:2.0.13")

    def _get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, "DynamoDBLocal.jar")

    def get_ddb_agent_jar_path(self):
        return os.path.join(self.get_installed_dir(), "ddb-local-loader-0.1.jar")


dynamodblocal_package = DynamoDBLocalPackage()

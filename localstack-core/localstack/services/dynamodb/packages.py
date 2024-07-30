import os
from typing import List

from localstack import config
from localstack.constants import ARTIFACTS_REPO, MAVEN_REPO_URL
from localstack.packages import InstallTarget, Package, PackageInstaller
from localstack.utils.archives import (
    download_and_extract_with_retry,
    update_jar_manifest,
    upgrade_jar_file,
)
from localstack.utils.files import save_file
from localstack.utils.functions import run_safe
from localstack.utils.http import download
from localstack.utils.run import run

DDB_AGENT_JAR_URL = f"{ARTIFACTS_REPO}/raw/388cd73f45bfd3bcf7ad40aa35499093061c7962/dynamodb-local-patch/target/ddb-local-loader-0.1.jar"
DDBLOCAL_ZIP_URL = "https://d1ni2b6xgvw0s0.cloudfront.net/v2.x/dynamodb_local_latest.zip"
JAVASSIST_JAR_URL = f"{MAVEN_REPO_URL}/org/javassist/javassist/3.30.2-GA/javassist-3.30.2-GA.jar"


class DynamoDBLocalPackage(Package):
    def __init__(self):
        super().__init__(name="DynamoDBLocal", default_version="latest")

    def _get_installer(self, _) -> PackageInstaller:
        return DynamoDBLocalPackageInstaller()

    def get_versions(self) -> List[str]:
        return ["latest"]


class DynamoDBLocalPackageInstaller(PackageInstaller):
    def __init__(self):
        super().__init__("dynamodb-local", "latest")

    def _install(self, target: InstallTarget):
        # download and extract archive
        tmp_archive = os.path.join(config.dirs.cache, "localstack.ddb.zip")
        install_dir = self._get_install_dir(target)
        download_and_extract_with_retry(DDBLOCAL_ZIP_URL, tmp_archive, install_dir)

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

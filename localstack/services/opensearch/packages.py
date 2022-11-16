import glob
import logging
import os
import re
import shutil
import threading
from typing import List

import semver

from localstack import config
from localstack.constants import (
    ELASTICSEARCH_DEFAULT_VERSION,
    ELASTICSEARCH_DELETE_MODULES,
    ELASTICSEARCH_PLUGIN_LIST,
    OPENSEARCH_DEFAULT_VERSION,
    OPENSEARCH_PLUGIN_LIST,
)
from localstack.packages import InstallTarget, Package, PackageInstaller
from localstack.services.opensearch import versions
from localstack.utils.archives import download_and_extract_with_retry
from localstack.utils.files import chmod_r, load_file, mkdir, rm_rf, save_file
from localstack.utils.run import run
from localstack.utils.sync import SynchronizedDefaultDict, retry

LOG = logging.getLogger(__name__)


_OPENSEARCH_INSTALL_LOCKS = SynchronizedDefaultDict(threading.RLock)


class OpensearchPackage(Package):
    def __init__(self, default_version: str = OPENSEARCH_DEFAULT_VERSION):
        super().__init__(name="OpenSearch", default_version=default_version)

    def _get_installer(self, version: str) -> PackageInstaller:
        if version in versions._prefixed_elasticsearch_install_versions:
            return ElasticsearchPackageInstaller(version)
        else:
            return OpensearchPackageInstaller(version)

    def get_versions(self) -> List[str]:
        return list(versions.install_versions.keys())


class OpensearchPackageInstaller(PackageInstaller):
    def __init__(self, version: str):
        super().__init__("opensearch", version)

    def _install(self, target: InstallTarget):
        # locally import to avoid having a dependency on ASF when starting the CLI
        from localstack.aws.api.opensearch import EngineType
        from localstack.services.opensearch import versions

        version = self._get_opensearch_install_version()
        install_dir = self._get_install_dir(target)
        with _OPENSEARCH_INSTALL_LOCKS[version]:
            if not os.path.exists(install_dir):
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

    def _get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, "bin", "opensearch")

    def _get_opensearch_install_version(self) -> str:
        from localstack.services.opensearch import versions

        if config.SKIP_INFRA_DOWNLOADS:
            self.version = OPENSEARCH_DEFAULT_VERSION

        return versions.get_install_version(self.version)


class ElasticsearchPackageInstaller(PackageInstaller):
    def __init__(self, version: str):
        super().__init__("elasticsearch", version)

    def _install(self, target: InstallTarget):
        # locally import to avoid having a dependency on ASF when starting the CLI
        from localstack.aws.api.opensearch import EngineType
        from localstack.services.opensearch import versions

        version = self.get_elasticsearch_install_version()
        install_dir = self._get_install_dir(target)
        installed_executable = os.path.join(install_dir, "bin", "elasticsearch")
        if not os.path.exists(installed_executable):
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

    def _get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, "bin", "elasticsearch")

    def get_elasticsearch_install_version(self) -> str:
        from localstack.services.opensearch import versions

        if config.SKIP_INFRA_DOWNLOADS:
            return ELASTICSEARCH_DEFAULT_VERSION

        return versions.get_install_version(self.version)


opensearch_package = OpensearchPackage(default_version=OPENSEARCH_DEFAULT_VERSION)
elasticsearch_package = OpensearchPackage(default_version=ELASTICSEARCH_DEFAULT_VERSION)

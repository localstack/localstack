import os
from typing import List

from localstack.packages import InstallTarget, OSPackageInstaller, Package
from localstack.utils.files import new_tmp_file, rm_rf, save_file
from localstack.utils.http import download
from localstack.utils.run import run

POSTGRES_MAJOR_VERSION_RANGE = ["11", "12", "13"]
POSTGRES_RPM_REPOSITORY = "https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm"
REDHAT_PLPYTHON_VERSION_MAPPING = {"11": "11.17", "12": "12.12", "13": "13.8"}


class PostgresqlPackageInstaller(OSPackageInstaller):
    def __init__(self, version: str):
        super().__init__("postgresql", version)

        # Debian
        self._debian_install_dir = os.path.join("/usr/lib/postgresql", self.version)
        self._debian_package_list = [
            f"postgresql-{self.version}",
            f"postgresql-plpython3-{self.version}",
        ]

        # Redhat
        self._redhat_install_dir = os.path.join(f"/usr/pgsql-{self.version}/")
        self._redhat_package_list = [
            f"postgresql{self.version}-devel",
            f"postgresql{self.version}-server",
            f"postgresql{self.version}-plpython3-{REDHAT_PLPYTHON_VERSION_MAPPING.get(self.version)}",
        ]

    def _debian_get_install_dir(self, target: InstallTarget):
        return self._debian_install_dir

    def _debian_get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, "bin", "psql")

    def _debian_packages(self) -> List[str]:
        return self._debian_package_list

    def _debian_prepare_install(self, target: InstallTarget):
        # Install the debian repo
        if not os.path.exists("/etc/apt/sources.list.d/pgdg.list"):
            # update package index
            tmp_path = new_tmp_file()
            download("https://www.postgresql.org/media/keys/ACCC4CF8.asc", tmp_path)
            run(["apt-key", "add", tmp_path])
            rm_rf(tmp_path)
            lsb_release = run(["lsb_release", "-cs"]).strip()
            content = f"deb http://apt.postgresql.org/pub/repos/apt {lsb_release}-pgdg main"
            save_file("/etc/apt/sources.list.d/pgdg.list", content)
        super()._debian_prepare_install(target)

    def _redhat_get_install_dir(self, target: InstallTarget):
        return self._redhat_install_dir

    def _redhat_get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, "bin", "psql")

    def _redhat_packages(self) -> List[str]:
        return self._redhat_package_list

    def _redhat_prepare_install(self, target: InstallTarget):
        # Install the redhat repo
        run(["dnf", "install", "-y", POSTGRES_RPM_REPOSITORY])
        super()._redhat_prepare_install(target)


class PostgresqlPackage(Package):
    def __init__(self, default_version: str = "11"):
        super().__init__(name="PostgreSQL", default_version=default_version)

    def get_versions(self) -> List[str]:
        return POSTGRES_MAJOR_VERSION_RANGE

    def _get_installer(self, version):
        return PostgresqlPackageInstaller(version)

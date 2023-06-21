import os
from typing import List

from localstack.packages import Package, PackageInstaller
from localstack.packages.core import ArchiveDownloadAndExtractInstaller
from localstack.utils.platform import get_arch

FFMPEG_STATIC_BIN_URL = (
    "https://www.johnvansickle.com/ffmpeg/old-releases/ffmpeg-{version}-{arch}-static.tar.xz"
)


class FfmpegPackage(Package):
    def __init__(self):
        super().__init__(name="ffmpeg", default_version="4.4.1")

    def _get_installer(self, version: str) -> PackageInstaller:
        return FfmpegPackageInstaller(version)

    def get_versions(self) -> List[str]:
        return ["4.4.1"]


class FfmpegPackageInstaller(ArchiveDownloadAndExtractInstaller):
    def __init__(self, version: str):
        super().__init__("ffmpeg", version)

    def _get_download_url(self) -> str:
        return FFMPEG_STATIC_BIN_URL.format(arch=get_arch(), version=self.version)

    def _get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, self._get_archive_subdir())

    def _get_archive_subdir(self) -> str:
        return f"ffmpeg-{self.version}-{get_arch()}-static"

    def get_ffmpeg_path(self) -> str:
        return os.path.join(self.get_installed_dir(), "ffmpeg")

    def get_ffprobe_path(self) -> str:
        return os.path.join(self.get_installed_dir(), "ffprobe")


ffmpeg_package = FfmpegPackage()

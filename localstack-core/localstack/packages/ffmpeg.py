import os
from typing import List

from localstack.packages import Package
from localstack.packages.core import ArchiveDownloadAndExtractInstaller
from localstack.utils.platform import Arch, get_arch

# Mapping LocalStack architecture to BtbN's naming convention
ARCH_MAPPING = {Arch.amd64: "linux64", Arch.arm64: "linuxarm64"}

# Download URL template for ffmpeg 7.1 LGPL builds from BtbN GitHub Releases
FFMPEG_STATIC_BIN_URL = "https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-n{version}-latest-{arch}-lgpl-{version}.tar.xz"


class FfmpegPackage(Package["FfmpegPackageInstaller"]):
    def __init__(self) -> None:
        super().__init__(name="ffmpeg", default_version="7.1")

    def _get_installer(self, version: str) -> "FfmpegPackageInstaller":
        return FfmpegPackageInstaller(version)

    def get_versions(self) -> List[str]:
        return ["7.1"]


class FfmpegPackageInstaller(ArchiveDownloadAndExtractInstaller):
    def __init__(self, version: str):
        super().__init__("ffmpeg", version)

    def _get_download_url(self) -> str:
        return FFMPEG_STATIC_BIN_URL.format(arch=ARCH_MAPPING.get(get_arch()), version=self.version)

    def _get_install_marker_path(self, install_dir: str) -> str:
        return os.path.join(install_dir, self._get_archive_subdir())

    def _get_archive_subdir(self) -> str:
        return f"ffmpeg-n{self.version}-latest-{ARCH_MAPPING.get(get_arch())}-lgpl-{self.version}"

    def get_ffmpeg_path(self) -> str:
        return os.path.join(self.get_installed_dir(), "bin", "ffmpeg")  # type: ignore[arg-type]

    def get_ffprobe_path(self) -> str:
        return os.path.join(self.get_installed_dir(), "bin", "ffprobe")  # type: ignore[arg-type]


ffmpeg_package = FfmpegPackage()

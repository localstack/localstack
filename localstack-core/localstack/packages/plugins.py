from typing import TYPE_CHECKING

from localstack.packages.api import Package, package

if TYPE_CHECKING:
    from localstack.packages.ffmpeg import FfmpegPackageInstaller
    from localstack.packages.java import JavaPackageInstaller
    from localstack.packages.terraform import TerraformPackageInstaller


@package(name="terraform")
def terraform_package() -> Package["TerraformPackageInstaller"]:
    from .terraform import terraform_package

    return terraform_package


@package(name="ffmpeg")
def ffmpeg_package() -> Package["FfmpegPackageInstaller"]:
    from localstack.packages.ffmpeg import ffmpeg_package

    return ffmpeg_package


@package(name="java")
def java_package() -> Package["JavaPackageInstaller"]:
    from localstack.packages.java import java_package

    return java_package

from localstack.packages.api import Package, package


@package(name="terraform")
def terraform_package() -> Package:
    from .terraform import terraform_package

    return terraform_package


@package(name="ffmpeg")
def ffmpeg_package() -> Package:
    from localstack.packages.ffmpeg import ffmpeg_package

    return ffmpeg_package

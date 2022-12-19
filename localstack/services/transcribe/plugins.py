from localstack.packages import Package, package


@package(name="ffmpeg")
def ffmpeg_package() -> Package:
    from localstack.services.transcribe.packages import ffmpeg_package

    return ffmpeg_package

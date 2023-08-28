from localstack.packages import Package, package


@package(name="vosk")
def vosk_package() -> Package:
    from localstack.services.transcribe.packages import vosk_package

    return vosk_package

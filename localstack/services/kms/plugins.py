from localstack.packages import Package, package


@package(name="local-kms")
def local_kms_package() -> Package:
    from localstack.services.kms.packages import kms_local_package

    return kms_local_package

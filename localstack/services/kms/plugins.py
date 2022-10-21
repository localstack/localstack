from localstack.packages import Package, packages


@packages()
def kms_package() -> Package:
    from localstack.services.kms.packages import kms_local_package

    return kms_local_package

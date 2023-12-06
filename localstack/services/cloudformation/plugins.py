from localstack.packages import Package, package


@package(name="cloudformation-libs")
def cloudformation_package() -> Package:
    from localstack.services.cloudformation.packages import cloudformation_package

    return cloudformation_package

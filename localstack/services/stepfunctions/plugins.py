from localstack.packages import Package, package


@package(name="stepfunctions-local")
def stepfunctions_local_packages() -> Package:
    from localstack.services.stepfunctions.packages import stepfunctions_local_package

    return stepfunctions_local_package

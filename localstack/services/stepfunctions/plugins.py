from localstack.packages import Package, packages


@packages()
def stepfunctions_local_package() -> Package:
    from localstack.services.stepfunctions.packages import stepfunctions_local_package

    return stepfunctions_local_package

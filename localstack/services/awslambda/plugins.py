from localstack.packages import Package, packages


@packages()
def awslambda_runtime_package() -> Package:
    from localstack.services.awslambda.packages import awslambda_runtime_package

    return awslambda_runtime_package

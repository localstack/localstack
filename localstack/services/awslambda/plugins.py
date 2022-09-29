from localstack.packages import Package, packages


@packages()
def awslambda_runtime_package() -> Package:
    from localstack.services.awslambda.packages import awslambda_runtime_package

    return awslambda_runtime_package


@packages(name="awslambda_go_runtime")
def awslambda_go_runtime_package() -> Package:
    from localstack.services.awslambda.packages import awslambda_go_runtime_package

    return awslambda_go_runtime_package


@packages(name="lambda_java_libs")
def lambda_javalibs_package() -> Package:
    from localstack.services.awslambda.packages import lambda_java_libs_package

    return lambda_java_libs_package

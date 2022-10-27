from localstack.packages import Package, package


@package(name="awslambda-go-runtime")
def awslambda_go_runtime_package() -> Package:
    from localstack.services.awslambda.packages import awslambda_go_runtime_package

    return awslambda_go_runtime_package


@package(name="awslambda-runtime")
def awslambda_runtime_package() -> Package:
    from localstack.services.awslambda.packages import awslambda_runtime_package

    return awslambda_runtime_package


@package(name="lambda-java-libs")
def lambda_java_libs() -> Package:
    from localstack.services.awslambda.packages import lambda_java_libs_package

    return lambda_java_libs_package

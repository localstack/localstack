from localstack.packages import Package, package


@package(name="kinesis-mock")
def kinesismock_package() -> Package:
    from localstack.services.kinesis.packages import kinesismock_package

    return kinesismock_package

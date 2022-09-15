from localstack import config
from localstack.packages import Package, packages


@packages(should_load=lambda: config.KINESIS_PROVIDER == "kinesalite")
def kinesalite_package() -> Package:
    from localstack.services.kinesis.packages import kinesalite_package

    return kinesalite_package


@packages(should_load=lambda: config.KINESIS_PROVIDER != "kinesalite")
def kinesismock_package() -> Package:
    from localstack.services.kinesis.packages import kinesismock_package

    return kinesismock_package

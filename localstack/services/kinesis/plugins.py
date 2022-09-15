from localstack import config
from localstack.packages import Package, packages


@packages()
def kinesis_package() -> Package:
    if config.KINESIS_PROVIDER == "kinesalite":
        from localstack.services.kinesis.packages import kinesalite_package

        return kinesalite_package
    else:
        from localstack.services.kinesis.packages import kinesismock_package

        return kinesismock_package

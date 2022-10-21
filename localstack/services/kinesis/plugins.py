from localstack import config
from localstack.packages import Package, packages


def _common_package() -> Package:
    if config.KINESIS_PROVIDER == "kinesalite":
        from localstack.services.kinesis.packages import kinesalite_package

        return kinesalite_package
    else:
        from localstack.services.kinesis.packages import kinesismock_package

        return kinesismock_package


@packages()
def kinesis_package() -> Package:
    return _common_package()


@packages(name="legacy")
def kinesis_package_legacy() -> Package:
    return _common_package()

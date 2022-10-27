from localstack.packages.api import Package, package


@package(name="terraform")
def terraform_package() -> Package:
    from .terraform import terraform_package

    return terraform_package

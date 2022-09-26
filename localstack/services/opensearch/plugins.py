from localstack.packages import Package, packages


@packages()
def opensearch_package() -> Package:
    from localstack.services.opensearch.packages import opensearch_package

    return opensearch_package

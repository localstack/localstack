from localstack.packages import Package, packages


@packages(service="opensearch")
def opensearch_package() -> Package:
    from localstack.services.opensearch.packages import opensearch_package

    return opensearch_package

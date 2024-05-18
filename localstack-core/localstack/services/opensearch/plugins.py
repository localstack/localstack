from localstack.packages import Package, package


@package(name="opensearch")
def opensearch_package() -> Package:
    from localstack.services.opensearch.packages import opensearch_package

    return opensearch_package

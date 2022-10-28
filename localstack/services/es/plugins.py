from localstack.packages import Package, package


@package(name="elasticsearch")
def elasticsearch_package() -> Package:
    from localstack.services.opensearch.packages import elasticsearch_package

    return elasticsearch_package

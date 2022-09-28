from localstack.packages import Package, packages


@packages()
def elasticsearch_package() -> Package:
    from localstack.services.opensearch.packages import elasticsearch_package

    return elasticsearch_package

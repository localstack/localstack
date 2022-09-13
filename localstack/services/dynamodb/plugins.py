from localstack.packages import Package, packages


@packages(service="dynamodb")
def dynamodb_package() -> Package:
    from localstack.services.dynamodb.packages import dynamodblocal_package

    return dynamodblocal_package

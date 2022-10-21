from localstack.packages import package


@package(name="elasticmq")
def elasticmq_package():
    from localstack.services.sqs.legacy.packages import elasticmq_package

    return elasticmq_package

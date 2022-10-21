from localstack.packages import packages


@packages(api="sqs", name="legacy")
def sqs_package():
    from localstack.services.sqs.legacy.packages import elasticmq_package

    return elasticmq_package

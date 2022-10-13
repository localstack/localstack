from localstack.packages import packages


@packages()
def cloudformation_package():
    from localstack.services.cloudformation.packages import cloudformation_package

    return cloudformation_package

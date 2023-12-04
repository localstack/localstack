from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class S3BucketProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::S3::Bucket"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.s3.resource_providers.aws_s3_bucket import S3BucketProvider

        self.factory = S3BucketProvider

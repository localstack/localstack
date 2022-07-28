from abc import ABC

from localstack.aws.api.resourcegroupstaggingapi import ResourcegroupstaggingapiApi


class ResourcegroupstaggingapiProvider(ResourcegroupstaggingapiApi, ABC):
    pass

from abc import ABC

from localstack.aws.api.resourcegroupstaggingapi import ResourcegroupstaggingapiApi
from localstack.state import StateVisitor


class ResourcegroupstaggingapiProvider(ResourcegroupstaggingapiApi, ABC):
    def accept_state_visitor(self, visitor: StateVisitor):
        # currently, Moto resourcegroupstaggingapi stores all tags into the other services backend, so their backend
        # does not hold any state and is not worth saving. It only holds direct references to other services
        # It only holds pagination tokens that are not worth keeping
        pass

import logging

LOG = logging.getLogger(__name__)

# dict key used to store the deployment state of a resource
KEY_RESOURCE_STATE = "_state_"


class DependencyNotYetSatisfied(Exception):
    """Exception indicating that a resource dependency is not (yet) deployed/available."""

    def __init__(self, resource_ids, message=None):
        message = message or "Unresolved dependencies: %s" % resource_ids
        super(DependencyNotYetSatisfied, self).__init__(message)
        resource_ids = resource_ids if isinstance(resource_ids, list) else [resource_ids]
        self.resource_ids = resource_ids

import logging
from typing import Optional, TypedDict

from localstack.utils.aws import aws_stack

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


class ResourceJson(TypedDict):
    Type: str
    Properties: dict


class GenericBaseModel:
    """Abstract base class representing a resource model class in LocalStack.
    This class keeps references to a combination of (1) the CF resource
    properties (as defined in the template), and (2) the current deployment
    state of a resource.

    Concrete subclasses will implement convenience methods to manage resources,
    e.g., fetching the latest deployment state, getting the resource name, etc.
    """

    def __init__(self, resource_json: dict, region_name: Optional[str] = None, **params):
        # self.stack_name = stack_name # TODO: add stack name to params
        self.region_name = region_name or aws_stack.get_region()
        self.resource_json = resource_json
        self.resource_type = resource_json["Type"]
        # Properties, as defined in the resource template
        self.properties = resource_json["Properties"] = resource_json.get("Properties") or {}
        # State, as determined from the deployed resource; use a special dict key here to keep
        # track of state changes within resource_json (this way we encapsulate all state details
        # in `resource_json` and the changes will survive creation of multiple instances of this class)
        self.state = resource_json[KEY_RESOURCE_STATE] = resource_json.get(KEY_RESOURCE_STATE) or {}

    # ----------------------
    # ABSTRACT BASE METHODS
    # ----------------------

    def fetch_state(self, stack_name, resources):
        """Fetch the latest deployment state of this resource, or return None if not currently deployed (NOTE: THIS IS NOT ALWAYS TRUE)."""
        return None

    def update_resource(self, new_resource, stack_name, resources):
        """Update the deployment of this resource, using the updated properties (implemented by subclasses)."""
        raise NotImplementedError

    def is_updatable(self) -> bool:
        return type(self).update_resource != GenericBaseModel.update_resource

    @classmethod
    def cloudformation_type(cls):
        """Return the CloudFormation resource type name, e.g., "AWS::S3::Bucket" (implemented by subclasses)."""
        pass

    @staticmethod
    def get_deploy_templates():
        """Return template configurations used to create the final API requests (implemented by subclasses)."""
        pass

    # TODO: rework to normal instance method when resources aren't mutated in different place anymore
    @staticmethod
    def add_defaults(resource, stack_name: str):
        """Set any defaults required, including auto-generating names. Must be called before deploying the resource"""
        pass

    # ----------------------
    # GENERIC BASE METHODS
    # ----------------------

    def get_cfn_attribute(self, attribute_name):
        """Retrieve the given CF attribute for this resource"""
        return self.props.get(attribute_name)

    # TODO: make this stricter
    def get_ref(self):
        return self.physical_resource_id

    # ---------------------
    # GENERIC UTIL METHODS
    # ---------------------

    # TODO: remove
    def fetch_and_update_state(self, *args, **kwargs):
        if self.physical_resource_id is None:
            return None

        from localstack.services.cloudformation.engine import template_deployer

        try:
            state = self.fetch_state(*args, **kwargs)
            self.update_state(state)
            return state
        except Exception as e:
            if not template_deployer.check_not_found_exception(
                e, self.resource_type, self.properties
            ):
                LOG.debug("Unable to fetch state for resource %s: %s", self, e)

    # TODO: remove
    def fetch_state_if_missing(self, *args, **kwargs):
        if not self.state:
            self.fetch_and_update_state(*args, **kwargs)
        return self.state

    # TODO: remove
    def update_state(self, details):
        """Update the deployment state of this resource (existing attributes will be overwritten)."""
        details = details or {}
        self.state.update(details)
        return self.props

    @property
    def physical_resource_id(self) -> str | None:
        """Return the (cached) physical resource ID."""
        return self.resource_json.get("PhysicalResourceId")

    @property
    def logical_resource_id(self) -> str:
        """Return the logical resource ID."""
        return self.resource_json["LogicalResourceId"]

    # TODO: rename? make it clearer what props are in comparison with state, properties and resource_json
    @property
    def props(self) -> dict:
        """Return a copy of (1) the resource properties (from the template), combined with
        (2) the current deployment state properties of the resource."""
        result = dict(self.properties)
        result.update(self.state or {})
        return result

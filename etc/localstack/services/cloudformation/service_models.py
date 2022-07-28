import logging

# TODO: remove
from moto.cloudformation.exceptions import UnformattedGetAttTemplateException

from localstack.utils.aws import aws_stack
from localstack.utils.common import camel_to_snake_case

LOG = logging.getLogger(__name__)

# dict key used to store the deployment state of a resource
KEY_RESOURCE_STATE = "_state_"

# ref attribute definitions
REF_ATTRS = ["PhysicalResourceId", "Ref"]
REF_ID_ATTRS = REF_ATTRS + ["Id"]
REF_ARN_ATTRS = ["Ref", "Arn"]


class DependencyNotYetSatisfied(Exception):
    """Exception indicating that a resource dependency is not (yet) deployed/available."""

    def __init__(self, resource_ids, message=None):
        message = message or "Unresolved dependencies: %s" % resource_ids
        super(DependencyNotYetSatisfied, self).__init__(message)
        resource_ids = resource_ids if isinstance(resource_ids, list) else [resource_ids]
        self.resource_ids = resource_ids


class GenericBaseModel:
    """Abstract base class representing a resource model class in LocalStack.
    This class keeps references to a combination of (1) the CF resource
    properties (as defined in the template), and (2) the current deployment
    state of a resource.

    Concrete subclasses will implement convenience methods to manage resources,
    e.g., fetching the latest deployment state, getting the resource name, etc.
    """

    def __init__(self, resource_json, region_name=None, **params):
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

    def get_resource_name(self):
        """Return the name of this resource, based on its properties (to be overwritten by subclasses)"""
        return None

    def get_physical_resource_id(self, attribute=None, **kwargs):
        """Determine the physical resource ID (Ref) of this resource (to be overwritten by subclasses)"""
        return None

    # TODO: change the signature to pass in a Stack instance (instead of stack_name and resources)
    def fetch_state(self, stack_name, resources):
        """Fetch the latest deployment state of this resource, or return None if not currently deployed."""
        return None

    # TODO: change the signature to pass in a Stack instance (instead of stack_name and resources)
    def update_resource(self, new_resource, stack_name, resources):
        """Update the deployment of this resource, using the updated properties (implemented by subclasses)."""
        # TODO: evaluate if we can add a generic implementation here, using "update" parameters from
        # get_deploy_templates() responses, and based on checking whether resource attributes have changed
        pass

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
        """Retrieve the given CF attribute for this resource (inherited from moto's CloudFormationModel)"""
        if attribute_name in REF_ARN_ATTRS and hasattr(self, "arn"):
            return self.arn
        if attribute_name in REF_ATTRS:
            result = self.get_physical_resource_id(attribute=attribute_name)
            if result:
                return result
        props = self.props
        if attribute_name in props:
            return props.get(attribute_name)

        raise UnformattedGetAttTemplateException()

    # ---------------------
    # GENERIC UTIL METHODS
    # ---------------------

    def fetch_and_update_state(self, *args, **kwargs):
        from localstack.utils.cloudformation import template_deployer

        try:
            state = self.fetch_state(*args, **kwargs)
            self.update_state(state)
            return state
        except Exception as e:
            if not template_deployer.check_not_found_exception(
                e, self.resource_type, self.properties
            ):
                LOG.debug("Unable to fetch state for resource %s: %s", self, e)

    def fetch_state_if_missing(self, *args, **kwargs):
        if not self.state:
            self.fetch_and_update_state(*args, **kwargs)
        return self.state

    def set_resource_state(self, state):
        """Set the deployment state of this resource."""
        self.state = state or {}

    def update_state(self, details):
        """Update the deployment state of this resource (existing attributes will be overwritten)."""
        details = details or {}
        self.state.update(details)
        return self.props

    @property
    def physical_resource_id(self):
        """Return the (cached) physical resource ID."""
        return self.resource_json.get("PhysicalResourceId")

    @property
    def logical_resource_id(self):
        """Return the logical resource ID."""
        return self.resource_json.get("LogicalResourceId")

    @property
    def props(self):
        """Return a copy of (1) the resource properties (from the template), combined with
        (2) the current deployment state properties of the resource."""
        result = dict(self.properties)
        result.update(self.state or {})
        return result

    @property
    def resource_id(self):
        """Return the logical resource ID of this resource (i.e., the ref. name within the stack's resources)."""
        return self.resource_json["LogicalResourceId"]

    @classmethod
    def update_from_cloudformation_json(
        cls, original_resource, new_resource_name, cloudformation_json, region_name
    ):
        props = cloudformation_json.get("Properties", {})
        for key, val in props.items():
            snake_key = camel_to_snake_case(key)
            lower_key = key.lower()
            for candidate in [key, lower_key, snake_key]:
                if hasattr(original_resource, candidate) or candidate == snake_key:
                    setattr(original_resource, candidate, val)
                    break
        return original_resource

    @classmethod
    def create_from_cloudformation_json(cls, resource_name, resource_json, region_name):
        return cls(
            resource_name=resource_name,
            resource_json=resource_json,
            region_name=region_name,
        )

    @classmethod
    def resolve_refs_recursively(cls, stack_name, value, resources):
        # TODO: restructure code to avoid circular import here
        from localstack.services.cloudformation.provider import find_stack
        from localstack.utils.cloudformation.template_deployer import resolve_refs_recursively

        stack = find_stack(stack_name)
        return resolve_refs_recursively(stack, value)

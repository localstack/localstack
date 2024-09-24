from typing import Any, Callable, Optional, TypedDict

# ---------------------
# TYPES
# ---------------------

# Callable here takes the arguments:
# - resource_props
# - stack_name
# - resources
# - resource_id
ResourceProp = str | Callable[[dict, str, dict, str], dict]
ResourceDefinition = dict[str, ResourceProp]


class FuncDetailsValue(TypedDict):
    # Callable here takes the arguments:
    # - logical_resource_id
    # - resource
    # - stack_name
    function: str | Callable[[str, dict, str], Any]
    """Either an api method to call directly with `parameters` or a callable to directly invoke"""
    # Callable here takes the arguments:
    # - resource_props
    # - stack_name
    # - resources
    # - resource_id
    parameters: Optional[ResourceDefinition | Callable[[dict, str, list[dict], str], dict]]
    """arguments to the function, or a function that generates the arguments to the function"""
    # Callable here takes the arguments
    # - result
    # - resource_id
    # - resources
    # - resource_type
    result_handler: Optional[Callable[[dict, str, list[dict], str], None]]
    """Take the result of the operation and patch the state of the resources, yuck..."""
    types: Optional[dict[str, Callable]]
    """Possible type conversions"""


# Type definition for func_details supplied to invoke_function
FuncDetails = list[FuncDetailsValue] | FuncDetailsValue

# Type definition returned by GenericBaseModel.get_deploy_templates
DeployTemplates = dict[str, FuncDetails | Callable]

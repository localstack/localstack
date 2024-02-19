import logging

from localstack.services.cloudformation.engine.quirks import VALID_GETATT_PROPERTIES

LOG = logging.getLogger(__name__)

# def get_attr_from_model_instance(
#         resource: dict, attribute_name: str, resource_type: str, resource_id: str
# ) -> str:
#     properties = resource.get("Properties", {})
#
#     # TODO: fix this somewhere else
#     if legacy_state := resource.get("_state_"):
#         properties = {**properties, **legacy_state}
#
#         if legacy_deployed_state := resource.get("_last_deployed_state"):
#             properties = {**properties, **legacy_deployed_state}
#
#     # if there's no entry in VALID_GETATT_PROPERTIES for the resource type we still default to "open" and accept anything
#     valid_atts = VALID_GETATT_PROPERTIES.get(resource_type)
#     if valid_atts is not None and attribute_name not in valid_atts:
#         LOG.warning(
#             f"Invalid attribute in Fn::GetAtt for {resource_type}:  | {resource_id}.{attribute_name}"
#         )
#         raise Exception(
#             f"Resource type {resource_type} does not support attribute {{{attribute_name}}}"
#         )  # TODO: check CFn behavior via snapshot
#
#     attribute_candidate = properties.get(attribute_name)
#     if "." in attribute_name:
#         if attribute_candidate:
#             # in case we explicitly add a property with a dot, e.g. resource["Properties"]["Endpoint.Port"]
#             return attribute_candidate
#         parts = attribute_name.split(".")
#         attribute = properties
#         # TODO: the attribute fetching below is a temporary workaround for the dependency resolution.
#         #  It is caused by trying to access the resource attribute that has not been deployed yet.
#         #  This should be a hard error.“
#         for part in parts:
#             if attribute is None:
#                 return None
#             attribute = attribute.get(part)
#         return attribute
#
#     # If we couldn't find the attribute, this is actually an irrecoverable error.
#     # After the resource has a state of CREATE_COMPLETE, all attributes should already be set.
#     # TODO: raise here instead
#     # if attribute_candidate is None:
#     # raise Exception(
#     #     f"Failed to resolve attribute for Fn::GetAtt in {resource_type}: {resource_id}.{attribute_name}"
#     # )  # TODO: check CFn behavior via snapshot
#     return attribute_candidate


def get_attr_from_model_instance(
    resource: dict, attribute_name: str, resource_type: str, resource_id: str
) -> str:
    properties = resource.get("Properties", {})
    # if there's no entry in VALID_GETATT_PROPERTIES for the resource type we still default to "open" and accept anything
    valid_atts = VALID_GETATT_PROPERTIES.get(resource_type)
    if valid_atts is not None and attribute_name not in valid_atts:
        LOG.warning(
            f"Invalid attribute in Fn::GetAtt for {resource_type}:  | {resource_id}.{attribute_name}"
        )
        raise Exception(
            f"Resource type {resource_type} does not support attribute {{{attribute_name}}}"
        )  # TODO: check CFn behavior via snapshot

    attribute_candidate = properties.get(attribute_name)
    if "." in attribute_name:
        # was used for legacy, but keeping it since it might have to work for a custom resource as well
        if attribute_candidate:
            return attribute_candidate

        # some resources (e.g. ElastiCache) have their readOnly attributes defined as Aa.Bb but the property is named AaBb
        if attribute_candidate := properties.get(attribute_name.replace(".", "")):
            return attribute_candidate

        # accessing nested properties
        parts = attribute_name.split(".")
        attribute = properties
        # TODO: the attribute fetching below is a temporary workaround for the dependency resolution.
        #  It is caused by trying to access the resource attribute that has not been deployed yet.
        #  This should be a hard error.“
        for part in parts:
            if attribute is None:
                return None  # FIXME
            attribute = attribute.get(part)
        return attribute

    # If we couldn't find the attribute, this is actually an irrecoverable error.
    # After the resource has a state of CREATE_COMPLETE, all attributes should already be set.
    # TODO: raise here instead
    # if attribute_candidate is None:
    # raise Exception(
    #     f"Failed to resolve attribute for Fn::GetAtt in {resource_type}: {resource_id}.{attribute_name}"
    # )  # TODO: check CFn behavior via snapshot
    return attribute_candidate

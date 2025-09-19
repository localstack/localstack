from __future__ import annotations

from typing import Any

from localstack import config
from localstack.services.cloudformation.engine.v2.change_set_model import (
    Maybe,
    NodeIntrinsicFunction,
    NodeProperty,
    NodeResource,
    NodeTemplate,
    Nothing,
    is_nothing,
)
from localstack.services.cloudformation.engine.v2.change_set_model_static_preproc import (
    _AWS_URL_SUFFIX,
    _PSEUDO_PARAMETERS,
    MOCKED_REFERENCE,
    ChangeSetModelStaticPreproc,
    PreprocEntityDelta,
    PreprocOutput,
    PreprocProperties,
    PreprocResource,
    is_computable,
)

__all__ = [
    "_AWS_URL_SUFFIX",
    "_PSEUDO_PARAMETERS",
    "ChangeSetModelPreproc",
    "PreprocEntityDelta",
    "PreprocOutput",
    "PreprocProperties",
    "PreprocResource",
    "MOCKED_REFERENCE",
]
from localstack.services.cloudformation.engine.validations import ValidationError
from localstack.utils.objects import get_value_from_path


class ChangeSetModelPreproc(ChangeSetModelStaticPreproc):
    def _get_node_resource_for(
        self, resource_name: str, node_template: NodeTemplate
    ) -> NodeResource:
        # TODO: this could be improved with hashmap lookups if the Node contained bindings and not lists.
        for node_resource in node_template.resources.resources:
            if node_resource.name == resource_name:
                self.visit(node_resource)
                return node_resource
        raise ValidationError(
            f"Template format error: Unresolved resource dependencies [{resource_name}] in the Resources block of the template"
        )

    def _get_node_property_for(
        self, property_name: str, node_resource: NodeResource
    ) -> NodeProperty | None:
        # TODO: this could be improved with hashmap lookups if the Node contained bindings and not lists.
        for node_property in node_resource.properties.properties:
            if node_property.name == property_name:
                self.visit(node_property)
                return node_property
        return None

    def _deployed_property_value_of(
        self, resource_logical_id: str, property_name: str, resolved_resources: dict
    ) -> Any:
        # We have to override this function to make sure it does not try to access the
        # resolved resource

        # Before we can obtain deployed value for a resource, we need to first ensure to
        # process the resource if this wasn't processed already. Ideally, values should only
        # be accessible through delta objects, to ensure computation is always complete at
        # every level.
        _ = self._get_node_resource_for(
            resource_name=resource_logical_id,
            node_template=self._change_set.update_model.node_template,
        )
        resolved_resource = resolved_resources.get(resource_logical_id)
        if resolved_resource is None:
            raise RuntimeError(
                f"No deployed instances of resource '{resource_logical_id}' were found"
            )
        properties = resolved_resource.get("Properties", {})
        # TODO support structured properties, e.g. NestedStack.Outputs.OutputName
        property_value: Any | None = get_value_from_path(properties, property_name)

        if property_value:
            if not isinstance(property_value, (str, list)):
                # TODO: is this correct? If there is a bug in the logic here, it's probably
                #  better to know about it with a clear error message than to receive some form
                #  of message about trying to use a dictionary in place of a string
                raise RuntimeError(
                    f"Accessing property '{property_name}' from '{resource_logical_id}' resulted in a non-string value nor list"
                )
            return property_value
        elif config.CFN_IGNORE_UNSUPPORTED_RESOURCE_TYPES:
            return MOCKED_REFERENCE

        return property_value

    def _before_deployed_property_value_of(
        self, resource_logical_id: str, property_name: str
    ) -> Any:
        return self._deployed_property_value_of(
            resource_logical_id=resource_logical_id,
            property_name=property_name,
            resolved_resources=self._before_resolved_resources,
        )

    def _after_deployed_property_value_of(
        self, resource_logical_id: str, property_name: str
    ) -> str | None:
        return self._before_deployed_property_value_of(
            resource_logical_id=resource_logical_id, property_name=property_name
        )

    def _resolve_reference(self, logical_id: str) -> PreprocEntityDelta:
        static_value = super()._resolve_reference(logical_id)
        if is_computable(static_value):
            # value was resolvable statically
            return static_value

        node_resource = self._get_node_resource_for(
            resource_name=logical_id, node_template=self._change_set.update_model.node_template
        )
        resource_delta = self.visit(node_resource)
        before = resource_delta.before
        after = resource_delta.after

        return PreprocEntityDelta(before=before, after=after)

    def _resolve_attribute(self, arguments: str | list[str], select_before: bool) -> str:
        # TODO: add arguments validation.
        arguments_list: list[str]
        if isinstance(arguments, str):
            arguments_list = arguments.split(".")
        else:
            arguments_list = arguments
        logical_name_of_resource = arguments_list[0]
        attribute_name = arguments_list[1]

        node_resource = self._get_node_resource_for(
            resource_name=logical_name_of_resource,
            node_template=self._change_set.update_model.node_template,
        )
        node_property: NodeProperty | None = self._get_node_property_for(
            property_name=attribute_name, node_resource=node_resource
        )
        if node_property is not None:
            # The property is statically defined in the template and its value can be computed.
            property_delta = self.visit(node_property)
            value = property_delta.before if select_before else property_delta.after
        else:
            # The property is not statically defined and must therefore be available in
            # the properties deployed set.
            if select_before:
                value = self._before_deployed_property_value_of(
                    resource_logical_id=logical_name_of_resource,
                    property_name=attribute_name,
                )
            else:
                value = self._after_deployed_property_value_of(
                    resource_logical_id=logical_name_of_resource,
                    property_name=attribute_name,
                )
        return value

    def visit_node_intrinsic_function_fn_get_att(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        # TODO: validate the return value according to the spec.
        arguments_delta = self.visit(node_intrinsic_function.arguments)
        before_arguments: Maybe[str | list[str]] = arguments_delta.before
        after_arguments: Maybe[str | list[str]] = arguments_delta.after

        before = self._before_cache.get(node_intrinsic_function.scope, Nothing)
        if is_nothing(before) and not is_nothing(before_arguments):
            before = self._resolve_attribute(arguments=before_arguments, select_before=True)

        after = self._after_cache.get(node_intrinsic_function.scope, Nothing)
        if is_nothing(after) and not is_nothing(after_arguments):
            after = self._resolve_attribute(arguments=after_arguments, select_before=False)

        return PreprocEntityDelta(before=before, after=after)

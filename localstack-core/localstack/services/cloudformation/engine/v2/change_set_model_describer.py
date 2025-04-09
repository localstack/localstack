from __future__ import annotations

import json
from typing import Final, Optional

import localstack.aws.api.cloudformation as cfn_api
from localstack.services.cloudformation.engine.v2.change_set_model import (
    NodeIntrinsicFunction,
    NodeResource,
    NodeTemplate,
    PropertiesKey,
)
from localstack.services.cloudformation.engine.v2.change_set_model_preproc import (
    ChangeSetModelPreproc,
    PreprocEntityDelta,
    PreprocProperties,
    PreprocResource,
)

CHANGESET_KNOWN_AFTER_APPLY: Final[str] = "{{changeSet:KNOWN_AFTER_APPLY}}"


class ChangeSetModelDescriber(ChangeSetModelPreproc):
    _include_property_values: Final[bool]
    _changes: Final[cfn_api.Changes]

    def __init__(self, node_template: NodeTemplate, include_property_values: bool):
        super().__init__(node_template=node_template)
        self._include_property_values = include_property_values
        self._changes = list()

    def get_changes(self) -> cfn_api.Changes:
        self._changes.clear()
        self.process()
        return self._changes

    def visit_node_intrinsic_function_fn_get_att(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        # TODO: If we can properly compute the before and after value, why should we
        #  artificially limit the precision of our output to match AWS's?

        arguments_delta = self.visit(node_intrinsic_function.arguments)
        before_argument_list = arguments_delta.before
        after_argument_list = arguments_delta.after

        before = None
        if before_argument_list:
            before_logical_name_of_resource = before_argument_list[0]
            before_attribute_name = before_argument_list[1]
            before_node_resource = self._get_node_resource_for(
                resource_name=before_logical_name_of_resource, node_template=self._node_template
            )
            before_node_property = self._get_node_property_for(
                property_name=before_attribute_name, node_resource=before_node_resource
            )
            before_property_delta = self.visit(before_node_property)
            before = before_property_delta.before

        after = None
        if after_argument_list:
            after_logical_name_of_resource = after_argument_list[0]
            after_attribute_name = after_argument_list[1]
            after_node_resource = self._get_node_resource_for(
                resource_name=after_logical_name_of_resource, node_template=self._node_template
            )
            after_node_property = self._get_node_property_for(
                property_name=after_attribute_name, node_resource=after_node_resource
            )
            after_property_delta = self.visit(after_node_property)
            if after_property_delta.before == after_property_delta.after:
                after = after_property_delta.after
            else:
                after = CHANGESET_KNOWN_AFTER_APPLY

        return PreprocEntityDelta(before=before, after=after)

    def _register_resource_change(
        self,
        logical_id: str,
        type_: str,
        before_properties: Optional[PreprocProperties],
        after_properties: Optional[PreprocProperties],
    ) -> None:
        # unchanged: nothing to do.
        if before_properties == after_properties:
            return

        action = cfn_api.ChangeAction.Modify
        if before_properties is None:
            action = cfn_api.ChangeAction.Add
        elif after_properties is None:
            action = cfn_api.ChangeAction.Remove

        resource_change = cfn_api.ResourceChange()
        resource_change["Action"] = action
        resource_change["LogicalResourceId"] = logical_id
        resource_change["ResourceType"] = type_
        if self._include_property_values and before_properties is not None:
            before_context_properties = {PropertiesKey: before_properties.properties}
            before_context_properties_json_str = json.dumps(before_context_properties)
            resource_change["BeforeContext"] = before_context_properties_json_str
        if self._include_property_values and after_properties is not None:
            after_context_properties = {PropertiesKey: after_properties.properties}
            after_context_properties_json_str = json.dumps(after_context_properties)
            resource_change["AfterContext"] = after_context_properties_json_str
        self._changes.append(
            cfn_api.Change(Type=cfn_api.ChangeType.Resource, ResourceChange=resource_change)
        )

    def _describe_resource_change(
        self, name: str, before: Optional[PreprocResource], after: Optional[PreprocResource]
    ) -> None:
        if before is not None and after is not None:
            # Case: change on same type.
            if before.resource_type == after.resource_type:
                # Register a Modified if changed.
                self._register_resource_change(
                    logical_id=name,
                    type_=before.resource_type,
                    before_properties=before.properties,
                    after_properties=after.properties,
                )
            # Case: type migration.
            # TODO: Add test to assert that on type change the resources are replaced.
            else:
                # Register a Removed for the previous type.
                self._register_resource_change(
                    logical_id=name,
                    type_=before.resource_type,
                    before_properties=before.properties,
                    after_properties=None,
                )
                # Register a Create for the next type.
                self._register_resource_change(
                    logical_id=name,
                    type_=after.resource_type,
                    before_properties=None,
                    after_properties=after.properties,
                )
        elif before is not None:
            # Case: removal
            self._register_resource_change(
                logical_id=name,
                type_=before.resource_type,
                before_properties=before.properties,
                after_properties=None,
            )
        elif after is not None:
            # Case: addition
            self._register_resource_change(
                logical_id=name,
                type_=after.resource_type,
                before_properties=None,
                after_properties=after.properties,
            )

    def visit_node_resource(
        self, node_resource: NodeResource
    ) -> PreprocEntityDelta[PreprocResource, PreprocResource]:
        delta = super().visit_node_resource(node_resource=node_resource)
        self._describe_resource_change(
            name=node_resource.name, before=delta.before, after=delta.after
        )
        return delta

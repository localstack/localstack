from __future__ import annotations

import json
from typing import Final, Optional

import localstack.aws.api.cloudformation as cfn_api
from localstack.services.cloudformation.engine.v2.change_set_model import (
    NodeIntrinsicFunction,
    NodeProperty,
    NodeResource,
    NodeResources,
    PropertiesKey,
    is_nothing,
)
from localstack.services.cloudformation.engine.v2.change_set_model_preproc import (
    ChangeSetModelPreproc,
    PreprocEntityDelta,
    PreprocProperties,
    PreprocResource,
)
from localstack.services.cloudformation.v2.entities import ChangeSet

CHANGESET_KNOWN_AFTER_APPLY: Final[str] = "{{changeSet:KNOWN_AFTER_APPLY}}"


class ChangeSetModelDescriber(ChangeSetModelPreproc):
    _include_property_values: Final[bool]
    _changes: Final[cfn_api.Changes]

    def __init__(
        self,
        change_set: ChangeSet,
        include_property_values: bool,
    ):
        super().__init__(change_set=change_set)
        self._include_property_values = include_property_values
        self._changes = list()

    def get_changes(self) -> cfn_api.Changes:
        self._changes.clear()
        self.process()
        return self._changes

    def _setup_runtime_cache(self) -> None:
        # The describer can output {{changeSet:KNOWN_AFTER_APPLY}} values as not every field
        # is computable at describe time. Until a filtering logic or executor override logic
        # is available, the describer cannot benefit of previous evaluations to compute
        # change set resource changes.
        pass

    def _save_runtime_cache(self) -> None:
        # The describer can output {{changeSet:KNOWN_AFTER_APPLY}} values as not every field
        # is computable at describe time. Until a filtering logic or executor override logic
        # is available, there are no benefits in having the describer saving its runtime cache
        # for future changes chains.
        pass

    def _resolve_attribute(self, arguments: str | list[str], select_before: bool) -> str:
        if select_before:
            return super()._resolve_attribute(arguments=arguments, select_before=select_before)

        # Replicate AWS's limitations in describing change set's updated values.
        # Consideration: If we can properly compute the before and after value, why should we
        #                artificially limit the precision of our output to match AWS's?

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
        node_property: Optional[NodeProperty] = self._get_node_property_for(
            property_name=attribute_name, node_resource=node_resource
        )
        if node_property is not None:
            property_delta = self.visit(node_property)
            if property_delta.before == property_delta.after:
                value = property_delta.after
            else:
                value = CHANGESET_KNOWN_AFTER_APPLY
        else:
            try:
                value = self._after_deployed_property_value_of(
                    resource_logical_id=logical_name_of_resource,
                    property_name=attribute_name,
                )
            except RuntimeError:
                value = CHANGESET_KNOWN_AFTER_APPLY

        return value

    def visit_node_intrinsic_function_fn_join(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        # TODO: investigate the behaviour and impact of this logic with the user defining
        #       {{changeSet:KNOWN_AFTER_APPLY}} string literals as delimiters or arguments.
        delta = super().visit_node_intrinsic_function_fn_join(
            node_intrinsic_function=node_intrinsic_function
        )
        delta_before = delta.before
        if isinstance(delta_before, str) and CHANGESET_KNOWN_AFTER_APPLY in delta_before:
            delta.before = CHANGESET_KNOWN_AFTER_APPLY
        delta_after = delta.after
        if isinstance(delta_after, str) and CHANGESET_KNOWN_AFTER_APPLY in delta_after:
            delta.after = CHANGESET_KNOWN_AFTER_APPLY
        return delta

    def _register_resource_change(
        self,
        logical_id: str,
        type_: str,
        physical_id: Optional[str],
        before_properties: Optional[PreprocProperties],
        after_properties: Optional[PreprocProperties],
    ) -> None:
        action = cfn_api.ChangeAction.Modify
        if before_properties is None:
            action = cfn_api.ChangeAction.Add
        elif after_properties is None:
            action = cfn_api.ChangeAction.Remove

        resource_change = cfn_api.ResourceChange()
        resource_change["Action"] = action
        resource_change["LogicalResourceId"] = logical_id
        resource_change["ResourceType"] = type_
        if physical_id:
            resource_change["PhysicalResourceId"] = physical_id
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
        if before == after:
            # unchanged: nothing to do.
            return
        if not is_nothing(before) and not is_nothing(after):
            # Case: change on same type.
            if before.resource_type == after.resource_type:
                # Register a Modified if changed.
                self._register_resource_change(
                    logical_id=name,
                    physical_id=before.physical_resource_id,
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
                    physical_id=before.physical_resource_id,
                    type_=before.resource_type,
                    before_properties=before.properties,
                    after_properties=None,
                )
                # Register a Create for the next type.
                self._register_resource_change(
                    logical_id=name,
                    physical_id=None,
                    type_=after.resource_type,
                    before_properties=None,
                    after_properties=after.properties,
                )
        elif not is_nothing(before):
            # Case: removal
            self._register_resource_change(
                logical_id=name,
                physical_id=before.physical_resource_id,
                type_=before.resource_type,
                before_properties=before.properties,
                after_properties=None,
            )
        elif not is_nothing(after):
            # Case: addition
            self._register_resource_change(
                logical_id=name,
                physical_id=None,
                type_=after.resource_type,
                before_properties=None,
                after_properties=after.properties,
            )

    def visit_node_resources(self, node_resources: NodeResources) -> None:
        for node_resource in node_resources.resources:
            delta_resource = self.visit(node_resource)
            self._describe_resource_change(
                name=node_resource.name, before=delta_resource.before, after=delta_resource.after
            )

    def visit_node_resource(
        self, node_resource: NodeResource
    ) -> PreprocEntityDelta[PreprocResource, PreprocResource]:
        delta = super().visit_node_resource(node_resource=node_resource)
        after_resource = delta.after
        if not is_nothing(after_resource) and after_resource.physical_resource_id is None:
            after_resource.physical_resource_id = CHANGESET_KNOWN_AFTER_APPLY
        return delta

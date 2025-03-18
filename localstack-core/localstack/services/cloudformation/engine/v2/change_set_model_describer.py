from __future__ import annotations

import abc
from typing import Any, Final, Optional

from localstack.aws.api.cloudformation import ChangeAction, ResourceChange
from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeSetEntity,
    ChangeType,
    NodeArray,
    NodeIntrinsicFunction,
    NodeObject,
    NodeProperties,
    NodeProperty,
    NodeResource,
    NodeResources,
    NodeTemplate,
    PropertiesKey,
    TerminalValue,
    TerminalValueCreated,
    TerminalValueModified,
    TerminalValueRemoved,
    TerminalValueUnchanged,
)
from localstack.services.cloudformation.engine.v2.change_set_model_visitor import (
    ChangeSetModelVisitor,
)

CHANGESET_KNOWN_AFTER_APPLY: Final[str] = "{{changeSet:KNOWN_AFTER_APPLY}}"


class DescribeUnit(abc.ABC):
    before_context: Optional[Any] = None
    after_context: Optional[Any] = None

    def __init__(self, before_context: Optional[Any] = None, after_context: Optional[Any] = None):
        self.before_context = before_context
        self.after_context = after_context


class ChangeSetModelDescriber(ChangeSetModelVisitor):
    _node_template: Final[NodeTemplate]
    _resource_changes: Final[list[ResourceChange]]

    def __init__(self, node_template: NodeTemplate):
        self._node_template = node_template
        self._resource_changes = list()
        self.visit(self._node_template)

    def get_resource_changes(self) -> list[ResourceChange]:
        # TODO return 'list[Change]' instead.
        return [{"ResourceChange": change, "Type": "Resource"} for change in self._resource_changes]

    def visit(self, change_set_entity: ChangeSetEntity) -> DescribeUnit:
        # Overridden for the return type-hints.
        return super().visit(change_set_entity=change_set_entity)

    def visit_terminal_value_modified(
        self, terminal_value_modified: TerminalValueModified
    ) -> DescribeUnit:
        return DescribeUnit(
            before_context=terminal_value_modified.value,
            after_context=terminal_value_modified.modified_value,
        )

    def visit_terminal_value_created(
        self, terminal_value_created: TerminalValueCreated
    ) -> DescribeUnit:
        return DescribeUnit(after_context=terminal_value_created.value)

    def visit_terminal_value_removed(
        self, terminal_value_removed: TerminalValueRemoved
    ) -> DescribeUnit:
        return DescribeUnit(before_context=terminal_value_removed.value)

    def visit_terminal_value_unchanged(
        self, terminal_value_unchanged: TerminalValueUnchanged
    ) -> DescribeUnit:
        return DescribeUnit(
            before_context=terminal_value_unchanged.value,
            after_context=terminal_value_unchanged.value,
        )

    def visit_node_object(self, node_object: NodeObject) -> DescribeUnit:
        # TODO: improve check syntax
        if len(node_object.bindings) == 1:
            binding_values = list(node_object.bindings.values())
            unique_value = binding_values[0]
            if isinstance(unique_value, NodeIntrinsicFunction):
                return self.visit(unique_value)

        before_context = dict()
        after_context = dict()
        for name, change_set_entity in node_object.bindings.items():
            describe_unit: DescribeUnit = self.visit(change_set_entity=change_set_entity)
            match change_set_entity.change_type:
                case ChangeType.MODIFIED:
                    before_context[name] = describe_unit.before_context
                    after_context[name] = describe_unit.after_context
                case ChangeType.CREATED:
                    after_context[name] = describe_unit.after_context
                case ChangeType.REMOVED:
                    before_context[name] = describe_unit.before_context
                case ChangeType.UNCHANGED:
                    before_context[name] = describe_unit.before_context
                    after_context[name] = describe_unit.before_context
        return DescribeUnit(before_context=before_context, after_context=after_context)

    @staticmethod
    def _get_node_resource_for(resource_name: str, node_template: NodeTemplate) -> NodeResource:
        # TODO: this could be improved with hashmap lookups if the Node contained bindings and not lists.
        for node_resource in node_template.resources.resources:
            if node_resource.name == resource_name:
                return node_resource
        # TODO
        raise RuntimeError()

    @staticmethod
    def _get_node_property_for(property_name: str, node_resource: NodeResource) -> NodeProperty:
        # TODO: this could be improved with hashmap lookups if the Node contained bindings and not lists.
        for node_property in node_resource.properties.properties:
            if node_property.name == property_name:
                return node_property
        # TODO
        raise RuntimeError()

    def visit_node_intrinsic_function_fn_get_att(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> DescribeUnit:
        arguments_unit = self.visit(node_intrinsic_function.arguments)
        # TODO: validate the return value according to the spec.
        before_argument_list = arguments_unit.before_context
        before_logical_name_of_resource = before_argument_list[0]
        before_attribute_name = before_argument_list[1]
        before_node_resource = self._get_node_resource_for(
            resource_name=before_logical_name_of_resource, node_template=self._node_template
        )
        node_property: TerminalValue = self._get_node_property_for(
            property_name=before_attribute_name, node_resource=before_node_resource
        )

        before_context = node_property.value.value
        if node_property.change_type != ChangeType.UNCHANGED:
            after_context = CHANGESET_KNOWN_AFTER_APPLY
        else:
            after_context = node_property.value.value

        match node_intrinsic_function.change_type:
            case ChangeType.MODIFIED:
                return DescribeUnit(before_context=before_context, after_context=after_context)
            case ChangeType.CREATED:
                return DescribeUnit(after_context=after_context)
            case ChangeType.REMOVED:
                return DescribeUnit(before_context=before_context)
        # Unchanged
        return DescribeUnit(before_context=before_context, after_context=after_context)

    def visit_node_array(self, node_array: NodeArray) -> DescribeUnit:
        before_context = list()
        after_context = list()
        for change_set_entity in node_array.array:
            describe_unit: DescribeUnit = self.visit(change_set_entity=change_set_entity)
            match change_set_entity.change_type:
                case ChangeType.MODIFIED:
                    before_context.append(describe_unit.before_context)
                    after_context.append(describe_unit.after_context)
                case ChangeType.CREATED:
                    after_context.append(describe_unit.after_context)
                case ChangeType.REMOVED:
                    before_context.append(describe_unit.before_context)
                case ChangeType.UNCHANGED:
                    before_context.append(describe_unit.before_context)
                    after_context.append(describe_unit.before_context)
        return DescribeUnit(before_context=before_context, after_context=after_context)

    def visit_node_properties(self, node_properties: NodeProperties) -> DescribeUnit:
        before_context: dict[str, Any] = dict()
        after_context: dict[str, Any] = dict()
        for node_property in node_properties.properties:
            describe_unit = self.visit(node_property.value)
            property_name = node_property.name
            match node_property.change_type:
                case ChangeType.MODIFIED:
                    before_context[property_name] = describe_unit.before_context
                    after_context[property_name] = describe_unit.after_context
                case ChangeType.CREATED:
                    after_context[property_name] = describe_unit.after_context
                case ChangeType.REMOVED:
                    before_context[property_name] = describe_unit.before_context
                case ChangeType.UNCHANGED:
                    if node_properties.change_type != ChangeType.UNCHANGED:
                        before_context[property_name] = describe_unit.before_context
                        after_context[property_name] = describe_unit.before_context
        # TODO: this object can probably be well-typed instead of a free dict(?)
        before_context = {PropertiesKey: before_context}
        after_context = {PropertiesKey: after_context}
        return DescribeUnit(before_context=before_context, after_context=after_context)

    def visit_node_resource(self, node_resource: NodeResource) -> DescribeUnit:
        resource_change = ResourceChange()
        resource_change["LogicalResourceId"] = node_resource.name

        # TODO: investigate effects on type changes
        type_describe_unit = self.visit(node_resource.type_)
        resource_change["ResourceType"] = (
            type_describe_unit.before_context or type_describe_unit.after_context
        )

        properties_describe_unit = self.visit_node_properties(node_resource.properties)
        match node_resource.change_type:
            case ChangeType.MODIFIED:
                resource_change["Action"] = ChangeAction.Modify
                resource_change["BeforeContext"] = properties_describe_unit.before_context
                resource_change["AfterContext"] = properties_describe_unit.after_context
            case ChangeType.CREATED:
                resource_change["Action"] = ChangeAction.Add
                resource_change["AfterContext"] = properties_describe_unit.after_context
            case ChangeType.REMOVED:
                resource_change["Action"] = ChangeAction.Remove
                resource_change["BeforeContext"] = properties_describe_unit.before_context

        self._resource_changes.append(resource_change)

        # TODO
        return None

    def visit_node_resources(self, node_resources: NodeResources) -> DescribeUnit:
        for node_resource in node_resources.resources:
            if node_resource.change_type != ChangeType.UNCHANGED:
                self.visit_node_resource(node_resource=node_resource)
        # TODO
        return None

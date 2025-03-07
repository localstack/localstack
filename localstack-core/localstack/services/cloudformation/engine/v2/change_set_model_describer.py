from __future__ import annotations

import abc
from typing import Any, Optional

from localstack.aws.api.cloudformation import ChangeAction, ResourceChange
from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeSetEntity,
    ChangeType,
    NodeArray,
    NodeObject,
    NodeProperties,
    NodeResource,
    TerminalValueCreated,
    TerminalValueModified,
    TerminalValueRemoved,
    TerminalValueUnchanged,
)
from localstack.services.cloudformation.engine.v2.change_set_model_visitor import (
    ChangeSetModelVisitor,
)


class DescribeUnit(abc.ABC):
    context: Optional[Any]

    def __init__(self, context: Optional[Any]):
        self.context = context


class Created(DescribeUnit):
    pass


class Removed(DescribeUnit):
    pass


# TODO: unchanged can probably be pruned from the evaluation and be an empty value?
class Unchanged(DescribeUnit):
    pass


class Modified(DescribeUnit):
    after_context: Optional[Any]

    def __init__(self, context: Optional[Any], after_context: Optional[Any]):
        super().__init__(context=context)
        self.after_context = after_context


class ChangeSetModelDescriber(ChangeSetModelVisitor):
    # TODO: expand to other change types?
    changes: list[ResourceChange] = list()

    def __init__(self):
        self.changes = list()

    def visit(self, change_set_entity: ChangeSetEntity) -> DescribeUnit:
        # Overridden for the return type hints.
        return super().visit(change_set_entity=change_set_entity)

    def visit_terminal_value_modified(
        self, terminal_value_modified: TerminalValueModified
    ) -> Modified:
        return Modified(
            context=terminal_value_modified.value,
            after_context=terminal_value_modified.modified_value,
        )

    def visit_terminal_value_created(self, terminal_value_created: TerminalValueCreated) -> Created:
        return Created(context=terminal_value_created.value)

    def visit_terminal_value_removed(self, terminal_value_removed: TerminalValueRemoved) -> Removed:
        return Removed(context=terminal_value_removed.value)

    def visit_terminal_value_unchanged(
        self, terminal_value_unchanged: TerminalValueUnchanged
    ) -> Unchanged:
        return Unchanged(context=terminal_value_unchanged.value)

    def visit_node_object(self, node_object: NodeObject) -> DescribeUnit:
        before_context = dict()
        after_context = dict()
        for name, change_set_update in node_object.bindings.items():
            describe_unit: DescribeUnit = self.visit(change_set_entity=change_set_update)
            if isinstance(describe_unit, Modified):
                before_context[name] = describe_unit.context
                after_context[name] = describe_unit.after_context
            elif isinstance(describe_unit, Created):
                after_context[name] = describe_unit.context
            elif isinstance(describe_unit, Removed):
                before_context[name] = describe_unit.context
            elif isinstance(describe_unit, Unchanged):
                before_context[name] = describe_unit.context
                after_context[name] = describe_unit.context
            # Note: block is exhaustive about ChangeSetDescribeUnit
        match node_object.change_type:
            case ChangeType.MODIFIED:
                return Modified(context=before_context, after_context=after_context)
            case ChangeType.CREATED:
                return Created(context=after_context)
            case ChangeType.UNCHANGED:
                return Unchanged(context=before_context)
            case ChangeType.REMOVED:
                return Removed(context=before_context)
            case unsupported:
                # Note: match block is exhaustive about ChangeSet.
                raise RuntimeError(f"Unsupported ChangeType: '{unsupported}'")

    def visit_node_array(self, node_array: NodeArray) -> DescribeUnit:
        # TODO: is it worth chasing this duplication with visit_node_object?
        before_context = list()
        after_context = list()
        for change_set_entity in node_array.array:
            describe_unit: DescribeUnit = self.visit(change_set_entity=change_set_entity)
            if isinstance(describe_unit, Modified):
                before_context.append(describe_unit.context)
                after_context.append(describe_unit.after_context)
            elif isinstance(describe_unit, Created):
                after_context.append(describe_unit.context)
            elif isinstance(describe_unit, Removed):
                before_context.append(describe_unit.context)
            elif isinstance(describe_unit, Unchanged):
                before_context.append(describe_unit.context)
                after_context.append(describe_unit.context)
        # Note: block is exhaustive about ChangeSetDescribeUnit
        match node_array.change_type:
            case ChangeType.MODIFIED:
                return Modified(context=before_context, after_context=after_context)
            case ChangeType.CREATED:
                return Created(context=after_context)
            case ChangeType.UNCHANGED:
                return Unchanged(context=before_context)
            case ChangeType.REMOVED:
                return Removed(context=before_context)
            case unsupported:
                # Note: match block is exhaustive about ChangeSet.
                raise RuntimeError(f"Unsupported ChangeType: '{unsupported}'")

    def visit_node_properties(self, node_properties: NodeProperties) -> DescribeUnit:
        before_context: dict[str, Any] = dict()
        after_context: dict[str, Any] = dict()
        for node_property in node_properties.properties:
            if node_property.change_type == ChangeType.UNCHANGED:
                continue
            describe_unit = self.visit(node_property.value)
            property_name = node_property.name
            # TODO: duplication
            if isinstance(describe_unit, Modified):
                before_context[property_name] = describe_unit.context
                after_context[property_name] = describe_unit.after_context
            elif isinstance(describe_unit, Created):
                after_context[property_name] = describe_unit.context
            elif isinstance(describe_unit, Removed):
                before_context[property_name] = describe_unit.context
            elif isinstance(describe_unit, Unchanged):
                before_context[property_name] = describe_unit.context
                after_context[property_name] = describe_unit.context
        # TODO: this object can probably be well-typed instead of a free dict(?)
        before_context = {"Properties": before_context}
        after_context = {"Properties": after_context}
        match node_properties.change_type:
            case ChangeType.MODIFIED:
                return Modified(context=before_context, after_context=after_context)
            case ChangeType.CREATED:
                return Created(context=after_context)
            case ChangeType.UNCHANGED:
                return Unchanged(context=before_context)
            case ChangeType.REMOVED:
                return Removed(context=before_context)
            case unsupported:
                # Note: match block is exhaustive about ChangeSet.
                raise RuntimeError(f"Unsupported ChangeType: '{unsupported}'")

    def visit_node_resource(self, node_resource: NodeResource) -> DescribeUnit:
        # TODO: It seems like all unit changes should have before and after, look at the
        #  duplication in change type deductions.
        describe_unit = self.visit_node_properties(node_resource.properties)
        resource_change = ResourceChange()
        resource_change["LogicalResourceId"] = node_resource.name
        if isinstance(describe_unit, Modified):
            resource_change["BeforeContext"] = describe_unit.context
            resource_change["AfterContext"] = describe_unit.after_context
        elif isinstance(describe_unit, Created):
            resource_change["AfterContext"] = describe_unit.context
        elif isinstance(describe_unit, Removed):
            resource_change["BeforeContext"] = describe_unit.context
        elif isinstance(describe_unit, Unchanged):
            resource_change["BeforeContext"] = describe_unit.context
        match node_resource.change_type:
            case ChangeType.CREATED:
                resource_change["Action"] = ChangeAction.Add
                self.changes.append(resource_change)
            case ChangeType.REMOVED:
                resource_change["Action"] = ChangeAction.Remove
                self.changes.append(resource_change)
            case ChangeType.MODIFIED:
                resource_change["Action"] = ChangeAction.Modify
                self.changes.append(resource_change)
        # TODO
        return None

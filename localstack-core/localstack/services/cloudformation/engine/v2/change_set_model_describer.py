from __future__ import annotations

import abc
from typing import Any, Final, Optional

import localstack.aws.api.cloudformation as cfn_api
from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeSetEntity,
    ChangeType,
    NodeArray,
    NodeCondition,
    NodeDivergence,
    NodeIntrinsicFunction,
    NodeObject,
    NodeParameter,
    NodeProperties,
    NodeProperty,
    NodeResource,
    NodeTemplate,
    NothingType,
    PropertiesKey,
    Scope,
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
    _changes: Final[cfn_api.Changes]
    _describe_unit_cache: dict[Scope, DescribeUnit]

    def __init__(self, node_template: NodeTemplate):
        self._node_template = node_template
        self._changes = list()
        self._describe_unit_cache = dict()
        self.visit(self._node_template)

    def get_changes(self) -> cfn_api.Changes:
        return self._changes

    def visit(self, change_set_entity: ChangeSetEntity) -> DescribeUnit:
        describe_unit = self._describe_unit_cache.get(change_set_entity.scope)
        if describe_unit is not None:
            return describe_unit
        describe_unit = super().visit(change_set_entity=change_set_entity)
        self._describe_unit_cache[change_set_entity.scope] = describe_unit
        return describe_unit

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

    def visit_node_divergence(self, node_divergence: NodeDivergence) -> DescribeUnit:
        # TODO
        raise NotImplementedError()

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

    def visit_node_intrinsic_function_fn_equals(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ):
        # TODO: check for KNOWN AFTER APPLY values for logical ids coming from intrinsic functions as arguments.
        arguments_unit = self.visit(node_intrinsic_function.arguments)
        before_values = arguments_unit.before_context
        after_values = arguments_unit.after_context
        before_context = None
        if before_values:
            before_context = before_values[0] == before_values[1]
        after_context = None
        if after_values:
            after_context = after_values[0] == after_values[1]
        match node_intrinsic_function.change_type:
            case ChangeType.MODIFIED:
                return DescribeUnit(before_context=before_context, after_context=after_context)
            case ChangeType.CREATED:
                return DescribeUnit(after_context=after_context)
            case ChangeType.REMOVED:
                return DescribeUnit(before_context=before_context)
        # Unchanged
        return DescribeUnit(before_context=before_context, after_context=after_context)

    def _get_node_parameter_if_exists(self, parameter_name: str) -> Optional[NodeParameter]:
        parameters: list[NodeParameter] = self._node_template.parameters.parameters
        # TODO: another scenarios suggesting property lookups might be preferable.
        for parameter in parameters:
            if parameter.name == parameter_name:
                return parameter
        return None

    def _get_node_condition_if_exists(self, condition_name: str) -> Optional[NodeCondition]:
        conditions: list[NodeCondition] = self._node_template.conditions.conditions
        # TODO: another scenarios suggesting property lookups might be preferable.
        for condition in conditions:
            if condition.name == condition_name:
                return condition
        return None

    def visit_node_parameter(self, node_parameter: NodeParameter) -> DescribeUnit:
        # TODO: add caching for these operation, parameters may be referenced more than once.
        # TODO: add support for default value sampling
        dynamic_value = node_parameter.dynamic_value
        describe_unit = self.visit(dynamic_value)
        return describe_unit

    def visit_node_condition(self, node_condition: NodeCondition) -> DescribeUnit:
        describe_unit = self.visit(node_condition.body)
        return describe_unit

    def _resolve_reference(self, logica_id: str) -> DescribeUnit:
        node_condition = self._get_node_condition_if_exists(condition_name=logica_id)
        if isinstance(node_condition, NodeCondition):
            condition_unit = self.visit(node_condition)
            return condition_unit

        node_parameter = self._get_node_parameter_if_exists(parameter_name=logica_id)
        if isinstance(node_parameter, NodeParameter):
            parameter_unit = self.visit(node_parameter)
            return parameter_unit

        # TODO: check for KNOWN AFTER APPLY values for logical ids coming from intrinsic functions as arguments.
        #   node_resource = self._get_node_resource_for(
        #       resource_name=logica_id, node_template=self._node_template
        #   )
        limitation_str = "Cannot yet compute Ref values for Resources"
        resource_unit = DescribeUnit(before_context=limitation_str, after_context=limitation_str)
        return resource_unit

    def _resolve_reference_binding(
        self, before_logical_id: str, after_logical_id: str
    ) -> DescribeUnit:
        before_unit = self._resolve_reference(logica_id=before_logical_id)
        after_unit = self._resolve_reference(logica_id=after_logical_id)
        return DescribeUnit(
            before_context=before_unit.before_context, after_context=after_unit.after_context
        )

    def visit_node_intrinsic_function_ref(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> DescribeUnit:
        arguments_unit = self.visit(node_intrinsic_function.arguments)

        # TODO: add tests with created and deleted parameters and verify this logic holds.
        before_logical_id = arguments_unit.before_context
        before_unit = self._resolve_reference(logica_id=before_logical_id)
        before_context = before_unit.before_context

        after_logical_id = arguments_unit.after_context
        after_unit = self._resolve_reference(logica_id=after_logical_id)
        after_context = after_unit.after_context

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
                    before_context[property_name] = describe_unit.before_context
                    after_context[property_name] = describe_unit.before_context
        # TODO: this object can probably be well-typed instead of a free dict(?)
        before_context = {PropertiesKey: before_context}
        after_context = {PropertiesKey: after_context}
        return DescribeUnit(before_context=before_context, after_context=after_context)

    def _resolve_resource_condition_reference(self, reference: TerminalValue) -> DescribeUnit:
        reference_unit = self.visit(reference)
        before_reference = reference_unit.before_context
        after_reference = reference_unit.after_context
        condition_unit = self._resolve_reference_binding(
            before_logical_id=before_reference, after_logical_id=after_reference
        )
        before_context = (
            condition_unit.before_context if not isinstance(before_reference, NothingType) else True
        )
        after_context = (
            condition_unit.after_context if not isinstance(after_reference, NothingType) else True
        )
        return DescribeUnit(before_context=before_context, after_context=after_context)

    def visit_node_resource(self, node_resource: NodeResource) -> DescribeUnit:
        condition_unit = self._resolve_resource_condition_reference(
            node_resource.condition_reference
        )
        condition_before = condition_unit.before_context
        condition_after = condition_unit.after_context
        if not condition_before and condition_after:
            change_type = ChangeType.CREATED
        elif condition_before and not condition_after:
            change_type = ChangeType.REMOVED
        else:
            change_type = node_resource.change_type
        if change_type == ChangeType.UNCHANGED:
            # TODO
            return None

        resource_change = cfn_api.ResourceChange()
        resource_change["LogicalResourceId"] = node_resource.name

        # TODO: investigate effects on type changes
        type_describe_unit = self.visit(node_resource.type_)
        resource_change["ResourceType"] = (
            type_describe_unit.before_context or type_describe_unit.after_context
        )

        properties_describe_unit = self.visit(node_resource.properties)
        match change_type:
            case ChangeType.MODIFIED:
                resource_change["Action"] = cfn_api.ChangeAction.Modify
                resource_change["BeforeContext"] = properties_describe_unit.before_context
                resource_change["AfterContext"] = properties_describe_unit.after_context
            case ChangeType.CREATED:
                resource_change["Action"] = cfn_api.ChangeAction.Add
                resource_change["AfterContext"] = properties_describe_unit.after_context
            case ChangeType.REMOVED:
                resource_change["Action"] = cfn_api.ChangeAction.Remove
                resource_change["BeforeContext"] = properties_describe_unit.before_context

        self._changes.append(
            cfn_api.Change(Type=cfn_api.ChangeType.Resource, ResourceChange=resource_change)
        )

        # TODO
        return None

    # def visit_node_resources(self, node_resources: NodeResources) -> DescribeUnit:
    #     for node_resource in node_resources.resources:
    #         if node_resource.change_type != ChangeType.UNCHANGED:
    #             self.visit_node_resource(node_resource=node_resource)
    #     # TODO
    #     return None

from __future__ import annotations

import abc
from typing import Any, Final, Optional

import localstack.aws.api.cloudformation as cfn_api
from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeSetEntity,
    ChangeType,
    ConditionKey,
    ExportKey,
    NodeArray,
    NodeCondition,
    NodeDivergence,
    NodeIntrinsicFunction,
    NodeObject,
    NodeOutput,
    NodeOutputs,
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
    ValueKey,
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
        node_resource = self._get_node_resource_for(
            resource_name=logica_id, node_template=self._node_template
        )
        resource_unit = self.visit(node_resource)
        before_context = resource_unit.before_context
        after_context = resource_unit.after_context
        return DescribeUnit(before_context=before_context, after_context=after_context)

    def _resolve_reference_binding(
        self, before_logical_id: str, after_logical_id: str
    ) -> DescribeUnit:
        before_unit = self._resolve_reference(logica_id=before_logical_id)
        after_unit = self._resolve_reference(logica_id=after_logical_id)
        return DescribeUnit(
            before_context=before_unit.before_context, after_context=after_unit.after_context
        )

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
        before_unit = self.visit(node_divergence.value)
        after_unit = self.visit(node_divergence.divergence)
        return DescribeUnit(
            before_context=before_unit.before_context, after_context=after_unit.after_context
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

    def visit_node_intrinsic_function_fn_get_att(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> DescribeUnit:
        arguments_unit = self.visit(node_intrinsic_function.arguments)
        # TODO: validate the return value according to the spec.
        before_argument_list = arguments_unit.before_context
        after_argument_list = arguments_unit.after_context

        before_context = None
        if before_argument_list:
            before_logical_name_of_resource = before_argument_list[0]
            before_attribute_name = before_argument_list[1]
            before_node_resource = self._get_node_resource_for(
                resource_name=before_logical_name_of_resource, node_template=self._node_template
            )
            before_node_property = self._get_node_property_for(
                property_name=before_attribute_name, node_resource=before_node_resource
            )
            before_property_unit = self.visit(before_node_property)
            before_context = before_property_unit.before_context

        after_context = None
        if after_argument_list:
            after_context = CHANGESET_KNOWN_AFTER_APPLY
            # TODO: the following is the logic to resolve the attribute in the `after` template
            #  this should be moved to the new base class and then be masked in this describer.
            # after_logical_name_of_resource = after_argument_list[0]
            # after_attribute_name = after_argument_list[1]
            # after_node_resource = self._get_node_resource_for(
            #     resource_name=after_logical_name_of_resource, node_template=self._node_template
            # )
            # after_node_property = self._get_node_property_for(
            #     property_name=after_attribute_name, node_resource=after_node_resource
            # )
            # after_property_unit = self.visit(after_node_property)
            # after_context = after_property_unit.after_context

        return DescribeUnit(before_context=before_context, after_context=after_context)

    def visit_node_intrinsic_function_fn_equals(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> DescribeUnit:
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

    def visit_node_intrinsic_function_fn_if(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> DescribeUnit:
        # TODO: check for KNOWN AFTER APPLY values for logical ids coming from intrinsic functions as arguments.
        arguments_unit = self.visit(node_intrinsic_function.arguments)

        def _compute_unit_for_if_statement(args: list[Any]) -> DescribeUnit:
            condition_name = args[0]
            boolean_expression_unit = self._resolve_reference(logica_id=condition_name)
            return DescribeUnit(
                before_context=args[1] if boolean_expression_unit.before_context else args[2],
                after_context=args[1] if boolean_expression_unit.after_context else args[2],
            )

        # TODO: add support for this being created or removed.
        before_outcome_unit = _compute_unit_for_if_statement(arguments_unit.before_context)
        before_context = before_outcome_unit.before_context
        after_outcome_unit = _compute_unit_for_if_statement(arguments_unit.after_context)
        after_context = after_outcome_unit.after_context
        return DescribeUnit(before_context=before_context, after_context=after_context)

    def visit_node_intrinsic_function_fn_not(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> DescribeUnit:
        # TODO: check for KNOWN AFTER APPLY values for logical ids coming from intrinsic functions as arguments.
        # TODO: add type checking/validation for result unit?
        arguments_unit = self.visit(node_intrinsic_function.arguments)
        before_condition = arguments_unit.before_context
        after_condition = arguments_unit.after_context
        if before_condition:
            before_condition_outcome = before_condition[0]
            before_context = not before_condition_outcome
        else:
            before_context = None

        if after_condition:
            after_condition_outcome = after_condition[0]
            after_context = not after_condition_outcome
        else:
            after_context = None
        # Implicit change type computation.
        return DescribeUnit(before_context=before_context, after_context=after_context)

    def visit_node_parameter(self, node_parameter: NodeParameter) -> DescribeUnit:
        # TODO: add caching for these operation, parameters may be referenced more than once.
        # TODO: add support for default value sampling
        dynamic_value = node_parameter.dynamic_value
        describe_unit = self.visit(dynamic_value)
        return describe_unit

    def visit_node_condition(self, node_condition: NodeCondition) -> DescribeUnit:
        describe_unit = self.visit(node_condition.body)
        return describe_unit

    def visit_node_intrinsic_function_ref(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> DescribeUnit:
        arguments_unit = self.visit(node_intrinsic_function.arguments)

        # TODO: add tests with created and deleted parameters and verify this logic holds.
        before_logical_id = arguments_unit.before_context
        before_context = None
        if before_logical_id is not None:
            before_unit = self._resolve_reference(logica_id=before_logical_id)
            before_context = before_unit.before_context

        after_logical_id = arguments_unit.after_context
        after_context = None
        if after_logical_id is not None:
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

    def visit_node_output(self, node_output: NodeOutput) -> DescribeUnit:
        # This logic is not required for Describe operations,
        # and should be ported a new base for this class type.
        change_type = node_output.change_type
        value_unit = self.visit(node_output.value)

        condition_unit = None
        if node_output.condition_reference is not None:
            condition_unit = self._resolve_resource_condition_reference(
                node_output.condition_reference
            )
            condition_before = condition_unit.before_context
            condition_after = condition_unit.after_context
            if not condition_before and condition_after:
                change_type = ChangeType.CREATED
            elif condition_before and not condition_after:
                change_type = ChangeType.REMOVED

        export_unit = None
        if node_output.export is not None:
            export_unit = self.visit(node_output.export)

        before_context = None
        after_context = None
        if change_type != ChangeType.REMOVED:
            after_context = {"Name": node_output.name, ValueKey: value_unit.after_context}
            if export_unit:
                after_context[ExportKey] = export_unit.after_context
            if condition_unit:
                after_context[ConditionKey] = condition_unit.after_context
        if change_type != ChangeType.CREATED:
            before_context = {"Name": node_output.name, ValueKey: value_unit.before_context}
            if export_unit:
                before_context[ExportKey] = export_unit.before_context
            if condition_unit:
                before_context[ConditionKey] = condition_unit.before_context
        return DescribeUnit(before_context=before_context, after_context=after_context)

    def visit_node_outputs(self, node_outputs: NodeOutputs) -> DescribeUnit:
        # This logic is not required for Describe operations,
        # and should be ported a new base for this class type.
        before_context = list()
        after_context = list()
        for node_output in node_outputs.outputs:
            output_unit = self.visit(node_output)
            output_before = output_unit.before_context
            output_after = output_unit.after_context
            if output_before:
                before_context.append(output_before)
            if output_after:
                after_context.append(output_after)
        return DescribeUnit(before_context=before_context, after_context=after_context)

    def visit_node_resource(self, node_resource: NodeResource) -> DescribeUnit:
        change_type = node_resource.change_type
        if node_resource.condition_reference is not None:
            condition_unit = self._resolve_resource_condition_reference(
                node_resource.condition_reference
            )
            condition_before = condition_unit.before_context
            condition_after = condition_unit.after_context
            if not condition_before and condition_after:
                change_type = ChangeType.CREATED
            elif condition_before and not condition_after:
                change_type = ChangeType.REMOVED

        resource_change = cfn_api.ResourceChange()
        resource_change["LogicalResourceId"] = node_resource.name

        # TODO: investigate effects on type changes
        type_describe_unit = self.visit(node_resource.type_)
        resource_change["ResourceType"] = (
            type_describe_unit.before_context or type_describe_unit.after_context
        )

        properties_describe_unit = self.visit(node_resource.properties)

        if change_type != ChangeType.UNCHANGED:
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

        before_context = None
        after_context = None
        # TODO: reconsider what is the describe unit return value for a resource type.
        if change_type != ChangeType.CREATED:
            before_context = node_resource.name
        if change_type != ChangeType.REMOVED:
            after_context = node_resource.name
        return DescribeUnit(before_context=before_context, after_context=after_context)

from __future__ import annotations

from typing import Any, Final, Generic, Optional, TypedDict, TypeVar

from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeSetEntity,
    ChangeType,
    ConditionKey,
    ExportKey,
    NodeArray,
    NodeCondition,
    NodeDivergence,
    NodeIntrinsicFunction,
    NodeMapping,
    NodeObject,
    NodeOutput,
    NodeOutputs,
    NodeParameter,
    NodeProperties,
    NodeProperty,
    NodeResource,
    NodeTemplate,
    NothingType,
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

TBefore = TypeVar("TBefore")
TAfter = TypeVar("TAfter")


class ResolvedEntityDelta(Generic[TBefore, TAfter]):
    before: Optional[TBefore]
    after: Optional[TAfter]

    def __init__(self, before: Optional[TBefore] = None, after: Optional[TAfter] = None):
        self.before = before
        self.after = after


class ResolvedProperties(TypedDict):
    Properties: dict


class ResolvedResource:
    condition: Optional[bool]
    logical_resource_id: str
    resource_type: str
    properties: dict

    def __init__(
        self,
        condition: Optional[bool],
        logical_resource_id: str,
        resource_type: str,
        properties: dict,
    ):
        self.condition = condition
        self.logical_resource_id = logical_resource_id
        self.resource_type = resource_type
        self.properties = properties


class ChangeSetModelProcessor(ChangeSetModelVisitor):
    _node_template: Final[NodeTemplate]
    _processed: dict[Scope, ResolvedEntityDelta]

    def __init__(self, node_template: NodeTemplate):
        self._node_template = node_template
        self._processed = dict()

    def process(self) -> None:
        self.visit(self._node_template)

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

    def _get_node_mapping(self, map_name: str) -> NodeMapping:
        mappings: list[NodeMapping] = self._node_template.mappings.mappings
        # TODO: another scenarios suggesting property lookups might be preferable.
        for mapping in mappings:
            if mapping.name == map_name:
                return mapping
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

    def _resolve_reference(self, logica_id: str) -> ResolvedEntityDelta:
        node_condition = self._get_node_condition_if_exists(condition_name=logica_id)
        if isinstance(node_condition, NodeCondition):
            condition_delta = self.visit(node_condition)
            return condition_delta

        node_parameter = self._get_node_parameter_if_exists(parameter_name=logica_id)
        if isinstance(node_parameter, NodeParameter):
            parameter_delta = self.visit(node_parameter)
            return parameter_delta

        # TODO: check for KNOWN AFTER APPLY values for logical ids coming from intrinsic functions as arguments.
        node_resource = self._get_node_resource_for(
            resource_name=logica_id, node_template=self._node_template
        )
        resource_delta = self.visit(node_resource)
        before = resource_delta.before
        after = resource_delta.after
        return ResolvedEntityDelta(before=before, after=after)

    def _resolve_mapping(
        self, map_name: str, top_level_key: str, second_level_key
    ) -> ResolvedEntityDelta:
        # TODO: add support for nested intrinsic functions, and KNOWN AFTER APPLY logical ids.
        node_mapping: NodeMapping = self._get_node_mapping(map_name=map_name)
        top_level_value = node_mapping.bindings.bindings.get(top_level_key)
        if not isinstance(top_level_value, NodeObject):
            raise RuntimeError()
        second_level_value = top_level_value.bindings.get(second_level_key)
        mapping_value_delta = self.visit(second_level_value)
        return mapping_value_delta

    def _resolve_reference_binding(
        self, before_logical_id: str, after_logical_id: str
    ) -> ResolvedEntityDelta:
        before_delta = self._resolve_reference(logica_id=before_logical_id)
        after_delta = self._resolve_reference(logica_id=after_logical_id)
        return ResolvedEntityDelta(before=before_delta.before, after=after_delta.after)

    def visit(self, change_set_entity: ChangeSetEntity) -> ResolvedEntityDelta:
        delta = self._processed.get(change_set_entity.scope)
        if delta is not None:
            return delta
        delta = super().visit(change_set_entity=change_set_entity)
        self._processed[change_set_entity.scope] = delta
        return delta

    def visit_terminal_value_modified(
        self, terminal_value_modified: TerminalValueModified
    ) -> ResolvedEntityDelta:
        return ResolvedEntityDelta(
            before=terminal_value_modified.value,
            after=terminal_value_modified.modified_value,
        )

    def visit_terminal_value_created(
        self, terminal_value_created: TerminalValueCreated
    ) -> ResolvedEntityDelta:
        return ResolvedEntityDelta(after=terminal_value_created.value)

    def visit_terminal_value_removed(
        self, terminal_value_removed: TerminalValueRemoved
    ) -> ResolvedEntityDelta:
        return ResolvedEntityDelta(before=terminal_value_removed.value)

    def visit_terminal_value_unchanged(
        self, terminal_value_unchanged: TerminalValueUnchanged
    ) -> ResolvedEntityDelta:
        return ResolvedEntityDelta(
            before=terminal_value_unchanged.value,
            after=terminal_value_unchanged.value,
        )

    def visit_node_divergence(self, node_divergence: NodeDivergence) -> ResolvedEntityDelta:
        before_delta = self.visit(node_divergence.value)
        after_delta = self.visit(node_divergence.divergence)
        return ResolvedEntityDelta(before=before_delta.before, after=after_delta.after)

    def visit_node_object(self, node_object: NodeObject) -> ResolvedEntityDelta:
        # TODO: improve check syntax
        if len(node_object.bindings) == 1:
            binding_values = list(node_object.bindings.values())
            unique_value = binding_values[0]
            if isinstance(unique_value, NodeIntrinsicFunction):
                return self.visit(unique_value)

        before = dict()
        after = dict()
        for name, change_set_entity in node_object.bindings.items():
            delta: ResolvedEntityDelta = self.visit(change_set_entity=change_set_entity)
            match change_set_entity.change_type:
                case ChangeType.MODIFIED:
                    before[name] = delta.before
                    after[name] = delta.after
                case ChangeType.CREATED:
                    after[name] = delta.after
                case ChangeType.REMOVED:
                    before[name] = delta.before
                case ChangeType.UNCHANGED:
                    before[name] = delta.before
                    after[name] = delta.before
        return ResolvedEntityDelta(before=before, after=after)

    def visit_node_intrinsic_function_fn_get_att(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> ResolvedEntityDelta:
        arguments_delta = self.visit(node_intrinsic_function.arguments)
        # TODO: validate the return value according to the spec.
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
            # TODO: when are values only accessible at runtime?
            after_logical_name_of_resource = after_argument_list[0]
            after_attribute_name = after_argument_list[1]
            after_node_resource = self._get_node_resource_for(
                resource_name=after_logical_name_of_resource, node_template=self._node_template
            )
            after_node_property = self._get_node_property_for(
                property_name=after_attribute_name, node_resource=after_node_resource
            )
            after_property_delta = self.visit(after_node_property)
            after = after_property_delta.after

        return ResolvedEntityDelta(before=before, after=after)

    def visit_node_intrinsic_function_fn_equals(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> ResolvedEntityDelta:
        # TODO: check for KNOWN AFTER APPLY values for logical ids coming from intrinsic functions as arguments.
        arguments_delta = self.visit(node_intrinsic_function.arguments)
        before_values = arguments_delta.before
        after_values = arguments_delta.after
        before = None
        if before_values:
            before = before_values[0] == before_values[1]
        after = None
        if after_values:
            after = after_values[0] == after_values[1]
        match node_intrinsic_function.change_type:
            case ChangeType.MODIFIED:
                return ResolvedEntityDelta(before=before, after=after)
            case ChangeType.CREATED:
                return ResolvedEntityDelta(after=after)
            case ChangeType.REMOVED:
                return ResolvedEntityDelta(before=before)
        # Unchanged
        return ResolvedEntityDelta(before=before, after=after)

    def visit_node_intrinsic_function_fn_if(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> ResolvedEntityDelta:
        # TODO: check for KNOWN AFTER APPLY values for logical ids coming from intrinsic functions as arguments.
        arguments_delta = self.visit(node_intrinsic_function.arguments)

        def _compute_delta_for_if_statement(args: list[Any]) -> ResolvedEntityDelta:
            condition_name = args[0]
            boolean_expression_delta = self._resolve_reference(logica_id=condition_name)
            return ResolvedEntityDelta(
                before=args[1] if boolean_expression_delta.before else args[2],
                after=args[1] if boolean_expression_delta.after else args[2],
            )

        # TODO: add support for this being created or removed.
        before_outcome_delta = _compute_delta_for_if_statement(arguments_delta.before)
        before = before_outcome_delta.before
        after_outcome_delta = _compute_delta_for_if_statement(arguments_delta.after)
        after = after_outcome_delta.after
        return ResolvedEntityDelta(before=before, after=after)

    def visit_node_intrinsic_function_fn_not(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> ResolvedEntityDelta:
        # TODO: check for KNOWN AFTER APPLY values for logical ids coming from intrinsic functions as arguments.
        # TODO: add type checking/validation for result unit?
        arguments_delta = self.visit(node_intrinsic_function.arguments)
        before_condition = arguments_delta.before
        after_condition = arguments_delta.after
        if before_condition:
            before_condition_outcome = before_condition[0]
            before = not before_condition_outcome
        else:
            before = None

        if after_condition:
            after_condition_outcome = after_condition[0]
            after = not after_condition_outcome
        else:
            after = None
        # Implicit change type computation.
        return ResolvedEntityDelta(before=before, after=after)

    def visit_node_intrinsic_function_fn_find_in_map(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> ResolvedEntityDelta:
        # TODO: check for KNOWN AFTER APPLY values for logical ids coming from intrinsic functions as arguments.
        # TODO: add type checking/validation for result unit?
        arguments_delta = self.visit(node_intrinsic_function.arguments)
        before_arguments = arguments_delta.before
        after_arguments = arguments_delta.after
        if before_arguments:
            before_value_delta = self._resolve_mapping(*before_arguments)
            before = before_value_delta.before
        else:
            before = None
        if after_arguments:
            after_value_delta = self._resolve_mapping(*after_arguments)
            after = after_value_delta.after
        else:
            after = None
        return ResolvedEntityDelta(before=before, after=after)

    def visit_node_mapping(self, node_mapping: NodeMapping) -> ResolvedEntityDelta:
        bindings_delta = self.visit(node_mapping.bindings)
        return bindings_delta

    def visit_node_parameter(self, node_parameter: NodeParameter) -> ResolvedEntityDelta:
        # TODO: add support for default value sampling
        dynamic_value = node_parameter.dynamic_value
        delta = self.visit(dynamic_value)
        return delta

    def visit_node_condition(self, node_condition: NodeCondition) -> ResolvedEntityDelta:
        delta = self.visit(node_condition.body)
        return delta

    def _reduce_intrinsic_function_ref_value(self, resolved_value: Any) -> Any:
        if isinstance(resolved_value, ResolvedResource):
            value = resolved_value.logical_resource_id
        else:
            value = resolved_value
        return value

    def visit_node_intrinsic_function_ref(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> ResolvedEntityDelta:
        arguments_delta = self.visit(node_intrinsic_function.arguments)

        # TODO: add tests with created and deleted parameters and verify this logic holds.
        before_logical_id = arguments_delta.before
        before = None
        if before_logical_id is not None:
            before_delta = self._resolve_reference(logica_id=before_logical_id)
            before_value = before_delta.before
            before = self._reduce_intrinsic_function_ref_value(before_value)

        after_logical_id = arguments_delta.after
        after = None
        if after_logical_id is not None:
            after_delta = self._resolve_reference(logica_id=after_logical_id)
            after_value = after_delta.after
            after = self._reduce_intrinsic_function_ref_value(after_value)

        return ResolvedEntityDelta(before=before, after=after)

    def visit_node_array(self, node_array: NodeArray) -> ResolvedEntityDelta:
        before = list()
        after = list()
        for change_set_entity in node_array.array:
            delta: ResolvedEntityDelta = self.visit(change_set_entity=change_set_entity)
            match change_set_entity.change_type:
                case ChangeType.MODIFIED:
                    before.append(delta.before)
                    after.append(delta.after)
                case ChangeType.CREATED:
                    after.append(delta.after)
                case ChangeType.REMOVED:
                    before.append(delta.before)
                case ChangeType.UNCHANGED:
                    before.append(delta.before)
                    after.append(delta.before)
        return ResolvedEntityDelta(before=before, after=after)

    def visit_node_properties(
        self, node_properties: NodeProperties
    ) -> ResolvedEntityDelta[ResolvedProperties, ResolvedProperties]:
        before_bindings: dict[str, Any] = dict()
        after_bindings: dict[str, Any] = dict()
        for node_property in node_properties.properties:
            delta = self.visit(node_property.value)
            property_name = node_property.name
            if node_property.change_type != ChangeType.CREATED:
                before_bindings[property_name] = delta.before
            if node_property.change_type != ChangeType.REMOVED:
                after_bindings[property_name] = delta.after
        before = None
        if before_bindings:
            before = ResolvedProperties(Properties=before_bindings)
        after = None
        if after_bindings:
            after = ResolvedProperties(Properties=after_bindings)
        return ResolvedEntityDelta(before=before, after=after)

    def _resolve_resource_condition_reference(
        self, reference: TerminalValue
    ) -> ResolvedEntityDelta:
        reference_delta = self.visit(reference)
        before_reference = reference_delta.before
        after_reference = reference_delta.after
        condition_delta = self._resolve_reference_binding(
            before_logical_id=before_reference, after_logical_id=after_reference
        )
        before = condition_delta.before if not isinstance(before_reference, NothingType) else True
        after = condition_delta.after if not isinstance(after_reference, NothingType) else True
        return ResolvedEntityDelta(before=before, after=after)

    def visit_node_resource(
        self, node_resource: NodeResource
    ) -> ResolvedEntityDelta[ResolvedResource, ResolvedResource]:
        change_type = node_resource.change_type
        condition_before = None
        condition_after = None
        if node_resource.condition_reference is not None:
            condition_delta = self._resolve_resource_condition_reference(
                node_resource.condition_reference
            )
            condition_before = condition_delta.before
            condition_after = condition_delta.after
            if not condition_before and condition_after:
                change_type = ChangeType.CREATED
            elif condition_before and not condition_after:
                change_type = ChangeType.REMOVED

        logical_resource_id: str = node_resource.name
        type_delta = self.visit(node_resource.type_)
        properties_delta = self.visit(node_resource.properties)

        before = None
        after = None
        if change_type != ChangeType.CREATED:
            before = ResolvedResource(
                condition=condition_before,
                logical_resource_id=logical_resource_id,
                resource_type=type_delta.before,
                properties=properties_delta.before,
            )
        if change_type != ChangeType.REMOVED:
            after = ResolvedResource(
                condition=condition_after,
                logical_resource_id=logical_resource_id,
                resource_type=type_delta.after,
                properties=properties_delta.after,
            )
        return ResolvedEntityDelta(before=before, after=after)

    def visit_node_output(self, node_output: NodeOutput) -> ResolvedEntityDelta:
        # This logic is not required for Describe operations,
        # and should be ported a new base for this class type.
        change_type = node_output.change_type
        value_delta = self.visit(node_output.value)

        condition_delta = None
        if node_output.condition_reference is not None:
            condition_delta = self._resolve_resource_condition_reference(
                node_output.condition_reference
            )
            condition_before = condition_delta.before
            condition_after = condition_delta.after
            if not condition_before and condition_after:
                change_type = ChangeType.CREATED
            elif condition_before and not condition_after:
                change_type = ChangeType.REMOVED

        export_delta = None
        if node_output.export is not None:
            export_delta = self.visit(node_output.export)

        before = None
        after = None
        if change_type != ChangeType.REMOVED:
            after = {"Name": node_output.name, ValueKey: value_delta.after}
            if export_delta:
                after[ExportKey] = export_delta.after
            if condition_delta:
                after[ConditionKey] = condition_delta.after
        if change_type != ChangeType.CREATED:
            before = {"Name": node_output.name, ValueKey: value_delta.before}
            if export_delta:
                before[ExportKey] = export_delta.before
            if condition_delta:
                before[ConditionKey] = condition_delta.before
        return ResolvedEntityDelta(before=before, after=after)

    def visit_node_outputs(self, node_outputs: NodeOutputs) -> ResolvedEntityDelta:
        # This logic is not required for Describe operations,
        # and should be ported a new base for this class type.
        before = list()
        after = list()
        for node_output in node_outputs.outputs:
            output_delta = self.visit(node_output)
            output_before = output_delta.before
            output_after = output_delta.after
            if output_before:
                before.append(output_before)
            if output_after:
                after.append(output_after)
        return ResolvedEntityDelta(before=before, after=after)

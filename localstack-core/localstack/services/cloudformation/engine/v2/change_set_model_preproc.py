from __future__ import annotations

import re
from typing import Any, Final, Generic, Optional, TypeVar

from localstack.services.cloudformation.engine.transformers import (
    Transformer,
    execute_macro,
    transformers,
)
from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeSetEntity,
    ChangeType,
    Maybe,
    NodeArray,
    NodeCondition,
    NodeDependsOn,
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
    Nothing,
    Scope,
    TerminalValue,
    TerminalValueCreated,
    TerminalValueModified,
    TerminalValueRemoved,
    TerminalValueUnchanged,
    is_nothing,
)
from localstack.services.cloudformation.engine.v2.change_set_model_visitor import (
    ChangeSetModelVisitor,
)
from localstack.services.cloudformation.stores import get_cloudformation_store
from localstack.services.cloudformation.v2.entities import ChangeSet
from localstack.utils.aws.arns import get_partition
from localstack.utils.urls import localstack_host

_AWS_URL_SUFFIX = localstack_host().host  # The value in AWS is "amazonaws.com"

_PSEUDO_PARAMETERS: Final[set[str]] = {
    "AWS::Partition",
    "AWS::AccountId",
    "AWS::Region",
    "AWS::StackName",
    "AWS::StackId",
    "AWS::URLSuffix",
    "AWS::NoValue",
    "AWS::NotificationARNs",
}

TBefore = TypeVar("TBefore")
TAfter = TypeVar("TAfter")


class PreprocEntityDelta(Generic[TBefore, TAfter]):
    before: Maybe[TBefore]
    after: Maybe[TAfter]

    def __init__(self, before: Maybe[TBefore] = Nothing, after: Maybe[TAfter] = Nothing):
        self.before = before
        self.after = after

    def __eq__(self, other):
        if not isinstance(other, PreprocEntityDelta):
            return False
        return self.before == other.before and self.after == other.after


class PreprocProperties:
    properties: dict[str, Any]

    def __init__(self, properties: dict[str, Any]):
        self.properties = properties

    def __eq__(self, other):
        if not isinstance(other, PreprocProperties):
            return False
        return self.properties == other.properties


class PreprocResource:
    logical_id: str
    physical_resource_id: Optional[str]
    condition: Optional[bool]
    resource_type: str
    properties: PreprocProperties
    depends_on: Optional[list[str]]

    def __init__(
        self,
        logical_id: str,
        physical_resource_id: str,
        condition: Optional[bool],
        resource_type: str,
        properties: PreprocProperties,
        depends_on: Optional[list[str]],
    ):
        self.logical_id = logical_id
        self.physical_resource_id = physical_resource_id
        self.condition = condition
        self.resource_type = resource_type
        self.properties = properties
        self.depends_on = depends_on

    @staticmethod
    def _compare_conditions(c1: bool, c2: bool):
        # The lack of condition equates to a true condition.
        c1 = c1 if isinstance(c1, bool) else True
        c2 = c2 if isinstance(c2, bool) else True
        return c1 == c2

    def __eq__(self, other):
        if not isinstance(other, PreprocResource):
            return False
        return all(
            [
                self.logical_id == other.logical_id,
                self._compare_conditions(self.condition, other.condition),
                self.resource_type == other.resource_type,
                self.properties == other.properties,
            ]
        )


class PreprocOutput:
    name: str
    value: Any
    export: Optional[Any]
    condition: Optional[bool]

    def __init__(self, name: str, value: Any, export: Optional[Any], condition: Optional[bool]):
        self.name = name
        self.value = value
        self.export = export
        self.condition = condition

    def __eq__(self, other):
        if not isinstance(other, PreprocOutput):
            return False
        return all(
            [
                self.name == other.name,
                self.value == other.value,
                self.export == other.export,
                self.condition == other.condition,
            ]
        )


class ChangeSetModelPreproc(ChangeSetModelVisitor):
    _change_set: Final[ChangeSet]
    _node_template: Final[NodeTemplate]
    _before_resolved_resources: Final[dict]
    _processed: dict[Scope, Any]

    def __init__(self, change_set: ChangeSet):
        self._change_set = change_set
        self._node_template = change_set.update_graph
        self._before_resolved_resources = change_set.stack.resolved_resources
        self._processed = dict()

    def process(self) -> None:
        self._processed.clear()
        self.visit(self._node_template)

    def _get_node_resource_for(
        self, resource_name: str, node_template: NodeTemplate
    ) -> NodeResource:
        # TODO: this could be improved with hashmap lookups if the Node contained bindings and not lists.
        for node_resource in node_template.resources.resources:
            if node_resource.name == resource_name:
                self.visit(node_resource)
                return node_resource
        raise RuntimeError(f"No resource '{resource_name}' was found")

    def _get_node_property_for(
        self, property_name: str, node_resource: NodeResource
    ) -> Optional[NodeProperty]:
        # TODO: this could be improved with hashmap lookups if the Node contained bindings and not lists.
        for node_property in node_resource.properties.properties:
            if node_property.name == property_name:
                self.visit(node_property)
                return node_property
        return None

    def _deployed_property_value_of(
        self, resource_logical_id: str, property_name: str, resolved_resources: dict
    ) -> Any:
        # TODO: typing around resolved resources is needed and should be reflected here.

        # Before we can obtain deployed value for a resource, we need to first ensure to
        # process the resource if this wasn't processed already. Ideally, values should only
        # be accessible through delta objects, to ensure computation is always complete at
        # every level.
        _ = self._get_node_resource_for(
            resource_name=resource_logical_id, node_template=self._node_template
        )
        resolved_resource = resolved_resources.get(resource_logical_id)
        if resolved_resource is None:
            raise RuntimeError(
                f"No deployed instances of resource '{resource_logical_id}' were found"
            )
        properties = resolved_resource.get("Properties", dict())
        property_value: Optional[Any] = properties.get(property_name)
        if property_value is None:
            raise RuntimeError(
                f"No '{property_name}' found for deployed resource '{resource_logical_id}' was found"
            )
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
    ) -> Optional[str]:
        return self._before_deployed_property_value_of(
            resource_logical_id=resource_logical_id, property_name=property_name
        )

    def _get_node_mapping(self, map_name: str) -> NodeMapping:
        mappings: list[NodeMapping] = self._node_template.mappings.mappings
        # TODO: another scenarios suggesting property lookups might be preferable.
        for mapping in mappings:
            if mapping.name == map_name:
                self.visit(mapping)
                return mapping
        raise RuntimeError(f"Undefined '{map_name}' mapping")

    def _get_node_parameter_if_exists(self, parameter_name: str) -> Maybe[NodeParameter]:
        parameters: list[NodeParameter] = self._node_template.parameters.parameters
        # TODO: another scenarios suggesting property lookups might be preferable.
        for parameter in parameters:
            if parameter.name == parameter_name:
                self.visit(parameter)
                return parameter
        return Nothing

    def _get_node_condition_if_exists(self, condition_name: str) -> Maybe[NodeCondition]:
        conditions: list[NodeCondition] = self._node_template.conditions.conditions
        # TODO: another scenarios suggesting property lookups might be preferable.
        for condition in conditions:
            if condition.name == condition_name:
                self.visit(condition)
                return condition
        return Nothing

    def _resolve_condition(self, logical_id: str) -> PreprocEntityDelta:
        node_condition = self._get_node_condition_if_exists(condition_name=logical_id)
        if isinstance(node_condition, NodeCondition):
            condition_delta = self.visit(node_condition)
            return condition_delta
        raise RuntimeError(f"No condition '{logical_id}' was found.")

    def _resolve_pseudo_parameter(self, pseudo_parameter_name: str) -> Any:
        match pseudo_parameter_name:
            case "AWS::Partition":
                return get_partition(self._change_set.region_name)
            case "AWS::AccountId":
                return self._change_set.stack.account_id
            case "AWS::Region":
                return self._change_set.stack.region_name
            case "AWS::StackName":
                return self._change_set.stack.stack_name
            case "AWS::StackId":
                return self._change_set.stack.stack_id
            case "AWS::URLSuffix":
                return _AWS_URL_SUFFIX
            case "AWS::NoValue":
                return None
            case _:
                raise RuntimeError(f"The use of '{pseudo_parameter_name}' is currently unsupported")

    def _resolve_reference(self, logical_id: str) -> PreprocEntityDelta:
        if logical_id in _PSEUDO_PARAMETERS:
            pseudo_parameter_value = self._resolve_pseudo_parameter(
                pseudo_parameter_name=logical_id
            )
            # Pseudo parameters are constants within the lifecycle of a template.
            return PreprocEntityDelta(before=pseudo_parameter_value, after=pseudo_parameter_value)

        node_parameter = self._get_node_parameter_if_exists(parameter_name=logical_id)
        if isinstance(node_parameter, NodeParameter):
            parameter_delta = self.visit(node_parameter)
            return parameter_delta

        node_resource = self._get_node_resource_for(
            resource_name=logical_id, node_template=self._node_template
        )
        resource_delta = self.visit(node_resource)
        before = resource_delta.before
        after = resource_delta.after
        return PreprocEntityDelta(before=before, after=after)

    def _resolve_mapping(
        self, map_name: str, top_level_key: str, second_level_key
    ) -> PreprocEntityDelta:
        # TODO: add support for nested intrinsic functions, and KNOWN AFTER APPLY logical ids.
        node_mapping: NodeMapping = self._get_node_mapping(map_name=map_name)
        top_level_value = node_mapping.bindings.bindings.get(top_level_key)
        if not isinstance(top_level_value, NodeObject):
            raise RuntimeError()
        second_level_value = top_level_value.bindings.get(second_level_key)
        mapping_value_delta = self.visit(second_level_value)
        return mapping_value_delta

    def visit(self, change_set_entity: ChangeSetEntity) -> PreprocEntityDelta:
        scope = change_set_entity.scope
        if scope in self._processed:
            delta = self._processed[scope]
            return delta
        delta = super().visit(change_set_entity=change_set_entity)
        self._processed[scope] = delta
        return delta

    def visit_terminal_value_modified(
        self, terminal_value_modified: TerminalValueModified
    ) -> PreprocEntityDelta:
        return PreprocEntityDelta(
            before=terminal_value_modified.value,
            after=terminal_value_modified.modified_value,
        )

    def visit_terminal_value_created(
        self, terminal_value_created: TerminalValueCreated
    ) -> PreprocEntityDelta:
        return PreprocEntityDelta(after=terminal_value_created.value)

    def visit_terminal_value_removed(
        self, terminal_value_removed: TerminalValueRemoved
    ) -> PreprocEntityDelta:
        return PreprocEntityDelta(before=terminal_value_removed.value)

    def visit_terminal_value_unchanged(
        self, terminal_value_unchanged: TerminalValueUnchanged
    ) -> PreprocEntityDelta:
        return PreprocEntityDelta(
            before=terminal_value_unchanged.value,
            after=terminal_value_unchanged.value,
        )

    def visit_node_divergence(self, node_divergence: NodeDivergence) -> PreprocEntityDelta:
        before_delta = self.visit(node_divergence.value)
        after_delta = self.visit(node_divergence.divergence)
        return PreprocEntityDelta(before=before_delta.before, after=after_delta.after)

    def visit_node_object(self, node_object: NodeObject) -> PreprocEntityDelta:
        node_change_type = node_object.change_type
        before = dict() if node_change_type != ChangeType.CREATED else Nothing
        after = dict() if node_change_type != ChangeType.REMOVED else Nothing
        for name, change_set_entity in node_object.bindings.items():
            delta: PreprocEntityDelta = self.visit(change_set_entity=change_set_entity)
            delta_before = delta.before
            delta_after = delta.after
            if not is_nothing(before) and not is_nothing(delta_before) and delta_before is not None:
                before[name] = delta_before
            if not is_nothing(after) and not is_nothing(delta_after) and delta_after is not None:
                after[name] = delta_after
        return PreprocEntityDelta(before=before, after=after)

    def visit_node_intrinsic_function_fn_get_att(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        # TODO: validate the return value according to the spec.
        arguments_delta = self.visit(node_intrinsic_function.arguments)
        before_argument: Maybe[list[str]] = arguments_delta.before
        if isinstance(before_argument, str):
            before_argument = before_argument.split(".")
        after_argument: Maybe[list[str]] = arguments_delta.after
        if isinstance(after_argument, str):
            after_argument = after_argument.split(".")

        before = Nothing
        if before_argument:
            before_logical_name_of_resource = before_argument[0]
            before_attribute_name = before_argument[1]

            before_node_resource = self._get_node_resource_for(
                resource_name=before_logical_name_of_resource, node_template=self._node_template
            )
            before_node_property: Optional[NodeProperty] = self._get_node_property_for(
                property_name=before_attribute_name, node_resource=before_node_resource
            )
            if before_node_property is not None:
                # The property is statically defined in the template and its value can be computed.
                before_property_delta = self.visit(before_node_property)
                before = before_property_delta.before
            else:
                # The property is not statically defined and must therefore be available in
                # the properties deployed set.
                before = self._before_deployed_property_value_of(
                    resource_logical_id=before_logical_name_of_resource,
                    property_name=before_attribute_name,
                )

        after = Nothing
        if after_argument:
            after_logical_name_of_resource = after_argument[0]
            after_attribute_name = after_argument[1]
            after_node_resource = self._get_node_resource_for(
                resource_name=after_logical_name_of_resource, node_template=self._node_template
            )
            after_node_property = self._get_node_property_for(
                property_name=after_attribute_name, node_resource=after_node_resource
            )
            if after_node_property is not None:
                # The property is statically defined in the template and its value can be computed.
                after_property_delta = self.visit(after_node_property)
                after = after_property_delta.after
            else:
                # The property is not statically defined and must therefore be available in
                # the properties deployed set.
                after = self._after_deployed_property_value_of(
                    resource_logical_id=after_logical_name_of_resource,
                    property_name=after_attribute_name,
                )

        return PreprocEntityDelta(before=before, after=after)

    def visit_node_intrinsic_function_fn_equals(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        arguments_delta = self.visit(node_intrinsic_function.arguments)
        before_values = arguments_delta.before
        after_values = arguments_delta.after
        before = Nothing
        if before_values:
            before = before_values[0] == before_values[1]
        after = Nothing
        if after_values:
            after = after_values[0] == after_values[1]
        return PreprocEntityDelta(before=before, after=after)

    def visit_node_intrinsic_function_fn_if(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        arguments_delta = self.visit(node_intrinsic_function.arguments)
        arguments_before = arguments_delta.before
        arguments_after = arguments_delta.after

        def _compute_delta_for_if_statement(args: list[Any]) -> PreprocEntityDelta:
            condition_name = args[0]
            boolean_expression_delta = self._resolve_condition(logical_id=condition_name)
            return PreprocEntityDelta(
                before=args[1] if boolean_expression_delta.before else args[2],
                after=args[1] if boolean_expression_delta.after else args[2],
            )

        # TODO: add support for this being created or removed.
        before = Nothing
        if not is_nothing(arguments_before):
            before_outcome_delta = _compute_delta_for_if_statement(arguments_before)
            before = before_outcome_delta.before
        after = Nothing
        if not is_nothing(arguments_after):
            after_outcome_delta = _compute_delta_for_if_statement(arguments_after)
            after = after_outcome_delta.after
        return PreprocEntityDelta(before=before, after=after)

    def visit_node_intrinsic_function_fn_not(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        arguments_delta = self.visit(node_intrinsic_function.arguments)
        before_condition = arguments_delta.before
        after_condition = arguments_delta.after
        before = Nothing
        if not is_nothing(before_condition):
            before_condition_outcome = before_condition[0]
            before = not before_condition_outcome
        after = Nothing
        if not is_nothing(after_condition):
            after_condition_outcome = after_condition[0]
            after = not after_condition_outcome
        # Implicit change type computation.
        return PreprocEntityDelta(before=before, after=after)

    def _compute_fn_transform(self, args: dict[str, Any]) -> Any:
        # TODO: add typing to arguments before this level.
        # TODO: add schema validation
        # TODO: add support for other transform types

        account_id = self._change_set.account_id
        region_name = self._change_set.region_name
        transform_name: str = args.get("Name")
        if not isinstance(transform_name, str):
            raise RuntimeError("Invalid or missing Fn::Transform 'Name' argument")
        transform_parameters: dict = args.get("Parameters")
        if not isinstance(transform_parameters, dict):
            raise RuntimeError("Invalid or missing Fn::Transform 'Parameters' argument")

        if transform_name in transformers:
            # TODO: port and refactor this 'transformers' logic to this package.
            builtin_transformer_class = transformers[transform_name]
            builtin_transformer: Transformer = builtin_transformer_class()
            transform_output: Any = builtin_transformer.transform(
                account_id=account_id, region_name=region_name, parameters=transform_parameters
            )
            return transform_output

        macros_store = get_cloudformation_store(
            account_id=account_id, region_name=region_name
        ).macros
        if transform_name in macros_store:
            # TODO: this formatting of stack parameters is odd but required to integrate with v1 execute_macro util.
            #  consider porting this utils and passing the plain list of parameters instead.
            stack_parameters = {
                parameter["ParameterKey"]: parameter
                for parameter in self._change_set.stack.parameters
            }
            transform_output: Any = execute_macro(
                account_id=account_id,
                region_name=region_name,
                parsed_template=dict(),  # TODO: review the requirements for this argument.
                macro=args,  # TODO: review support for non dict bindings (v1).
                stack_parameters=stack_parameters,
                transformation_parameters=transform_parameters,
                is_intrinsic=True,
            )
            return transform_output

        raise RuntimeError(
            f"Unsupported transform function '{transform_name}' in '{self._change_set.stack.stack_name}'"
        )

    def visit_node_intrinsic_function_fn_transform(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        arguments_delta = self.visit(node_intrinsic_function.arguments)
        arguments_before = arguments_delta.before
        arguments_after = arguments_delta.after

        # TODO: review the use of cache in self.precessed from the 'before' run to
        #  ensure changes to the lambda (such as after UpdateFunctionCode) do not
        #  generalise tot he before value at this depth (thus making it seems as
        #  though for this transformation before==after). Another options may be to
        #  have specialised caching for transformations.

        # TODO: add tests to review the behaviour of CFN with changes to transformation
        #  function code and no changes to the template.

        before = Nothing
        if not is_nothing(arguments_before):
            before = self._compute_fn_transform(args=arguments_before)
        after = Nothing
        if not is_nothing(arguments_after):
            after = self._compute_fn_transform(args=arguments_after)
        return PreprocEntityDelta(before=before, after=after)

    def visit_node_intrinsic_function_fn_sub(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        arguments_delta = self.visit(node_intrinsic_function.arguments)
        arguments_before = arguments_delta.before
        arguments_after = arguments_delta.after

        def _compute_sub(args: str | list[Any], select_before: bool = False) -> str:
            # TODO: add further schema validation.
            string_template: str
            sub_parameters: dict
            if isinstance(args, str):
                string_template = args
                sub_parameters = dict()
            elif (
                isinstance(args, list)
                and len(args) == 2
                and isinstance(args[0], str)
                and isinstance(args[1], dict)
            ):
                string_template = args[0]
                sub_parameters = args[1]
            else:
                raise RuntimeError(
                    "Invalid arguments shape for Fn::Sub, expected a String "
                    f"or a Tuple of String and Map but got '{args}'"
                )
            sub_string = string_template
            template_variable_names = re.findall("\\${([^}]+)}", string_template)
            for template_variable_name in template_variable_names:
                if template_variable_name in _PSEUDO_PARAMETERS:
                    template_variable_value = self._resolve_pseudo_parameter(
                        pseudo_parameter_name=template_variable_name
                    )
                elif template_variable_name in sub_parameters:
                    template_variable_value = sub_parameters[template_variable_name]
                else:
                    try:
                        resource_delta = self._resolve_reference(logical_id=template_variable_name)
                        template_variable_value = (
                            resource_delta.before if select_before else resource_delta.after
                        )
                        if isinstance(template_variable_value, PreprocResource):
                            template_variable_value = template_variable_value.logical_id
                    except RuntimeError:
                        raise RuntimeError(
                            f"Undefined variable name in Fn::Sub string template '{template_variable_name}'"
                        )
                sub_string = sub_string.replace(
                    f"${{{template_variable_name}}}", template_variable_value
                )
            return sub_string

        before = Nothing
        if not is_nothing(arguments_before):
            before = _compute_sub(args=arguments_before, select_before=True)
        after = Nothing
        if not is_nothing(arguments_after):
            after = _compute_sub(args=arguments_after)
        return PreprocEntityDelta(before=before, after=after)

    def visit_node_intrinsic_function_fn_join(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        arguments_delta = self.visit(node_intrinsic_function.arguments)
        arguments_before = arguments_delta.before
        arguments_after = arguments_delta.after

        def _compute_join(args: list[Any]) -> str:
            # TODO: add support for schema validation.
            # TODO: add tests for joining non string values.
            delimiter: str = str(args[0])
            values: list[Any] = args[1]
            if not isinstance(values, list):
                raise RuntimeError(f"Invalid arguments list definition for Fn::Join: '{args}'")
            join_result = delimiter.join(map(str, values))
            return join_result

        before = Nothing
        if isinstance(arguments_before, list) and len(arguments_before) == 2:
            before = _compute_join(arguments_before)
        after = Nothing
        if isinstance(arguments_after, list) and len(arguments_after) == 2:
            after = _compute_join(arguments_after)
        return PreprocEntityDelta(before=before, after=after)

    def visit_node_intrinsic_function_fn_select(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ):
        # TODO: add further support for schema validation
        arguments_delta = self.visit(node_intrinsic_function.arguments)
        arguments_before = arguments_delta.before
        arguments_after = arguments_delta.after

        def _compute_fn_select(args: list[Any]) -> Any:
            values: list[Any] = args[1]
            if not isinstance(values, list) or not values:
                raise RuntimeError(f"Invalid arguments list value for Fn::Select: '{values}'")
            values_len = len(values)
            index: int = int(args[0])
            if not isinstance(index, int) or index < 0 or index > values_len:
                raise RuntimeError(f"Invalid or out of range index value for Fn::Select: '{index}'")
            selection = values[index]
            return selection

        before = Nothing
        if not is_nothing(arguments_before):
            before = _compute_fn_select(arguments_before)

        after = Nothing
        if not is_nothing(arguments_after):
            after = _compute_fn_select(arguments_after)

        return PreprocEntityDelta(before=before, after=after)

    def visit_node_intrinsic_function_fn_find_in_map(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        # TODO: add type checking/validation for result unit?
        arguments_delta = self.visit(node_intrinsic_function.arguments)
        before_arguments = arguments_delta.before
        after_arguments = arguments_delta.after
        before = Nothing
        if before_arguments:
            before_value_delta = self._resolve_mapping(*before_arguments)
            before = before_value_delta.before
        after = Nothing
        if after_arguments:
            after_value_delta = self._resolve_mapping(*after_arguments)
            after = after_value_delta.after
        return PreprocEntityDelta(before=before, after=after)

    def visit_node_mapping(self, node_mapping: NodeMapping) -> PreprocEntityDelta:
        bindings_delta = self.visit(node_mapping.bindings)
        return bindings_delta

    def visit_node_parameter(self, node_parameter: NodeParameter) -> PreprocEntityDelta:
        dynamic_value = node_parameter.dynamic_value
        dynamic_delta = self.visit(dynamic_value)

        default_value = node_parameter.default_value
        default_delta = self.visit(default_value)

        before = dynamic_delta.before or default_delta.before
        after = dynamic_delta.after or default_delta.after

        return PreprocEntityDelta(before=before, after=after)

    def visit_node_depends_on(self, node_depends_on: NodeDependsOn) -> PreprocEntityDelta:
        array_identifiers_delta = self.visit(node_depends_on.depends_on)
        return array_identifiers_delta

    def visit_node_condition(self, node_condition: NodeCondition) -> PreprocEntityDelta:
        delta = self.visit(node_condition.body)
        return delta

    def _resource_physical_resource_id_from(
        self, logical_resource_id: str, resolved_resources: dict
    ) -> str:
        # TODO: typing around resolved resources is needed and should be reflected here.
        resolved_resource = resolved_resources.get(logical_resource_id, dict())
        physical_resource_id: Optional[str] = resolved_resource.get("PhysicalResourceId")
        if not isinstance(physical_resource_id, str):
            raise RuntimeError(f"No PhysicalResourceId found for resource '{logical_resource_id}'")
        return physical_resource_id

    def _before_resource_physical_id(self, resource_logical_id: str) -> str:
        # TODO: typing around resolved resources is needed and should be reflected here.
        return self._resource_physical_resource_id_from(
            logical_resource_id=resource_logical_id,
            resolved_resources=self._before_resolved_resources,
        )

    def _after_resource_physical_id(self, resource_logical_id: str) -> str:
        return self._before_resource_physical_id(resource_logical_id=resource_logical_id)

    def visit_node_intrinsic_function_ref(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        arguments_delta = self.visit(node_intrinsic_function.arguments)
        before_logical_id = arguments_delta.before
        after_logical_id = arguments_delta.after

        # TODO: extend this to support references to other types.
        before = Nothing
        if not is_nothing(before_logical_id):
            before_delta = self._resolve_reference(logical_id=before_logical_id)
            before = before_delta.before
            if isinstance(before, PreprocResource):
                before = before.physical_resource_id

        after = Nothing
        if not is_nothing(after_logical_id):
            after_delta = self._resolve_reference(logical_id=after_logical_id)
            after = after_delta.after
            if isinstance(after, PreprocResource):
                after = after.physical_resource_id

        return PreprocEntityDelta(before=before, after=after)

    def visit_node_array(self, node_array: NodeArray) -> PreprocEntityDelta:
        node_change_type = node_array.change_type
        before = list() if node_change_type != ChangeType.CREATED else Nothing
        after = list() if node_change_type != ChangeType.REMOVED else Nothing
        for change_set_entity in node_array.array:
            delta: PreprocEntityDelta = self.visit(change_set_entity=change_set_entity)
            delta_before = delta.before
            delta_after = delta.after
            if not is_nothing(before) and not is_nothing(delta_before):
                before.append(delta_before)
            if not is_nothing(after) and not is_nothing(delta_after):
                after.append(delta_after)
        return PreprocEntityDelta(before=before, after=after)

    def visit_node_property(self, node_property: NodeProperty) -> PreprocEntityDelta:
        return self.visit(node_property.value)

    def visit_node_properties(
        self, node_properties: NodeProperties
    ) -> PreprocEntityDelta[PreprocProperties, PreprocProperties]:
        node_change_type = node_properties.change_type
        before_bindings = dict() if node_change_type != ChangeType.CREATED else Nothing
        after_bindings = dict() if node_change_type != ChangeType.REMOVED else Nothing
        for node_property in node_properties.properties:
            property_name = node_property.name
            delta = self.visit(node_property)
            delta_before = delta.before
            delta_after = delta.after
            if (
                not is_nothing(before_bindings)
                and not is_nothing(delta_before)
                and delta_before is not None
            ):
                before_bindings[property_name] = delta_before
            if (
                not is_nothing(after_bindings)
                and not is_nothing(delta_after)
                and delta_after is not None
            ):
                after_bindings[property_name] = delta_after
        before = Nothing
        if not is_nothing(before_bindings):
            before = PreprocProperties(properties=before_bindings)
        after = Nothing
        if not is_nothing(after_bindings):
            after = PreprocProperties(properties=after_bindings)
        return PreprocEntityDelta(before=before, after=after)

    def _resolve_resource_condition_reference(self, reference: TerminalValue) -> PreprocEntityDelta:
        reference_delta = self.visit(reference)
        before_reference = reference_delta.before
        before = Nothing
        if isinstance(before_reference, str):
            before_delta = self._resolve_condition(logical_id=before_reference)
            before = before_delta.before
        after = Nothing
        after_reference = reference_delta.after
        if isinstance(after_reference, str):
            after_delta = self._resolve_condition(logical_id=after_reference)
            after = after_delta.after
        return PreprocEntityDelta(before=before, after=after)

    def visit_node_resource(
        self, node_resource: NodeResource
    ) -> PreprocEntityDelta[PreprocResource, PreprocResource]:
        change_type = node_resource.change_type
        condition_before = Nothing
        condition_after = Nothing
        if not is_nothing(node_resource.condition_reference):
            condition_delta = self._resolve_resource_condition_reference(
                node_resource.condition_reference
            )
            condition_before = condition_delta.before
            condition_after = condition_delta.after

        depends_on_before = Nothing
        depends_on_after = Nothing
        if not is_nothing(node_resource.depends_on):
            depends_on_delta = self.visit(node_resource.depends_on)
            depends_on_before = depends_on_delta.before
            depends_on_after = depends_on_delta.after

        type_delta = self.visit(node_resource.type_)
        properties_delta: PreprocEntityDelta[PreprocProperties, PreprocProperties] = self.visit(
            node_resource.properties
        )

        before = Nothing
        after = Nothing
        if change_type != ChangeType.CREATED and is_nothing(condition_before) or condition_before:
            logical_resource_id = node_resource.name
            before_physical_resource_id = self._before_resource_physical_id(
                resource_logical_id=logical_resource_id
            )
            before = PreprocResource(
                logical_id=logical_resource_id,
                physical_resource_id=before_physical_resource_id,
                condition=condition_before,
                resource_type=type_delta.before,
                properties=properties_delta.before,
                depends_on=depends_on_before,
            )
        if change_type != ChangeType.REMOVED and is_nothing(condition_after) or condition_after:
            logical_resource_id = node_resource.name
            try:
                after_physical_resource_id = self._after_resource_physical_id(
                    resource_logical_id=logical_resource_id
                )
            except RuntimeError:
                after_physical_resource_id = None
            after = PreprocResource(
                logical_id=logical_resource_id,
                physical_resource_id=after_physical_resource_id,
                condition=condition_after,
                resource_type=type_delta.after,
                properties=properties_delta.after,
                depends_on=depends_on_after,
            )
        return PreprocEntityDelta(before=before, after=after)

    def visit_node_output(
        self, node_output: NodeOutput
    ) -> PreprocEntityDelta[PreprocOutput, PreprocOutput]:
        change_type = node_output.change_type
        value_delta = self.visit(node_output.value)

        condition_delta = Nothing
        if not is_nothing(node_output.condition_reference):
            condition_delta = self._resolve_resource_condition_reference(
                node_output.condition_reference
            )
            condition_before = condition_delta.before
            condition_after = condition_delta.after
            if not condition_before and condition_after:
                change_type = ChangeType.CREATED
            elif condition_before and not condition_after:
                change_type = ChangeType.REMOVED

        export_delta = Nothing
        if not is_nothing(node_output.export):
            export_delta = self.visit(node_output.export)

        before: Maybe[PreprocOutput] = Nothing
        if change_type != ChangeType.CREATED:
            before = PreprocOutput(
                name=node_output.name,
                value=value_delta.before,
                export=export_delta.before if export_delta else None,
                condition=condition_delta.before if condition_delta else None,
            )
        after: Maybe[PreprocOutput] = Nothing
        if change_type != ChangeType.REMOVED:
            after = PreprocOutput(
                name=node_output.name,
                value=value_delta.after,
                export=export_delta.after if export_delta else None,
                condition=condition_delta.after if condition_delta else None,
            )
        return PreprocEntityDelta(before=before, after=after)

    def visit_node_outputs(
        self, node_outputs: NodeOutputs
    ) -> PreprocEntityDelta[list[PreprocOutput], list[PreprocOutput]]:
        before: list[PreprocOutput] = list()
        after: list[PreprocOutput] = list()
        for node_output in node_outputs.outputs:
            output_delta: PreprocEntityDelta[PreprocOutput, PreprocOutput] = self.visit(node_output)
            output_before = output_delta.before
            output_after = output_delta.after
            if not is_nothing(output_before):
                before.append(output_before)
            if not is_nothing(output_after):
                after.append(output_after)
        return PreprocEntityDelta(before=before, after=after)

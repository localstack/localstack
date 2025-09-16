from __future__ import annotations

import abc
import enum
from collections.abc import Generator
from itertools import zip_longest
from typing import Any, Final, TypedDict, cast

from typing_extensions import TypeVar

from localstack.aws.api.cloudformation import ChangeAction
from localstack.services.cloudformation.resource_provider import ResourceProviderExecutor
from localstack.services.cloudformation.v2.types import (
    EngineParameter,
    engine_parameter_value,
)
from localstack.utils.json import extract_jsonpath
from localstack.utils.strings import camel_to_snake_case

T = TypeVar("T")


class NothingType:
    """A sentinel that denotes 'no value' (distinct from None)."""

    _singleton = None
    __slots__ = ()

    def __new__(cls):
        if cls._singleton is None:
            cls._singleton = super().__new__(cls)
        return cls._singleton

    def __eq__(self, other):
        return is_nothing(other)

    def __str__(self):
        return repr(self)

    def __repr__(self) -> str:
        return "Nothing"

    def __bool__(self):
        return False

    def __iter__(self):
        return iter(())

    def __contains__(self, item):
        return False


Maybe = T | NothingType
Nothing = NothingType()


def is_nothing(value: Any) -> bool:
    return isinstance(value, NothingType)


def is_created(before: Maybe[Any], after: Maybe[Any]) -> bool:
    return is_nothing(before) and not is_nothing(after)


def is_removed(before: Maybe[Any], after: Maybe[Any]) -> bool:
    return not is_nothing(before) and is_nothing(after)


def parent_change_type_of(children: list[Maybe[ChangeSetEntity]]):
    change_types = [c.change_type for c in children if not is_nothing(c)]
    if not change_types:
        return ChangeType.UNCHANGED
    # TODO: rework this logic. Currently if any values are different then we consider it
    #  modified, but e.g. if everything is unchanged or created, the result should probably be
    #  "created"
    first_type = change_types[0]
    if all(ct == first_type for ct in change_types):
        return first_type
    return ChangeType.MODIFIED


def change_type_of(before: Maybe[Any], after: Maybe[Any], children: list[Maybe[ChangeSetEntity]]):
    if is_created(before, after):
        change_type = ChangeType.CREATED
    elif is_removed(before, after):
        change_type = ChangeType.REMOVED
    else:
        change_type = parent_change_type_of(children)
    return change_type


class NormalisedGlobalTransformDefinition(TypedDict):
    Name: Any
    Parameters: Maybe[Any]


class Scope(str):
    _ROOT_SCOPE: Final[str] = ""
    _SEPARATOR: Final[str] = "/"

    def __new__(cls, scope: str = _ROOT_SCOPE) -> Scope:
        return cast(Scope, super().__new__(cls, scope))

    def open_scope(self, name: Scope | str) -> Scope:
        return Scope(self._SEPARATOR.join([self, name]))

    def open_index(self, index: int) -> Scope:
        return Scope(self._SEPARATOR.join([self, str(index)]))

    def unwrap(self) -> list[str]:
        return self.split(self._SEPARATOR)

    @property
    def parent(self) -> Scope:
        return Scope(self._SEPARATOR.join(self.split(self._SEPARATOR)[:-1]))

    @property
    def jsonpath(self) -> str:
        parts = self.split("/")
        json_parts = []

        for part in parts:
            if not part:  # Skip empty strings from leading/trailing slashes
                continue

            if part == "divergence":
                continue

            # Wrap keys with special characters (e.g., colon) in quotes
            if ":" in part:
                json_parts.append(f'"{part}"')
            else:
                json_parts.append(part)

        return f"$.{'.'.join(json_parts)}"


class ChangeType(enum.Enum):
    UNCHANGED = "Unchanged"
    CREATED = "Created"
    MODIFIED = "Modified"
    REMOVED = "Removed"

    def __str__(self):
        return self.value

    def to_change_action(self) -> ChangeAction:
        # Convert this change type into the change action used throughout the CFn API
        return {
            ChangeType.CREATED: ChangeAction.Add,
            ChangeType.MODIFIED: ChangeAction.Modify,
            ChangeType.REMOVED: ChangeAction.Remove,
        }.get(self, ChangeAction.Add)


class ChangeSetEntity(abc.ABC):
    scope: Final[Scope]
    change_type: ChangeType

    def __init__(self, scope: Scope, change_type: ChangeType):
        self.scope = scope
        self.change_type = change_type

    def get_children(self) -> Generator[ChangeSetEntity]:
        for child in self.__dict__.values():
            yield from self._get_children_in(child)

    @staticmethod
    def _get_children_in(obj: Any) -> Generator[ChangeSetEntity]:
        # TODO: could avoid the inductive logic here, and check for loops?
        if isinstance(obj, ChangeSetEntity):
            yield obj
        elif isinstance(obj, list):
            for item in obj:
                yield from ChangeSetEntity._get_children_in(item)
        elif isinstance(obj, dict):
            for item in obj.values():
                yield from ChangeSetEntity._get_children_in(item)

    def __str__(self):
        return f"({self.__class__.__name__}| {vars(self)}"

    def __repr__(self):
        return str(self)


class ChangeSetNode(ChangeSetEntity, abc.ABC): ...


class ChangeSetTerminal(ChangeSetEntity, abc.ABC): ...


class UpdateModel:
    # TODO: may be expanded to keep track of other runtime values such as resolved_parameters.

    node_template: Final[NodeTemplate]
    before_runtime_cache: Final[dict]
    after_runtime_cache: Final[dict]

    def __init__(
        self,
        node_template: NodeTemplate,
    ):
        self.node_template = node_template
        self.before_runtime_cache = {}
        self.after_runtime_cache = {}


class NodeTemplate(ChangeSetNode):
    transform: Final[NodeTransform]
    mappings: Final[NodeMappings]
    parameters: Final[NodeParameters]
    conditions: Final[NodeConditions]
    resources: Final[NodeResources]
    outputs: Final[NodeOutputs]

    def __init__(
        self,
        scope: Scope,
        transform: NodeTransform,
        mappings: NodeMappings,
        parameters: NodeParameters,
        conditions: NodeConditions,
        resources: NodeResources,
        outputs: NodeOutputs,
    ):
        change_type = parent_change_type_of(
            [transform, mappings, parameters, conditions, resources, outputs]
        )
        super().__init__(scope=scope, change_type=change_type)
        self.transform = transform
        self.mappings = mappings
        self.parameters = parameters
        self.conditions = conditions
        self.resources = resources
        self.outputs = outputs


class NodeDivergence(ChangeSetNode):
    value: Final[ChangeSetEntity]
    divergence: Final[ChangeSetEntity]

    def __init__(self, scope: Scope, value: ChangeSetEntity, divergence: ChangeSetEntity):
        super().__init__(scope=scope, change_type=ChangeType.MODIFIED)
        self.value = value
        self.divergence = divergence


class NodeParameter(ChangeSetNode):
    name: Final[str]
    type_: Final[ChangeSetEntity]
    dynamic_value: Final[ChangeSetEntity]
    default_value: Final[Maybe[ChangeSetEntity]]

    def __init__(
        self,
        scope: Scope,
        name: str,
        type_: ChangeSetEntity,
        dynamic_value: ChangeSetEntity,
        default_value: Maybe[ChangeSetEntity],
    ):
        change_type = parent_change_type_of([type_, default_value, dynamic_value])
        super().__init__(scope=scope, change_type=change_type)
        self.name = name
        self.type_ = type_
        self.dynamic_value = dynamic_value
        self.default_value = default_value


class NodeParameters(ChangeSetNode):
    parameters: Final[list[NodeParameter]]

    def __init__(self, scope: Scope, parameters: list[NodeParameter]):
        change_type = parent_change_type_of(parameters)
        super().__init__(scope=scope, change_type=change_type)
        self.parameters = parameters


class NodeMapping(ChangeSetNode):
    name: Final[str]
    bindings: Final[NodeObject]

    def __init__(self, scope: Scope, name: str, bindings: NodeObject):
        super().__init__(scope=scope, change_type=bindings.change_type)
        self.name = name
        self.bindings = bindings


class NodeMappings(ChangeSetNode):
    mappings: Final[list[NodeMapping]]

    def __init__(self, scope: Scope, mappings: list[NodeMapping]):
        change_type = parent_change_type_of(mappings)
        super().__init__(scope=scope, change_type=change_type)
        self.mappings = mappings


class NodeOutput(ChangeSetNode):
    name: Final[str]
    value: Final[ChangeSetEntity]
    export: Final[Maybe[ChangeSetEntity]]
    condition_reference: Final[Maybe[TerminalValue]]

    def __init__(
        self,
        scope: Scope,
        name: str,
        value: ChangeSetEntity,
        export: Maybe[ChangeSetEntity],
        conditional_reference: Maybe[TerminalValue],
    ):
        change_type = parent_change_type_of([value, export, conditional_reference])
        super().__init__(scope=scope, change_type=change_type)
        self.name = name
        self.value = value
        self.export = export
        self.condition_reference = conditional_reference


class NodeOutputs(ChangeSetNode):
    outputs: Final[list[NodeOutput]]

    def __init__(self, scope: Scope, outputs: list[NodeOutput]):
        change_type = parent_change_type_of(outputs)
        super().__init__(scope=scope, change_type=change_type)
        self.outputs = outputs


class NodeCondition(ChangeSetNode):
    name: Final[str]
    body: Final[ChangeSetEntity]

    def __init__(self, scope: Scope, name: str, body: ChangeSetEntity):
        super().__init__(scope=scope, change_type=body.change_type)
        self.name = name
        self.body = body


class NodeConditions(ChangeSetNode):
    conditions: Final[list[NodeCondition]]

    def __init__(self, scope: Scope, conditions: list[NodeCondition]):
        change_type = parent_change_type_of(conditions)
        super().__init__(scope=scope, change_type=change_type)
        self.conditions = conditions


class NodeGlobalTransform(ChangeSetNode):
    name: Final[TerminalValue]
    parameters: Final[Maybe[ChangeSetEntity]]

    def __init__(self, scope: Scope, name: TerminalValue, parameters: Maybe[ChangeSetEntity]):
        if not is_nothing(parameters):
            change_type = parent_change_type_of([name, parameters])
        else:
            change_type = name.change_type
        super().__init__(scope=scope, change_type=change_type)
        self.name = name
        self.parameters = parameters


class NodeTransform(ChangeSetNode):
    global_transforms: Final[list[NodeGlobalTransform]]

    def __init__(self, scope: Scope, global_transforms: list[NodeGlobalTransform]):
        change_type = parent_change_type_of(global_transforms)
        super().__init__(scope=scope, change_type=change_type)
        self.global_transforms = global_transforms


class NodeResources(ChangeSetNode):
    resources: Final[list[NodeResource]]
    fn_transform: Final[Maybe[NodeIntrinsicFunctionFnTransform]]
    fn_foreaches: Final[list[NodeForEach]]

    def __init__(
        self,
        scope: Scope,
        resources: list[NodeResource],
        fn_transform: Maybe[NodeIntrinsicFunctionFnTransform],
        fn_foreaches: list[NodeForEach],
    ):
        change_type = parent_change_type_of(resources + [fn_transform] + fn_foreaches)
        super().__init__(scope=scope, change_type=change_type)
        self.resources = resources
        self.fn_transform = fn_transform
        self.fn_foreaches = fn_foreaches


class NodeResource(ChangeSetNode):
    name: Final[str]
    type_: Final[ChangeSetTerminal]
    properties: Final[NodeProperties]
    condition_reference: Final[Maybe[TerminalValue]]
    depends_on: Final[Maybe[NodeDependsOn]]
    requires_replacement: Final[bool]
    deletion_policy: Final[Maybe[ChangeSetTerminal]]
    update_replace_policy: Final[Maybe[ChangeSetTerminal]]
    fn_transform: Final[Maybe[NodeIntrinsicFunctionFnTransform]]

    def __init__(
        self,
        scope: Scope,
        change_type: ChangeType,
        name: str,
        type_: ChangeSetTerminal,
        properties: NodeProperties,
        condition_reference: Maybe[TerminalValue],
        depends_on: Maybe[NodeDependsOn],
        requires_replacement: bool,
        deletion_policy: Maybe[ChangeSetTerminal],
        update_replace_policy: Maybe[ChangeSetTerminal],
        fn_transform: Maybe[NodeIntrinsicFunctionFnTransform],
    ):
        super().__init__(scope=scope, change_type=change_type)
        self.name = name
        self.type_ = type_
        self.properties = properties
        self.condition_reference = condition_reference
        self.depends_on = depends_on
        self.requires_replacement = requires_replacement
        self.deletion_policy = deletion_policy
        self.update_replace_policy = update_replace_policy
        self.fn_transform = fn_transform


class NodeProperties(ChangeSetNode):
    properties: Final[list[NodeProperty]]
    fn_transform: Final[Maybe[NodeIntrinsicFunctionFnTransform]]

    def __init__(
        self,
        scope: Scope,
        properties: list[NodeProperty],
        fn_transform: Maybe[NodeIntrinsicFunctionFnTransform],
    ):
        change_type = parent_change_type_of(properties)
        super().__init__(scope=scope, change_type=change_type)
        self.properties = properties
        self.fn_transform = fn_transform


class NodeDependsOn(ChangeSetNode):
    depends_on: Final[NodeArray]

    def __init__(self, scope: Scope, depends_on: NodeArray):
        super().__init__(scope=scope, change_type=depends_on.change_type)
        self.depends_on = depends_on


class NodeProperty(ChangeSetNode):
    name: Final[str]
    value: Final[ChangeSetEntity]

    def __init__(self, scope: Scope, name: str, value: ChangeSetEntity):
        super().__init__(scope=scope, change_type=value.change_type)
        self.name = name
        self.value = value


class NodeIntrinsicFunction(ChangeSetNode):
    intrinsic_function: Final[str]
    arguments: Final[ChangeSetEntity]

    def __init__(
        self,
        scope: Scope,
        change_type: ChangeType,
        intrinsic_function: str,
        arguments: ChangeSetEntity,
    ):
        super().__init__(scope=scope, change_type=change_type)
        self.intrinsic_function = intrinsic_function
        self.arguments = arguments


class NodeIntrinsicFunctionFnTransform(NodeIntrinsicFunction):
    def __init__(
        self,
        scope: Scope,
        change_type: ChangeType,
        intrinsic_function: str,
        arguments: ChangeSetEntity,
        before_siblings: list[Any],
        after_siblings: list[Any],
    ):
        super().__init__(
            scope=scope,
            change_type=change_type,
            intrinsic_function=intrinsic_function,
            arguments=arguments,
        )
        self.before_siblings = before_siblings
        self.after_siblings = after_siblings


class NodeForEach(ChangeSetNode):
    def __init__(
        self,
        scope: Scope,
        change_type: Final[ChangeType],
        arguments: Final[ChangeSetEntity],
    ):
        super().__init__(
            scope=scope,
            change_type=change_type,
        )
        self.arguments = arguments


class NodeObject(ChangeSetNode):
    bindings: Final[dict[str, ChangeSetEntity]]

    def __init__(self, scope: Scope, change_type: ChangeType, bindings: dict[str, ChangeSetEntity]):
        super().__init__(scope=scope, change_type=change_type)
        self.bindings = bindings


class NodeArray(ChangeSetNode):
    array: Final[list[ChangeSetEntity]]

    def __init__(self, scope: Scope, change_type: ChangeType, array: list[ChangeSetEntity]):
        super().__init__(scope=scope, change_type=change_type)
        self.array = array


class TerminalValue(ChangeSetTerminal, abc.ABC):
    value: Final[Any]

    def __init__(self, scope: Scope, change_type: ChangeType, value: Any):
        super().__init__(scope=scope, change_type=change_type)
        self.value = value


class TerminalValueModified(TerminalValue):
    modified_value: Final[Any]

    def __init__(self, scope: Scope, value: Any, modified_value: Any):
        super().__init__(scope=scope, change_type=ChangeType.MODIFIED, value=value)
        self.modified_value = modified_value


class TerminalValueCreated(TerminalValue):
    def __init__(self, scope: Scope, value: Any):
        super().__init__(scope=scope, change_type=ChangeType.CREATED, value=value)


class TerminalValueRemoved(TerminalValue):
    def __init__(self, scope: Scope, value: Any):
        super().__init__(scope=scope, change_type=ChangeType.REMOVED, value=value)


class TerminalValueUnchanged(TerminalValue):
    def __init__(self, scope: Scope, value: Any):
        super().__init__(scope=scope, change_type=ChangeType.UNCHANGED, value=value)


NameKey: Final[str] = "Name"
TransformKey: Final[str] = "Transform"
TypeKey: Final[str] = "Type"
ConditionKey: Final[str] = "Condition"
ConditionsKey: Final[str] = "Conditions"
MappingsKey: Final[str] = "Mappings"
ResourcesKey: Final[str] = "Resources"
PropertiesKey: Final[str] = "Properties"
ParametersKey: Final[str] = "Parameters"
DefaultKey: Final[str] = "Default"
ValueKey: Final[str] = "Value"
ExportKey: Final[str] = "Export"
OutputsKey: Final[str] = "Outputs"
DependsOnKey: Final[str] = "DependsOn"
DeletionPolicyKey: Final[str] = "DeletionPolicy"
UpdateReplacePolicyKey: Final[str] = "UpdateReplacePolicy"
# TODO: expand intrinsic functions set.
RefKey: Final[str] = "Ref"
RefConditionKey: Final[str] = "Condition"
FnIfKey: Final[str] = "Fn::If"
FnAnd: Final[str] = "Fn::And"
FnOr: Final[str] = "Fn::Or"
FnNotKey: Final[str] = "Fn::Not"
FnJoinKey: Final[str] = "Fn::Join"
FnGetAttKey: Final[str] = "Fn::GetAtt"
FnEqualsKey: Final[str] = "Fn::Equals"
FnFindInMapKey: Final[str] = "Fn::FindInMap"
FnSubKey: Final[str] = "Fn::Sub"
FnTransform: Final[str] = "Fn::Transform"
FnSelect: Final[str] = "Fn::Select"
FnSplit: Final[str] = "Fn::Split"
FnGetAZs: Final[str] = "Fn::GetAZs"
FnBase64: Final[str] = "Fn::Base64"
FnImportValue: Final[str] = "Fn::ImportValue"
INTRINSIC_FUNCTIONS: Final[set[str]] = {
    RefKey,
    RefConditionKey,
    FnIfKey,
    FnAnd,
    FnOr,
    FnNotKey,
    FnJoinKey,
    FnEqualsKey,
    FnGetAttKey,
    FnFindInMapKey,
    FnSubKey,
    FnTransform,
    FnSelect,
    FnSplit,
    FnGetAZs,
    FnBase64,
    FnImportValue,
}


class ChangeSetModel:
    # TODO: should this instead be generalised to work on "Stack" objects instead of just "Template"s?

    # TODO: can probably improve the typehints to use CFN's 'language' eg. dict -> Template|Properties, etc.

    # TODO: add support for 'replacement' computation, and ensure this state is propagated in tree traversals
    #  such as intrinsic functions.

    _before_template: Final[Maybe[dict]]
    _after_template: Final[Maybe[dict]]
    _before_parameters: Final[Maybe[dict]]
    _after_parameters: Final[Maybe[dict]]
    _visited_scopes: Final[dict[str, ChangeSetEntity]]
    _node_template: Final[NodeTemplate]

    def __init__(
        self,
        before_template: dict | None,
        after_template: dict | None,
        before_parameters: dict | None,
        after_parameters: dict[str, EngineParameter] | None,
    ):
        self._before_template = before_template or Nothing
        self._after_template = after_template or Nothing
        self._before_parameters = before_parameters or Nothing
        self._after_parameters = after_parameters or Nothing
        self._visited_scopes = {}
        # TODO: move this modeling process to the `get_update_model` method as constructors shouldn't do work
        self._node_template = self._model(
            before_template=self._before_template, after_template=self._after_template
        )
        # TODO: need to do template preprocessing e.g. parameter resolution, conditions etc.

    def get_update_model(self) -> UpdateModel:
        return UpdateModel(node_template=self._node_template)

    def _visit_terminal_value(
        self, scope: Scope, before_value: Maybe[Any], after_value: Maybe[Any]
    ) -> TerminalValue:
        terminal_value = self._visited_scopes.get(scope)
        if isinstance(terminal_value, TerminalValue):
            return terminal_value
        if is_created(before=before_value, after=after_value):
            terminal_value = TerminalValueCreated(scope=scope, value=after_value)
        elif is_removed(before=before_value, after=after_value):
            terminal_value = TerminalValueRemoved(scope=scope, value=before_value)
        elif before_value == after_value:
            terminal_value = TerminalValueUnchanged(scope=scope, value=before_value)
        else:
            terminal_value = TerminalValueModified(
                scope=scope, value=before_value, modified_value=after_value
            )
        self._visited_scopes[scope] = terminal_value
        return terminal_value

    def _visit_intrinsic_function(
        self,
        scope: Scope,
        intrinsic_function: str,
        before_arguments: Maybe[Any],
        after_arguments: Maybe[Any],
    ) -> NodeIntrinsicFunction:
        node_intrinsic_function = self._visited_scopes.get(scope)
        if isinstance(node_intrinsic_function, NodeIntrinsicFunction):
            return node_intrinsic_function
        arguments_scope = scope.open_scope("args")
        arguments = self._visit_value(
            scope=arguments_scope, before_value=before_arguments, after_value=after_arguments
        )

        if intrinsic_function == "Ref" and arguments.value == "AWS::NoValue":
            arguments.value = Nothing

        if is_created(before=before_arguments, after=after_arguments):
            change_type = ChangeType.CREATED
        elif is_removed(before=before_arguments, after=after_arguments):
            change_type = ChangeType.REMOVED
        else:
            function_name = intrinsic_function.replace("::", "_")
            function_name = camel_to_snake_case(function_name)
            resolve_function_name = f"_resolve_intrinsic_function_{function_name}"
            if hasattr(self, resolve_function_name):
                resolve_function = getattr(self, resolve_function_name)
                change_type = resolve_function(arguments)
            else:
                change_type = arguments.change_type

        if intrinsic_function == FnTransform:
            if scope.count(FnTransform) > 1:
                raise RuntimeError(
                    "Invalid: Fn::Transforms cannot be nested inside another Fn::Transform"
                )

            path = scope.parent.jsonpath
            before_siblings = extract_jsonpath(self._before_template, path)
            after_siblings = extract_jsonpath(self._after_template, path)

            node_intrinsic_function = NodeIntrinsicFunctionFnTransform(
                scope=scope,
                change_type=change_type,
                arguments=arguments,
                intrinsic_function=intrinsic_function,
                before_siblings=before_siblings,
                after_siblings=after_siblings,
            )
        else:
            node_intrinsic_function = NodeIntrinsicFunction(
                scope=scope,
                change_type=change_type,
                intrinsic_function=intrinsic_function,
                arguments=arguments,
            )
        self._visited_scopes[scope] = node_intrinsic_function
        return node_intrinsic_function

    def _visit_foreach(
        self, scope: Scope, before_arguments: Maybe[list], after_arguments: Maybe[list]
    ) -> NodeForEach:
        node_foreach = self._visited_scopes.get(scope)
        if isinstance(node_foreach, NodeForEach):
            return node_foreach
        arguments_scope = scope.open_scope("args")
        arguments = self._visit_array(
            arguments_scope, before_array=before_arguments, after_array=after_arguments
        )
        return NodeForEach(scope=scope, change_type=arguments.change_type, arguments=arguments)

    def _resolve_intrinsic_function_fn_sub(self, arguments: ChangeSetEntity) -> ChangeType:
        # TODO: This routine should instead export the implicit Ref and GetAtt calls within the first
        #       string template parameter and compute the respective change set types. Currently,
        #       changes referenced by Fn::Sub templates are only picked up during preprocessing; not
        #       at modelling.
        return arguments.change_type

    def _resolve_intrinsic_function_fn_get_att(self, arguments: ChangeSetEntity) -> ChangeType:
        # TODO: add support for nested intrinsic functions.
        # TODO: validate arguments structure and type.
        # TODO: should this check for deletion of resources and/or properties, if so what error should be raised?

        if not isinstance(arguments, NodeArray) or not arguments.array:
            raise RuntimeError()
        logical_name_of_resource_entity = arguments.array[0]
        if not isinstance(logical_name_of_resource_entity, TerminalValue):
            raise RuntimeError()
        logical_name_of_resource: str = logical_name_of_resource_entity.value
        if not isinstance(logical_name_of_resource, str):
            raise RuntimeError()
        node_resource: NodeResource = self._retrieve_or_visit_resource(
            resource_name=logical_name_of_resource
        )

        node_property_attribute_name = arguments.array[1]
        if not isinstance(node_property_attribute_name, TerminalValue):
            raise RuntimeError()
        if isinstance(node_property_attribute_name, TerminalValueModified):
            attribute_name = node_property_attribute_name.modified_value
        else:
            attribute_name = node_property_attribute_name.value

        # TODO: this is another use case for which properties should be referenced by name
        for node_property in node_resource.properties.properties:
            if node_property.name == attribute_name:
                return node_property.change_type

        return ChangeType.UNCHANGED

    def _resolve_intrinsic_function_ref(self, arguments: ChangeSetEntity) -> ChangeType:
        if arguments.change_type != ChangeType.UNCHANGED:
            return arguments.change_type
        if not isinstance(arguments, TerminalValue):
            return arguments.change_type

        logical_id = arguments.value

        if isinstance(logical_id, str) and logical_id.startswith("AWS::"):
            return arguments.change_type

        node_condition = self._retrieve_condition_if_exists(condition_name=logical_id)
        if isinstance(node_condition, NodeCondition):
            return node_condition.change_type

        node_parameter = self._retrieve_parameter_if_exists(parameter_name=logical_id)
        if isinstance(node_parameter, NodeParameter):
            return node_parameter.change_type

        # TODO: this should check the replacement flag for a resource update.
        node_resource = self._retrieve_or_visit_resource(resource_name=logical_id)
        return node_resource.change_type

    def _resolve_intrinsic_function_condition(self, arguments: ChangeSetEntity) -> ChangeType:
        if arguments.change_type != ChangeType.UNCHANGED:
            return arguments.change_type
        if not isinstance(arguments, TerminalValue):
            return arguments.change_type

        condition_name = arguments.value
        node_condition = self._retrieve_condition_if_exists(condition_name=condition_name)
        if isinstance(node_condition, NodeCondition):
            return node_condition.change_type
        raise RuntimeError(f"Undefined condition '{condition_name}'")

    def _resolve_intrinsic_function_fn_find_in_map(self, arguments: ChangeSetEntity) -> ChangeType:
        if arguments.change_type != ChangeType.UNCHANGED:
            return arguments.change_type
        # TODO: validate arguments structure and type.
        # TODO: add support for nested functions, here we assume the arguments are string literals.

        if not isinstance(arguments, NodeArray) or not arguments.array:
            raise RuntimeError()
        argument_mapping_name = arguments.array[0]
        if not isinstance(argument_mapping_name, TerminalValue):
            raise NotImplementedError()
        argument_top_level_key = arguments.array[1]
        if not isinstance(argument_top_level_key, TerminalValue):
            raise NotImplementedError()
        argument_second_level_key = arguments.array[2]
        if not isinstance(argument_second_level_key, TerminalValue):
            raise NotImplementedError()
        mapping_name = argument_mapping_name.value
        top_level_key = argument_top_level_key.value
        second_level_key = argument_second_level_key.value

        node_mapping = self._retrieve_mapping(mapping_name=mapping_name)
        # TODO: a lookup would be beneficial in this scenario too;
        #  consider implications downstream and for replication.
        top_level_object = node_mapping.bindings.bindings.get(top_level_key)
        if not isinstance(top_level_object, NodeObject):
            raise RuntimeError()
        target_map_value = top_level_object.bindings.get(second_level_key)
        return target_map_value.change_type

    def _resolve_intrinsic_function_fn_if(self, arguments: ChangeSetEntity) -> ChangeType:
        # TODO: validate arguments structure and type.
        if not isinstance(arguments, NodeArray) or not arguments.array:
            raise RuntimeError()
        logical_name_of_condition_entity = arguments.array[0]
        if not isinstance(logical_name_of_condition_entity, TerminalValue):
            raise RuntimeError()
        logical_name_of_condition: str = logical_name_of_condition_entity.value
        if not isinstance(logical_name_of_condition, str):
            raise RuntimeError()

        node_condition = self._retrieve_condition_if_exists(
            condition_name=logical_name_of_condition
        )
        if not isinstance(node_condition, NodeCondition):
            raise RuntimeError()
        change_type = parent_change_type_of([node_condition, *arguments.array[1:]])
        return change_type

    def _resolve_requires_replacement(
        self, node_properties: NodeProperties, resource_type: TerminalValue
    ) -> bool:
        # a bit hacky but we have to load the resource provider executor _and_ resource provider to get the schema
        # Note: we don't log the attempt to load the resource provider, we need to make sure this is only done once and we already do this in the executor

        resource_provider = ResourceProviderExecutor.try_load_resource_provider(resource_type.value)
        if not resource_provider:
            # if we don't support a resource, assume an in-place update for simplicity
            return False

        create_only_properties: list[str] = resource_provider.SCHEMA.get("createOnlyProperties", [])
        # TODO: also hacky: strip the leading `/properties/` string from the definition
        #       ideally we should use a jsonpath or similar
        create_only_properties = [
            property.replace("/properties/", "", 1) for property in create_only_properties
        ]
        for node_property in node_properties.properties:
            if (
                node_property.change_type == ChangeType.MODIFIED
                and node_property.name in create_only_properties
            ):
                return True
        return False

    def _visit_array(
        self, scope: Scope, before_array: Maybe[list], after_array: Maybe[list]
    ) -> NodeArray:
        array: list[ChangeSetEntity] = []
        for index, (before_value, after_value) in enumerate(
            zip_longest(before_array, after_array, fillvalue=Nothing)
        ):
            value_scope = scope.open_index(index=index)
            value = self._visit_value(
                scope=value_scope, before_value=before_value, after_value=after_value
            )
            array.append(value)
        change_type = change_type_of(before_array, after_array, array)
        return NodeArray(scope=scope, change_type=change_type, array=array)

    def _visit_object(
        self, scope: Scope, before_object: Maybe[dict], after_object: Maybe[dict]
    ) -> NodeObject:
        node_object = self._visited_scopes.get(scope)
        if isinstance(node_object, NodeObject):
            return node_object
        binding_names = self._safe_keys_of(before_object, after_object)
        bindings: dict[str, ChangeSetEntity] = {}
        for binding_name in binding_names:
            binding_scope, (before_value, after_value) = self._safe_access_in(
                scope, binding_name, before_object, after_object
            )
            value = self._visit_value(
                scope=binding_scope, before_value=before_value, after_value=after_value
            )
            bindings[binding_name] = value
        change_type = change_type_of(before_object, after_object, list(bindings.values()))
        node_object = NodeObject(scope=scope, change_type=change_type, bindings=bindings)
        self._visited_scopes[scope] = node_object
        return node_object

    def _visit_divergence(
        self, scope: Scope, before_value: Maybe[Any], after_value: Maybe[Any]
    ) -> NodeDivergence:
        scope_value = scope.open_scope("value")
        value = self._visit_value(scope=scope_value, before_value=before_value, after_value=Nothing)
        scope_divergence = scope.open_scope("divergence")
        divergence = self._visit_value(
            scope=scope_divergence, before_value=Nothing, after_value=after_value
        )
        return NodeDivergence(scope=scope, value=value, divergence=divergence)

    def _visit_value(
        self, scope: Scope, before_value: Maybe[Any], after_value: Maybe[Any]
    ) -> ChangeSetEntity:
        value = self._visited_scopes.get(scope)
        if isinstance(value, ChangeSetEntity):
            return value

        before_type_name = self._type_name_of(before_value)
        after_type_name = self._type_name_of(after_value)
        unset = object()
        if before_type_name == after_type_name:
            dominant_value = before_value
        elif is_created(before=before_value, after=after_value):
            dominant_value = after_value
        elif is_removed(before=before_value, after=after_value):
            dominant_value = before_value
        else:
            dominant_value = unset
        if dominant_value is not unset:
            dominant_type_name = self._type_name_of(dominant_value)
            if self._is_terminal(value=dominant_value):
                value = self._visit_terminal_value(
                    scope=scope, before_value=before_value, after_value=after_value
                )
            elif self._is_object(value=dominant_value):
                value = self._visit_object(
                    scope=scope, before_object=before_value, after_object=after_value
                )
            elif self._is_array(value=dominant_value):
                value = self._visit_array(
                    scope=scope, before_array=before_value, after_array=after_value
                )
            elif self._is_intrinsic_function_name(dominant_type_name):
                intrinsic_function_scope, (before_arguments, after_arguments) = (
                    self._safe_access_in(scope, dominant_type_name, before_value, after_value)
                )
                value = self._visit_intrinsic_function(
                    scope=intrinsic_function_scope,
                    intrinsic_function=dominant_type_name,
                    before_arguments=before_arguments,
                    after_arguments=after_arguments,
                )
            else:
                raise RuntimeError(f"Unsupported type {type(dominant_value)}")
        # Case: type divergence.
        else:
            value = self._visit_divergence(
                scope=scope, before_value=before_value, after_value=after_value
            )
        self._visited_scopes[scope] = value
        return value

    def _visit_property(
        self,
        scope: Scope,
        property_name: str,
        before_property: Maybe[Any],
        after_property: Maybe[Any],
    ) -> NodeProperty:
        node_property = self._visited_scopes.get(scope)
        if isinstance(node_property, NodeProperty):
            return node_property
        # TODO: Review the use of Fn::Transform as resource properties.
        value = self._visit_value(
            scope=scope, before_value=before_property, after_value=after_property
        )
        node_property = NodeProperty(scope=scope, name=property_name, value=value)
        self._visited_scopes[scope] = node_property
        return node_property

    def _visit_properties(
        self, scope: Scope, before_properties: Maybe[dict], after_properties: Maybe[dict]
    ) -> NodeProperties:
        node_properties = self._visited_scopes.get(scope)
        if isinstance(node_properties, NodeProperties):
            return node_properties
        property_names: list[str] = self._safe_keys_of(before_properties, after_properties)
        properties: list[NodeProperty] = []
        fn_transform = Nothing

        for property_name in property_names:
            property_scope, (before_property, after_property) = self._safe_access_in(
                scope, property_name, before_properties, after_properties
            )
            if property_name == FnTransform:
                fn_transform = self._visit_intrinsic_function(
                    property_scope, FnTransform, before_property, after_property
                )
                continue

            property_ = self._visit_property(
                scope=property_scope,
                property_name=property_name,
                before_property=before_property,
                after_property=after_property,
            )
            properties.append(property_)

        node_properties = NodeProperties(
            scope=scope, properties=properties, fn_transform=fn_transform
        )
        self._visited_scopes[scope] = node_properties
        return node_properties

    def _visit_type(self, scope: Scope, before_type: Any, after_type: Any) -> TerminalValue:
        value = self._visit_value(scope=scope, before_value=before_type, after_value=after_type)
        if not isinstance(value, TerminalValue):
            # TODO: decide where template schema validation should occur.
            raise RuntimeError()
        return value

    def _visit_deletion_policy(
        self, scope: Scope, before_deletion_policy: Any, after_deletion_policy: Any
    ) -> TerminalValue:
        value = self._visit_value(
            scope=scope, before_value=before_deletion_policy, after_value=after_deletion_policy
        )
        if not isinstance(value, TerminalValue):
            # TODO: decide where template schema validation should occur.
            raise RuntimeError()
        return value

    def _visit_update_replace_policy(
        self, scope: Scope, before_update_replace_policy: Any, after_deletion_policy: Any
    ) -> TerminalValue:
        value = self._visit_value(
            scope=scope,
            before_value=before_update_replace_policy,
            after_value=after_deletion_policy,
        )
        if not isinstance(value, TerminalValue):
            # TODO: decide where template schema validation should occur.
            raise RuntimeError()
        return value

    def _visit_resource(
        self,
        scope: Scope,
        resource_name: str,
        before_resource: Maybe[dict],
        after_resource: Maybe[dict],
    ) -> NodeResource:
        node_resource = self._visited_scopes.get(scope)
        if isinstance(node_resource, NodeResource):
            return node_resource

        scope_type, (before_type, after_type) = self._safe_access_in(
            scope, TypeKey, before_resource, after_resource
        )
        terminal_value_type = self._visit_type(
            scope=scope_type, before_type=before_type, after_type=after_type
        )

        condition_reference = Nothing
        scope_condition, (before_condition, after_condition) = self._safe_access_in(
            scope, ConditionKey, before_resource, after_resource
        )
        if before_condition or after_condition:
            condition_reference = self._visit_terminal_value(
                scope_condition, before_condition, after_condition
            )

        depends_on = Nothing
        scope_depends_on, (before_depends_on, after_depends_on) = self._safe_access_in(
            scope, DependsOnKey, before_resource, after_resource
        )
        if before_depends_on or after_depends_on:
            depends_on = self._visit_depends_on(
                scope_depends_on, before_depends_on, after_depends_on
            )

        scope_properties, (before_properties, after_properties) = self._safe_access_in(
            scope, PropertiesKey, before_resource, after_resource
        )
        properties = self._visit_properties(
            scope=scope_properties,
            before_properties=before_properties,
            after_properties=after_properties,
        )

        deletion_policy = Nothing
        scope_deletion_policy, (before_deletion_policy, after_deletion_policy) = (
            self._safe_access_in(scope, DeletionPolicyKey, before_resource, after_resource)
        )
        if before_deletion_policy or after_deletion_policy:
            deletion_policy = self._visit_deletion_policy(
                scope_deletion_policy, before_deletion_policy, after_deletion_policy
            )

        update_replace_policy = Nothing
        scope_update_replace_policy, (before_update_replace_policy, after_update_replace_policy) = (
            self._safe_access_in(scope, UpdateReplacePolicyKey, before_resource, after_resource)
        )
        if before_update_replace_policy or after_update_replace_policy:
            update_replace_policy = self._visit_update_replace_policy(
                scope_update_replace_policy,
                before_update_replace_policy,
                after_update_replace_policy,
            )

        fn_transform = Nothing
        scope_fn_transform, (before_fn_transform_args, after_fn_transform_args) = (
            self._safe_access_in(scope, FnTransform, before_resource, after_resource)
        )
        if not is_nothing(before_fn_transform_args) or not is_nothing(after_fn_transform_args):
            if scope_fn_transform.count(FnTransform) > 1:
                raise RuntimeError(
                    "Invalid: Fn::Transforms cannot be nested inside another Fn::Transform"
                )
            path = "$" + ".".join(scope_fn_transform.split("/")[:-1])
            before_siblings = extract_jsonpath(self._before_template, path)
            after_siblings = extract_jsonpath(self._after_template, path)
            arguments_scope = scope.open_scope("args")
            arguments = self._visit_value(
                scope=arguments_scope,
                before_value=before_fn_transform_args,
                after_value=after_fn_transform_args,
            )
            fn_transform = NodeIntrinsicFunctionFnTransform(
                scope=scope_fn_transform,
                change_type=ChangeType.MODIFIED,  # TODO
                arguments=arguments,  # TODO
                intrinsic_function=FnTransform,
                before_siblings=before_siblings,
                after_siblings=after_siblings,
            )

        change_type = change_type_of(
            before_resource,
            after_resource,
            [
                properties,
                condition_reference,
                depends_on,
                deletion_policy,
                update_replace_policy,
                fn_transform,
            ],
        )
        requires_replacement = self._resolve_requires_replacement(
            node_properties=properties, resource_type=terminal_value_type
        )
        node_resource = NodeResource(
            scope=scope,
            change_type=change_type,
            name=resource_name,
            type_=terminal_value_type,
            properties=properties,
            condition_reference=condition_reference,
            depends_on=depends_on,
            requires_replacement=requires_replacement,
            deletion_policy=deletion_policy,
            update_replace_policy=update_replace_policy,
            fn_transform=fn_transform,
        )
        self._visited_scopes[scope] = node_resource
        return node_resource

    def _visit_resources(
        self, scope: Scope, before_resources: Maybe[dict], after_resources: Maybe[dict]
    ) -> NodeResources:
        # TODO: investigate type changes behavior.
        resources: list[NodeResource] = []
        resource_names = self._safe_keys_of(before_resources, after_resources)
        fn_transform = Nothing
        fn_foreaches = []
        for resource_name in resource_names:
            resource_scope, (before_resource, after_resource) = self._safe_access_in(
                scope, resource_name, before_resources, after_resources
            )
            if resource_name == FnTransform:
                fn_transform = self._visit_intrinsic_function(
                    scope=resource_scope,
                    intrinsic_function=resource_name,
                    before_arguments=before_resource,
                    after_arguments=after_resource,
                )
                continue
            elif resource_name.startswith("Fn::ForEach"):
                fn_for_each = self._visit_foreach(
                    scope=resource_scope,
                    before_arguments=before_resource,
                    after_arguments=after_resource,
                )
                fn_foreaches.append(fn_for_each)
                continue
            resource = self._visit_resource(
                scope=resource_scope,
                resource_name=resource_name,
                before_resource=before_resource,
                after_resource=after_resource,
            )
            resources.append(resource)
        return NodeResources(
            scope=scope,
            resources=resources,
            fn_transform=fn_transform,
            fn_foreaches=fn_foreaches,
        )

    def _visit_mapping(
        self, scope: Scope, name: str, before_mapping: Maybe[dict], after_mapping: Maybe[dict]
    ) -> NodeMapping:
        bindings = self._visit_object(
            scope=scope, before_object=before_mapping, after_object=after_mapping
        )
        return NodeMapping(scope=scope, name=name, bindings=bindings)

    def _visit_mappings(
        self, scope: Scope, before_mappings: Maybe[dict], after_mappings: Maybe[dict]
    ) -> NodeMappings:
        mappings: list[NodeMapping] = []
        mapping_names = self._safe_keys_of(before_mappings, after_mappings)
        for mapping_name in mapping_names:
            scope_mapping, (before_mapping, after_mapping) = self._safe_access_in(
                scope, mapping_name, before_mappings, after_mappings
            )
            mapping = self._visit_mapping(
                scope=scope_mapping,
                name=mapping_name,
                before_mapping=before_mapping,
                after_mapping=after_mapping,
            )
            mappings.append(mapping)
        return NodeMappings(scope=scope, mappings=mappings)

    def _visit_dynamic_parameter(self, parameter_name: str) -> ChangeSetEntity:
        scope = Scope("Dynamic").open_scope("Parameters")
        scope_parameter, (before_parameter_dct, after_parameter_dct) = self._safe_access_in(
            scope, parameter_name, self._before_parameters, self._after_parameters
        )

        before_parameter = Nothing
        if not is_nothing(before_parameter_dct):
            before_parameter = before_parameter_dct.get("resolved_value") or engine_parameter_value(
                before_parameter_dct
            )

        after_parameter = Nothing
        if not is_nothing(after_parameter_dct):
            after_parameter = after_parameter_dct.get("resolved_value") or engine_parameter_value(
                after_parameter_dct
            )

        parameter = self._visit_value(
            scope=scope_parameter, before_value=before_parameter, after_value=after_parameter
        )
        return parameter

    def _visit_parameter(
        self,
        scope: Scope,
        parameter_name: str,
        before_parameter: Maybe[dict],
        after_parameter: Maybe[dict],
    ) -> NodeParameter:
        node_parameter = self._visited_scopes.get(scope)
        if isinstance(node_parameter, NodeParameter):
            return node_parameter

        type_scope, (before_type, after_type) = self._safe_access_in(
            scope, TypeKey, before_parameter, after_parameter
        )
        type_ = self._visit_value(type_scope, before_type, after_type)

        default_scope, (before_default, after_default) = self._safe_access_in(
            scope, DefaultKey, before_parameter, after_parameter
        )
        default_value = self._visit_value(default_scope, before_default, after_default)

        dynamic_value = self._visit_dynamic_parameter(parameter_name=parameter_name)

        node_parameter = NodeParameter(
            scope=scope,
            name=parameter_name,
            type_=type_,
            default_value=default_value,
            dynamic_value=dynamic_value,
        )
        self._visited_scopes[scope] = node_parameter
        return node_parameter

    def _visit_parameters(
        self, scope: Scope, before_parameters: Maybe[dict], after_parameters: Maybe[dict]
    ) -> NodeParameters:
        node_parameters = self._visited_scopes.get(scope)
        if isinstance(node_parameters, NodeParameters):
            return node_parameters
        parameter_names: list[str] = self._safe_keys_of(before_parameters, after_parameters)
        parameters: list[NodeParameter] = []
        for parameter_name in parameter_names:
            parameter_scope, (before_parameter, after_parameter) = self._safe_access_in(
                scope, parameter_name, before_parameters, after_parameters
            )
            parameter = self._visit_parameter(
                scope=parameter_scope,
                parameter_name=parameter_name,
                before_parameter=before_parameter,
                after_parameter=after_parameter,
            )
            parameters.append(parameter)
        node_parameters = NodeParameters(scope=scope, parameters=parameters)
        self._visited_scopes[scope] = node_parameters
        return node_parameters

    @staticmethod
    def _normalise_depends_on_value(value: Maybe[str | list[str]]) -> Maybe[list[str]]:
        # To simplify downstream logics, reduce the type options to array of strings.
        # TODO: Add integrations tests for DependsOn validations (invalid types, duplicate identifiers, etc.)
        if isinstance(value, NothingType):
            return value
        if isinstance(value, str):
            value = [value]
        elif isinstance(value, list):
            value.sort()
        else:
            raise RuntimeError(
                f"Invalid type for DependsOn, expected a String or Array of String, but got: '{value}'"
            )
        return value

    def _visit_depends_on(
        self,
        scope: Scope,
        before_depends_on: Maybe[str | list[str]],
        after_depends_on: Maybe[str | list[str]],
    ) -> NodeDependsOn:
        before_depends_on = self._normalise_depends_on_value(value=before_depends_on)
        after_depends_on = self._normalise_depends_on_value(value=after_depends_on)
        node_array = self._visit_array(
            scope=scope, before_array=before_depends_on, after_array=after_depends_on
        )
        node_depends_on = NodeDependsOn(scope=scope, depends_on=node_array)
        return node_depends_on

    def _visit_condition(
        self,
        scope: Scope,
        condition_name: str,
        before_condition: Maybe[dict],
        after_condition: Maybe[dict],
    ) -> NodeCondition:
        node_condition = self._visited_scopes.get(scope)
        if isinstance(node_condition, NodeCondition):
            return node_condition
        body = self._visit_value(
            scope=scope, before_value=before_condition, after_value=after_condition
        )
        node_condition = NodeCondition(scope=scope, name=condition_name, body=body)
        self._visited_scopes[scope] = node_condition
        return node_condition

    def _visit_conditions(
        self, scope: Scope, before_conditions: Maybe[dict], after_conditions: Maybe[dict]
    ) -> NodeConditions:
        node_conditions = self._visited_scopes.get(scope)
        if isinstance(node_conditions, NodeConditions):
            return node_conditions
        condition_names: list[str] = self._safe_keys_of(before_conditions, after_conditions)
        conditions: list[NodeCondition] = []
        for condition_name in condition_names:
            condition_scope, (before_condition, after_condition) = self._safe_access_in(
                scope, condition_name, before_conditions, after_conditions
            )
            condition = self._visit_condition(
                scope=condition_scope,
                condition_name=condition_name,
                before_condition=before_condition,
                after_condition=after_condition,
            )
            conditions.append(condition)
        node_conditions = NodeConditions(scope=scope, conditions=conditions)
        self._visited_scopes[scope] = node_conditions
        return node_conditions

    def _visit_output(
        self, scope: Scope, name: str, before_output: Maybe[dict], after_output: Maybe[dict]
    ) -> NodeOutput:
        scope_value, (before_value, after_value) = self._safe_access_in(
            scope, ValueKey, before_output, after_output
        )
        value = self._visit_value(scope_value, before_value, after_value)

        export: Maybe[ChangeSetEntity] = Nothing
        scope_export, (before_export, after_export) = self._safe_access_in(
            scope, ExportKey, before_output, after_output
        )
        if before_export or after_export:
            export = self._visit_value(scope_export, before_export, after_export)

        # TODO: condition references should be resolved for the condition's change_type?
        condition_reference: Maybe[TerminalValue] = Nothing
        scope_condition, (before_condition, after_condition) = self._safe_access_in(
            scope, ConditionKey, before_output, after_output
        )
        if before_condition or after_condition:
            condition_reference = self._visit_terminal_value(
                scope_condition, before_condition, after_condition
            )

        return NodeOutput(
            scope=scope,
            name=name,
            value=value,
            export=export,
            conditional_reference=condition_reference,
        )

    def _visit_outputs(
        self, scope: Scope, before_outputs: Maybe[dict], after_outputs: Maybe[dict]
    ) -> NodeOutputs:
        outputs: list[NodeOutput] = []
        output_names: list[str] = self._safe_keys_of(before_outputs, after_outputs)
        for output_name in output_names:
            scope_output, (before_output, after_output) = self._safe_access_in(
                scope, output_name, before_outputs, after_outputs
            )
            output = self._visit_output(
                scope=scope_output,
                name=output_name,
                before_output=before_output,
                after_output=after_output,
            )
            outputs.append(output)
        return NodeOutputs(scope=scope, outputs=outputs)

    def _visit_global_transform(
        self,
        scope: Scope,
        before_global_transform: Maybe[NormalisedGlobalTransformDefinition],
        after_global_transform: Maybe[NormalisedGlobalTransformDefinition],
    ) -> NodeGlobalTransform:
        name_scope, (before_name, after_name) = self._safe_access_in(
            scope, NameKey, before_global_transform, after_global_transform
        )
        name = self._visit_terminal_value(
            scope=name_scope, before_value=before_name, after_value=after_name
        )

        parameters_scope, (before_parameters, after_parameters) = self._safe_access_in(
            scope, ParametersKey, before_global_transform, after_global_transform
        )
        parameters = self._visit_value(
            scope=parameters_scope, before_value=before_parameters, after_value=after_parameters
        )

        return NodeGlobalTransform(scope=scope, name=name, parameters=parameters)

    @staticmethod
    def _normalise_transformer_value(value: Maybe[str | list[Any]]) -> Maybe[list[Any]]:
        # To simplify downstream logics, reduce the type options to array of transformations.
        # TODO: add further validation logic
        # TODO: should we sort to avoid detecting user-side ordering changes as template changes?
        if isinstance(value, NothingType):
            return value
        elif isinstance(value, str):
            value = [NormalisedGlobalTransformDefinition(Name=value, Parameters=Nothing)]
        elif isinstance(value, list):
            tmp_value = []
            for item in value:
                if isinstance(item, str):
                    tmp_value.append(
                        NormalisedGlobalTransformDefinition(Name=item, Parameters=Nothing)
                    )
                else:
                    tmp_value.append(item)
            value = tmp_value
        elif isinstance(value, dict):
            if "Name" not in value:
                raise RuntimeError(f"Missing 'Name' field in Transform definition '{value}'")
            name = value["Name"]
            parameters = value.get("Parameters", Nothing)
            value = [NormalisedGlobalTransformDefinition(Name=name, Parameters=parameters)]
        else:
            raise RuntimeError(f"Invalid Transform definition: '{value}'")
        return value

    def _visit_transform(
        self, scope: Scope, before_transform: Maybe[Any], after_transform: Maybe[Any]
    ) -> NodeTransform:
        before_transform_normalised = self._normalise_transformer_value(before_transform)
        after_transform_normalised = self._normalise_transformer_value(after_transform)
        global_transforms = []
        for index, (before_global_transform, after_global_transform) in enumerate(
            zip_longest(before_transform_normalised, after_transform_normalised, fillvalue=Nothing)
        ):
            global_transform_scope = scope.open_index(index=index)
            global_transform: NodeGlobalTransform = self._visit_global_transform(
                scope=global_transform_scope,
                before_global_transform=before_global_transform,
                after_global_transform=after_global_transform,
            )
            global_transforms.append(global_transform)
        return NodeTransform(scope=scope, global_transforms=global_transforms)

    def _model(self, before_template: Maybe[dict], after_template: Maybe[dict]) -> NodeTemplate:
        root_scope = Scope()
        # TODO: visit other child types

        transform_scope, (before_transform, after_transform) = self._safe_access_in(
            root_scope, TransformKey, before_template, after_template
        )
        transform = self._visit_transform(
            scope=transform_scope,
            before_transform=before_transform,
            after_transform=after_transform,
        )

        mappings_scope, (before_mappings, after_mappings) = self._safe_access_in(
            root_scope, MappingsKey, before_template, after_template
        )
        mappings = self._visit_mappings(
            scope=mappings_scope, before_mappings=before_mappings, after_mappings=after_mappings
        )

        parameters_scope, (before_parameters, after_parameters) = self._safe_access_in(
            root_scope, ParametersKey, before_template, after_template
        )
        parameters = self._visit_parameters(
            scope=parameters_scope,
            before_parameters=before_parameters,
            after_parameters=after_parameters,
        )

        conditions_scope, (before_conditions, after_conditions) = self._safe_access_in(
            root_scope, ConditionsKey, before_template, after_template
        )
        conditions = self._visit_conditions(
            scope=conditions_scope,
            before_conditions=before_conditions,
            after_conditions=after_conditions,
        )

        resources_scope, (before_resources, after_resources) = self._safe_access_in(
            root_scope, ResourcesKey, before_template, after_template
        )
        resources = self._visit_resources(
            scope=resources_scope,
            before_resources=before_resources,
            after_resources=after_resources,
        )

        outputs_scope, (before_outputs, after_outputs) = self._safe_access_in(
            root_scope, OutputsKey, before_template, after_template
        )
        outputs = self._visit_outputs(
            scope=outputs_scope, before_outputs=before_outputs, after_outputs=after_outputs
        )

        return NodeTemplate(
            scope=root_scope,
            transform=transform,
            mappings=mappings,
            parameters=parameters,
            conditions=conditions,
            resources=resources,
            outputs=outputs,
        )

    def _retrieve_condition_if_exists(self, condition_name: str) -> Maybe[NodeCondition]:
        conditions_scope, (before_conditions, after_conditions) = self._safe_access_in(
            Scope(), ConditionsKey, self._before_template, self._after_template
        )
        before_conditions = before_conditions or {}
        after_conditions = after_conditions or {}
        if condition_name in before_conditions or condition_name in after_conditions:
            condition_scope, (before_condition, after_condition) = self._safe_access_in(
                conditions_scope, condition_name, before_conditions, after_conditions
            )
            node_condition = self._visit_condition(
                conditions_scope,
                condition_name,
                before_condition=before_condition,
                after_condition=after_condition,
            )
            return node_condition
        return Nothing

    def _retrieve_parameter_if_exists(self, parameter_name: str) -> Maybe[NodeParameter]:
        parameters_scope, (before_parameters, after_parameters) = self._safe_access_in(
            Scope(), ParametersKey, self._before_template, self._after_template
        )
        if parameter_name in before_parameters or parameter_name in after_parameters:
            parameter_scope, (before_parameter, after_parameter) = self._safe_access_in(
                parameters_scope, parameter_name, before_parameters, after_parameters
            )
            node_parameter = self._visit_parameter(
                parameter_scope,
                parameter_name,
                before_parameter=before_parameter,
                after_parameter=after_parameter,
            )
            return node_parameter
        return Nothing

    def _retrieve_mapping(self, mapping_name) -> NodeMapping:
        # TODO: add caching mechanism, and raise appropriate error if missing.
        scope_mappings, (before_mappings, after_mappings) = self._safe_access_in(
            Scope(), MappingsKey, self._before_template, self._after_template
        )
        if mapping_name in before_mappings or mapping_name in after_mappings:
            scope_mapping, (before_mapping, after_mapping) = self._safe_access_in(
                scope_mappings, mapping_name, before_mappings, after_mappings
            )
            node_mapping = self._visit_mapping(
                scope_mapping, mapping_name, before_mapping, after_mapping
            )
            return node_mapping
        raise RuntimeError()

    def _retrieve_or_visit_resource(self, resource_name: str) -> NodeResource:
        resources_scope, (before_resources, after_resources) = self._safe_access_in(
            Scope(),
            ResourcesKey,
            self._before_template,
            self._after_template,
        )
        resource_scope, (before_resource, after_resource) = self._safe_access_in(
            resources_scope, resource_name, before_resources, after_resources
        )
        return self._visit_resource(
            scope=resource_scope,
            resource_name=resource_name,
            before_resource=before_resource,
            after_resource=after_resource,
        )

    @staticmethod
    def _is_intrinsic_function_name(function_name: str) -> bool:
        # TODO: are intrinsic functions soft keywords?
        return function_name in INTRINSIC_FUNCTIONS

    @staticmethod
    def _safe_access_in(scope: Scope, key: str, *objects: Maybe[dict]) -> tuple[Scope, Maybe[Any]]:
        results = []
        for obj in objects:
            if not isinstance(obj, (dict, NothingType)):
                raise RuntimeError(f"Invalid definition type at '{obj}'")
            if not isinstance(obj, NothingType):
                results.append(obj.get(key, Nothing))
            else:
                results.append(obj)
        new_scope = scope.open_scope(name=key)
        return new_scope, results[0] if len(objects) == 1 else tuple(results)

    @staticmethod
    def _safe_keys_of(*objects: Maybe[dict]) -> list[str]:
        key_set: set[str] = set()
        for obj in objects:
            # TODO: raise errors if not dict
            if isinstance(obj, dict):
                key_set.update(obj.keys())
        # The keys list is sorted to increase reproducibility of the
        # update graph build process or downstream logics.
        keys = sorted(key_set)
        return keys

    @staticmethod
    def _name_if_intrinsic_function(value: Maybe[Any]) -> str | None:
        if isinstance(value, dict):
            keys = ChangeSetModel._safe_keys_of(value)
            if len(keys) == 1:
                key_name = keys[0]
                if ChangeSetModel._is_intrinsic_function_name(key_name):
                    return key_name
        return None

    @staticmethod
    def _type_name_of(value: Maybe[Any]) -> str:
        maybe_intrinsic_function_name = ChangeSetModel._name_if_intrinsic_function(value)
        if maybe_intrinsic_function_name is not None:
            return maybe_intrinsic_function_name
        return type(value).__name__

    @staticmethod
    def _is_terminal(value: Any) -> bool:
        return type(value) in {int, float, bool, str, None, NothingType}

    @staticmethod
    def _is_object(value: Any) -> bool:
        return isinstance(value, dict) and ChangeSetModel._name_if_intrinsic_function(value) is None

    @staticmethod
    def _is_array(value: Any) -> bool:
        return isinstance(value, list)

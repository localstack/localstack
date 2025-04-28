from __future__ import annotations

import abc
import enum
from itertools import zip_longest
from typing import Any, Final, Generator, Optional, Union, cast

from typing_extensions import TypeVar

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

    def __str__(self):
        return repr(self)

    def __repr__(self) -> str:
        return "Nothing"

    def __bool__(self):
        return False

    def __iter__(self):
        return iter(())


Maybe = Union[T, NothingType]
Nothing = NothingType()


class Scope(str):
    _ROOT_SCOPE: Final[str] = str()
    _SEPARATOR: Final[str] = "/"

    def __new__(cls, scope: str = _ROOT_SCOPE) -> Scope:
        return cast(Scope, super().__new__(cls, scope))

    def open_scope(self, name: Scope | str) -> Scope:
        return Scope(self._SEPARATOR.join([self, name]))

    def open_index(self, index: int) -> Scope:
        return Scope(self._SEPARATOR.join([self, str(index)]))

    def unwrap(self) -> list[str]:
        return self.split(self._SEPARATOR)


class ChangeType(enum.Enum):
    UNCHANGED = "Unchanged"
    CREATED = "Created"
    MODIFIED = "Modified"
    REMOVED = "Removed"

    def __str__(self):
        return self.value

    def for_child(self, child_change_type: ChangeType) -> ChangeType:
        if child_change_type == self:
            return self
        elif self == ChangeType.UNCHANGED:
            return child_change_type
        else:
            return ChangeType.MODIFIED


class ChangeSetEntity(abc.ABC):
    scope: Final[Scope]
    change_type: Final[ChangeType]

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


class NodeTemplate(ChangeSetNode):
    mappings: Final[NodeMappings]
    parameters: Final[NodeParameters]
    conditions: Final[NodeConditions]
    resources: Final[NodeResources]
    outputs: Final[NodeOutputs]

    def __init__(
        self,
        scope: Scope,
        change_type: ChangeType,
        mappings: NodeMappings,
        parameters: NodeParameters,
        conditions: NodeConditions,
        resources: NodeResources,
        outputs: NodeOutputs,
    ):
        super().__init__(scope=scope, change_type=change_type)
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
    default_value: Final[Optional[ChangeSetEntity]]

    def __init__(
        self,
        scope: Scope,
        change_type: ChangeType,
        name: str,
        type_: ChangeSetEntity,
        dynamic_value: ChangeSetEntity,
        default_value: Optional[ChangeSetEntity],
    ):
        super().__init__(scope=scope, change_type=change_type)
        self.name = name
        self.type_ = type_
        self.dynamic_value = dynamic_value
        self.default_value = default_value


class NodeParameters(ChangeSetNode):
    parameters: Final[list[NodeParameter]]

    def __init__(self, scope: Scope, change_type: ChangeType, parameters: list[NodeParameter]):
        super().__init__(scope=scope, change_type=change_type)
        self.parameters = parameters


class NodeMapping(ChangeSetNode):
    name: Final[str]
    bindings: Final[NodeObject]

    def __init__(self, scope: Scope, change_type: ChangeType, name: str, bindings: NodeObject):
        super().__init__(scope=scope, change_type=change_type)
        self.name = name
        self.bindings = bindings


class NodeMappings(ChangeSetNode):
    mappings: Final[list[NodeMapping]]

    def __init__(self, scope: Scope, change_type: ChangeType, mappings: list[NodeMapping]):
        super().__init__(scope=scope, change_type=change_type)
        self.mappings = mappings


class NodeOutput(ChangeSetNode):
    name: Final[str]
    value: Final[ChangeSetEntity]
    export: Final[Optional[ChangeSetEntity]]
    condition_reference: Final[Optional[TerminalValue]]

    def __init__(
        self,
        scope: Scope,
        change_type: ChangeType,
        name: str,
        value: ChangeSetEntity,
        export: Optional[ChangeSetEntity],
        conditional_reference: Optional[TerminalValue],
    ):
        super().__init__(scope=scope, change_type=change_type)
        self.name = name
        self.value = value
        self.export = export
        self.condition_reference = conditional_reference


class NodeOutputs(ChangeSetNode):
    outputs: Final[list[NodeOutput]]

    def __init__(self, scope: Scope, change_type: ChangeType, outputs: list[NodeOutput]):
        super().__init__(scope=scope, change_type=change_type)
        self.outputs = outputs


class NodeCondition(ChangeSetNode):
    name: Final[str]
    body: Final[ChangeSetEntity]

    def __init__(self, scope: Scope, change_type: ChangeType, name: str, body: ChangeSetEntity):
        super().__init__(scope=scope, change_type=change_type)
        self.name = name
        self.body = body


class NodeConditions(ChangeSetNode):
    conditions: Final[list[NodeCondition]]

    def __init__(self, scope: Scope, change_type: ChangeType, conditions: list[NodeCondition]):
        super().__init__(scope=scope, change_type=change_type)
        self.conditions = conditions


class NodeResources(ChangeSetNode):
    resources: Final[list[NodeResource]]

    def __init__(self, scope: Scope, change_type: ChangeType, resources: list[NodeResource]):
        super().__init__(scope=scope, change_type=change_type)
        self.resources = resources


class NodeResource(ChangeSetNode):
    name: Final[str]
    type_: Final[ChangeSetTerminal]
    condition_reference: Final[Optional[TerminalValue]]
    properties: Final[NodeProperties]

    def __init__(
        self,
        scope: Scope,
        change_type: ChangeType,
        name: str,
        type_: ChangeSetTerminal,
        condition_reference: TerminalValue,
        properties: NodeProperties,
    ):
        super().__init__(scope=scope, change_type=change_type)
        self.name = name
        self.type_ = type_
        self.condition_reference = condition_reference
        self.properties = properties


class NodeProperties(ChangeSetNode):
    properties: Final[list[NodeProperty]]

    def __init__(self, scope: Scope, change_type: ChangeType, properties: list[NodeProperty]):
        super().__init__(scope=scope, change_type=change_type)
        self.properties = properties


class NodeProperty(ChangeSetNode):
    name: Final[str]
    value: Final[ChangeSetEntity]

    def __init__(self, scope: Scope, change_type: ChangeType, name: str, value: ChangeSetEntity):
        super().__init__(scope=scope, change_type=change_type)
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
# TODO: expand intrinsic functions set.
RefKey: Final[str] = "Ref"
FnIf: Final[str] = "Fn::If"
FnNot: Final[str] = "Fn::Not"
FnGetAttKey: Final[str] = "Fn::GetAtt"
FnEqualsKey: Final[str] = "Fn::Equals"
FnFindInMapKey: Final[str] = "Fn::FindInMap"
INTRINSIC_FUNCTIONS: Final[set[str]] = {
    RefKey,
    FnIf,
    FnNot,
    FnEqualsKey,
    FnGetAttKey,
    FnFindInMapKey,
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
        before_template: Optional[dict],
        after_template: Optional[dict],
        before_parameters: Optional[dict],
        after_parameters: Optional[dict],
    ):
        self._before_template = before_template or Nothing
        self._after_template = after_template or Nothing
        self._before_parameters = before_parameters or Nothing
        self._after_parameters = after_parameters or Nothing
        self._visited_scopes = dict()
        self._node_template = self._model(
            before_template=self._before_template, after_template=self._after_template
        )
        # TODO: need to do template preprocessing e.g. parameter resolution, conditions etc.

    def get_update_model(self) -> NodeTemplate:
        # TODO: rethink naming of this for outer utils
        return self._node_template

    def _visit_terminal_value(
        self, scope: Scope, before_value: Maybe[Any], after_value: Maybe[Any]
    ) -> TerminalValue:
        terminal_value = self._visited_scopes.get(scope)
        if isinstance(terminal_value, TerminalValue):
            return terminal_value
        if self._is_created(before=before_value, after=after_value):
            terminal_value = TerminalValueCreated(scope=scope, value=after_value)
        elif self._is_removed(before=before_value, after=after_value):
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
        arguments = self._visit_value(
            scope=scope, before_value=before_arguments, after_value=after_arguments
        )
        if self._is_created(before=before_arguments, after=after_arguments):
            change_type = ChangeType.CREATED
        elif self._is_removed(before=before_arguments, after=after_arguments):
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
        node_intrinsic_function = NodeIntrinsicFunction(
            scope=scope,
            change_type=change_type,
            intrinsic_function=intrinsic_function,
            arguments=arguments,
        )
        self._visited_scopes[scope] = node_intrinsic_function
        return node_intrinsic_function

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
        # TODO: add support for nested functions, here we assume the argument is a logicalID.
        if not isinstance(arguments, TerminalValue):
            return arguments.change_type

        logical_id = arguments.value

        node_condition = self._retrieve_condition_if_exists(condition_name=logical_id)
        if isinstance(node_condition, NodeCondition):
            return node_condition.change_type

        node_parameter = self._retrieve_parameter_if_exists(parameter_name=logical_id)
        if isinstance(node_parameter, NodeParameter):
            return node_parameter.change_type

        # TODO: this should check the replacement flag for a resource update.
        node_resource = self._retrieve_or_visit_resource(resource_name=logical_id)
        return node_resource.change_type

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
        change_types = [node_condition.change_type, *arguments.array[1:]]
        change_type = self._change_type_for_parent_of(change_types=change_types)
        return change_type

    def _visit_array(
        self, scope: Scope, before_array: Maybe[list], after_array: Maybe[list]
    ) -> NodeArray:
        array: list[ChangeSetEntity] = list()
        for index, (before_value, after_value) in enumerate(
            zip_longest(before_array, after_array, fillvalue=Nothing)
        ):
            value_scope = scope.open_index(index=index)
            value = self._visit_value(
                scope=value_scope, before_value=before_value, after_value=after_value
            )
            array.append(value)
        change_type = self._change_type_for_parent_of([value.change_type for value in array])
        return NodeArray(scope=scope, change_type=change_type, array=array)

    def _visit_object(
        self, scope: Scope, before_object: Maybe[dict], after_object: Maybe[dict]
    ) -> NodeObject:
        node_object = self._visited_scopes.get(scope)
        if isinstance(node_object, NodeObject):
            return node_object

        change_type = ChangeType.UNCHANGED
        binding_names = self._safe_keys_of(before_object, after_object)
        bindings: dict[str, ChangeSetEntity] = dict()
        for binding_name in binding_names:
            binding_scope, (before_value, after_value) = self._safe_access_in(
                scope, binding_name, before_object, after_object
            )
            value = self._visit_value(
                scope=binding_scope, before_value=before_value, after_value=after_value
            )
            bindings[binding_name] = value
            change_type = change_type.for_child(value.change_type)
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
        elif self._is_created(before=before_value, after=after_value):
            dominant_value = after_value
        elif self._is_removed(before=before_value, after=after_value):
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
                    scope=scope,
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
        value = self._visit_value(
            scope=scope, before_value=before_property, after_value=after_property
        )
        node_property = NodeProperty(
            scope=scope, change_type=value.change_type, name=property_name, value=value
        )
        self._visited_scopes[scope] = node_property
        return node_property

    def _visit_properties(
        self, scope: Scope, before_properties: Maybe[dict], after_properties: Maybe[dict]
    ) -> NodeProperties:
        node_properties = self._visited_scopes.get(scope)
        if isinstance(node_properties, NodeProperties):
            return node_properties
        # TODO: double check we are sure not to have this be a NodeObject
        property_names: list[str] = self._safe_keys_of(before_properties, after_properties)
        properties: list[NodeProperty] = list()
        change_type = ChangeType.UNCHANGED
        for property_name in property_names:
            property_scope, (before_property, after_property) = self._safe_access_in(
                scope, property_name, before_properties, after_properties
            )
            property_ = self._visit_property(
                scope=property_scope,
                property_name=property_name,
                before_property=before_property,
                after_property=after_property,
            )
            properties.append(property_)
            change_type = change_type.for_child(property_.change_type)
        node_properties = NodeProperties(
            scope=scope, change_type=change_type, properties=properties
        )
        self._visited_scopes[scope] = node_properties
        return node_properties

    def _visit_type(self, scope: Scope, before_type: Any, after_type: Any) -> TerminalValue:
        value = self._visit_value(scope=scope, before_value=before_type, after_value=after_type)
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

        if self._is_created(before=before_resource, after=after_resource):
            change_type = ChangeType.CREATED
        elif self._is_removed(before=before_resource, after=after_resource):
            change_type = ChangeType.REMOVED
        else:
            change_type = ChangeType.UNCHANGED

        scope_type, (before_type, after_type) = self._safe_access_in(
            scope, TypeKey, before_resource, after_resource
        )
        terminal_value_type = self._visit_type(
            scope=scope_type, before_type=before_type, after_type=after_type
        )

        condition_reference = None
        scope_condition, (before_condition, after_condition) = self._safe_access_in(
            scope, ConditionKey, before_resource, after_resource
        )
        # TODO: condition references should be resolved for the condition's change_type?
        if before_condition or after_condition:
            condition_reference = self._visit_terminal_value(
                scope_condition, before_condition, after_condition
            )

        scope_properties, (before_properties, after_properties) = self._safe_access_in(
            scope, PropertiesKey, before_resource, after_resource
        )
        properties = self._visit_properties(
            scope=scope_properties,
            before_properties=before_properties,
            after_properties=after_properties,
        )
        if properties.properties:
            # Properties were defined in the before or after template, thus must play a role
            # in affecting the change type of this resource.
            change_type = change_type.for_child(properties.change_type)
        node_resource = NodeResource(
            scope=scope,
            change_type=change_type,
            name=resource_name,
            type_=terminal_value_type,
            condition_reference=condition_reference,
            properties=properties,
        )
        self._visited_scopes[scope] = node_resource
        return node_resource

    def _visit_resources(
        self, scope: Scope, before_resources: Maybe[dict], after_resources: Maybe[dict]
    ) -> NodeResources:
        # TODO: investigate type changes behavior.
        change_type = ChangeType.UNCHANGED
        resources: list[NodeResource] = list()
        resource_names = self._safe_keys_of(before_resources, after_resources)
        for resource_name in resource_names:
            resource_scope, (before_resource, after_resource) = self._safe_access_in(
                scope, resource_name, before_resources, after_resources
            )
            resource = self._visit_resource(
                scope=resource_scope,
                resource_name=resource_name,
                before_resource=before_resource,
                after_resource=after_resource,
            )
            resources.append(resource)
            change_type = change_type.for_child(resource.change_type)
        return NodeResources(scope=scope, change_type=change_type, resources=resources)

    def _visit_mapping(
        self, scope: Scope, name: str, before_mapping: Maybe[dict], after_mapping: Maybe[dict]
    ) -> NodeMapping:
        bindings = self._visit_object(
            scope=scope, before_object=before_mapping, after_object=after_mapping
        )
        return NodeMapping(
            scope=scope, change_type=bindings.change_type, name=name, bindings=bindings
        )

    def _visit_mappings(
        self, scope: Scope, before_mappings: Maybe[dict], after_mappings: Maybe[dict]
    ) -> NodeMappings:
        change_type = ChangeType.UNCHANGED
        mappings: list[NodeMapping] = list()
        mapping_names = self._safe_keys_of(before_mappings, after_mappings)
        for mapping_name in mapping_names:
            scope_mapping, (before_mapping, after_mapping) = self._safe_access_in(
                scope, mapping_name, before_mappings, after_mappings
            )
            mapping = self._visit_mapping(
                scope=scope,
                name=mapping_name,
                before_mapping=before_mapping,
                after_mapping=after_mapping,
            )
            mappings.append(mapping)
            change_type = change_type.for_child(mapping.change_type)
        return NodeMappings(scope=scope, change_type=change_type, mappings=mappings)

    def _visit_dynamic_parameter(self, parameter_name: str) -> ChangeSetEntity:
        scope = Scope("Dynamic").open_scope("Parameters")
        scope_parameter, (before_parameter, after_parameter) = self._safe_access_in(
            scope, parameter_name, self._before_parameters, self._after_parameters
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

        change_type = self._change_type_for_parent_of(
            change_types=[type_.change_type, default_value.change_type, dynamic_value.change_type]
        )

        node_parameter = NodeParameter(
            scope=scope,
            change_type=change_type,
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
        parameters: list[NodeParameter] = list()
        change_type = ChangeType.UNCHANGED
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
            change_type = change_type.for_child(parameter.change_type)
        node_parameters = NodeParameters(
            scope=scope, change_type=change_type, parameters=parameters
        )
        self._visited_scopes[scope] = node_parameters
        return node_parameters

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
        node_condition = NodeCondition(
            scope=scope, change_type=body.change_type, name=condition_name, body=body
        )
        self._visited_scopes[scope] = node_condition
        return node_condition

    def _visit_conditions(
        self, scope: Scope, before_conditions: Maybe[dict], after_conditions: Maybe[dict]
    ) -> NodeConditions:
        node_conditions = self._visited_scopes.get(scope)
        if isinstance(node_conditions, NodeConditions):
            return node_conditions
        condition_names: list[str] = self._safe_keys_of(before_conditions, after_conditions)
        conditions: list[NodeCondition] = list()
        change_type = ChangeType.UNCHANGED
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
            change_type = change_type.for_child(child_change_type=condition.change_type)
        node_conditions = NodeConditions(
            scope=scope, change_type=change_type, conditions=conditions
        )
        self._visited_scopes[scope] = node_conditions
        return node_conditions

    def _visit_output(
        self, scope: Scope, name: str, before_output: Maybe[dict], after_output: Maybe[dict]
    ) -> NodeOutput:
        change_type = ChangeType.UNCHANGED
        scope_value, (before_value, after_value) = self._safe_access_in(
            scope, ValueKey, before_output, after_output
        )
        value = self._visit_value(scope_value, before_value, after_value)
        change_type = change_type.for_child(value.change_type)

        export: Optional[ChangeSetEntity] = None
        scope_export, (before_export, after_export) = self._safe_access_in(
            scope, ExportKey, before_output, after_output
        )
        if before_export or after_export:
            export = self._visit_value(scope_export, before_export, after_export)
            change_type = change_type.for_child(export.change_type)

        # TODO: condition references should be resolved for the condition's change_type?
        condition_reference: Optional[TerminalValue] = None
        scope_condition, (before_condition, after_condition) = self._safe_access_in(
            scope, ConditionKey, before_output, after_output
        )
        if before_condition or after_condition:
            condition_reference = self._visit_terminal_value(
                scope_condition, before_condition, after_condition
            )
            change_type = change_type.for_child(condition_reference.change_type)

        return NodeOutput(
            scope=scope,
            change_type=change_type,
            name=name,
            value=value,
            export=export,
            conditional_reference=condition_reference,
        )

    def _visit_outputs(
        self, scope: Scope, before_outputs: Maybe[dict], after_outputs: Maybe[dict]
    ) -> NodeOutputs:
        change_type = ChangeType.UNCHANGED
        outputs: list[NodeOutput] = list()
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
            change_type = change_type.for_child(output.change_type)
        return NodeOutputs(scope=scope, change_type=change_type, outputs=outputs)

    def _model(self, before_template: Maybe[dict], after_template: Maybe[dict]) -> NodeTemplate:
        root_scope = Scope()
        # TODO: visit other child types

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

        # TODO: compute the change_type of the template properly.
        return NodeTemplate(
            scope=root_scope,
            change_type=resources.change_type,
            mappings=mappings,
            parameters=parameters,
            conditions=conditions,
            resources=resources,
            outputs=outputs,
        )

    def _retrieve_condition_if_exists(self, condition_name: str) -> Optional[NodeCondition]:
        conditions_scope, (before_conditions, after_conditions) = self._safe_access_in(
            Scope(), ConditionsKey, self._before_template, self._after_template
        )
        before_conditions = before_conditions or dict()
        after_conditions = after_conditions or dict()
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
        return None

    def _retrieve_parameter_if_exists(self, parameter_name: str) -> Optional[NodeParameter]:
        parameters_scope, (before_parameters, after_parameters) = self._safe_access_in(
            Scope(), ParametersKey, self._before_template, self._after_template
        )
        before_parameters = before_parameters or dict()
        after_parameters = after_parameters or dict()
        if parameter_name in before_parameters or parameter_name in after_parameters:
            parameter_scope, (before_parameter, after_parameter) = self._safe_access_in(
                parameters_scope, parameter_name, before_parameters, after_parameters
            )
            node_parameter = self._visit_parameter(
                parameters_scope,
                parameter_name,
                before_parameter=before_parameter,
                after_parameter=after_parameter,
            )
            return node_parameter
        return None

    def _retrieve_mapping(self, mapping_name) -> NodeMapping:
        # TODO: add caching mechanism, and raise appropriate error if missing.
        scope_mappings, (before_mappings, after_mappings) = self._safe_access_in(
            Scope(), MappingsKey, self._before_template, self._after_template
        )
        before_mappings = before_mappings or dict()
        after_mappings = after_mappings or dict()
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
        results = list()
        for obj in objects:
            # TODO: raise errors if not dict
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
    def _change_type_for_parent_of(change_types: list[ChangeType]) -> ChangeType:
        parent_change_type = ChangeType.UNCHANGED
        for child_change_type in change_types:
            parent_change_type = parent_change_type.for_child(child_change_type)
            if parent_change_type == ChangeType.MODIFIED:
                break
        return parent_change_type

    @staticmethod
    def _name_if_intrinsic_function(value: Maybe[Any]) -> Optional[str]:
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

    @staticmethod
    def _is_created(before: Maybe[Any], after: Maybe[Any]) -> bool:
        return isinstance(before, NothingType) and not isinstance(after, NothingType)

    @staticmethod
    def _is_removed(before: Maybe[Any], after: Maybe[Any]) -> bool:
        return not isinstance(before, NothingType) and isinstance(after, NothingType)

from __future__ import annotations

import abc
import enum
from itertools import zip_longest
from typing import Any, Final, Generator, Optional, Union

from typing_extensions import TypeVar

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


Maybe = Union[T, NothingType]
Nothing = NothingType()


class ChangeType(enum.Enum):
    UNCHANGED = "Unchanged"
    CREATED = "Created"
    MODIFIED = "Modified"
    REMOVED = "Removed"

    def __str__(self):
        return self.value


class ChangeSetEntity(abc.ABC):
    change_type: Final[ChangeType]

    def __init__(self, change_type: ChangeType):
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
    resources: Final[NodeResources]

    def __init__(self, change_type: ChangeType, resources: NodeResources):
        super().__init__(change_type=change_type)
        self.resources = resources


class NodeResources(ChangeSetNode):
    resources: Final[list[NodeResource]]

    def __init__(self, change_type: ChangeType, resources: list[NodeResource]):
        super().__init__(change_type=change_type)
        self.resources = resources


class NodeResource(ChangeSetNode):
    name: Final[str]
    type_: Final[ChangeSetTerminal]
    properties: Final[NodeProperties]

    def __init__(
        self,
        change_type: ChangeType,
        name: str,
        type_: ChangeSetTerminal,
        properties: NodeProperties,
    ):
        super().__init__(change_type=change_type)
        self.name = name
        self.type_ = type_
        self.properties = properties


class NodeProperties(ChangeSetNode):
    properties: Final[list[NodeProperty]]

    def __init__(self, change_type: ChangeType, properties: list[NodeProperty]):
        super().__init__(change_type=change_type)
        self.properties = properties


class NodeProperty(ChangeSetNode):
    name: Final[str]
    value: Final[ChangeSetEntity]

    def __init__(self, change_type: ChangeType, name: str, value: ChangeSetEntity):
        super().__init__(change_type=change_type)
        self.name = name
        self.value = value


class NodeObject(ChangeSetNode):
    bindings: Final[dict[str, ChangeSetEntity]]

    def __init__(self, change_type: ChangeType, bindings: dict[str, ChangeSetEntity]):
        super().__init__(change_type=change_type)
        self.bindings = bindings


class NodeArray(ChangeSetNode):
    array: Final[list[ChangeSetEntity]]

    def __init__(self, change_type: ChangeType, array: list[ChangeSetEntity]):
        super().__init__(change_type=change_type)
        self.array = array


class TerminalValue(ChangeSetTerminal, abc.ABC):
    value: Final[Any]

    def __init__(self, change_type: ChangeType, value: Any):
        super().__init__(change_type=change_type)
        self.value = value


class TerminalValueModified(TerminalValue):
    modified_value: Final[Any]

    def __init__(self, value: Any, modified_value: Any):
        super().__init__(change_type=ChangeType.MODIFIED, value=value)
        self.modified_value = modified_value


class TerminalValueCreated(TerminalValue):
    def __init__(self, value: Any):
        super().__init__(change_type=ChangeType.CREATED, value=value)


class TerminalValueRemoved(TerminalValue):
    def __init__(self, value: Any):
        super().__init__(change_type=ChangeType.REMOVED, value=value)


class TerminalValueUnchanged(TerminalValue):
    def __init__(self, value: Any):
        super().__init__(change_type=ChangeType.UNCHANGED, value=value)


ResourcesKey: Final[str] = "Resources"
PropertiesKey: Final[str] = "Properties"


class ChangeSetModel:
    # TODO: should this instead be generalised to work on "Stack" objects instead of just "Template"s?

    # TODO: can probably improve the typehints to use CFN's 'language' eg. dict -> Template|Properties, etc.

    # TODO: typechecks for key-value pairs?

    _before_template: Final[Maybe[dict]]
    _after_template: Final[Maybe[dict]]
    _node_template: Final[NodeTemplate]

    def __init__(self, before_template: Optional[dict], after_template: Optional[dict]):
        self._before_template = before_template or Nothing
        self._after_template = after_template or Nothing
        self._node_template = self._model(
            before_template=before_template, after_template=after_template
        )

    def get_update_model(self) -> NodeTemplate:
        # TODO: rethink naming of this for outer utils
        return self._node_template

    def _visit_terminal_value(  # noqa
        self, before_value: Maybe[Any], after_value: Maybe[Any]
    ) -> TerminalValue:
        if self._is_created(before=before_value, after=after_value):
            return TerminalValueCreated(value=after_value)
        if self._is_removed(before=before_value, after=after_value):
            return TerminalValueRemoved(value=before_value)
        if before_value == after_value:
            return TerminalValueUnchanged(value=before_value)
        return TerminalValueModified(value=before_value, modified_value=after_value)

    def _visit_array(self, before_array: Maybe[list], after_array: Maybe[list]) -> NodeArray:
        change_type = ChangeType.UNCHANGED
        array: list[ChangeSetEntity] = list()
        for before_value, after_value in zip_longest(before_array, after_array, fillvalue=Nothing):
            value = self._visit_value(before_value=before_value, after_value=after_value)
            array.append(value)
            if value.change_type != ChangeType.UNCHANGED:
                change_type = ChangeType.MODIFIED
        return NodeArray(change_type=change_type, array=array)

    def _visit_object(self, before_object: Maybe[dict], after_object: Maybe[dict]) -> NodeObject:
        change_type = ChangeType.UNCHANGED
        binding_names = self._keys_of(before_object, after_object)
        bindings: dict[str, ChangeSetEntity] = dict()
        for binding_name in binding_names:
            # TODO: check the binding names for intrinsic functions and redirect.
            before_value, after_value = self._sample_from(binding_name, before_object, after_object)
            value = self._visit_value(before_value=before_value, after_value=after_value)
            bindings[binding_name] = value
            if value.change_type != ChangeType.UNCHANGED:
                change_type = ChangeType.MODIFIED
        return NodeObject(change_type=change_type, bindings=bindings)

    def _visit_value(self, before_value: Maybe[Any], after_value: Maybe[Any]) -> ChangeSetEntity:
        before_type = type(before_value)
        after_type = type(after_value)

        if self._is_created(before=before_value, after=after_value):
            return TerminalValueCreated(value=after_value)
        if self._is_removed(before=before_value, after=after_value):
            return TerminalValueRemoved(value=before_value)

        # Case: update on the same type.
        if before_type == after_type:
            if self._is_terminal(value=before_value):
                value = self._visit_terminal_value(
                    before_value=before_value, after_value=after_value
                )
            elif self._is_object(value=before_value):
                value = self._visit_object(before_object=before_value, after_object=after_value)
            elif self._is_array(value=before_value):
                value = self._visit_array(before_array=before_value, after_array=after_value)
            else:
                raise RuntimeError(f"Unsupported type {before_type}")
            return value
        # Case: update to new type.
        else:
            return TerminalValueModified(value=before_value, modified_value=after_value)

    def _visit_property(
        self, property_name: str, before_property: Maybe[Any], after_property: Maybe[Any]
    ) -> NodeProperty:
        if self._is_created(before=before_property, after=after_property):
            return NodeProperty(
                change_type=ChangeType.CREATED,
                name=property_name,
                value=TerminalValueCreated(value=after_property),
            )
        if self._is_removed(before=before_property, after=after_property):
            return NodeProperty(
                change_type=ChangeType.REMOVED,
                name=property_name,
                value=TerminalValueRemoved(value=before_property),
            )
        value = self._visit_value(before_value=before_property, after_value=after_property)
        return NodeProperty(change_type=value.change_type, name=property_name, value=value)

    def _visit_properties(
        self, before_properties: Maybe[dict], after_properties: Maybe[dict]
    ) -> NodeProperties:
        # TODO: double check we are sure not to have this be a NodeObject
        property_names: set[str] = self._keys_of(before_properties, after_properties)
        properties: list[NodeProperty] = list()
        change_type = ChangeType.UNCHANGED
        for property_name in property_names:
            before_property, after_property = self._sample_from(
                property_name, before_properties, after_properties
            )
            property_ = self._visit_property(
                property_name=property_name,
                before_property=before_property,
                after_property=after_property,
            )
            properties.append(property_)
            # TODO: compute the properties change type properly.
            if property_.change_type != ChangeType.UNCHANGED:
                change_type = change_type.MODIFIED
        return NodeProperties(change_type=change_type, properties=properties)

    def _visit_resource(
        self, resource_name: str, before_resource: Maybe[dict], after_resource: Maybe[dict]
    ) -> NodeResource:
        if self._is_created(before=before_resource, after=after_resource):
            change_type = ChangeType.CREATED
        elif self._is_removed(before=before_resource, after=after_resource):
            change_type = ChangeType.REMOVED
        else:
            change_type = ChangeType.UNCHANGED

        before_properties, after_properties = self._sample_from(
            PropertiesKey, before_resource, after_resource
        )
        properties = self._visit_properties(
            before_properties=before_properties, after_properties=after_properties
        )

        if change_type == ChangeType.UNCHANGED and properties.change_type != ChangeType.UNCHANGED:
            change_type = ChangeType.MODIFIED

        return NodeResource(
            change_type=change_type,
            name=resource_name,
            # TODO: investigate behaviour with type changes, for now this is filler code.
            type_=TerminalValueUnchanged(value="<Type>"),
            properties=properties,
        )

    def _visit_resources(
        self, before_resources: Maybe[dict], after_resources: Maybe[dict]
    ) -> NodeResources:
        # TODO: investigate type changes behavior.
        change_type = ChangeType.UNCHANGED
        resources: list[NodeResource] = list()
        resource_names = self._keys_of(before_resources, after_resources)
        for resource_name in resource_names:
            before_resource, after_resource = self._sample_from(
                resource_name, before_resources, after_resources
            )
            resource = self._visit_resource(
                resource_name=resource_name,
                before_resource=before_resource,
                after_resource=after_resource,
            )
            resources.append(resource)
            # TODO: compute the properties change type properly.
            if resource.change_type != ChangeType.UNCHANGED:
                change_type = ChangeType.MODIFIED
        return NodeResources(change_type=change_type, resources=resources)

    def _model(self, before_template: Maybe[dict], after_template: Maybe[dict]) -> NodeTemplate:
        # TODO: visit other child types
        before_resources, after_resources = self._sample_from(
            ResourcesKey, before_template, after_template
        )
        resources = self._visit_resources(
            before_resources=before_resources, after_resources=after_resources
        )
        # TODO: what is a change type for templates?
        return NodeTemplate(change_type=resources.change_type, resources=resources)

    @staticmethod
    def _sample_from(key: str, *objects: Maybe[dict]) -> Maybe[Any]:
        results = list()
        for obj in objects:
            # TODO: raise errors if not dict
            if not isinstance(obj, NothingType):
                results.append(obj.get(key, Nothing))
            else:
                results.append(obj)
        return results[0] if len(objects) == 1 else tuple(results)

    @staticmethod
    def _keys_of(*objects: Maybe[dict]) -> set[str]:
        keys: set[str] = set()
        for obj in objects:
            # TODO: raise errors if not dict
            if isinstance(obj, dict):
                keys.update(obj.keys())
        return set(keys)

    @staticmethod
    def _is_terminal(value: Any) -> bool:
        return type(value) in {int, float, bool, str, None}

    @staticmethod
    def _is_object(value: Any) -> bool:
        return isinstance(value, dict)

    @staticmethod
    def _is_array(value: Any) -> bool:
        return isinstance(value, list)

    @staticmethod
    def _is_created(before: Maybe[Any], after: Maybe[Any]) -> bool:
        return isinstance(before, NothingType) and not isinstance(after, NothingType)

    @staticmethod
    def _is_removed(before: Maybe[Any], after: Maybe[Any]) -> bool:
        return not isinstance(before, NothingType) and isinstance(after, NothingType)

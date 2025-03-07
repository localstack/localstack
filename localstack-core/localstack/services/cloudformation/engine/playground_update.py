from __future__ import annotations

import abc
import enum
from itertools import zip_longest
from typing import Any, Final, Generator, Optional

from localstack.aws.api.cloudformation import ChangeAction, ResourceChange
from localstack.utils.strings import camel_to_snake_case


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


class NoSuchValue: ...


ResourcesKey: Final[str] = "Resources"
PropertiesKey: Final[str] = "Properties"


class ChangeSetModeler:
    # TODO: fix type hints in the modeler class, the use of Optional[...] is incorrect, it should reflect
    #  that the type could be NoSuchValue, like Maybe[innertype] === innertype | NoSuchValue
    def _visit_terminal_value(  # noqa
        self, before_value: Optional[Any], after_value: Optional[Any]
    ) -> TerminalValue:
        if self._is_created(before=before_value, after=after_value):
            return TerminalValueCreated(value=after_value)
        if self._is_removed(before=before_value, after=after_value):
            return TerminalValueRemoved(value=before_value)
        if before_value == after_value:
            return TerminalValueUnchanged(value=before_value)
        return TerminalValueModified(value=before_value, modified_value=after_value)

    def _visit_array(self, before_array: Optional[list], after_array: Optional[list]) -> NodeArray:
        change_type = ChangeType.UNCHANGED
        array: list[ChangeSetEntity] = list()
        for before_value, after_value in zip_longest(
            before_array, after_array, fillvalue=NoSuchValue()
        ):
            value = self._visit_value(before_value=before_value, after_value=after_value)
            array.append(value)
            if value.change_type != ChangeType.UNCHANGED:
                change_type = ChangeType.MODIFIED
        return NodeArray(change_type=change_type, array=array)

    def _visit_object(
        self, before_object: Optional[dict], after_object: Optional[dict]
    ) -> NodeObject:
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

    def _visit_value(
        self, before_value: Optional[Any], after_value: Optional[Any]
    ) -> ChangeSetEntity:
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
            # TODO: this is a type divergence at this depth, investigate how CFN handles this,
            #  we might need to introduce a NodeDivergence(before, after), or move the change_type
            #  to reusable (node and terminal) link classes?
            # raise NotImplementedError()

            # TODO: arguably, once a divergence is found, this is a terminal state for the update
            #  graph, as a value is changed.
            return TerminalValueModified(value=before_value, modified_value=after_value)

    def _visit_property(
        self, property_name: str, before_property: Optional[Any], after_property: Optional[Any]
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
        self, before_properties: Optional[dict], after_properties: Optional[dict]
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
        self, resource_name: str, before_resource: Optional[dict], after_resource: Optional[dict]
    ) -> NodeResource:
        # TODO: fix add/delete/unchanged logic, needs minor rework of node types being update informants
        before_properties, after_properties = self._sample_from(
            PropertiesKey, before_resource, after_resource
        )
        properties = self._visit_properties(
            before_properties=before_properties, after_properties=after_properties
        )

        change_type = properties.change_type
        if isinstance(before_resource, NoSuchValue) and after_resource:
            change_type = ChangeType.CREATED
        elif before_resource and isinstance(after_resource, NoSuchValue):
            change_type = ChangeType.REMOVED

        return NodeResource(
            change_type=change_type,
            name=resource_name,
            # TODO: investigate behaviour with type changes, for now this is filler code.
            type_=TerminalValueUnchanged(value="TODO!"),
            properties=properties,
        )

    def _visit_resources(self, before_resources: dict, after_resources: dict) -> NodeResources:
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

    def model(self, before_template: dict, after_template: dict) -> NodeTemplate:
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
    def _sample_from(key: str, *objects: dict | NoSuchValue) -> Any | NoSuchValue:
        results = list()
        for obj in objects:
            # TODO: raise errors if not dict
            if not isinstance(obj, NoSuchValue):
                results.append(obj.get(key, NoSuchValue()))
            else:
                results.append(obj)
        return results[0] if len(objects) == 1 else tuple(results)

    @staticmethod
    def _keys_of(*objects: dict | NoSuchValue) -> set[str]:
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
    def _is_created(before: Any | NoSuchValue, after: Any | NoSuchValue) -> bool:
        return isinstance(before, NoSuchValue) and not isinstance(after, NoSuchValue)

    @staticmethod
    def _is_removed(before: Any | NoSuchValue, after: Any | NoSuchValue) -> bool:
        return not isinstance(before, NoSuchValue) and isinstance(after, NoSuchValue)


class ChangeSetModelVisitor(abc.ABC):
    # TODO: this class should be auto generated.

    # TODO: add visitors for abstract classes so shared logic can be implemented
    #  just once in classes extending this.

    def visit(self, change_set_entity: ChangeSetEntity):
        # TODO: speed up this lookup logic
        type_str = change_set_entity.__class__.__name__
        type_str = camel_to_snake_case(type_str).lower()
        visit_function_name = f"visit_{type_str}"
        visit_function = getattr(self, visit_function_name)
        return visit_function(change_set_entity)

    def visit_children(self, change_set_entity: ChangeSetEntity):
        children = change_set_entity.get_children()
        for child in children:
            self.visit(child)

    def visit_node_template(self, node_template: NodeTemplate):
        self.visit_children(node_template)

    def visit_node_resources(self, node_resources: NodeResources):
        self.visit_children(node_resources)

    def visit_node_resource(self, node_resource: NodeResource):
        self.visit_children(node_resource)

    def visit_node_properties(self, node_properties: NodeProperties):
        self.visit_children(node_properties)

    def visit_node_property(self, node_property: NodeProperty):
        self.visit_children(node_property)

    def visit_node_object(self, node_object: NodeObject):
        self.visit_children(node_object)

    def visit_node_array(self, node_array: NodeArray):
        self.visit_children(node_array)

    def visit_terminal_value_modified(self, terminal_value_modified: TerminalValueModified):
        self.visit_children(terminal_value_modified)

    def visit_terminal_value_created(self, terminal_value_created: TerminalValueCreated):
        self.visit_children(terminal_value_created)

    def visit_terminal_value_removed(self, terminal_value_removed: TerminalValueRemoved):
        self.visit_children(terminal_value_removed)

    def visit_terminal_value_unchanged(self, terminal_value_unchanged: TerminalValueUnchanged):
        self.visit_children(terminal_value_unchanged)


class ChangeSetDescribeUnit(abc.ABC):
    context: Optional[Any]

    def __init__(self, context: Optional[Any]):
        self.context = context


class ChangeSetDescribeUnitAddition(ChangeSetDescribeUnit):
    pass


class ChangeSetDescribeUnitDeletion(ChangeSetDescribeUnit):
    pass


# TODO: unchanged can probably be pruned from the evaluation and be an empty value?
class ChangeSetDescribeUnitUnchanged(ChangeSetDescribeUnit):
    pass


class ChangeSetDescribeUnitUpdate(ChangeSetDescribeUnit):
    after_context: Optional[Any]

    def __init__(self, context: Optional[Any], after_context: Optional[Any]):
        super().__init__(context=context)
        self.after_context = after_context


class ChangeSetDescribeVisitor(ChangeSetModelVisitor):
    # TODO: expand to other change types?
    changes: list[ResourceChange] = list()

    def __init__(self):
        self.changes = list()

    def visit(self, change_set_entity: ChangeSetEntity) -> ChangeSetDescribeUnit:
        # Overridden for the return type hints.
        return super().visit(change_set_entity=change_set_entity)

    def visit_terminal_value_modified(
        self, terminal_value_modified: TerminalValueModified
    ) -> ChangeSetDescribeUnitUpdate:
        return ChangeSetDescribeUnitUpdate(
            context=terminal_value_modified.value,
            after_context=terminal_value_modified.modified_value,
        )

    def visit_terminal_value_created(
        self, terminal_value_created: TerminalValueCreated
    ) -> ChangeSetDescribeUnitAddition:
        return ChangeSetDescribeUnitAddition(context=terminal_value_created.value)

    def visit_terminal_value_removed(
        self, terminal_value_removed: TerminalValueRemoved
    ) -> ChangeSetDescribeUnitDeletion:
        return ChangeSetDescribeUnitDeletion(context=terminal_value_removed.value)

    def visit_terminal_value_unchanged(
        self, terminal_value_unchanged: TerminalValueUnchanged
    ) -> ChangeSetDescribeUnitUnchanged:
        return ChangeSetDescribeUnitUnchanged(context=terminal_value_unchanged.value)

    def visit_node_object(self, node_object: NodeObject) -> ChangeSetDescribeUnit:
        before_context = dict()
        after_context = dict()
        for name, change_set_update in node_object.bindings.items():
            describe_unit: ChangeSetDescribeUnit = self.visit(change_set_entity=change_set_update)
            if isinstance(describe_unit, ChangeSetDescribeUnitUpdate):
                before_context[name] = describe_unit.context
                after_context[name] = describe_unit.after_context
            elif isinstance(describe_unit, ChangeSetDescribeUnitAddition):
                after_context[name] = describe_unit.context
            elif isinstance(describe_unit, ChangeSetDescribeUnitDeletion):
                before_context[name] = describe_unit.context
            elif isinstance(describe_unit, ChangeSetDescribeUnitUnchanged):
                before_context[name] = describe_unit.context
                after_context[name] = describe_unit.context
            # Note: block is exhaustive about ChangeSetDescribeUnit
        match node_object.change_type:
            case ChangeType.MODIFIED:
                return ChangeSetDescribeUnitUpdate(
                    context=before_context, after_context=after_context
                )
            case ChangeType.CREATED:
                return ChangeSetDescribeUnitAddition(context=after_context)
            case ChangeType.UNCHANGED:
                return ChangeSetDescribeUnitUnchanged(context=before_context)
            case ChangeType.REMOVED:
                return ChangeSetDescribeUnitDeletion(context=before_context)
            case unsupported:
                # Note: match block is exhaustive about ChangeSet.
                raise RuntimeError(f"Unsupported ChangeType: '{unsupported}'")

    def visit_node_array(self, node_array: NodeArray) -> ChangeSetDescribeUnit:
        # TODO: is it worth chasing this duplication with visit_node_object?
        before_context = list()
        after_context = list()
        for change_set_entity in node_array.array:
            describe_unit: ChangeSetDescribeUnit = self.visit(change_set_entity=change_set_entity)
            if isinstance(describe_unit, ChangeSetDescribeUnitUpdate):
                before_context.append(describe_unit.context)
                after_context.append(describe_unit.after_context)
            elif isinstance(describe_unit, ChangeSetDescribeUnitAddition):
                after_context.append(describe_unit.context)
            elif isinstance(describe_unit, ChangeSetDescribeUnitDeletion):
                before_context.append(describe_unit.context)
            elif isinstance(describe_unit, ChangeSetDescribeUnitUnchanged):
                before_context.append(describe_unit.context)
                after_context.append(describe_unit.context)
        # Note: block is exhaustive about ChangeSetDescribeUnit
        match node_array.change_type:
            case ChangeType.MODIFIED:
                return ChangeSetDescribeUnitUpdate(
                    context=before_context, after_context=after_context
                )
            case ChangeType.CREATED:
                return ChangeSetDescribeUnitAddition(context=after_context)
            case ChangeType.UNCHANGED:
                return ChangeSetDescribeUnitUnchanged(context=before_context)
            case ChangeType.REMOVED:
                return ChangeSetDescribeUnitDeletion(context=before_context)
            case unsupported:
                # Note: match block is exhaustive about ChangeSet.
                raise RuntimeError(f"Unsupported ChangeType: '{unsupported}'")

    def visit_node_properties(self, node_properties: NodeProperties) -> ChangeSetDescribeUnit:
        before_context: dict[str, Any] = dict()
        after_context: dict[str, Any] = dict()
        for node_property in node_properties.properties:
            if node_property.change_type == ChangeType.UNCHANGED:
                continue
            describe_unit = self.visit(node_property.value)
            property_name = node_property.name
            # TODO: duplication
            if isinstance(describe_unit, ChangeSetDescribeUnitUpdate):
                before_context[property_name] = describe_unit.context
                after_context[property_name] = describe_unit.after_context
            elif isinstance(describe_unit, ChangeSetDescribeUnitAddition):
                after_context[property_name] = describe_unit.context
            elif isinstance(describe_unit, ChangeSetDescribeUnitDeletion):
                before_context[property_name] = describe_unit.context
            elif isinstance(describe_unit, ChangeSetDescribeUnitUnchanged):
                before_context[property_name] = describe_unit.context
                after_context[property_name] = describe_unit.context
        before_context = {PropertiesKey: before_context}
        after_context = {PropertiesKey: after_context}
        match node_properties.change_type:
            case ChangeType.MODIFIED:
                return ChangeSetDescribeUnitUpdate(
                    context=before_context, after_context=after_context
                )
            case ChangeType.CREATED:
                return ChangeSetDescribeUnitAddition(context=after_context)
            case ChangeType.UNCHANGED:
                return ChangeSetDescribeUnitUnchanged(context=before_context)
            case ChangeType.REMOVED:
                return ChangeSetDescribeUnitDeletion(context=before_context)
            case unsupported:
                # Note: match block is exhaustive about ChangeSet.
                raise RuntimeError(f"Unsupported ChangeType: '{unsupported}'")

    def visit_node_resource(self, node_resource: NodeResource) -> ChangeSetDescribeUnit:
        # TODO: It seems like all unit changes should have before and after, look at the
        #  duplication in change type deductions.
        describe_unit = self.visit_node_properties(node_resource.properties)
        resource_change = ResourceChange()
        resource_change["LogicalResourceId"] = node_resource.name
        if isinstance(describe_unit, ChangeSetDescribeUnitUpdate):
            resource_change["BeforeContext"] = describe_unit.context
            resource_change["AfterContext"] = describe_unit.after_context
        elif isinstance(describe_unit, ChangeSetDescribeUnitAddition):
            resource_change["AfterContext"] = describe_unit.context
        elif isinstance(describe_unit, ChangeSetDescribeUnitDeletion):
            resource_change["BeforeContext"] = describe_unit.context
        elif isinstance(describe_unit, ChangeSetDescribeUnitUnchanged):
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

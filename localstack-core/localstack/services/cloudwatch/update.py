from __future__ import annotations

import abc
from itertools import zip_longest
from typing import Any, Final, Generator, Optional

from localstack.aws.api.cloudformation import ChangeAction, ResourceChange
from localstack.utils.strings import camel_to_snake_case


class ChangeSetEntity(abc.ABC):
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


ChangeSetEntityBindings = dict[str, ChangeSetEntity]


class ChangeSetNode(ChangeSetEntity, abc.ABC): ...


class ChangeSetTerminal(ChangeSetEntity, abc.ABC): ...


class TemplateNode(ChangeSetNode):
    resources: Final[ResourcesNode]

    def __init__(self, resources: ResourcesNode):
        self.resources = resources


class ResourcesNode(ChangeSetNode):
    resources: Final[list[ResourceNode]]

    def __init__(self, resources: list[ResourceNode]):
        self.resources = resources


class ResourceNode(ChangeSetNode):
    typ: Final[ChangeSetTerminal]
    properties: Final[PropertiesNode]

    def __init__(self, typ: ChangeSetTerminal, properties: PropertiesNode):
        self.typ = typ
        self.properties = properties


class PropertiesNode(ChangeSetNode):
    properties: Final[ChangeSetEntityBindings]

    def __init__(self, properties: ChangeSetEntityBindings):
        self.properties = properties


class ObjectNode(ChangeSetNode):
    bindings: Final[ChangeSetEntityBindings]

    def __init__(self, bindings: ChangeSetEntityBindings):
        self.bindings = bindings


class UpdateValue(ChangeSetTerminal):
    before: Final[Any]
    after: Final[Any]

    def __init__(self, before: Any, after: Any):
        self.before = before
        self.after = after


class AddValue(ChangeSetTerminal):
    value: Final[Any]

    def __init__(self, value: Any):
        self.value = value


class DeleteValue(ChangeSetTerminal):
    value: Final[Any]

    def __init__(self, value: Any):
        self.value = value


class UnchangedValue(ChangeSetTerminal):
    value: Final[Any]

    def __init__(self, value: Any):
        self.value = value


class ChangeSetModeler:
    def _visit_terminal_value(  # noqa
        self, before_value: Optional[Any], after_value: Optional[Any]
    ) -> ChangeSetTerminal:
        # TODO: this needs to redirect to the function handler
        # TODO: this logic is potentially incompatible with bindings to NULLs, review.
        if before_value == after_value:
            return UnchangedValue(value=before_value)
        elif before_value is None and after_value is not None:
            return AddValue(value=after_value)
        elif before_value is not None and after_value is None:
            return DeleteValue(value=before_value)
        else:
            return UpdateValue(before=before_value, after=after_value)

    def _visit_array(
        self, before_array: Optional[list], after_array: Optional[list]
    ) -> list[ChangeSetTerminal]:
        array_change_set: list[ChangeSetTerminal] = list()
        for before_value, after_value in zip_longest(before_array, after_array, fillvalue=None):
            value_change_set = self._visit_terminal_value(
                before_value=before_value, after_value=after_value
            )
            array_change_set.append(value_change_set)
        return array_change_set

    def _visit_object(
        self, before_object: Optional[dict], after_object: Optional[dict]
    ) -> ObjectNode:
        # TODO: use reflection to visit object types and catch custom handlers in case.
        change_set_bindings: ChangeSetEntityBindings = dict()
        binding_names = {*before_object.keys(), *after_object.keys()}
        for binding_name in binding_names:
            before_value = before_object.get(binding_name)
            after_value = after_object.get(binding_name)
            # TODO: review/add support for different types.
            if isinstance(before_value, (int, str, bool)) or before_value is None:
                binding_change_entity = self._visit_terminal_value(
                    before_value=before_value, after_value=after_value
                )
            elif isinstance(before_value, list):
                binding_change_entity = self._visit_array(
                    before_array=before_value, after_array=after_value
                )
            elif isinstance(before_value, dict):
                binding_change_entity = self._visit_object(
                    before_object=before_value, after_object=after_value
                )
            else:
                print(f"Unsupported type {type(before_value)}")
                binding_change_entity = UnchangedValue(value=before_value)
            change_set_bindings[binding_name] = binding_change_entity
        return ObjectNode(bindings=change_set_bindings)

    def _visit_properties(
        self, before_properties: Optional[dict], after_properties: Optional[dict]
    ) -> PropertiesNode:
        object_node: ObjectNode = self._visit_object(
            before_object=before_properties, after_object=after_properties
        )
        return PropertiesNode(properties=object_node.bindings)

    def _visit_resource(
        self, before_resource: Optional[dict], after_resource: Optional[dict]
    ) -> ResourceNode:
        # TODO: fix add/delete/unchanged logic, needs minor rework of node types being update informants
        # if before_resource is None and after_resource is not None:
        #    return PropertiesNode
        #    return AddValue(value=after_resource)
        # elif before_resource is not None and after_resource is None:
        #    return DeleteValue(value=before_resource)

        # TODO: investigate behaviour with type changes, for now this is filler code.
        typ = UnchangedValue(value="Type updates are not supported yet")

        before_properties = before_resource.get("Properties")
        after_properties = after_resource.get("Properties")
        properties_change_set: PropertiesNode = self._visit_properties(
            before_properties=before_properties, after_properties=after_properties
        )

        return ResourceNode(typ=typ, properties=properties_change_set)

    def _visit_resources(self, before_resources: dict, after_resources: dict) -> ResourcesNode:
        resource_change_sets: list[ResourceNode] = list()
        # TODO: investigate type changes behavior.
        resource_names = {*before_resources.keys(), *after_resources.keys()}
        for resource_name in resource_names:
            before_resource = before_resources.get(resource_name)
            after_resource = after_resources.get(resource_name)
            resource_change_set = self._visit_resource(
                before_resource=before_resource, after_resource=after_resource
            )
            resource_change_sets.append(resource_change_set)
        return ResourcesNode(resources=resource_change_sets)

    def model(self, before_template: dict, after_template: dict) -> ChangeSetEntity:
        # TODO: visit other child types
        before_resources = before_template.get("Resources")
        after_resources = after_template.get("Resources")
        resources_change_set = self._visit_resources(
            before_resources=before_resources, after_resources=after_resources
        )
        return TemplateNode(resources=resources_change_set)


class ChangeSetModelVisitor(abc.ABC):
    def visit(self, change_set_entity: ChangeSetEntity):
        type_str = change_set_entity.__class__.__name__
        type_str = camel_to_snake_case(type_str).lower()
        visit_function_name = f"visit_{type_str}"
        visit_function = getattr(self, visit_function_name)
        return visit_function(change_set_entity)

    def visit_children(self, change_set_entity: ChangeSetEntity):
        children = change_set_entity.get_children()
        for child in children:
            self.visit(child)

    def visit_template_node(self, template_node: TemplateNode):
        self.visit_children(template_node)

    def visit_resources_node(self, resources_node: ResourcesNode):
        self.visit_children(resources_node)

    def visit_resource_node(self, resource_node: ResourceNode):
        self.visit_children(resource_node)

    def visit_properties_node(self, properties_node: PropertiesNode):
        self.visit_children(properties_node)

    def visit_object_node(self, object_node: ObjectNode):
        self.visit_children(object_node)

    def visit_update_value(self, update_value: UpdateValue):
        self.visit_children(update_value)

    def visit_add_value(self, add_value: AddValue):
        self.visit_children(add_value)

    def visit_delete_value(self, delete_value: DeleteValue):
        self.visit_children(delete_value)

    def visit_unchanged_value(self, unchanged_value: UnchangedValue):
        self.visit_children(unchanged_value)


class ChangeSetDescribeUnit(abc.ABC):
    context: Optional[Any]

    def __init__(self, context: Optional[Any]):
        self.context = context


class ChangeSetDescribeUnitAddition(ChangeSetDescribeUnit):
    pass


class ChangeSetDescribeUnitDeletion(ChangeSetDescribeUnit):
    pass


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
        return super().visit(change_set_entity=change_set_entity)

    def visit_update_value(self, update_value: UpdateValue) -> ChangeSetDescribeUnit:
        return ChangeSetDescribeUnitUpdate(
            context=update_value.before, after_context=update_value.after
        )

    def visit_add_value(self, add_value: AddValue) -> ChangeSetDescribeUnit:
        return ChangeSetDescribeUnitAddition(context=add_value.value)

    def visit_unchanged_value(
        self, unchanged_value: UnchangedValue
    ) -> ChangeSetDescribeUnitUnchanged:
        return ChangeSetDescribeUnitUnchanged(context=unchanged_value.value)

    def visit_object_node(self, object_node: ObjectNode) -> ChangeSetDescribeUnit:
        before_context = dict()
        after_context = dict()
        for name, change_set_update in object_node.bindings.items():
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

        # TODO: compute the priority of multiple change natures properly instead
        if any((lambda d: isinstance(d, ChangeSetDescribeUnitUpdate), before_context.values())):
            return ChangeSetDescribeUnitUpdate(context=before_context, after_context=after_context)
        elif all(
            map(lambda d: isinstance(d, ChangeSetDescribeUnitAddition), before_context.values())
        ):
            return ChangeSetDescribeUnitAddition(context=after_context)
        elif all(
            map(lambda d: isinstance(d, ChangeSetDescribeUnitUnchanged), before_context.values())
        ):
            return ChangeSetDescribeUnitUnchanged(context=before_context)
        return ChangeSetDescribeUnitUpdate(context=before_context, after_context=after_context)

    def visit_properties_node(self, properties_node: PropertiesNode) -> ChangeSetDescribeUnit:
        # TODO: fix properties nesting to be like resources and resource
        describe_unit: ChangeSetDescribeUnit = self.visit_object_node(
            ObjectNode(properties_node.properties)
        )
        if isinstance(describe_unit, ChangeSetDescribeUnitUpdate):
            return ChangeSetDescribeUnitUpdate(
                context={"Properties": describe_unit.context},
                after_context={"Properties": describe_unit.after_context},
            )
        elif isinstance(describe_unit, ChangeSetDescribeUnitAddition):
            return ChangeSetDescribeUnitAddition(
                context={"Properties": describe_unit.context},
            )
        # TODO: add support for delete, unchanged..

    def visit_resource_node(self, resource_node: ResourceNode) -> ChangeSetDescribeUnit:
        return self.visit_properties_node(resource_node.properties)

    def visit_resources_node(self, resources_node: ResourcesNode) -> ChangeSetDescribeUnit:
        for resource_node in resources_node.resources:
            describe_unit = self.visit_resource_node(resource_node=resource_node)
            if isinstance(describe_unit, ChangeSetDescribeUnitUpdate):
                self.changes.append(
                    ResourceChange(
                        Action=ChangeAction.Modify,
                        BeforeContext=describe_unit.context,
                        AfterContext=describe_unit.after_context,
                        # TODO: add other props
                    )
                )
            elif isinstance(describe_unit, ChangeSetDescribeUnitAddition):
                self.changes.append(
                    ResourceChange(
                        Action=ChangeAction.Add,
                        AfterContext=describe_unit.context,
                        # TODO: add other props
                    )
                )

        # TODO: pass info upstream
        return None

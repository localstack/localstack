import abc

from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeSetEntity,
    NodeArray,
    NodeObject,
    NodeProperties,
    NodeProperty,
    NodeResource,
    NodeResources,
    NodeTemplate,
    TerminalValueCreated,
    TerminalValueModified,
    TerminalValueRemoved,
    TerminalValueUnchanged,
)
from localstack.utils.strings import camel_to_snake_case


class ChangeSetModelVisitor(abc.ABC):
    # TODO: this class should be auto generated.

    # TODO: add visitors for abstract classes so shared logic can be implemented
    #  just once in classes extending this.

    def visit(self, change_set_entity: ChangeSetEntity):
        # TODO: speed up this lookup logic
        type_str = change_set_entity.__class__.__name__
        type_str = camel_to_snake_case(type_str)
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

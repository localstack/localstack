import abc

from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeSetEntity,
    NodeArray,
    NodeCondition,
    NodeConditions,
    NodeDependsOn,
    NodeDivergence,
    NodeIntrinsicFunction,
    NodeMapping,
    NodeMappings,
    NodeObject,
    NodeOutput,
    NodeOutputs,
    NodeParameter,
    NodeParameters,
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
        # Visit the resources, which will lazily evaluate all the referenced (direct and indirect)
        # entities (parameters, mappings, conditions, etc.). Then compute the output fields; computing
        # only the output fields would only result in the deployment logic of the referenced outputs
        # being evaluated, hence enforce the visiting of all the resources first.
        self.visit(node_template.resources)
        self.visit(node_template.outputs)

    def visit_node_outputs(self, node_outputs: NodeOutputs):
        self.visit_children(node_outputs)

    def visit_node_output(self, node_output: NodeOutput):
        self.visit_children(node_output)

    def visit_node_mapping(self, node_mapping: NodeMapping):
        self.visit_children(node_mapping)

    def visit_node_mappings(self, node_mappings: NodeMappings):
        self.visit_children(node_mappings)

    def visit_node_parameters(self, node_parameters: NodeParameters):
        self.visit_children(node_parameters)

    def visit_node_parameter(self, node_parameter: NodeParameter):
        self.visit_children(node_parameter)

    def visit_node_conditions(self, node_conditions: NodeConditions):
        self.visit_children(node_conditions)

    def visit_node_condition(self, node_condition: NodeCondition):
        self.visit_children(node_condition)

    def visit_node_depends_on(self, node_depends_on: NodeDependsOn):
        self.visit_children(node_depends_on)

    def visit_node_resources(self, node_resources: NodeResources):
        self.visit_children(node_resources)

    def visit_node_resource(self, node_resource: NodeResource):
        self.visit_children(node_resource)

    def visit_node_properties(self, node_properties: NodeProperties):
        self.visit_children(node_properties)

    def visit_node_property(self, node_property: NodeProperty):
        self.visit_children(node_property)

    def visit_node_intrinsic_function(self, node_intrinsic_function: NodeIntrinsicFunction):
        # TODO: speed up this lookup logic
        function_name = node_intrinsic_function.intrinsic_function
        function_name = function_name.replace("::", "_")
        function_name = camel_to_snake_case(function_name)
        visit_function_name = f"visit_node_intrinsic_function_{function_name}"
        visit_function = getattr(self, visit_function_name)
        return visit_function(node_intrinsic_function)

    def visit_node_intrinsic_function_fn_get_att(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ):
        self.visit_children(node_intrinsic_function)

    def visit_node_intrinsic_function_fn_equals(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ):
        self.visit_children(node_intrinsic_function)

    def visit_node_intrinsic_function_fn_transform(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ):
        self.visit_children(node_intrinsic_function)

    def visit_node_intrinsic_function_fn_select(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ):
        self.visit_children(node_intrinsic_function)

    def visit_node_intrinsic_function_fn_sub(self, node_intrinsic_function: NodeIntrinsicFunction):
        self.visit_children(node_intrinsic_function)

    def visit_node_intrinsic_function_fn_if(self, node_intrinsic_function: NodeIntrinsicFunction):
        self.visit_children(node_intrinsic_function)

    def visit_node_intrinsic_function_fn_not(self, node_intrinsic_function: NodeIntrinsicFunction):
        self.visit_children(node_intrinsic_function)

    def visit_node_intrinsic_function_fn_join(self, node_intrinsic_function: NodeIntrinsicFunction):
        self.visit_children(node_intrinsic_function)

    def visit_node_intrinsic_function_fn_find_in_map(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ):
        self.visit_children(node_intrinsic_function)

    def visit_node_intrinsic_function_ref(self, node_intrinsic_function: NodeIntrinsicFunction):
        self.visit_children(node_intrinsic_function)

    def visit_node_divergence(self, node_divergence: NodeDivergence):
        self.visit_children(node_divergence)

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

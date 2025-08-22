import re
from typing import Any

from botocore.exceptions import ParamValidationError

from localstack.services.cloudformation.engine.v2.change_set_model import (
    Maybe,
    NodeIntrinsicFunction,
    NodeProperty,
    NodeResource,
    NodeTemplate,
    Nothing,
    is_nothing,
)
from localstack.services.cloudformation.engine.v2.change_set_model_preproc import (
    _PSEUDO_PARAMETERS,
    ChangeSetModelPreproc,
    PreprocEntityDelta,
    PreprocResource,
)


class ChangeSetModelValidator(ChangeSetModelPreproc):
    def validate(self):
        self.process()

    def visit_node_template(self, node_template: NodeTemplate):
        self.visit(node_template.mappings)
        self.visit(node_template.resources)

    def visit_node_intrinsic_function_fn_get_att(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        arguments_delta = self.visit(node_intrinsic_function.arguments)
        before_arguments: Maybe[str | list[str]] = arguments_delta.before
        after_arguments: Maybe[str | list[str]] = arguments_delta.after

        before = self._before_cache.get(node_intrinsic_function.scope, Nothing)
        if is_nothing(before) and not is_nothing(before_arguments):
            before = ".".join(before_arguments)

        after = self._after_cache.get(node_intrinsic_function.scope, Nothing)
        if is_nothing(after) and not is_nothing(after_arguments):
            after = ".".join(after_arguments)

        return PreprocEntityDelta(before=before, after=after)

    def visit_node_intrinsic_function_fn_sub(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        def _compute_sub(args: str | list[Any], select_before: bool) -> str:
            # TODO: add further schema validation.
            string_template: str
            sub_parameters: dict
            if isinstance(args, str):
                string_template = args
                sub_parameters = {}
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
                template_variable_value = Nothing

                # Try to resolve the variable name as pseudo parameter.
                if template_variable_name in _PSEUDO_PARAMETERS:
                    template_variable_value = self._resolve_pseudo_parameter(
                        pseudo_parameter_name=template_variable_name
                    )

                # Try to resolve the variable name as an entry to the defined parameters.
                elif template_variable_name in sub_parameters:
                    template_variable_value = sub_parameters[template_variable_name]

                # Try to resolve the variable name as GetAtt.
                elif "." in template_variable_name:
                    try:
                        template_variable_value = self._resolve_attribute(
                            arguments=template_variable_name, select_before=select_before
                        )
                    except RuntimeError:
                        pass

                # Try to resolve the variable name as Ref.
                else:
                    try:
                        resource_delta = self._resolve_reference(logical_id=template_variable_name)
                        template_variable_value = (
                            resource_delta.before if select_before else resource_delta.after
                        )
                        if isinstance(template_variable_value, PreprocResource):
                            template_variable_value = template_variable_value.physical_resource_id
                    except RuntimeError:
                        pass

                if is_nothing(template_variable_value):
                    # override the base method just for this line to prevent accessing the
                    # resource properties since we are not deploying any resources
                    template_variable_value = ""

                if not isinstance(template_variable_value, str):
                    template_variable_value = str(template_variable_value)

                sub_string = sub_string.replace(
                    f"${{{template_variable_name}}}", template_variable_value
                )

            # FIXME: the following type reduction is ported from v1; however it appears as though such
            #        reduction is not performed by the engine, and certainly not at this depth given the
            #        lack of context. This section should be removed with Fn::Sub always retuning a string
            #        and the resource providers reviewed.
            account_id = self._change_set.account_id
            is_another_account_id = sub_string.isdigit() and len(sub_string) == len(account_id)
            if sub_string == account_id or is_another_account_id:
                result = sub_string
            elif sub_string.isdigit():
                result = int(sub_string)
            else:
                try:
                    result = float(sub_string)
                except ValueError:
                    result = sub_string
            return result

        arguments_delta = self.visit(node_intrinsic_function.arguments)
        arguments_before = arguments_delta.before
        arguments_after = arguments_delta.after
        before = self._before_cache.get(node_intrinsic_function.scope, Nothing)
        if is_nothing(before) and not is_nothing(arguments_before):
            before = _compute_sub(args=arguments_before, select_before=True)
        after = self._after_cache.get(node_intrinsic_function.scope, Nothing)
        if is_nothing(after) and not is_nothing(arguments_after):
            after = _compute_sub(args=arguments_after, select_before=False)
        return PreprocEntityDelta(before=before, after=after)

    def visit_node_intrinsic_function_fn_transform(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ):
        # TODO Research this issue:
        # Function is already resolved in the template reaching this point
        # But transformation is still present in update model
        return self.visit(node_intrinsic_function.arguments)

    def visit_node_intrinsic_function_fn_split(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        try:
            # If an argument is a Parameter it should be resolved, any other case, ignore it
            return super().visit_node_intrinsic_function_fn_split(node_intrinsic_function)
        except RuntimeError:
            return self.visit(node_intrinsic_function.arguments)

    def visit_node_intrinsic_function_fn_select(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        try:
            # If an argument is a Parameter it should be resolved, any other case, ignore it
            return super().visit_node_intrinsic_function_fn_select(node_intrinsic_function)
        except RuntimeError:
            return self.visit(node_intrinsic_function.arguments)

    def visit_node_resource(self, node_resource: NodeResource) -> PreprocEntityDelta:
        try:
            if delta := super().visit_node_resource(node_resource):
                return delta
            return super().visit_node_properties(node_resource.properties)
        except RuntimeError:
            return super().visit_node_properties(node_resource.properties)

    def visit_node_property(self, node_property: NodeProperty) -> PreprocEntityDelta:
        try:
            return super().visit_node_property(node_property)
        except ParamValidationError:
            return self.visit(node_property.value)

    # ignore errors from dynamic replacements
    def _maybe_perform_dynamic_replacements(self, delta: PreprocEntityDelta) -> PreprocEntityDelta:
        try:
            return super()._maybe_perform_dynamic_replacements(delta)
        except Exception:
            return delta

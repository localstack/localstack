import re
from typing import Any

from localstack.services.cloudformation.engine.v2.change_set_model import (
    Maybe,
    NodeIntrinsicFunction,
    NodeProperty,
    Nothing,
    is_nothing,
)
from localstack.services.cloudformation.engine.v2.change_set_model_static_preproc import (
    _PSEUDO_PARAMETERS,
    ChangeSetModelStaticPreproc,
    PreprocEntityDelta,
    PreprocResource,
)
from localstack.services.cloudformation.engine.validations import ValidationError


class ChangeSetModelPreproc(ChangeSetModelStaticPreproc):
    def visit_node_intrinsic_function_fn_get_att(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        # TODO: validate the return value according to the spec.
        arguments_delta = self.visit(node_intrinsic_function.arguments)
        before_arguments: Maybe[str | list[str]] = arguments_delta.before
        after_arguments: Maybe[str | list[str]] = arguments_delta.after

        before = self._before_cache.get(node_intrinsic_function.scope, Nothing)
        if is_nothing(before) and not is_nothing(before_arguments):
            before = self._resolve_attribute(arguments=before_arguments, select_before=True)

        after = self._after_cache.get(node_intrinsic_function.scope, Nothing)
        if is_nothing(after) and not is_nothing(after_arguments):
            after = self._resolve_attribute(arguments=after_arguments, select_before=False)

        return PreprocEntityDelta(before=before, after=after)

    def visit_node_intrinsic_function_fn_select(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ):
        # TODO: add further support for schema validation
        def _compute_fn_select(args: list[Any]) -> Any:
            values = args[1]
            # defer evaluation if the selection list contains unresolved elements (e.g., unresolved intrinsics)
            if isinstance(values, list) and not all(isinstance(value, str) for value in values):
                raise RuntimeError("Fn::Select list contains unresolved elements")

            if not isinstance(values, list) or not values:
                raise ValidationError(
                    "Template error: Fn::Select requires a list argument with two elements: an integer index and a list"
                )
            try:
                index: int = int(args[0])
            except ValueError as e:
                raise ValidationError(
                    "Template error: Fn::Select requires a list argument with two elements: an integer index and a list"
                ) from e

            values_len = len(values)
            if index < 0 or index >= values_len:
                raise ValidationError(
                    "Template error: Fn::Select requires a list argument with two elements: an integer index and a list"
                )
            selection = values[index]
            return selection

        arguments_delta = self.visit(node_intrinsic_function.arguments)
        delta = self._cached_apply(
            scope=node_intrinsic_function.scope,
            arguments_delta=arguments_delta,
            resolver=_compute_fn_select,
        )
        return delta

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
                    raise RuntimeError(
                        f"Undefined variable name in Fn::Sub string template '{template_variable_name}'"
                    )

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

    def _resolve_reference(self, logical_id: str) -> PreprocEntityDelta:
        if static_value := super()._resolve_reference(logical_id):
            return static_value

        node_resource = self._get_node_resource_for(
            resource_name=logical_id, node_template=self._change_set.update_model.node_template
        )
        resource_delta = self.visit(node_resource)
        before = resource_delta.before
        after = resource_delta.after
        return PreprocEntityDelta(before=before, after=after)

    def _resolve_attribute(self, arguments: str | list[str], select_before: bool) -> str:
        # TODO: add arguments validation.
        arguments_list: list[str]
        if isinstance(arguments, str):
            arguments_list = arguments.split(".")
        else:
            arguments_list = arguments

        if len(arguments_list) < 2:
            raise ValidationError(
                "Template error: every Fn::GetAtt object requires two non-empty parameters, the resource name and the resource attribute"
            )

        logical_name_of_resource = arguments_list[0]
        attribute_name = ".".join(arguments_list[1:])

        node_resource = self._get_node_resource_for(
            resource_name=logical_name_of_resource,
            node_template=self._change_set.update_model.node_template,
        )

        if not is_nothing(node_resource.condition_reference):
            condition = self._get_node_condition_if_exists(node_resource.condition_reference.value)
            evaluation_result = self._resolve_condition(condition.name)

            if select_before and not evaluation_result.before:
                raise ValidationError(
                    f"Template format error: Unresolved resource dependencies [{logical_name_of_resource}] in the Resources block of the template"
                )

            if not select_before and not evaluation_result.after:
                raise ValidationError(
                    f"Template format error: Unresolved resource dependencies [{logical_name_of_resource}] in the Resources block of the template"
                )

        # Custom Resources can mutate their definition
        # So the preproc should search first in the resource values and then check the template
        if select_before:
            value = self._before_deployed_property_value_of(
                resource_logical_id=logical_name_of_resource,
                property_name=attribute_name,
            )
        else:
            value = self._after_deployed_property_value_of(
                resource_logical_id=logical_name_of_resource,
                property_name=attribute_name,
            )
        if value is not None:
            return value

        node_property: NodeProperty | None = self._get_node_property_for(
            property_name=attribute_name, node_resource=node_resource
        )
        if node_property is not None:
            # The property is statically defined in the template and its value can be computed.
            property_delta = self.visit(node_property)
            value = property_delta.before if select_before else property_delta.after

        return value

    def _compute_fn_split(self, args: list[Any]) -> Any:
        delimiter = args[0]
        if not isinstance(delimiter, str) or not delimiter:
            raise RuntimeError(f"Invalid delimiter value for Fn::Split: '{delimiter}'")
        source_string = args[1]
        if not isinstance(source_string, str):
            raise RuntimeError(f"Invalid source string value for Fn::Split: '{source_string}'")
        split_string = source_string.split(delimiter)
        return split_string

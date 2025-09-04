from __future__ import annotations

import base64
import copy
import re
from collections.abc import Callable
from typing import Any, Final, Generic, TypeVar

from botocore.exceptions import ClientError

from localstack import config
from localstack.aws.api.cloudformation import ResourceStatus
from localstack.aws.api.ec2 import AvailabilityZoneList, DescribeAvailabilityZonesResult
from localstack.aws.connect import connect_to
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
    NodeParameters,
    NodeProperties,
    NodeProperty,
    NodeResource,
    NodeTemplate,
    Nothing,
    NothingType,
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
from localstack.services.cloudformation.engine.v2.resolving import (
    extract_dynamic_reference,
    perform_dynamic_reference_lookup,
)
from localstack.services.cloudformation.engine.validations import ValidationError
from localstack.services.cloudformation.stores import (
    exports_map,
)
from localstack.services.cloudformation.v2.entities import ChangeSet
from localstack.services.cloudformation.v2.types import ResolvedResource
from localstack.utils.aws.arns import get_partition
from localstack.utils.objects import get_value_from_path
from localstack.utils.run import to_str
from localstack.utils.strings import to_bytes
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
_T = TypeVar("_T")

REGEX_OUTPUT_APIGATEWAY = re.compile(
    rf"^(https?://.+\.execute-api\.)(?:[^-]+-){{2,3}}\d\.(amazonaws\.com|{_AWS_URL_SUFFIX})/?(.*)$"
)
MOCKED_REFERENCE = "unknown"

VALID_LOGICAL_RESOURCE_ID_RE = re.compile(r"^[A-Za-z0-9]+$")


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
    physical_resource_id: str | None
    condition: bool | None
    resource_type: str
    properties: PreprocProperties
    depends_on: list[str] | None
    requires_replacement: bool
    status: ResourceStatus | None

    def __init__(
        self,
        logical_id: str,
        physical_resource_id: str,
        condition: bool | None,
        resource_type: str,
        properties: PreprocProperties,
        depends_on: list[str] | None,
        requires_replacement: bool,
        status: ResourceStatus | None = None,
    ):
        self.logical_id = logical_id
        self.physical_resource_id = physical_resource_id
        self.condition = condition
        self.resource_type = resource_type
        self.properties = properties
        self.depends_on = depends_on
        self.requires_replacement = requires_replacement
        self.status = status

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
    export: Any | None
    condition: bool | None

    def __init__(self, name: str, value: Any, export: Any | None, condition: bool | None):
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
    _before_resolved_resources: Final[dict]
    _before_cache: Final[dict[Scope, Any]]
    _after_cache: Final[dict[Scope, Any]]

    def __init__(self, change_set: ChangeSet):
        self._change_set = change_set
        self._before_resolved_resources = change_set.stack.resolved_resources
        self._before_cache = {}
        self._after_cache = {}

    def _setup_runtime_cache(self) -> None:
        runtime_cache_key = self.__class__.__name__

        self._before_cache.clear()
        self._after_cache.clear()

        before_runtime_cache = self._change_set.update_model.before_runtime_cache
        if cache := before_runtime_cache.get(runtime_cache_key):
            self._before_cache.update(cache)

        after_runtime_cache = self._change_set.update_model.after_runtime_cache
        if cache := after_runtime_cache.get(runtime_cache_key):
            self._after_cache.update(cache)

    def _save_runtime_cache(self) -> None:
        runtime_cache_key = self.__class__.__name__

        before_runtime_cache = self._change_set.update_model.before_runtime_cache
        before_runtime_cache[runtime_cache_key] = copy.deepcopy(self._before_cache)

        after_runtime_cache = self._change_set.update_model.after_runtime_cache
        after_runtime_cache[runtime_cache_key] = copy.deepcopy(self._after_cache)

    def process(self) -> None:
        self._setup_runtime_cache()
        node_template = self._change_set.update_model.node_template
        self.visit(node_template)
        self._save_runtime_cache()

    def _get_node_resource_for(
        self, resource_name: str, node_template: NodeTemplate
    ) -> NodeResource:
        # TODO: this could be improved with hashmap lookups if the Node contained bindings and not lists.
        for node_resource in node_template.resources.resources:
            if node_resource.name == resource_name:
                self.visit(node_resource)
                return node_resource
        raise ValidationError(
            f"Template format error: Unresolved resource dependencies [{resource_name}] in the Resources block of the template"
        )

    def _get_node_property_for(
        self, property_name: str, node_resource: NodeResource
    ) -> NodeProperty | None:
        # TODO: this could be improved with hashmap lookups if the Node contained bindings and not lists.
        for node_property in node_resource.properties.properties:
            if node_property.name == property_name:
                self.visit(node_property)
                return node_property
        return None

    def _deployed_property_value_of(
        self, resource_logical_id: str, property_name: str, resolved_resources: dict
    ) -> Any:
        # We have to override this function to make sure it does not try to access the
        # resolved resource

        # Before we can obtain deployed value for a resource, we need to first ensure to
        # process the resource if this wasn't processed already. Ideally, values should only
        # be accessible through delta objects, to ensure computation is always complete at
        # every level.
        _ = self._get_node_resource_for(
            resource_name=resource_logical_id,
            node_template=self._change_set.update_model.node_template,
        )
        resolved_resource = resolved_resources.get(resource_logical_id)
        if resolved_resource is None:
            raise RuntimeError(
                f"No deployed instances of resource '{resource_logical_id}' were found"
            )
        properties = resolved_resource.get("Properties", {})
        # TODO support structured properties, e.g. NestedStack.Outputs.OutputName
        property_value: Any | None = get_value_from_path(properties, property_name)

        if property_value:
            if not isinstance(property_value, (str, list)):
                # TODO: is this correct? If there is a bug in the logic here, it's probably
                #  better to know about it with a clear error message than to receive some form
                #  of message about trying to use a dictionary in place of a string
                raise RuntimeError(
                    f"Accessing property '{property_name}' from '{resource_logical_id}' resulted in a non-string value nor list"
                )
            return property_value
        elif config.CFN_IGNORE_UNSUPPORTED_RESOURCE_TYPES:
            return MOCKED_REFERENCE

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
    ) -> str | None:
        return self._before_deployed_property_value_of(
            resource_logical_id=resource_logical_id, property_name=property_name
        )

    def _get_node_mapping(self, map_name: str) -> NodeMapping:
        mappings: list[NodeMapping] = self._change_set.update_model.node_template.mappings.mappings
        # TODO: another scenarios suggesting property lookups might be preferable.
        for mapping in mappings:
            if mapping.name == map_name:
                self.visit(mapping)
                return mapping
        raise RuntimeError(f"Undefined '{map_name}' mapping")

    def _get_node_parameter_if_exists(self, parameter_name: str) -> Maybe[NodeParameter]:
        parameters: list[NodeParameter] = (
            self._change_set.update_model.node_template.parameters.parameters
        )
        # TODO: another scenarios suggesting property lookups might be preferable.
        for parameter in parameters:
            if parameter.name == parameter_name:
                self.visit(parameter)
                return parameter
        return Nothing

    def _get_node_condition_if_exists(self, condition_name: str) -> Maybe[NodeCondition]:
        conditions: list[NodeCondition] = (
            self._change_set.update_model.node_template.conditions.conditions
        )
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
            resource_name=logical_id, node_template=self._change_set.update_model.node_template
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
            error_key = "::".join([map_name, top_level_key, second_level_key])
            raise ValidationError(f"Template error: Unable to get mapping for {error_key}")
        second_level_value = top_level_value.bindings.get(second_level_key)
        if not isinstance(second_level_value, (TerminalValue, NodeArray, NodeObject)):
            error_key = "::".join([map_name, top_level_key, second_level_key])
            raise ValidationError(f"Template error: Unable to get mapping for {error_key}")
        mapping_value_delta = self.visit(second_level_value)
        return mapping_value_delta

    def visit(self, change_set_entity: ChangeSetEntity) -> PreprocEntityDelta:
        entity_scope = change_set_entity.scope
        if entity_scope in self._before_cache and entity_scope in self._after_cache:
            before = self._before_cache[entity_scope]
            after = self._after_cache[entity_scope]
            return PreprocEntityDelta(before=before, after=after)
        delta = super().visit(change_set_entity=change_set_entity)
        if isinstance(delta, PreprocEntityDelta):
            delta = self._maybe_perform_replacements(delta)
            self._before_cache[entity_scope] = delta.before
            self._after_cache[entity_scope] = delta.after
        return delta

    def _maybe_perform_replacements(self, delta: PreprocEntityDelta) -> PreprocEntityDelta:
        delta = self._maybe_perform_static_replacements(delta)
        delta = self._maybe_perform_dynamic_replacements(delta)
        return delta

    def _maybe_perform_static_replacements(self, delta: PreprocEntityDelta) -> PreprocEntityDelta:
        return self._maybe_perform_on_delta(delta, self._perform_static_replacements)

    def _maybe_perform_dynamic_replacements(self, delta: PreprocEntityDelta) -> PreprocEntityDelta:
        return self._maybe_perform_on_delta(delta, self._perform_dynamic_replacements)

    def _maybe_perform_on_delta(
        self, delta: PreprocEntityDelta | None, f: Callable[[_T], _T]
    ) -> PreprocEntityDelta | None:
        if isinstance(delta.before, str):
            delta.before = f(delta.before)
        if isinstance(delta.after, str):
            delta.after = f(delta.after)
        return delta

    def _perform_dynamic_replacements(self, value: _T) -> _T:
        if not isinstance(value, str):
            return value
        if dynamic_ref := extract_dynamic_reference(value):
            new_value = perform_dynamic_reference_lookup(
                reference=dynamic_ref,
                account_id=self._change_set.account_id,
                region_name=self._change_set.region_name,
            )
            if new_value:
                return new_value

        return value

    @staticmethod
    def _perform_static_replacements(value: str) -> str:
        api_match = REGEX_OUTPUT_APIGATEWAY.match(value)
        if api_match and value not in config.CFN_STRING_REPLACEMENT_DENY_LIST:
            prefix = api_match[1]
            host = api_match[2]
            path = api_match[3]
            port = localstack_host().port
            value = f"{prefix}{host}:{port}/{path}"
            return value

        return value

    def _cached_apply(
        self, scope: Scope, arguments_delta: PreprocEntityDelta, resolver: Callable[[Any], Any]
    ) -> PreprocEntityDelta:
        """
        Applies the resolver function to the given input delta if and only if the required
        values are not already present in the runtime caches. This function handles both
        the 'before' and 'after' components of the delta independently.

        The resolver function receives either the 'before' or 'after' value from the input
        delta and returns a resolved value. If the result returned by the resolver is
        itself a PreprocEntityDelta, the function automatically extracts the appropriate
        component from it:  the 'before' value if the input was 'before', and the 'after'
        value if the input was 'after'.

        This function only reads from the cache and does not update it. It is the caller's
        responsibility to handle caching, either manually or via the upstream visit method
        of this class.

        Args:
            scope (Scope): The current scope used as a key for cache lookup.
            arguments_delta (PreprocEntityDelta): The delta containing 'before' and 'after' values to resolve.
            resolver (Callable[[Any], Any]): Function to apply on uncached 'before' or 'after' argument values.

        Returns:
            PreprocEntityDelta: A new delta with resolved 'before' and 'after' values.
        """

        # TODO: Update all visit_* methods in this class and its subclasses to use this function.
        #       This ensures maximal reuse of precomputed 'before' (and 'after') values from
        #       prior runtimes on the change sets template, thus avoiding unnecessary recomputation.

        arguments_before = arguments_delta.before
        arguments_after = arguments_delta.after

        before = self._before_cache.get(scope, Nothing)
        if is_nothing(before) and not is_nothing(arguments_before):
            before = resolver(arguments_before)
            if isinstance(before, PreprocEntityDelta):
                before = before.before

        after = self._after_cache.get(scope, Nothing)
        if is_nothing(after) and not is_nothing(arguments_after):
            after = resolver(arguments_after)
            if isinstance(after, PreprocEntityDelta):
                after = after.after

        return PreprocEntityDelta(before=before, after=after)

    def visit_node_property(self, node_property: NodeProperty) -> PreprocEntityDelta:
        return self.visit(node_property.value)

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
        before = {} if node_change_type != ChangeType.CREATED else Nothing
        after = {} if node_change_type != ChangeType.REMOVED else Nothing
        for name, change_set_entity in node_object.bindings.items():
            delta: PreprocEntityDelta = self.visit(change_set_entity=change_set_entity)
            delta_before = delta.before
            delta_after = delta.after
            if not is_nothing(before) and not is_nothing(delta_before):
                before[name] = delta_before
            if not is_nothing(after) and not is_nothing(delta_after):
                after[name] = delta_after
        return PreprocEntityDelta(before=before, after=after)

    def _resolve_attribute(self, arguments: str | list[str], select_before: bool) -> str:
        # TODO: add arguments validation.
        arguments_list: list[str]
        if isinstance(arguments, str):
            arguments_list = arguments.split(".")
        else:
            arguments_list = arguments
        logical_name_of_resource = arguments_list[0]
        attribute_name = arguments_list[1]

        node_resource = self._get_node_resource_for(
            resource_name=logical_name_of_resource,
            node_template=self._change_set.update_model.node_template,
        )
        node_property: NodeProperty | None = self._get_node_property_for(
            property_name=attribute_name, node_resource=node_resource
        )
        if node_property is not None:
            # The property is statically defined in the template and its value can be computed.
            property_delta = self.visit(node_property)
            value = property_delta.before if select_before else property_delta.after
        else:
            # The property is not statically defined and must therefore be available in
            # the properties deployed set.
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
        return value

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

    def visit_node_intrinsic_function_fn_equals(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        # TODO: add argument shape validation.
        def _compute_fn_equals(args: list[Any]) -> bool:
            return args[0] == args[1]

        arguments_delta = self.visit(node_intrinsic_function.arguments)
        delta = self._cached_apply(
            scope=node_intrinsic_function.scope,
            arguments_delta=arguments_delta,
            resolver=_compute_fn_equals,
        )
        return delta

    def visit_node_intrinsic_function_fn_if(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        # `if` needs to be short-circuiting i.e. if the condition is True we don't evaluate the
        # False branch. If the condition is False, we don't evaluate the True branch.
        if len(node_intrinsic_function.arguments.array) != 3:
            raise ValueError(
                f"Incorrectly constructed Fn::If usage, expected 3 arguments, found {len(node_intrinsic_function.arguments.array)}"
            )

        condition_delta = self.visit(node_intrinsic_function.arguments.array[0])
        if_delta = PreprocEntityDelta()
        if not is_nothing(condition_delta.before):
            node_condition = self._get_node_condition_if_exists(
                condition_name=condition_delta.before
            )
            condition_value = self.visit(node_condition).before
            if condition_value:
                arg_delta = self.visit(node_intrinsic_function.arguments.array[1])
            else:
                arg_delta = self.visit(node_intrinsic_function.arguments.array[2])
            if_delta.before = arg_delta.before

        if not is_nothing(condition_delta.after):
            node_condition = self._get_node_condition_if_exists(
                condition_name=condition_delta.after
            )
            condition_value = self.visit(node_condition).after
            if condition_value:
                arg_delta = self.visit(node_intrinsic_function.arguments.array[1])
            else:
                arg_delta = self.visit(node_intrinsic_function.arguments.array[2])
            if_delta.after = arg_delta.after

        return if_delta

    def visit_node_intrinsic_function_fn_and(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        def _compute_fn_and(args: list[bool]) -> bool:
            result = all(args)
            return result

        arguments_delta = self.visit(node_intrinsic_function.arguments)
        delta = self._cached_apply(
            scope=node_intrinsic_function.scope,
            arguments_delta=arguments_delta,
            resolver=_compute_fn_and,
        )
        return delta

    def visit_node_intrinsic_function_fn_or(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        def _compute_fn_or(args: list[bool]):
            result = any(args)
            return result

        arguments_delta = self.visit(node_intrinsic_function.arguments)
        delta = self._cached_apply(
            scope=node_intrinsic_function.scope,
            arguments_delta=arguments_delta,
            resolver=_compute_fn_or,
        )
        return delta

    def visit_node_intrinsic_function_fn_not(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        def _compute_fn_not(arg: list[bool] | bool) -> bool:
            # Is the argument ever a lone boolean?
            if isinstance(arg, list):
                return not arg[0]
            else:
                return not arg

        arguments_delta = self.visit(node_intrinsic_function.arguments)
        delta = self._cached_apply(
            scope=node_intrinsic_function.scope,
            arguments_delta=arguments_delta,
            resolver=_compute_fn_not,
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

    def visit_node_intrinsic_function_fn_join(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        # TODO: add support for schema validation.
        # TODO: add tests for joining non string values.
        def _compute_fn_join(args: list[Any]) -> str | NothingType:
            if not (isinstance(args, list) and len(args) == 2):
                return Nothing
            delimiter: str = str(args[0])
            values: list[Any] = args[1]
            if not isinstance(values, list):
                # shortcut if values is the empty string, for example:
                # {"Fn::Join": ["", {"Ref": <parameter>}]}
                # CDK bootstrap does this
                if values == "":
                    return ""
                raise RuntimeError(f"Invalid arguments list definition for Fn::Join: '{args}'")
            str_values: list[str] = []
            for value in values:
                if value is None:
                    continue
                str_value = str(value)
                str_values.append(str_value)
            join_result = delimiter.join(str_values)
            return join_result

        arguments_delta = self.visit(node_intrinsic_function.arguments)
        delta = self._cached_apply(
            scope=node_intrinsic_function.scope,
            arguments_delta=arguments_delta,
            resolver=_compute_fn_join,
        )
        return delta

    def visit_node_intrinsic_function_fn_select(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ):
        # TODO: add further support for schema validation
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

        arguments_delta = self.visit(node_intrinsic_function.arguments)
        delta = self._cached_apply(
            scope=node_intrinsic_function.scope,
            arguments_delta=arguments_delta,
            resolver=_compute_fn_select,
        )
        return delta

    def visit_node_intrinsic_function_fn_split(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ):
        # TODO: add further support for schema validation
        def _compute_fn_split(args: list[Any]) -> Any:
            delimiter = args[0]
            if not isinstance(delimiter, str) or not delimiter:
                raise RuntimeError(f"Invalid delimiter value for Fn::Split: '{delimiter}'")
            source_string = args[1]
            if not isinstance(source_string, str):
                raise RuntimeError(f"Invalid source string value for Fn::Split: '{source_string}'")
            split_string = source_string.split(delimiter)
            return split_string

        arguments_delta = self.visit(node_intrinsic_function.arguments)
        delta = self._cached_apply(
            scope=node_intrinsic_function.scope,
            arguments_delta=arguments_delta,
            resolver=_compute_fn_split,
        )
        return delta

    def visit_node_intrinsic_function_fn_get_a_zs(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        # TODO: add further support for schema validation

        def _compute_fn_get_a_zs(region) -> Any:
            if not isinstance(region, str):
                raise RuntimeError(f"Invalid region value for Fn::GetAZs: '{region}'")

            if not region:
                region = self._change_set.region_name

            account_id = self._change_set.account_id
            ec2_client = connect_to(aws_access_key_id=account_id, region_name=region).ec2
            try:
                get_availability_zones_result: DescribeAvailabilityZonesResult = (
                    ec2_client.describe_availability_zones()
                )
            except ClientError:
                raise RuntimeError(
                    "Could not describe zones availability whilst evaluating Fn::GetAZs"
                )
            availability_zones: AvailabilityZoneList = get_availability_zones_result[
                "AvailabilityZones"
            ]
            azs = [az["ZoneName"] for az in availability_zones]
            return azs

        arguments_delta = self.visit(node_intrinsic_function.arguments)
        delta = self._cached_apply(
            scope=node_intrinsic_function.scope,
            arguments_delta=arguments_delta,
            resolver=_compute_fn_get_a_zs,
        )
        return delta

    def visit_node_intrinsic_function_fn_base64(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        # TODO: add further support for schema validation
        def _compute_fn_base_64(string) -> Any:
            if not isinstance(string, str):
                raise RuntimeError(f"Invalid valueToEncode for Fn::Base64: '{string}'")
            # Ported from v1:
            base64_string = to_str(base64.b64encode(to_bytes(string)))
            return base64_string

        arguments_delta = self.visit(node_intrinsic_function.arguments)
        delta = self._cached_apply(
            scope=node_intrinsic_function.scope,
            arguments_delta=arguments_delta,
            resolver=_compute_fn_base_64,
        )
        return delta

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

    def visit_node_parameters(
        self, node_parameters: NodeParameters
    ) -> PreprocEntityDelta[dict[str, Any], dict[str, Any]]:
        before_parameters = {}
        after_parameters = {}
        for parameter in node_parameters.parameters:
            parameter_delta = self.visit(parameter)
            parameter_before = parameter_delta.before
            if not is_nothing(parameter_before):
                before_parameters[parameter.name] = parameter_before
            parameter_after = parameter_delta.after
            if not is_nothing(parameter_after):
                after_parameters[parameter.name] = parameter_after
        return PreprocEntityDelta(before=before_parameters, after=after_parameters)

    def visit_node_parameter(self, node_parameter: NodeParameter) -> PreprocEntityDelta:
        dynamic_value = node_parameter.dynamic_value
        dynamic_delta = self.visit(dynamic_value)

        default_value = node_parameter.default_value
        default_delta = self.visit(default_value)

        before = dynamic_delta.before or default_delta.before
        after = dynamic_delta.after or default_delta.after

        parameter_type = self.visit(node_parameter.type_)

        def _resolve_parameter_type(value: str, type_: str) -> Any:
            match type_:
                case "List<String>" | "CommaDelimitedList":
                    return [item.strip() for item in value.split(",")]
            return value

        if not is_nothing(after):
            after = _resolve_parameter_type(after, parameter_type.after)

        return PreprocEntityDelta(before=before, after=after)

    def visit_node_depends_on(self, node_depends_on: NodeDependsOn) -> PreprocEntityDelta:
        array_identifiers_delta = self.visit(node_depends_on.depends_on)
        return array_identifiers_delta

    def visit_node_condition(self, node_condition: NodeCondition) -> PreprocEntityDelta:
        delta = self.visit(node_condition.body)
        return delta

    def _resource_physical_resource_id_from(
        self, logical_resource_id: str, resolved_resources: dict[str, ResolvedResource]
    ) -> str | None:
        # TODO: typing around resolved resources is needed and should be reflected here.
        resolved_resource = resolved_resources.get(logical_resource_id, {})
        if resolved_resource.get("ResourceStatus") not in {
            ResourceStatus.CREATE_COMPLETE,
            ResourceStatus.UPDATE_COMPLETE,
        }:
            return None

        physical_resource_id = resolved_resource.get("PhysicalResourceId")
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
        def _compute_fn_ref(logical_id: str) -> PreprocEntityDelta:
            if logical_id == "AWS::NoValue":
                return Nothing

            reference_delta: PreprocEntityDelta = self._resolve_reference(logical_id=logical_id)
            if isinstance(before := reference_delta.before, PreprocResource):
                reference_delta.before = before.physical_resource_id
            if isinstance(after := reference_delta.after, PreprocResource):
                reference_delta.after = after.physical_resource_id
            return reference_delta

        arguments_delta = self.visit(node_intrinsic_function.arguments)
        delta = self._cached_apply(
            scope=node_intrinsic_function.scope,
            arguments_delta=arguments_delta,
            resolver=_compute_fn_ref,
        )
        return delta

    def visit_node_intrinsic_function_condition(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        arguments_delta = self.visit(node_intrinsic_function.arguments)

        def _delta_of_condition(name: str) -> PreprocEntityDelta:
            node_condition = self._get_node_condition_if_exists(condition_name=name)
            if is_nothing(node_condition):
                raise RuntimeError(f"Undefined condition '{name}'")
            condition_delta = self.visit(node_condition)
            return condition_delta

        delta = self._cached_apply(
            resolver=_delta_of_condition,
            scope=node_intrinsic_function.scope,
            arguments_delta=arguments_delta,
        )
        return delta

    def visit_node_array(self, node_array: NodeArray) -> PreprocEntityDelta:
        node_change_type = node_array.change_type
        before = [] if node_change_type != ChangeType.CREATED else Nothing
        after = [] if node_change_type != ChangeType.REMOVED else Nothing
        for change_set_entity in node_array.array:
            delta: PreprocEntityDelta = self.visit(change_set_entity=change_set_entity)
            delta_before = delta.before
            delta_after = delta.after
            if not is_nothing(before) and not is_nothing(delta_before):
                before.append(delta_before)
            if not is_nothing(after) and not is_nothing(delta_after):
                after.append(delta_after)
        return PreprocEntityDelta(before=before, after=after)

    def visit_node_properties(
        self, node_properties: NodeProperties
    ) -> PreprocEntityDelta[PreprocProperties, PreprocProperties]:
        node_change_type = node_properties.change_type
        before_bindings = {} if node_change_type != ChangeType.CREATED else Nothing
        after_bindings = {} if node_change_type != ChangeType.REMOVED else Nothing
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
        if not VALID_LOGICAL_RESOURCE_ID_RE.match(node_resource.name):
            raise ValidationError(
                f"Template format error: Resource name {node_resource.name} is non alphanumeric."
            )
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
                requires_replacement=False,
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
                requires_replacement=node_resource.requires_replacement,
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
        before: list[PreprocOutput] = []
        after: list[PreprocOutput] = []
        for node_output in node_outputs.outputs:
            output_delta: PreprocEntityDelta[PreprocOutput, PreprocOutput] = self.visit(node_output)
            output_before = output_delta.before
            output_after = output_delta.after
            if not is_nothing(output_before):
                before.append(output_before)
            if not is_nothing(output_after):
                after.append(output_after)
        return PreprocEntityDelta(before=before, after=after)

    def visit_node_intrinsic_function_fn_import_value(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ) -> PreprocEntityDelta:
        def _compute_fn_import_value(string) -> str:
            if not isinstance(string, str):
                raise RuntimeError(f"Invalid parameter for import: '{string}'")

            exports = exports_map(
                account_id=self._change_set.account_id, region_name=self._change_set.region_name
            )

            return exports.get(string, {}).get("Value") or Nothing

        arguments_delta = self.visit(node_intrinsic_function.arguments)
        delta = self._cached_apply(
            scope=node_intrinsic_function.scope,
            arguments_delta=arguments_delta,
            resolver=_compute_fn_import_value,
        )
        return delta

    def visit_node_intrinsic_function_fn_transform(
        self, node_intrinsic_function: NodeIntrinsicFunction
    ):
        raise RuntimeError("Fn::Transform should have been handled by the Transformer")

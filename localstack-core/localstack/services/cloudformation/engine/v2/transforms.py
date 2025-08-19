from __future__ import annotations

import copy
import json
import logging
import os
import re
from collections.abc import Callable
from copy import deepcopy
from typing import Any, Final

import boto3
from botocore.exceptions import ClientError
from samtranslator.translator.managed_policy_translator import ManagedPolicyLoader
from samtranslator.translator.transform import transform as transform_sam

from localstack.aws.api import CommonServiceException
from localstack.aws.connect import connect_to
from localstack.services.cloudformation.engine.validations import ValidationError
from localstack.services.cloudformation.stores import get_cloudformation_store
from localstack.services.cloudformation.v2.entities import Stack
from localstack.services.cloudformation.v2.types import (
    EngineParameter,
    engine_parameter_value,
    AWSNoValue,
    _AWSNoValueType,
)
from localstack.utils import testutil
from localstack.utils.aws.arns import get_partition
from localstack.utils.objects import recurse_object
from localstack.utils.strings import long_uid
from localstack.utils.urls import localstack_host

SERVERLESS_TRANSFORM = "AWS::Serverless-2016-10-31"
EXTENSIONS_TRANSFORM = "AWS::LanguageExtensions"
SECRETSMANAGER_TRANSFORM = "AWS::SecretsManager-2020-07-23"

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


policy_loader = None

LOG = logging.getLogger(__name__)


class FailedTransformationException(Exception):
    transformation: str
    msg: str

    def __init__(self, transformation: str, message: str = ""):
        self.transformation = transformation
        self.message = message
        super().__init__(self.message)


def create_policy_loader() -> ManagedPolicyLoader:
    global policy_loader
    if not policy_loader:
        iam_client = connect_to().iam
        policy_loader = ManagedPolicyLoader(iam_client=iam_client)
    return policy_loader


def format_intrinsic_transformations_into_list(transforms: list | dict | str) -> list[dict]:
    formatted_transforms = []
    if isinstance(transforms, str):
        formatted_transforms.append({"Name": transforms})
    elif isinstance(transforms, dict):
        formatted_transforms.append(transforms)
    elif isinstance(transforms, list):
        formatted_transforms.extend(transforms)

    return formatted_transforms


def format_template_transformations_into_list(transforms: list | dict | str) -> list[dict]:
    """
    The value of the Transform attribute can be:
     - a transformation name
     - an object like {Name: transformation, Parameters:{}}
     - a list a list of names of the transformations to apply
     - a list of objects defining a transformation
     so the objective of this function is to normalize the list of transformations to apply into a list of transformation objects
    """
    formatted_transformations = []
    if isinstance(transforms, str):
        formatted_transformations.append({"Name": transforms})

    if isinstance(transforms, dict):
        formatted_transformations.append(transforms)

    if isinstance(transforms, list):
        for transformation in transforms:
            if isinstance(transformation, str):
                formatted_transformations.append({"Name": transformation})
            if isinstance(transformation, dict):
                formatted_transformations.append(transformation)

    return formatted_transformations


class ResolverVisitor:
    """
    Resolver for statically resolvable values, i.e. before template deployment
    """

    # TODO: I don't think conditions can be resolved before transformation
    def __init__(
        self,
        stack_parameters: dict[str, EngineParameter],
        mappings: dict,
        conditions: dict,
        stack: Stack,
    ):
        self._stack_parameters = stack_parameters
        self._mappings = mappings
        self._conditions = conditions
        self._stack = stack

    def visit(self, obj: Any) -> Any:
        method_name = f"_visit_{obj.__class__.__name__}"
        if method := getattr(self, method_name, None):
            return method(obj)

        raise RuntimeError(f"No method '{method_name}' found for {self.__class__.__name__}")

    def find_intrinsic_function_calls(self, template: dict, function_name: str) -> list[dict]:
        found = []

        def visit(obj: Any, path: str, **_):
            if isinstance(obj, dict) and function_name in obj:
                found.append(obj)
            return obj

        recurse_object(template, visit)

        return found

    def _visit_dict(self, obj: dict) -> dict | str:
        # visit children
        out = {}
        for key, value in obj.items():
            # handle intrinsic functions
            if isinstance(value, dict) and "Ref" in value:
                out[key] = self._visit_ref(value["Ref"])
            else:
                out[key] = self.visit(value)

        if "Ref" in out:
            return self._visit_ref(out["Ref"])

        if "Fn::Sub" in out:
            return self._visit_sub(out["Fn::Sub"])

        if "Fn::FindInMap" in out:
            return self._visit_find_in_map(out["Fn::FindInMap"])

        return out

    def _visit_str(self, obj: str) -> str:
        return obj

    def _visit_list(self, obj: list) -> list:
        out = []
        for item in obj:
            out.append(self.visit(item))
        return out

    def _visit_ref(self, name: str) -> str | list:
        # Try to resolve the variable name as pseudo parameter.
        value: str | list | None = None
        if name in _PSEUDO_PARAMETERS:
            value = self._visit_pseudo_parameter(name)

        # try to resolve the reference from the stack parameters
        if stack_parameter := self._stack_parameters.get(name):
            value = stack_parameter.get("resolved_value") or engine_parameter_value(stack_parameter)
            if stack_parameter["type_"] == "CommaDelimitedList":
                value = value.split(",")

        # TODO: mappings

        if value is None:
            # TODO: error message validation
            raise RuntimeError(f"Undefined variable name in Fn::Sub string template '{name}'")

        return value

    def _visit_sub(self, payload: Any) -> str:
        string_template: str
        sub_parameters: dict
        if isinstance(payload, str):
            string_template = payload
            sub_parameters = {}
        elif isinstance(payload, list):
            string_template = payload[0]
            sub_parameters = self.visit(payload[1])
        else:
            raise RuntimeError(f"Unhandled type '{payload.__class__.__name__}' for Fn::Sub payload")

        sub_string = string_template
        template_variable_names = re.findall("\\${([^}]+)}", string_template)
        for template_variable_name in template_variable_names:
            if sub_parameter := sub_parameters.get(template_variable_name):
                template_variable_name = sub_parameter

            template_variable_value = self._visit_ref(template_variable_name)

            sub_string = sub_string.replace(
                f"${{{template_variable_name}}}", template_variable_value
            )

        return sub_string

    def _visit_find_in_map(self, payload: list) -> str | list:
        if len(payload) != 3:
            raise ValidationError("MESSAGE TODO")

        map_name, top_level_key, second_level_key = [self.visit(item) for item in payload]
        error_key = "::".join([map_name, top_level_key, second_level_key])
        mapping = self._mappings.get(map_name)
        if not mapping:
            raise ValidationError(f"Template error: Unable to get mapping for {error_key}")
        top_level_map = mapping.get(top_level_key)
        if not top_level_map:
            raise ValidationError(f"Template error: Unable to get mapping for {error_key}")
        value = top_level_map.get(second_level_key)
        if value is None:
            raise ValidationError(f"Template error: Unable to get mapping for {error_key}")

        return self.visit(value)

    def _visit_pseudo_parameter(self, name: str) -> str | _AWSNoValueType:
        match name:
            case "AWS::Partition":
                return get_partition(self._stack.region_name)
            case "AWS::AccountId":
                return self._stack.account_id
            case "AWS::Region":
                return self._stack.region_name
            case "AWS::StackName":
                return self._stack.stack_name
            case "AWS::StackId":
                return self._stack.stack_id
            case "AWS::URLSuffix":
                return _AWS_URL_SUFFIX
            case "AWS::NoValue":
                return AWSNoValue
            case _:
                raise RuntimeError(f"The use of '{name}' is currently unsupported")


def resolve_transform_refs(
    payload: dict,
    stack_parameters: dict[str, EngineParameter],
    mappings: dict,
    conditions: dict,
    stack: Stack,
) -> dict:
    resolver = ResolverVisitor(stack_parameters, mappings, conditions, stack)
    return resolver.visit(payload)


def apply_serverless_transformation(
    account_id: str,
    region_name: str,
    parsed_template: dict,
    template_parameters: dict[str, EngineParameter],
) -> str | None:
    """only returns string when parsing SAM template, otherwise None"""
    # TODO: we might also want to override the access key ID to account ID
    region_before = os.environ.get("AWS_DEFAULT_REGION")
    if boto3.session.Session().region_name is None:
        os.environ["AWS_DEFAULT_REGION"] = region_name
    loader = create_policy_loader()
    simplified_parameters = {
        k: v.get("resolved_value") or engine_parameter_value(v)
        for k, v in template_parameters.items()
    }

    try:
        transformed = transform_sam(parsed_template, simplified_parameters, loader)
        return transformed
    except Exception as e:
        raise FailedTransformationException(transformation=SERVERLESS_TRANSFORM, message=str(e))
    finally:
        # Note: we need to fix boto3 region, otherwise AWS SAM transformer fails
        os.environ.pop("AWS_DEFAULT_REGION", None)
        if region_before is not None:
            os.environ["AWS_DEFAULT_REGION"] = region_before


def apply_language_extensions_transform(
    template: dict,
    stack_parameters: dict[str, EngineParameter],
    mappings: dict,
    conditions: dict,
    stack: Stack,
) -> dict:
    """
    Resolve language extensions constructs
    """

    def _visit(obj, path, **_):
        # Fn::ForEach
        # TODO: can this be used in non-resource positions?
        if isinstance(obj, dict) and any("Fn::ForEach" in key for key in obj):
            newobj = {}
            for key in obj:
                if "Fn::ForEach" not in key:
                    newobj[key] = obj[key]
                    continue

                new_entries = expand_fn_foreach(
                    obj[key],
                    stack_parameters=stack_parameters,
                    mappings=mappings,
                    conditions=conditions,
                    stack=stack,
                )
                newobj.update(**new_entries)
            return newobj
        # Fn::Length
        elif isinstance(obj, dict) and "Fn::Length" in obj:
            value = obj["Fn::Length"]
            if isinstance(value, dict):
                value = resolve_transform_refs(
                    payload=value,
                    stack_parameters=stack_parameters,
                    mappings=mappings,
                    conditions=conditions,
                    stack=stack,
                )

            if isinstance(value, list):
                # TODO: what if one of the elements was AWS::NoValue?
                # no conversion required
                return len(value)
            elif isinstance(value, str):
                length = len(value.split(","))
                return length
            return obj
        elif isinstance(obj, dict) and "Fn::ToJsonString" in obj:
            # TODO: is the default representation ok here?
            return json.dumps(obj["Fn::ToJsonString"], default=str, separators=(",", ":"))

            # reference
        return obj

    return recurse_object(template, _visit)


def expand_fn_foreach(
    foreach_defn: list,
    stack_parameters: dict[str, EngineParameter],
    mappings: dict,
    conditions: dict,
    stack: Stack,
    extra_replace_mapping: dict | None = None,
) -> dict:
    if len(foreach_defn) != 3:
        raise ValidationError(
            f"Fn::ForEach: invalid number of arguments, expected 3 got {len(foreach_defn)}"
        )
    output = {}
    iteration_name, iteration_value, template = foreach_defn
    if not isinstance(iteration_name, str):
        raise ValidationError(
            f"Fn::ForEach: incorrect type for iteration name '{iteration_name}', expected str"
        )
    if isinstance(iteration_value, dict):
        # we have a reference
        if "Ref" in iteration_value:
            iteration_value = resolve_transform_refs(
                iteration_value, stack_parameters, mappings, conditions, stack
            )
        else:
            raise NotImplementedError(
                f"Fn::Transform: intrinsic {iteration_value} not supported in this position yet"
            )
    if not isinstance(iteration_value, list):
        raise ValidationError(
            f"Fn::ForEach: incorrect type for iteration variables '{iteration_value}', expected list"
        )

    if not isinstance(template, dict):
        raise ValidationError(
            f"Fn::ForEach: incorrect type for template '{template}', expected dict"
        )

    # TODO: locations other than resources
    replace_template_value = "${" + iteration_name + "}"
    for variable in iteration_value:
        # there might be multiple children, which could themselves be a `Fn::ForEach` call
        for logical_resource_id_template in template:
            if logical_resource_id_template.startswith("Fn::ForEach"):
                result = expand_fn_foreach(
                    template[logical_resource_id_template],
                    stack_parameters,
                    mappings,
                    conditions,
                    stack,
                    {iteration_name: variable},
                )
                output.update(**result)
                continue

            if replace_template_value not in logical_resource_id_template:
                raise ValidationError("Fn::ForEach: no placeholder in logical resource id")

            def gen_visit(variable: str) -> Callable:
                def _visit(obj: Any, path: Any):
                    if isinstance(obj, dict) and "Ref" in obj:
                        ref_variable = obj["Ref"]
                        if ref_variable == iteration_name:
                            return variable
                    elif isinstance(obj, dict) and "Fn::Sub" in obj:
                        arguments = recurse_object(obj["Fn::Sub"], _visit)
                        if isinstance(arguments, str):
                            # simple case
                            # TODO: can this reference anything outside of the template?
                            result = arguments
                            variables_found = re.findall("\\${([^}]+)}", arguments)
                            for var in variables_found:
                                if var == iteration_name:
                                    result = result.replace(f"${{{var}}}", variable)
                            return result
                        else:
                            raise NotImplementedError
                    elif isinstance(obj, dict) and "Fn::Join" in obj:
                        # first visit arguments
                        arguments = recurse_object(
                            obj["Fn::Join"],
                            _visit,
                        )
                        separator, items = arguments
                        return separator.join(items)
                    return obj

                return _visit

            logical_resource_id = logical_resource_id_template.replace(
                replace_template_value, variable
            )
            for key, value in (extra_replace_mapping or {}).items():
                logical_resource_id = logical_resource_id.replace("${" + key + "}", value)
            resource_body = copy.deepcopy(template[logical_resource_id_template])
            body = recurse_object(resource_body, gen_visit(variable))
            output[logical_resource_id] = body

    return output


def apply_global_transformations(
    stack: Stack,
    template: dict,
    mappings: dict,
    conditions: dict[str, bool],
    stack_parameters: dict,
) -> dict:
    account_id = stack.account_id
    region_name = stack.region_name
    processed_template = deepcopy(template)
    transformations = format_template_transformations_into_list(template.get("Transform", []))
    for transformation in transformations:
        transformation_parameters = resolve_transform_refs(
            payload=transformation.get("Parameters") or {},
            stack_parameters=stack_parameters,
            mappings=mappings,
            conditions=conditions,
            stack=stack,
        )

        if not isinstance(transformation["Name"], str):
            raise CommonServiceException(
                code="ValidationError",
                status_code=400,
                message="Key Name of transform definition must be a string.",
                sender_fault=True,
            )
        transform_name = transformation["Name"]
        if transformer_cls := transformers.get(transform_name):
            transformer = transformer_cls()
            transformed = transformer.transform(account_id, region_name, transformation_parameters)
            processed_template.update(**transformed)
            pass
        elif transform_name == SERVERLESS_TRANSFORM:
            processed_template = apply_serverless_transformation(
                account_id, region_name, processed_template, stack_parameters
            )
        elif transform_name == EXTENSIONS_TRANSFORM:
            processed_template = apply_language_extensions_transform(
                processed_template,
                stack_parameters=stack_parameters,
                mappings=mappings,
                conditions=conditions,
                stack=stack,
            )
        elif transform_name == SECRETSMANAGER_TRANSFORM:
            # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/transform-aws-secretsmanager.html
            LOG.warning("%s is not yet supported. Ignoring.", SECRETSMANAGER_TRANSFORM)
        else:
            processed_template = execute_macro(
                account_id,
                region_name,
                parsed_template=processed_template,
                macro=transformation,
                stack_parameters=stack_parameters,
                transformation_parameters=transformation_parameters,
            )

    processed_template.pop("Transform", None)
    return processed_template


TransformResult = dict | str


class Transformer:
    """Abstract class for Fn::Transform intrinsic functions"""

    def transform(self, account_id: str, region_name: str, parameters: dict) -> TransformResult:
        """Apply the transformer to the given parameters and return the modified construct"""


class AwsIncludeTransformer(Transformer):
    """Implements the 'AWS::Include' transform intrinsic function"""

    def transform(self, account_id: str, region_name: str, parameters: dict) -> TransformResult:
        # TODO: migrate from v1 to v2
        from localstack.services.cloudformation.engine.template_preparer import parse_template

        location = parameters.get("Location")
        if location and location.startswith("s3://"):
            s3_client = connect_to(aws_access_key_id=account_id, region_name=region_name).s3
            bucket, _, path = location.removeprefix("s3://").partition("/")
            try:
                content = testutil.download_s3_object(s3_client, bucket, path)
            except ClientError:
                LOG.error("client error downloading S3 object '%s/%s'", bucket, path)
                raise
            content = parse_template(content)
            return content
        else:
            LOG.warning("Unexpected Location parameter for AWS::Include transformer: %s", location)
        return parameters


# maps transformer names to implementing classes
transformers: dict[str, type] = {"AWS::Include": AwsIncludeTransformer}


def apply_intrinsic_transformations(
    stack: Stack,
    template: dict,
    mappings: dict,
    conditions: dict[str, bool],
    stack_parameters: dict,
) -> dict:
    """Resolve constructs using the 'Fn::Transform' intrinsic function."""
    account_id = stack.account_id
    region_name = stack.region_name

    def _visit(obj, path, **_):
        if isinstance(obj, dict) and "Fn::Transform" in obj:
            obj_copy = deepcopy(obj)
            transforms = format_intrinsic_transformations_into_list(obj["Fn::Transform"])
            obj_copy.pop("Fn::Transform")
            for transform in transforms:
                transform_name = transform.get("Name")
                transformer_class = transformers.get(transform_name)
                macro_store = get_cloudformation_store(account_id, region_name).macros
                parameters = resolve_transform_refs(
                    payload=transform.get("Parameters") or {},
                    stack_parameters=stack_parameters,
                    mappings=mappings,
                    conditions=conditions,
                    stack=stack,
                )
                if transformer_class:
                    transformer = transformer_class()
                    transformed = transformer.transform(account_id, region_name, parameters)
                    obj_copy.update(**transformed)

                elif transform_name in macro_store:
                    result = execute_macro(
                        account_id,
                        region_name,
                        obj_copy,
                        transform,
                        stack_parameters,
                        parameters,
                        True,
                    )
                    if isinstance(result, dict):
                        obj_copy.update(**result)
                    else:
                        obj_copy = result
                else:
                    LOG.warning("Unsupported transform function '%s'", transform_name)
            return obj_copy

        return obj

    return recurse_object(template, _visit)


def execute_macro(
    account_id: str,
    region_name: str,
    parsed_template: dict,
    macro: dict,
    stack_parameters: dict[str, EngineParameter],
    transformation_parameters: dict,
    is_intrinsic=False,
) -> dict:
    macro_definition = get_cloudformation_store(account_id, region_name).macros.get(macro["Name"])
    if not macro_definition:
        raise FailedTransformationException(
            macro["Name"], f"Transformation {macro['Name']} is not supported."
        )

    formatted_stack_parameters = {}
    for key, value in stack_parameters.items():
        # TODO: we want to support other types of parameters
        parameter_value = value.get("resolved_value") or engine_parameter_value(value)
        if value["type_"] == "CommaDelimitedList" and isinstance(parameter_value, str):
            formatted_stack_parameters[key] = parameter_value.split(",")
        else:
            formatted_stack_parameters[key] = parameter_value

    transformation_id = f"{account_id}::{macro['Name']}"
    event = {
        "region": region_name,
        "accountId": account_id,
        "fragment": parsed_template,
        "transformId": transformation_id,
        "params": transformation_parameters,
        "requestId": long_uid(),
        "templateParameterValues": formatted_stack_parameters,
    }

    client = connect_to(aws_access_key_id=account_id, region_name=region_name).lambda_
    try:
        invocation = client.invoke(
            FunctionName=macro_definition["FunctionName"], Payload=json.dumps(event)
        )
    except ClientError:
        LOG.error(
            "client error executing lambda function '%s' with payload '%s'",
            macro_definition["FunctionName"],
            json.dumps(event),
        )
        raise
    if invocation.get("StatusCode") != 200 or invocation.get("FunctionError") == "Unhandled":
        raise FailedTransformationException(
            transformation=macro["Name"],
            message=f"Received malformed response from transform {transformation_id}. Rollback requested by user.",
        )
    result = json.loads(invocation["Payload"].read())

    if result.get("status") != "success":
        error_message = result.get("errorMessage")
        message = (
            f"Transform {transformation_id} failed with: {error_message}. Rollback requested by user."
            if error_message
            else f"Transform {transformation_id} failed without an error message.. Rollback requested by user."
        )
        raise FailedTransformationException(transformation=macro["Name"], message=message)

    if not isinstance(result.get("fragment"), dict) and not is_intrinsic:
        raise FailedTransformationException(
            transformation=macro["Name"],
            message="Template format error: unsupported structure.. Rollback requested by user.",
        )

    return result.get("fragment")


def transform_template(
    stack: Stack,
    template: dict,
    resolved_parameters: dict,
) -> dict:
    mappings = template.get("Mappings", {})
    conditions = template.get("Conditions", {})

    # apply 'Fn::Transform' intrinsic functions (note: needs to be applied before global
    #  transforms below, as some utils - incl samtransformer - expect them to be resolved already)
    processed_template = apply_intrinsic_transformations(
        stack,
        template,
        mappings,
        conditions,
        resolved_parameters,
    )

    # apply global transforms
    processed_template = apply_global_transformations(
        stack,
        processed_template,
        mappings,
        conditions,
        resolved_parameters,
    )

    return processed_template

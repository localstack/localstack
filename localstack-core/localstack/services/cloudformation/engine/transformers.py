import copy
import json
import logging
import os
import re
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import ClientError
from samtranslator.translator.transform import transform as transform_sam

from localstack.aws.api import CommonServiceException
from localstack.aws.connect import connect_to
from localstack.services.cloudformation.engine.parameters import StackParameter
from localstack.services.cloudformation.engine.policy_loader import create_policy_loader
from localstack.services.cloudformation.engine.template_deployer import resolve_refs_recursively
from localstack.services.cloudformation.engine.validations import ValidationError
from localstack.services.cloudformation.stores import get_cloudformation_store
from localstack.utils import testutil
from localstack.utils.objects import recurse_object
from localstack.utils.strings import long_uid

LOG = logging.getLogger(__name__)

SERVERLESS_TRANSFORM = "AWS::Serverless-2016-10-31"
EXTENSIONS_TRANSFORM = "AWS::LanguageExtensions"
SECRETSMANAGER_TRANSFORM = "AWS::SecretsManager-2020-07-23"

TransformResult = dict | str


@dataclass
class ResolveRefsRecursivelyContext:
    account_id: str
    region_name: str
    stack_name: str
    resources: dict
    mappings: dict
    conditions: dict
    parameters: dict[str, StackParameter]

    def resolve(self, value: Any) -> Any:
        return resolve_refs_recursively(
            self.account_id,
            self.region_name,
            self.stack_name,
            self.resources,
            self.mappings,
            self.conditions,
            self.parameters,
            value,
        )


class Transformer:
    """Abstract class for Fn::Transform intrinsic functions"""

    def transform(self, account_id: str, region_name: str, parameters: dict) -> TransformResult:
        """Apply the transformer to the given parameters and return the modified construct"""


class AwsIncludeTransformer(Transformer):
    """Implements the 'AWS::Include' transform intrinsic function"""

    def transform(self, account_id: str, region_name: str, parameters: dict) -> TransformResult:
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
    account_id: str,
    region_name: str,
    template: dict,
    stack_name: str,
    resources: dict,
    mappings: dict,
    conditions: dict[str, bool],
    stack_parameters: dict,
) -> dict:
    """Resolve constructs using the 'Fn::Transform' intrinsic function."""

    def _visit(obj, path, **_):
        if isinstance(obj, dict) and "Fn::Transform" in obj:
            transform = (
                obj["Fn::Transform"]
                if isinstance(obj["Fn::Transform"], dict)
                else {"Name": obj["Fn::Transform"]}
            )
            transform_name = transform.get("Name")
            transformer_class = transformers.get(transform_name)
            macro_store = get_cloudformation_store(account_id, region_name).macros
            parameters = transform.get("Parameters") or {}
            parameters = resolve_refs_recursively(
                account_id,
                region_name,
                stack_name,
                resources,
                mappings,
                conditions,
                stack_parameters,
                parameters,
            )
            if transformer_class:
                transformer = transformer_class()
                transformed = transformer.transform(account_id, region_name, parameters)
                obj_copy = deepcopy(obj)
                obj_copy.pop("Fn::Transform")
                obj_copy.update(transformed)
                return obj_copy

            elif transform_name in macro_store:
                obj_copy = deepcopy(obj)
                obj_copy.pop("Fn::Transform")
                result = execute_macro(
                    account_id, region_name, obj_copy, transform, stack_parameters, parameters, True
                )
                return result
            else:
                LOG.warning(
                    "Unsupported transform function '%s' used in %s", transform_name, stack_name
                )
        return obj

    return recurse_object(template, _visit)


def apply_global_transformations(
    account_id: str,
    region_name: str,
    template: dict,
    stack_name: str,
    resources: dict,
    mappings: dict,
    conditions: dict[str, bool],
    stack_parameters: dict,
) -> dict:
    processed_template = deepcopy(template)
    transformations = format_template_transformations_into_list(
        processed_template.get("Transform", [])
    )
    for transformation in transformations:
        transformation_parameters = resolve_refs_recursively(
            account_id,
            region_name,
            stack_name,
            resources,
            mappings,
            conditions,
            stack_parameters,
            transformation.get("Parameters", {}),
        )

        if not isinstance(transformation["Name"], str):
            # TODO this should be done during template validation
            raise CommonServiceException(
                code="ValidationError",
                status_code=400,
                message="Key Name of transform definition must be a string.",
                sender_fault=True,
            )
        elif transformation["Name"] == SERVERLESS_TRANSFORM:
            processed_template = apply_serverless_transformation(
                account_id, region_name, processed_template, stack_parameters
            )
        elif transformation["Name"] == EXTENSIONS_TRANSFORM:
            resolve_context = ResolveRefsRecursivelyContext(
                account_id,
                region_name,
                stack_name,
                resources,
                mappings,
                conditions,
                stack_parameters,
            )

            processed_template = apply_language_extensions_transform(
                processed_template,
                resolve_context,
            )
        elif transformation["Name"] == SECRETSMANAGER_TRANSFORM:
            # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/transform-aws-secretsmanager.html
            LOG.warning("%s is not yet supported. Ignoring.", SECRETSMANAGER_TRANSFORM)
        else:
            processed_template = execute_macro(
                account_id,
                region_name,
                parsed_template=template,
                macro=transformation,
                stack_parameters=stack_parameters,
                transformation_parameters=transformation_parameters,
            )

    return processed_template


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


def execute_macro(
    account_id: str,
    region_name: str,
    parsed_template: dict,
    macro: dict,
    stack_parameters: dict,
    transformation_parameters: dict,
    is_intrinsic=False,
) -> str:
    macro_definition = get_cloudformation_store(account_id, region_name).macros.get(macro["Name"])
    if not macro_definition:
        raise FailedTransformationException(
            macro["Name"], f"Transformation {macro['Name']} is not supported."
        )

    formatted_stack_parameters = {}
    for key, value in stack_parameters.items():
        # TODO: we want to support other types of parameters
        parameter_value = value.get("ParameterValue")
        if value.get("ParameterType") == "CommaDelimitedList" and isinstance(parameter_value, str):
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


def apply_language_extensions_transform(
    template: dict,
    resolve_context: ResolveRefsRecursivelyContext,
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

                new_entries = expand_fn_foreach(obj[key], resolve_context)
                newobj.update(**new_entries)
            return newobj
        # Fn::Length
        elif isinstance(obj, dict) and "Fn::Length" in obj:
            value = obj["Fn::Length"]
            if isinstance(value, dict):
                value = resolve_context.resolve(value)

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
    resolve_context: ResolveRefsRecursivelyContext,
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
            iteration_value = resolve_context.resolve(iteration_value)
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
                    resolve_context,
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


def apply_serverless_transformation(
    account_id: str, region_name: str, parsed_template: dict, template_parameters: dict
) -> str | None:
    """only returns string when parsing SAM template, otherwise None"""
    # TODO: we might also want to override the access key ID to account ID
    region_before = os.environ.get("AWS_DEFAULT_REGION")
    if boto3.session.Session().region_name is None:
        os.environ["AWS_DEFAULT_REGION"] = region_name
    loader = create_policy_loader()
    simplified_parameters = {
        k: v.get("ResolvedValue") or v["ParameterValue"] for k, v in template_parameters.items()
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


class FailedTransformationException(Exception):
    transformation: str
    msg: str

    def __init__(self, transformation: str, message: str = ""):
        self.transformation = transformation
        self.message = message
        super().__init__(self.message)

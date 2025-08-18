from __future__ import annotations
import json
import logging
import os
from copy import deepcopy
import boto3
from botocore.exceptions import ClientError
from samtranslator.translator.managed_policy_translator import ManagedPolicyLoader
from samtranslator.translator.transform import transform as transform_sam
from localstack.aws.api import CommonServiceException
from localstack.aws.connect import connect_to
from localstack.services.cloudformation.stores import get_cloudformation_store
from localstack.services.cloudformation.v2.types import EngineParameter, engine_parameter_value
from localstack.utils import testutil
from localstack.utils.objects import recurse_object
from localstack.utils.strings import long_uid

SERVERLESS_TRANSFORM = "AWS::Serverless-2016-10-31"
EXTENSIONS_TRANSFORM = "AWS::LanguageExtensions"
SECRETSMANAGER_TRANSFORM = "AWS::SecretsManager-2020-07-23"

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


def resolve_transform_ref():
    pass


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
        # TODO
        # transformation_parameters = resolve_transform_ref()
        transformation_parameters = transformation.get("Parameters", {})

        # transformation_parameters = resolve_refs_recursively(
        #     account_id,
        #     region_name,
        #     stack_name,
        #     resources,
        #     mappings,
        #     conditions,
        #     stack_parameters,
        #     transformation.get("Parameters", {}),
        # )

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
            # resolve_context = ResolveRefsRecursivelyContext(
            #     account_id,
            #     region_name,
            #     stack_name,
            #     resources,
            #     mappings,
            #     conditions,
            #     stack_parameters,
            # )
            #
            # processed_template = apply_language_extensions_transform(
            #     processed_template,
            #     resolve_context,
            # )
            raise RuntimeError("TODO")
        elif transform_name == SECRETSMANAGER_TRANSFORM:
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
            # parameters = resolve_refs_recursively(
            #     account_id,
            #     region_name,
            #     stack_name,
            #     resources,
            #     mappings,
            #     conditions,
            #     stack_parameters,
            #     parameters,
            # )
            # TODO
            parameters = resolve_transform_ref()
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


def execute_macro(
    account_id: str,
    region_name: str,
    parsed_template: dict,
    macro: dict,
    stack_parameters: dict[str, EngineParameter],
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
    account_id: str,
    region_name: str,
    template: dict,
    stack_name: str,
    resolved_parameters: dict,
) -> dict:
    # TODO we should not need to use resoures at all 🤞
    resources = template.get("Resources", {})
    mappings = template.get("Mappings", {})
    conditions = template.get("Conditions", {})

    # apply 'Fn::Transform' intrinsic functions (note: needs to be applied before global
    #  transforms below, as some utils - incl samtransformer - expect them to be resolved already)
    proccesed_template = apply_intrinsic_transformations(
        account_id,
        region_name,
        template,
        stack_name,
        resources,
        mappings,
        conditions,
        resolved_parameters,
    )

    # apply global transforms
    proccesed_template = apply_global_transformations(
        account_id,
        region_name,
        proccesed_template,
        stack_name,
        resources,
        mappings,
        conditions,
        resolved_parameters,
    )

    return proccesed_template

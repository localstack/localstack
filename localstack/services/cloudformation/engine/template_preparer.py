import json
import logging
import os
from typing import Dict, List

import boto3
from flask import Response
from samtranslator.translator.transform import transform as transform_sam

from localstack.services.cloudformation.engine import yaml_parser
from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api import CommonServiceException
from localstack.aws.api.cloudformation import InsufficientCapabilitiesException
from localstack.services.awslambda.lambda_api import func_arn, run_lambda
from localstack.services.cloudformation.engine.entities import Stack
from localstack.services.cloudformation.engine.policy_loader import create_policy_loader
from localstack.services.cloudformation.stores import get_cloudformation_store
from localstack.utils.aws import aws_stack
from localstack.utils.json import clone_safe
from localstack.utils.strings import long_uid

LOG = logging.getLogger(__name__)
SERVERLESS_TRANSFORM = "AWS::Serverless-2016-10-31"


def parse_template(template: str) -> dict:
    try:
        return json.loads(template)
    except Exception:
        try:
            return clone_safe(yaml_parser.parse_yaml(template))
        except Exception as e:
            LOG.debug("Unable to parse CloudFormation template (%s): %s", e, template)
            raise


def template_to_json(template: str) -> str:
    template = parse_template(template)
    return json.dumps(template)


def transform_template(stack: Stack):
    if "CAPABILITY_AUTO_EXPAND" not in stack.metadata.get("Capabilities", []):
        raise InsufficientCapabilitiesException("Requires capabilities : [CAPABILITY_AUTO_EXPAND]")

    do_transformations(stack)


def do_transformations(stack: Stack):
    result = dict(stack.template)

    for transformation in stack.metadata.get("Transform", []):
        if not isinstance(transformation["Name"], str):
            raise CommonServiceException(
                code="ValidationError",
                status_code=400,
                message="Key Name of transform definition must be a string.",
                sender_fault=True,
            )
        elif transformation["Name"] == SERVERLESS_TRANSFORM:
            result = apply_serverless_transformation(result)
        else:
            result = execute_macro(
                parsed_template=result,
                macro=transformation,
                stack_parameters=stack.stack_parameters(),
            )

    stack.template = result
    stack.template_body = json.dumps(result)


def execute_macro(parsed_template: Dict, macro: Dict, stack_parameters: List) -> str:
    macro_definition = get_cloudformation_store().macros.get(macro["Name"])
    if not macro_definition:
        raise FailedTransformation(macro["Name"], "2DO")

    formatted_stack_parameters = {
        param["ParameterKey"]: param["ParameterValue"] for param in stack_parameters
    }

    formated_transform_parameters = macro.get("Parameters", {})
    for k, v in formated_transform_parameters.items():
        if isinstance(v, Dict) and "Ref" in v:
            formated_transform_parameters[k] = formatted_stack_parameters[v["Ref"]]
    transformation_id = f"{get_aws_account_id()}::{macro['Name']}"
    event = {
        "region": aws_stack.get_region(),
        "accountId": get_aws_account_id(),
        "fragment": parsed_template,
        "transformId": transformation_id,
        "params": formated_transform_parameters,
        "requestId": long_uid(),
        "templateParameterValues": formatted_stack_parameters,
    }

    function_arn = func_arn(macro_definition["FunctionName"])

    result = {}
    try:
        invocation = run_lambda(func_arn=function_arn, event=event)
        if isinstance(invocation.result, Response) and invocation.result.status_code == 500:
            raise FailedTransformation(
                transformation=macro["Name"],
                message=f"Received malformed response from transform {transformation_id}. Rollback requested by user.",
            )
        result = json.loads(invocation.result)
    except TypeError:
        raise FailedTransformation(
            transformation=macro["Name"],
            message="Template format error: unsupported structure.. Rollback requested by user.",
        )

    if result.get("status") != "success":
        error_message = result.get("errorMessage")
        message = (
            f"Transform {transformation_id} failed with: {error_message}. Rollback requested by user."
            if error_message
            else f"Transform {transformation_id} failed without an error message.. Rollback requested by user."
        )
        raise FailedTransformation(transformation=macro["Name"], message=message)

    if not isinstance(result.get("fragment"), dict):
        raise FailedTransformation(
            transformation=macro["Name"],
            message="Template format error: unsupported structure.. Rollback requested by user.",
        )

    return result.get("fragment")


def apply_serverless_transformation(parsed_template):
    """only returns string when parsing SAM template, otherwise None"""
    region_before = os.environ.get("AWS_DEFAULT_REGION")
    if boto3.session.Session().region_name is None:
        os.environ["AWS_DEFAULT_REGION"] = aws_stack.get_region()
    loader = create_policy_loader()

    try:
        transformed = transform_sam(parsed_template, {}, loader)
        return transformed
    except Exception as e:
        raise FailedTransformation(transformation=SERVERLESS_TRANSFORM, message=str(e))
    finally:
        # Note: we need to fix boto3 region, otherwise AWS SAM transformer fails
        os.environ.pop("AWS_DEFAULT_REGION", None)
        if region_before is not None:
            os.environ["AWS_DEFAULT_REGION"] = region_before


class FailedTransformation(Exception):
    transformation: str
    msg: str

    def __init__(self, transformation: str, message: str = ""):
        self.transformation = transformation
        self.message = message
        super().__init__(self.message)

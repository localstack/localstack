import json
import logging
import os
from typing import Dict, List

import boto3
from samtranslator.translator.transform import transform as transform_sam

from localstack.services.cloudformation.engine import yaml_parser
from localstack.aws.accounts import get_aws_account_id
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
    # template_body = get_template_body(req_data) # FIXME
    result = dict(stack.template)

    for transformation in stack.metadata.get("Transform", []):
        if transformation["Name"] == SERVERLESS_TRANSFORM:
            result = apply_serverless_transformation(result)
        else:
            result = execute_macro(
                parsed_template=result,
                macro=transformation,
                stack_parameters=stack.stack_parameters(),
            )

    stack.template = result
    stack.template_body = json.dumps(result)


def execute_macro(parsed_template: Dict, macro: Dict, stack_parameters: List) -> Dict:
    macro_definition = get_cloudformation_store().macros.get(macro["Name"])
    if not macro_definition:
        raise FailedTransformation(macro["Name"], "2DO")

    parsed_template.pop("Transform")
    parsed_template.pop("StackId")

    parsed_template = {
        k: v for k, v in parsed_template.items() if v and k not in ["StackName", "StackId"]
    }

    formatted_stack_parameters = {
        param["ParameterKey"]: param["ParameterValue"] for param in stack_parameters
    }

    formated_transform_parameters = macro.get("Parameters", {})
    for k, v in formated_transform_parameters.items():
        if isinstance(v, Dict) and "Ref" in v:
            formated_transform_parameters[k] = formatted_stack_parameters[v["Ref"]]

    event = {
        "region": aws_stack.get_region(),
        "accountId": get_aws_account_id(),
        "fragment": parsed_template,
        "transformId": f"{get_aws_account_id()}::{macro['Name']}",
        "params": formated_transform_parameters,
        "requestId": long_uid(),
        "templateParameterValues": formatted_stack_parameters,
    }

    function_arn = func_arn(macro_definition["FunctionName"])

    try:
        invocation_result = run_lambda(func_arn=function_arn, event=event)
        # TODO Validate Result
        return json.loads(invocation_result.result).get("fragment")
    except Exception as e:
        print(e)


def apply_serverless_transformation(parsed_template):
    """only returns string when parsing SAM template, otherwise None"""
    region_before = os.environ.get("AWS_DEFAULT_REGION")
    if boto3.session.Session().region_name is None:
        os.environ["AWS_DEFAULT_REGION"] = aws_stack.get_region()
    loader = create_policy_loader()

    failed = False
    try:
        transformed = transform_sam(parsed_template, {}, loader)
        return json.dumps(transformed)
    except Exception as e:
        print(e)
        failed = True
    finally:
        # Note: we need to fix boto3 region, otherwise AWS SAM transformer fails
        os.environ.pop("AWS_DEFAULT_REGION", None)
        if region_before is not None:
            os.environ["AWS_DEFAULT_REGION"] = region_before
        if failed:
            raise FailedTransformation(transformation=SERVERLESS_TRANSFORM)


class FailedTransformation(Exception):
    transformation: str
    msg: str

    def __init__(self, transformation: str, message: str = ""):
        self.transformation = transformation
        self.message = message
        super().__init__(self.message)

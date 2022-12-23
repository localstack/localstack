import json
import logging
import os

import boto3
import yaml
from moto.cloudformation.utils import yaml_tag_constructor
from samtranslator.translator.transform import transform as transform_sam

from localstack.services.cloudformation.engine.policy_loader import create_policy_loader
from localstack.utils.aws import aws_stack
from localstack.utils.json import clone_safe

LOG = logging.getLogger(__name__)

# create safe yaml loader that parses date strings as string, not date objects
NoDatesSafeLoader = yaml.SafeLoader
NoDatesSafeLoader.yaml_implicit_resolvers = {
    k: [r for r in v if r[0] != "tag:yaml.org,2002:timestamp"]
    for k, v in NoDatesSafeLoader.yaml_implicit_resolvers.items()
}


def parse_template(template: str) -> dict:
    try:
        return json.loads(template)
    except Exception:
        # FIXME: removing this still breaks all short-hand intrinsic functions :|
        yaml.add_multi_constructor("", yaml_tag_constructor, Loader=NoDatesSafeLoader)
        try:
            return clone_safe(yaml.safe_load(template))
        except Exception:
            try:
                return clone_safe(yaml.load(template, Loader=NoDatesSafeLoader))
            except Exception as e:
                LOG.debug("Unable to parse CloudFormation template (%s): %s", e, template)
                raise


def template_to_json(template: str) -> str:
    template = parse_template(template)
    return json.dumps(template)


def transform_template(template_body: str) -> str | None:
    """only returns string when parsing SAM template, otherwise None"""
    # template_body = get_template_body(req_data) # FIXME
    parsed = parse_template(template_body)
    if parsed.get("Transform") == "AWS::Serverless-2016-10-31":

        # Note: we need to fix boto3 region, otherwise AWS SAM transformer fails
        region_before = os.environ.get("AWS_DEFAULT_REGION")
        if boto3.session.Session().region_name is None:
            os.environ["AWS_DEFAULT_REGION"] = aws_stack.get_region()
        loader = create_policy_loader()
        try:
            transformed = transform_sam(parsed, {}, loader)
            return json.dumps(transformed)
        finally:
            os.environ.pop("AWS_DEFAULT_REGION", None)
            if region_before is not None:
                os.environ["AWS_DEFAULT_REGION"] = region_before

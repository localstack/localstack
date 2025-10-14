import json
import logging

from localstack.services.cloudformation.engine import yaml_parser
from localstack.services.cloudformation.engine.transformers import (
    apply_global_transformations,
    apply_intrinsic_transformations,
)
from localstack.services.cloudformation.engine.validations import ValidationError
from localstack.utils.json import clone_safe

LOG = logging.getLogger(__name__)


def parse_template(template: str) -> dict:
    try:
        return json.loads(template)
    except Exception:
        try:
            return clone_safe(yaml_parser.parse_yaml(template))
        except Exception as e:
            LOG.debug("Unable to parse CloudFormation template (%s): %s", e, template)
            raise


def parse_template_v2(template: str) -> dict:
    parsed_template = None
    try:
        parsed_template = json.loads(template)
    except Exception:
        try:
            parsed_template = clone_safe(yaml_parser.parse_yaml(template))
        except Exception as e:
            LOG.debug("Unable to parse CloudFormation template (%s): %s", e, template)

    if parsed_template is None:
        # TODO: static error message
        raise ValidationError("Template format error: YAML not well-formed. (line 1, column 2)")

    if not isinstance(parsed_template, dict):
        raise ValidationError("Template format error: unsupported structure.")

    return parsed_template


def template_to_json(template: str) -> str:
    template = parse_template(template)
    return json.dumps(template)


# TODO: consider moving to transformers.py as well
def transform_template(
    account_id: str,
    region_name: str,
    template: dict,
    stack_name: str,
    resources: dict,
    mappings: dict,
    conditions: dict[str, bool],
    resolved_parameters: dict,
) -> dict:
    proccesed_template = dict(template)

    # apply 'Fn::Transform' intrinsic functions (note: needs to be applied before global
    #  transforms below, as some utils - incl samtransformer - expect them to be resolved already)
    proccesed_template = apply_intrinsic_transformations(
        account_id,
        region_name,
        proccesed_template,
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

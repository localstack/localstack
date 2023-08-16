import logging
from typing import Dict, Type, Union

from localstack.aws.connect import connect_to
from localstack.utils import testutil
from localstack.utils.objects import recurse_object

LOG = logging.getLogger(__name__)

TransformResult = Union[dict, str]


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
            content = testutil.download_s3_object(s3_client, bucket, path)
            content = parse_template(content)
            return content
        else:
            LOG.warning("Unexpected Location parameter for AWS::Include transformer: %s", location)
        return parameters


# maps transformer names to implementing classes
transformers: Dict[str, Type] = {"AWS::Include": AwsIncludeTransformer}


def apply_transform_intrinsic_functions(
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
    from localstack.services.cloudformation.engine.template_deployer import resolve_refs_recursively

    def _visit(obj, **_):
        if isinstance(obj, dict) and obj.keys() == {"Fn::Transform"}:
            transform = obj["Fn::Transform"]
            transform_name = transform.get("Name")
            transformer_class = transformers.get(transform_name)
            if transformer_class:
                transformer = transformer_class()
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
                return transformer.transform(account_id, region_name, parameters)
        return obj

    return recurse_object(template, _visit)

import copy
import json
import logging
import os
from typing import Any, Final, TypedDict

import boto3
import jsonpath_ng
from botocore.exceptions import ClientError
from samtranslator.translator.transform import transform as transform_sam

from localstack.aws.connect import connect_to
from localstack.services.cloudformation.engine.policy_loader import create_policy_loader
from localstack.services.cloudformation.engine.template_preparer import parse_template
from localstack.services.cloudformation.engine.transformers import (
    FailedTransformationException,
)
from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeType,
    Maybe,
    NodeGlobalTransform,
    NodeIntrinsicFunctionFnTransform,
    NodeProperties,
    NodeResources,
    NodeTransform,
    Nothing,
    Scope,
    is_nothing,
)
from localstack.services.cloudformation.engine.v2.change_set_model_preproc import (
    ChangeSetModelPreproc,
    PreprocEntityDelta,
    PreprocProperties,
)
from localstack.services.cloudformation.engine.validations import ValidationError
from localstack.services.cloudformation.stores import get_cloudformation_store
from localstack.services.cloudformation.v2.entities import ChangeSet
from localstack.services.cloudformation.v2.types import engine_parameter_value
from localstack.utils import testutil
from localstack.utils.json import extract_jsonpath
from localstack.utils.strings import long_uid

LOG = logging.getLogger(__name__)

SERVERLESS_TRANSFORM = "AWS::Serverless-2016-10-31"
EXTENSIONS_TRANSFORM = "AWS::LanguageExtensions"
SECRETSMANAGER_TRANSFORM = "AWS::SecretsManager-2020-07-23"
INCLUDE_TRANSFORM = "AWS::Include"

_SCOPE_TRANSFORM_TEMPLATE_OUTCOME: Final[Scope] = Scope("TRANSFORM_TEMPLATE_OUTCOME")


# TODO: evaluate the use of subtypes to represent and validate types of transforms
class GlobalTransform:
    name: str
    parameters: Maybe[dict]

    def __init__(self, name: str, parameters: Maybe[dict]):
        self.name = name
        self.parameters = parameters


class TransformPreprocParameter(TypedDict):
    # TODO: expand
    ParameterKey: str
    ParameterValue: Any
    ParameterType: str | None


class ChangeSetModelTransform(ChangeSetModelPreproc):
    _before_parameters: Final[dict]
    _after_parameters: Final[dict]
    _before_template: Final[Maybe[dict]]
    _after_template: Final[Maybe[dict]]

    def __init__(
        self,
        change_set: ChangeSet,
        before_parameters: dict,
        after_parameters: dict,
        before_template: dict | None,
        after_template: dict | None,
    ):
        super().__init__(change_set=change_set)
        self._before_parameters = before_parameters
        self._after_parameters = after_parameters
        self._before_template = before_template or Nothing
        self._after_template = after_template or Nothing

    # Ported from v1:
    @staticmethod
    def _apply_global_serverless_transformation(
        region_name: str, template: dict, parameters: dict
    ) -> dict:
        """only returns string when parsing SAM template, otherwise None"""
        # TODO: we might also want to override the access key ID to account ID
        region_before = os.environ.get("AWS_DEFAULT_REGION")
        if boto3.session.Session().region_name is None:
            os.environ["AWS_DEFAULT_REGION"] = region_name
        loader = create_policy_loader()
        # The following transformation function can carry out in-place changes ensure this cannot occur.
        template = copy.deepcopy(template)
        parameters = copy.deepcopy(parameters)
        try:
            transformed = transform_sam(template, parameters, loader)
            return transformed
        except Exception as e:
            raise FailedTransformationException(transformation=SERVERLESS_TRANSFORM, message=str(e))
        finally:
            # Note: we need to fix boto3 region, otherwise AWS SAM transformer fails
            os.environ.pop("AWS_DEFAULT_REGION", None)
            if region_before is not None:
                os.environ["AWS_DEFAULT_REGION"] = region_before

    def _compute_include_transform(self, parameters: dict, fragment: dict) -> dict:
        location = parameters.get("Location")
        if not location or not location.startswith("s3://"):
            raise FailedTransformationException(
                transformation=INCLUDE_TRANSFORM,
                message="Unexpected Location parameter for AWS::Include transformer: %s" % location,
            )

        s3_client = connect_to(
            aws_access_key_id=self._change_set.account_id, region_name=self._change_set.region_name
        ).s3
        bucket, _, path = location.removeprefix("s3://").partition("/")
        try:
            content = testutil.download_s3_object(s3_client, bucket, path)
        except ClientError:
            raise FailedTransformationException(
                transformation=INCLUDE_TRANSFORM,
                message="Error downloading S3 object '%s/%s'" % (bucket, path),
            )
        try:
            template_to_include = parse_template(content)
        except Exception as e:
            raise FailedTransformationException(transformation=INCLUDE_TRANSFORM, message=str(e))

        return {**fragment, **template_to_include}

    def _apply_global_transform(
        self, global_transform: GlobalTransform, template: dict, parameters: dict
    ) -> dict:
        transform_name = global_transform.name
        if transform_name == EXTENSIONS_TRANSFORM:
            # Applied lazily in downstream tasks (see ChangeSetModelPreproc).
            transformed_template = template
        elif transform_name == SERVERLESS_TRANSFORM:
            transformed_template = self._apply_global_serverless_transformation(
                region_name=self._change_set.region_name,
                template=template,
                parameters=parameters,
            )
        elif transform_name == SECRETSMANAGER_TRANSFORM:
            # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/transform-aws-secretsmanager.html
            LOG.warning("%s is not yet supported. Ignoring.", SECRETSMANAGER_TRANSFORM)
            transformed_template = template
        elif transform_name == INCLUDE_TRANSFORM:
            transformed_template = self._compute_include_transform(
                parameters=global_transform.parameters,
                fragment=template,
            )
        else:
            transformed_template = self._invoke_macro(
                name=global_transform.name,
                parameters=global_transform.parameters
                if not is_nothing(global_transform.parameters)
                else {},
                fragment=template,
            )
        return transformed_template

    def transform(self) -> tuple[dict, dict]:
        self._setup_runtime_cache()

        node_template = self._change_set.update_model.node_template

        parameters_delta = self.visit_node_parameters(node_template.parameters)
        parameters_before = parameters_delta.before
        parameters_after = parameters_delta.after

        self.visit_node_resources(node_template.resources)

        transform_delta: PreprocEntityDelta[list[GlobalTransform], list[GlobalTransform]] = (
            self.visit_node_transform(node_template.transform)
        )
        transform_before: Maybe[list[GlobalTransform]] = transform_delta.before
        transform_after: Maybe[list[GlobalTransform]] = transform_delta.after

        transformed_before_template = self._before_template
        if transform_before and not is_nothing(self._before_template):
            transformed_before_template = self._before_template
            for before_global_transform in transform_before:
                if not is_nothing(before_global_transform.name):
                    transformed_before_template = self._apply_global_transform(
                        global_transform=before_global_transform,
                        parameters=parameters_before,
                        template=transformed_before_template,
                    )

            # Macro transformations won't remove the transform from the template
            if "Transform" in transformed_before_template:
                transformed_before_template.pop("Transform")
            self._before_cache[_SCOPE_TRANSFORM_TEMPLATE_OUTCOME] = transformed_before_template

        transformed_after_template = self._after_template
        if transform_after and not is_nothing(self._after_template):
            transformed_after_template = self._after_template
            for after_global_transform in transform_after:
                if not is_nothing(after_global_transform.name):
                    transformed_after_template = self._apply_global_transform(
                        global_transform=after_global_transform,
                        parameters=parameters_after,
                        template=transformed_after_template,
                    )
            # Macro transformations won't remove the transform from the template
            if "Transform" in transformed_after_template:
                transformed_after_template.pop("Transform")
            self._after_cache[_SCOPE_TRANSFORM_TEMPLATE_OUTCOME] = transformed_after_template

        self._save_runtime_cache()

        return transformed_before_template, transformed_after_template

    def visit_node_global_transform(
        self, node_global_transform: NodeGlobalTransform
    ) -> PreprocEntityDelta[GlobalTransform, GlobalTransform]:
        change_type = node_global_transform.change_type

        name_delta = self.visit(node_global_transform.name)
        parameters_delta = self.visit(node_global_transform.parameters)

        before = Nothing
        if change_type != ChangeType.CREATED:
            before = GlobalTransform(name=name_delta.before, parameters=parameters_delta.before)
        after = Nothing
        if change_type != ChangeType.REMOVED:
            after = GlobalTransform(name=name_delta.after, parameters=parameters_delta.after)
        return PreprocEntityDelta(before=before, after=after)

    def visit_node_transform(
        self, node_transform: NodeTransform
    ) -> PreprocEntityDelta[list[GlobalTransform], list[GlobalTransform]]:
        change_type = node_transform.change_type
        before = [] if change_type != ChangeType.CREATED else Nothing
        after = [] if change_type != ChangeType.REMOVED else Nothing
        for change_set_entity in node_transform.global_transforms:
            if not isinstance(change_set_entity.name.value, str):
                raise ValidationError("Key Name of transform definition must be a string.")

            delta: PreprocEntityDelta[GlobalTransform, GlobalTransform] = self.visit(
                change_set_entity=change_set_entity
            )
            delta_before = delta.before
            delta_after = delta.after
            if not is_nothing(before) and not is_nothing(delta_before):
                before.append(delta_before)
            if not is_nothing(after) and not is_nothing(delta_after):
                after.append(delta_after)
        return PreprocEntityDelta(before=before, after=after)

    def _compute_fn_transform(
        self,
        macro_definition: Any,
        siblings: Any,
    ) -> Any:
        def _normalize_transform(obj):
            transforms = []

            if isinstance(obj, str):
                transforms.append({"Name": obj, "Parameters": {}})

            if isinstance(obj, dict):
                transforms.append(obj)

            if isinstance(obj, list):
                for v in obj:
                    if isinstance(v, str):
                        transforms.append({"Name": v, "Parameters": {}})

                    if isinstance(v, dict):
                        if not v.get("Parameters"):
                            v["Parameters"] = {}
                        transforms.append(v)

            return transforms

        normalized_transforms = _normalize_transform(macro_definition)
        transform_output = copy.deepcopy(siblings)
        for transform in normalized_transforms:
            transform_name = transform["Name"]
            if transform_name == INCLUDE_TRANSFORM:
                transform_output = self._compute_include_transform(
                    parameters=transform["Parameters"], fragment=transform_output
                )

            else:
                transform_output: dict | str = self._invoke_macro(
                    fragment=transform_output,
                    name=transform["Name"],
                    parameters=transform.get("Parameters", {}),
                    allow_string=True,
                )

        if isinstance(transform_output, dict) and "Fn::Transform" in transform_output:
            transform_output.pop("Fn::Transform")

        return transform_output

    def _replace_at_jsonpath(self, template, node, result):
        path = node.scope.to_jsonpath()
        parent_path = ".".join(path.split(".")[:-1])

        pattern = jsonpath_ng.parse(parent_path)
        result_template = pattern.update(template, result)

        return result_template

    def visit_node_intrinsic_function_fn_transform(
        self, node_intrinsic_function: NodeIntrinsicFunctionFnTransform
    ) -> PreprocEntityDelta:
        arguments_delta = self.visit(node_intrinsic_function.arguments)

        if not is_nothing(arguments_delta.before):
            before = self._compute_fn_transform(
                arguments_delta.before,
                node_intrinsic_function.before_siblings,
            )
            updated_before_template = self._replace_at_jsonpath(
                self._before_template, node_intrinsic_function, before
            )
            self._after_cache[_SCOPE_TRANSFORM_TEMPLATE_OUTCOME] = updated_before_template
        else:
            before = Nothing

        if not is_nothing(arguments_delta.after):
            after = self._compute_fn_transform(
                arguments_delta.after,
                node_intrinsic_function.after_siblings,
            )
            updated_after_template = self._replace_at_jsonpath(
                self._after_template, node_intrinsic_function, after
            )
            self._after_cache[_SCOPE_TRANSFORM_TEMPLATE_OUTCOME] = updated_after_template
        else:
            after = Nothing

        self._save_runtime_cache()
        return PreprocEntityDelta(before=before, after=after)

    def visit_node_properties(
        self, node_properties: NodeProperties
    ) -> PreprocEntityDelta[PreprocProperties, PreprocProperties]:
        for i, node_property in enumerate(node_properties.properties):
            if node_property.name == "Fn::Transform":
                path = "$" + ".".join(node_property.scope.split("/")[:-1])
                before_siblings = extract_jsonpath(self._before_template, path)
                after_siblings = extract_jsonpath(self._after_template, path)
                intrinsic_transform = NodeIntrinsicFunctionFnTransform(
                    change_type=node_property.change_type,
                    intrinsic_function=node_property.name,
                    scope=node_property.scope,
                    arguments=node_property.value,
                    before_siblings=before_siblings,
                    after_siblings=after_siblings,
                )
                self.visit(intrinsic_transform)
                node_properties.properties.pop(i)
                break

        return super().visit_node_properties(node_properties=node_properties)

    def visit_node_resources(self, node_resources: NodeResources) -> PreprocEntityDelta:
        for i, node_resource in enumerate(node_resources.resources):
            if isinstance(node_resource, NodeIntrinsicFunctionFnTransform):
                self.visit(node_resource)
                node_resources.resources.pop(i)
                break
        return super().visit_node_resources(node_resources=node_resources)

    def _invoke_macro(self, name: str, parameters: dict, fragment: dict, allow_string=True):
        account_id = self._change_set.account_id
        region_name = self._change_set.region_name
        macro_definition = get_cloudformation_store(
            account_id=account_id, region_name=region_name
        ).macros.get(name)

        if not macro_definition:
            raise FailedTransformationException(name, f"Transformation {name} is not supported.")

        simplified_parameters = {}
        if resolved_parameters := self._change_set.resolved_parameters:
            for key, resolved_parameter in resolved_parameters.items():
                final_value = engine_parameter_value(resolved_parameter)
                simplified_parameters[key] = (
                    final_value.split(",")
                    if resolved_parameter["type_"] == "CommaDelimitedList"
                    else final_value
                )

        transformation_id = f"{account_id}::{name}"
        event = {
            "region": region_name,
            "accountId": account_id,
            "fragment": fragment,
            "transformId": transformation_id,
            "params": parameters,
            "requestId": long_uid(),
            "templateParameterValues": simplified_parameters,
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
                transformation=name,
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
            raise FailedTransformationException(transformation=name, message=message)

        if not isinstance(result.get("fragment"), dict) and not allow_string:
            raise FailedTransformationException(
                transformation=name,
                message="Template format error: unsupported structure.. Rollback requested by user.",
            )

        return result.get("fragment")

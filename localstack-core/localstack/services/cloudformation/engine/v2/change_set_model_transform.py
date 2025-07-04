import copy
import logging
import os
from typing import Any, Final, Optional, TypedDict

import boto3
from botocore.exceptions import ClientError
from samtranslator.translator.transform import transform as transform_sam

from localstack.aws.connect import connect_to
from localstack.services.cloudformation.engine.policy_loader import create_policy_loader
from localstack.services.cloudformation.engine.template_preparer import parse_template
from localstack.services.cloudformation.engine.transformers import (
    FailedTransformationException,
    Transformer,
    execute_macro,
    transformers,
)
from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeType,
    Maybe,
    NodeGlobalTransform,
    NodeParameter,
    NodeTransform,
    Nothing,
    Scope,
    is_nothing,
)
from localstack.services.cloudformation.engine.v2.change_set_model_preproc import (
    ChangeSetModelPreproc,
    PreprocEntityDelta,
)
from localstack.services.cloudformation.stores import get_cloudformation_store
from localstack.services.cloudformation.v2.entities import ChangeSet
from localstack.utils import testutil

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
    ParameterType: Optional[str]


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
        before_template: Optional[dict],
        after_template: Optional[dict],
    ):
        super().__init__(change_set=change_set)
        self._before_parameters = before_parameters
        self._after_parameters = after_parameters
        self._before_template = before_template or Nothing
        self._after_template = after_template or Nothing

    def visit_node_parameter(
        self, node_parameter: NodeParameter
    ) -> PreprocEntityDelta[
        dict[str, TransformPreprocParameter], dict[str, TransformPreprocParameter]
    ]:
        # Enable compatability with v1 util.
        # TODO: port v1's SSM parameter resolution

        parameter_value_delta = super().visit_node_parameter(node_parameter=node_parameter)
        parameter_value_before = parameter_value_delta.before
        parameter_value_after = parameter_value_delta.after

        parameter_type_delta = self.visit(node_parameter.type_)
        parameter_type_before = parameter_type_delta.before
        parameter_type_after = parameter_type_delta.after

        parameter_key = node_parameter.name

        before = Nothing
        if not is_nothing(parameter_value_before):
            before = TransformPreprocParameter(
                ParameterKey=parameter_key,
                ParameterValue=parameter_value_before,
                ParameterType=parameter_type_before
                if not is_nothing(parameter_type_before)
                else None,
            )
        after = Nothing
        if not is_nothing(parameter_value_after):
            after = TransformPreprocParameter(
                ParameterKey=parameter_key,
                ParameterValue=parameter_value_after,
                ParameterType=parameter_type_after
                if not is_nothing(parameter_type_after)
                else None,
            )

        return PreprocEntityDelta(before=before, after=after)

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

    @staticmethod
    def _apply_global_include(
        global_transform: GlobalTransform, template: dict, parameters: dict, account_id, region_name
    ) -> dict:
        location = global_transform.parameters.get("Location")
        if not location or not location.startswith("s3://"):
            raise FailedTransformationException(
                transformation=INCLUDE_TRANSFORM,
                message="Unexpected Location parameter for AWS::Include transformer: %s" % location,
            )

        s3_client = connect_to(aws_access_key_id=account_id, region_name=region_name).s3
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
        return {**template, **template_to_include}

    @staticmethod
    def _apply_global_macro_transformation(
        account_id: str,
        region_name,
        global_transform: GlobalTransform,
        template: dict,
        parameters: dict,
    ) -> Optional[dict]:
        macro_name = global_transform.name
        macros_store = get_cloudformation_store(
            account_id=account_id, region_name=region_name
        ).macros
        macro = macros_store.get(macro_name)
        if macro is None:
            raise RuntimeError(f"No definitions for global transform '{macro_name}'")
        transformation_parameters = global_transform.parameters or dict()
        transformed_template = execute_macro(
            account_id,
            region_name,
            parsed_template=template,
            macro=macro,
            stack_parameters=parameters,
            transformation_parameters=transformation_parameters,
        )
        # The type annotation on the v1 util appears to be incorrect.
        return transformed_template  # noqa

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
            transformed_template = self._apply_global_include(
                global_transform=global_transform,
                region_name=self._change_set.region_name,
                account_id=self._change_set.account_id,
                template=template,
                parameters=parameters,
            )
        else:
            transformed_template = self._apply_global_macro_transformation(
                account_id=self._change_set.account_id,
                region_name=self._change_set.region_name,
                global_transform=global_transform,
                template=template,
                parameters=parameters,
            )
        return transformed_template

    def transform(self) -> tuple[dict, dict]:
        self._setup_runtime_cache()

        node_template = self._change_set.update_model.node_template

        parameters_delta = self.visit_node_parameters(node_template.parameters)
        parameters_before = parameters_delta.before
        parameters_after = parameters_delta.after

        transform_delta: PreprocEntityDelta[list[GlobalTransform], list[GlobalTransform]] = (
            self.visit_node_transform(node_template.transform)
        )
        transform_before: Maybe[list[GlobalTransform]] = transform_delta.before
        transform_after: Maybe[list[GlobalTransform]] = transform_delta.after

        transformed_before_template = self._before_template
        if transform_before and not is_nothing(self._before_template):
            transformed_before_template = self._before_cache.get(_SCOPE_TRANSFORM_TEMPLATE_OUTCOME)
            if not transformed_before_template:
                transformed_before_template = self._before_template
                for before_global_transform in transform_before:
                    if not is_nothing(before_global_transform.name):
                        transformed_before_template = self._apply_global_transform(
                            global_transform=before_global_transform,
                            parameters=parameters_before,
                            template=transformed_before_template,
                        )
                self._before_cache[_SCOPE_TRANSFORM_TEMPLATE_OUTCOME] = transformed_before_template

        transformed_after_template = self._after_template
        if transform_after and not is_nothing(self._after_template):
            transformed_after_template = self._after_cache.get(_SCOPE_TRANSFORM_TEMPLATE_OUTCOME)
            if not transformed_after_template:
                transformed_after_template = self._after_template
                for after_global_transform in transform_after:
                    if not is_nothing(after_global_transform.name):
                        transformed_after_template = self._apply_global_transform(
                            global_transform=after_global_transform,
                            parameters=parameters_after,
                            template=transformed_after_template,
                        )
                self._after_cache[_SCOPE_TRANSFORM_TEMPLATE_OUTCOME] = transformed_after_template

        self._save_runtime_cache()

        ### Handle Embedded Fn::Transform
        transformed_before_template = self._execute_embedded_transformations(
            template=transformed_before_template, resolved_parameters=parameters_before
        )
        transformed_after_template = self._execute_embedded_transformations(
            template=transformed_after_template, resolved_parameters=parameters_after
        )

        return transformed_before_template, transformed_after_template

    def _execute_embedded_transformations(
        self, template, resolved_parameters
    ) -> PreprocEntityDelta:
        transformations = self._find_fn_transforms(template)
        normalized_transformations = self._normalize_transform_definitions(transformations)

        transformed_template = copy.deepcopy(template)
        for transformation in normalized_transformations:
            transformed_template = self._execute_embedded_transformation(
                transformation=transformation,
                template=transformed_template,
                resolved_parameters=resolved_parameters,
            )
        return transformed_template

    @staticmethod
    def _normalize_transform_definitions(
        transform_definitions: list[(any, str)],
    ) -> dict:
        def _normalize_individual_transform(transform_def: str | dict):
            # TODO: validate parameters, imports, refs to resources or conditionals are not supported.
            #      only literals, refs to parameters and basic intrinsic functions like sub and join, posibly select
            if isinstance(transform_def, str):
                return {"Name": transform_def, "Parameters": {}}

            if isinstance(transform_def, dict):
                return {
                    "Name": transform_def["Name"],
                    "Parameters": transform_def.get("Parameters", {}),
                }

            raise FailedTransformationException("Invalid Definition of transformation")

        normalized_transforms = []
        for path, value in transform_definitions:
            if isinstance(value, list):
                for transform in value:
                    normalized_transforms.append((_normalize_individual_transform(transform), path))
            else:
                normalized_transforms.append((_normalize_individual_transform(value), path))

        return normalized_transforms

    def _execute_embedded_transformation(
        self, transformation: (dict, str), template: dict, resolved_parameters: dict
    ) -> dict:
        macros_store = get_cloudformation_store(
            account_id=self._change_set.account_id, region_name=self._change_set.region_name
        ).macros

        def _apply_transform_on_template(scope, template, transformation_result, include=False):
            node = template
            prev_node = node
            for key in scope.split("/")[:-1]:
                prev_node = node
                node = node[key]

            if include and isinstance(prev_node, dict):
                del node["Fn::Transform"]
                prev_node[key].update(transformation_result)
            else:
                prev_node[key] = transformation_result

            return template

        scope = transformation[1]
        transform_name = transformation[0]["Name"]
        transform_parameters = transformation[0]["Parameters"]

        if transform_name in transformers:
            builtin_transformer_class = transformers[transform_name]
            builtin_transformer: Transformer = builtin_transformer_class()
            transform_output: Any = builtin_transformer.transform(
                account_id=self._change_set.account_id,
                region_name=self._change_set.region_name,
                parameters=transform_parameters,
            )
            return _apply_transform_on_template(scope, template, transform_output, True)

        if transform_name in macros_store:
            # A macro is only able to access their node parent and siblings
            parent_node = template
            for key in scope.split("/")[:-1]:
                parent_node = parent_node.get(key)

            transform_output: Any = execute_macro(
                account_id=self._change_set.account_id,
                region_name=self._change_set.region_name,
                parsed_template=parent_node,
                macro=transformation[0],
                stack_parameters=resolved_parameters,
                transformation_parameters=transform_parameters,
                is_intrinsic=True,
            )
            return _apply_transform_on_template(scope, template, transform_output)
        raise FailedTransformationException("Macro not found")

    def _find_fn_transforms(self, obj, path=None) -> list[(any, str)]:
        if path is None:
            path = []

        results = []

        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = path + [key]
                if key == "Fn::Transform":
                    results.append(("/".join(current_path), value))
                results.extend(self._find_fn_transforms(value, current_path))

        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                current_path = path + [f"{idx}"]
                results.extend(self._find_fn_transforms(item, current_path))

        return results

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
        before = list() if change_type != ChangeType.CREATED else Nothing
        after = list() if change_type != ChangeType.REMOVED else Nothing
        for change_set_entity in node_transform.global_transforms:
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

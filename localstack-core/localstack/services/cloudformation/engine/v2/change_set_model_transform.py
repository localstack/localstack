import copy
import logging
import os
from typing import Any, Final, Optional, TypedDict

import boto3
from samtranslator.translator.transform import transform as transform_sam

from localstack.services.cloudformation.engine.policy_loader import create_policy_loader
from localstack.services.cloudformation.engine.transformers import (
    FailedTransformationException,
    execute_macro,
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

LOG = logging.getLogger(__name__)

SERVERLESS_TRANSFORM = "AWS::Serverless-2016-10-31"
EXTENSIONS_TRANSFORM = "AWS::LanguageExtensions"
SECRETSMANAGER_TRANSFORM = "AWS::SecretsManager-2020-07-23"

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
                    transformed_after_template = self._apply_global_transform(
                        global_transform=after_global_transform,
                        parameters=parameters_after,
                        template=transformed_after_template,
                    )
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

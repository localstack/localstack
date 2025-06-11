import copy
import os
from typing import Final, Optional

import boto3
from samtranslator.translator.transform import transform as transform_sam

from localstack.services.cloudformation.engine.policy_loader import create_policy_loader
from localstack.services.cloudformation.engine.transformers import FailedTransformationException
from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeType,
    Maybe,
    NodeGlobalTransform,
    NodeTransform,
    Nothing,
    is_nothing,
)
from localstack.services.cloudformation.engine.v2.change_set_model_preproc import (
    ChangeSetModelPreproc,
    PreprocEntityDelta,
)
from localstack.services.cloudformation.v2.entities import ChangeSet

SERVERLESS_TRANSFORM = "AWS::Serverless-2016-10-31"


# TODO: evaluate the use of subtypes to represent and validate types of transforms
class GlobalTransform:
    name: str
    parameters: Maybe[dict]

    def __init__(self, name: str, parameters: Maybe[dict]):
        self.name = name
        self.parameters = parameters


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

    # Ported from v1:
    @staticmethod
    def _apply_serverless_transformation(
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

    def _apply_global_transform(
        self, global_transform: GlobalTransform, template: dict, parameters: dict
    ) -> dict:
        if global_transform.name == SERVERLESS_TRANSFORM:
            return self._apply_serverless_transformation(
                region_name=self._change_set.region_name,
                template=template,
                parameters=parameters,
            )
        # TODO: expand support
        raise RuntimeError(f"Unsupported global transform '{global_transform.name}'")

    def transform(self) -> tuple[dict, dict]:
        transform_delta: PreprocEntityDelta[list[GlobalTransform], list[GlobalTransform]] = (
            self.visit_node_transform(self._node_template.transform)
        )
        transform_before: Maybe[list[GlobalTransform]] = transform_delta.before
        transform_after: Maybe[list[GlobalTransform]] = transform_delta.after

        transformed_before_template = self._before_template
        if not is_nothing(transform_before) and not is_nothing(self._before_template):
            transformed_before_template = self._before_template
            for before_global_transform in transform_before:
                transformed_before_template = self._apply_global_transform(
                    global_transform=before_global_transform,
                    parameters=self._before_parameters,
                    template=transformed_before_template,
                )

        transformed_after_template = self._after_template
        if not is_nothing(transform_before) and not is_nothing(self._after_template):
            transformed_after_template = self._after_template
            for after_global_transform in transform_after:
                transformed_after_template = self._apply_global_transform(
                    global_transform=after_global_transform,
                    parameters=self._after_parameters,
                    template=transformed_after_template,
                )

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

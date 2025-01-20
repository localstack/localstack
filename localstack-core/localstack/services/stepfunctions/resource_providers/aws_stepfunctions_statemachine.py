# LocalStack Resource Provider Scaffolding v2
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional, TypedDict

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    LOG,
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)
from localstack.utils.strings import to_str


class StepFunctionsStateMachineProperties(TypedDict):
    RoleArn: Optional[str]
    Arn: Optional[str]
    Definition: Optional[dict]
    DefinitionS3Location: Optional[S3Location]
    DefinitionString: Optional[str]
    DefinitionSubstitutions: Optional[dict]
    LoggingConfiguration: Optional[LoggingConfiguration]
    Name: Optional[str]
    StateMachineName: Optional[str]
    StateMachineRevisionId: Optional[str]
    StateMachineType: Optional[str]
    Tags: Optional[list[TagsEntry]]
    TracingConfiguration: Optional[TracingConfiguration]


class CloudWatchLogsLogGroup(TypedDict):
    LogGroupArn: Optional[str]


class LogDestination(TypedDict):
    CloudWatchLogsLogGroup: Optional[CloudWatchLogsLogGroup]


class LoggingConfiguration(TypedDict):
    Destinations: Optional[list[LogDestination]]
    IncludeExecutionData: Optional[bool]
    Level: Optional[str]


class TracingConfiguration(TypedDict):
    Enabled: Optional[bool]


class S3Location(TypedDict):
    Bucket: Optional[str]
    Key: Optional[str]
    Version: Optional[str]


class TagsEntry(TypedDict):
    Key: Optional[str]
    Value: Optional[str]


REPEATED_INVOCATION = "repeated_invocation"


class StepFunctionsStateMachineProvider(ResourceProvider[StepFunctionsStateMachineProperties]):
    TYPE = "AWS::StepFunctions::StateMachine"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[StepFunctionsStateMachineProperties],
    ) -> ProgressEvent[StepFunctionsStateMachineProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/Arn

        Required properties:
          - RoleArn

        Create-only properties:
          - /properties/StateMachineName
          - /properties/StateMachineType

        Read-only properties:
          - /properties/Arn
          - /properties/Name
          - /properties/StateMachineRevisionId

        IAM permissions required:
          - states:CreateStateMachine
          - iam:PassRole
          - s3:GetObject

        """
        model = request.desired_state
        step_function = request.aws_client_factory.stepfunctions

        if not model.get("StateMachineName"):
            model["StateMachineName"] = util.generate_default_name(
                stack_name=request.stack_name, logical_resource_id=request.logical_resource_id
            )

        params = {
            "name": model.get("StateMachineName"),
            "roleArn": model.get("RoleArn"),
            "type": model.get("StateMachineType", "STANDARD"),
        }

        # get definition
        s3_client = request.aws_client_factory.s3

        definition_str = self._get_definition(model, s3_client)

        params["definition"] = definition_str

        response = step_function.create_state_machine(**params)

        model["Arn"] = response["stateMachineArn"]
        model["Name"] = model["StateMachineName"]

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def _get_definition(self, model, s3_client):
        if "DefinitionString" in model:
            definition_str = model.get("DefinitionString")
        elif "DefinitionS3Location" in model:
            # TODO: currently not covered by tests - add a test to mimick the behavior of "sam deploy ..."
            s3_location = model.get("DefinitionS3Location")
            LOG.debug("Fetching state machine definition from S3: %s", s3_location)
            result = s3_client.get_object(Bucket=s3_location["Bucket"], Key=s3_location["Key"])
            definition_str = to_str(result["Body"].read())
        elif "Definition" in model:
            definition = model.get("Definition")
            definition_str = json.dumps(definition)
        else:
            definition_str = None

        substitutions = model.get("DefinitionSubstitutions")
        if substitutions is not None:
            definition_str = _apply_substitutions(definition_str, substitutions)
        return definition_str

    def read(
        self,
        request: ResourceRequest[StepFunctionsStateMachineProperties],
    ) -> ProgressEvent[StepFunctionsStateMachineProperties]:
        """
        Fetch resource information

        IAM permissions required:
          - states:DescribeStateMachine
          - states:ListTagsForResource
        """
        raise NotImplementedError

    def list(
        self, request: ResourceRequest[StepFunctionsStateMachineProperties]
    ) -> ProgressEvent[StepFunctionsStateMachineProperties]:
        resources = request.aws_client_factory.stepfunctions.list_state_machines()["stateMachines"]
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_models=[
                StepFunctionsStateMachineProperties(Arn=resource["stateMachineArn"])
                for resource in resources
            ],
        )

    def delete(
        self,
        request: ResourceRequest[StepFunctionsStateMachineProperties],
    ) -> ProgressEvent[StepFunctionsStateMachineProperties]:
        """
        Delete a resource

        IAM permissions required:
          - states:DeleteStateMachine
          - states:DescribeStateMachine
        """
        model = request.desired_state
        step_function = request.aws_client_factory.stepfunctions

        step_function.delete_state_machine(stateMachineArn=model["Arn"])

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def update(
        self,
        request: ResourceRequest[StepFunctionsStateMachineProperties],
    ) -> ProgressEvent[StepFunctionsStateMachineProperties]:
        """
        Update a resource

        IAM permissions required:
          - states:UpdateStateMachine
          - states:TagResource
          - states:UntagResource
          - states:ListTagsForResource
          - iam:PassRole
        """
        model = request.desired_state
        step_function = request.aws_client_factory.stepfunctions

        if not model.get("Arn"):
            model["Arn"] = request.previous_state["Arn"]

        definition_str = self._get_definition(model, request.aws_client_factory.s3)
        params = {
            "stateMachineArn": model["Arn"],
            "definition": definition_str,
        }

        step_function.update_state_machine(**params)

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )


def _apply_substitutions(definition: str, substitutions: dict[str, str]) -> str:
    substitution_regex = re.compile("\\${[a-zA-Z0-9_]+}")  # might be a bit too strict in some cases
    tokens = substitution_regex.findall(definition)
    result = definition
    for token in tokens:
        raw_token = token[2:-1]  # strip ${ and }
        if raw_token not in substitutions:
            raise
        result = result.replace(token, substitutions[raw_token])

    return result

from __future__ import annotations

from typing import Optional, Type, TypedDict

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)
from localstack.utils.strings import short_uid


class SSMParameterProperties(TypedDict):
    Type: str
    Value: str
    AllowedPattern: Optional[str]
    DataType: Optional[str]
    Description: Optional[str]
    Id: Optional[str]
    Name: Optional[str]
    Policies: Optional[str]
    Tags: Optional[dict]
    Tier: Optional[str]


class SSMParameterProvider(ResourceProvider[SSMParameterProperties]):
    TYPE = "AWS::SSM::Parameter"

    def create(
        self,
        request: ResourceRequest[SSMParameterProperties],
    ) -> ProgressEvent[SSMParameterProperties]:
        """
        Create a new resource.
        """
        model = request.desired_state

        # TODO: validations
        assert model["Type"] in {"String", "SecureString", "StringList"}
        assert model["Value"] is not None

        # defaults
        if model.get("DataType") is None:
            model["DataType"] = "text"

        if model.get("Name") is None:
            # TODO: fix auto-generation
            model["Name"] = f"param-{short_uid()}"

        # TODO: add comment why we set this to Id as well
        model["Id"] = model["Name"]

        # idempotency
        try:
            request.aws_client_factory.ssm.get_parameter(Name=model["Name"])
        except request.aws_client_factory.ssm.exceptions.ParameterNotFound:
            pass
        else:
            # the resource already exists
            # for now raise an exception
            # TODO: return progress event
            raise RuntimeError(f"ssm parameter: {model['Name']} already exists")

        # create the parameter
        res = request.aws_client_factory.ssm.put_parameter(
            Name=model["Name"],
            Type=model["Type"],
            Value=model["Value"],
        )
        model["Tier"] = res.get("Tier", "Standard")

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

    def delete(
        self,
        request: ResourceRequest[SSMParameterProperties],
    ) -> ProgressEvent[SSMParameterProperties]:
        name = request.desired_state["Name"]
        request.aws_client_factory.ssm.delete_parameter(Name=name)
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=request.desired_state)


class SSMParameterProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::SSM::Parameter"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        self.factory = SSMParameterProvider

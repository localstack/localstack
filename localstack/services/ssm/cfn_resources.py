from dataclasses import dataclass
from typing import Optional

from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
    register_resource_provider,
)
from localstack.utils.strings import short_uid


@dataclass
class SSMParameterProperties:
    Value: str
    Type: str

    AllowedPattern: Optional[str] = None
    DataType: Optional[str] = None
    Description: Optional[str] = None
    Name: Optional[str] = None
    Policies: Optional[str] = None
    Tags: Optional[dict] = None
    Tier: Optional[str] = None


class SSMParameterAllProperties(SSMParameterProperties):
    id: Optional[str] = None
    physical_resource_id: Optional[str] = None


@register_resource_provider
class SSMParameterProvider(ResourceProvider[SSMParameterAllProperties]):
    TYPE = "AWS::SSM::Parameter"

    def create(
        self,
        request: ResourceRequest[SSMParameterAllProperties],
    ) -> ProgressEvent[SSMParameterAllProperties]:
        model = request.desired_state
        breakpoint()

        # Validations
        assert model.Type is not None

        # defaults
        model.DataType = "text"
        model.Name = f"param-{short_uid()}"

        # create the parameter
        request.aws_client_factory.ssm.put_parameter(
            Name=model.Name,
            Type=model.Type,
            Value=model.Value,
        )

        model.id = "my-ssm-parameter"

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

    def delete(
        self, request: ResourceRequest[SSMParameterAllProperties]
    ) -> ProgressEvent[SSMParameterAllProperties]:
        name = request.desired_state.Name
        request.aws_client_factory.ssm.delete_parameter(Name=name)
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=request.desired_state)

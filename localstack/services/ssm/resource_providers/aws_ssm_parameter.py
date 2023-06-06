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
    Type: str
    Value: str
    AllowedPattern: Optional[str] = None
    DataType: Optional[str] = None
    Description: Optional[str] = None
    Id: Optional[str] = None
    Name: Optional[str] = None
    Policies: Optional[str] = None
    Tags: Optional[dict] = None
    Tier: Optional[str] = None


class SSMParameterAllProperties(SSMParameterProperties):
    physical_resource_id: Optional[str] = None


@register_resource_provider
class SSMParameterProvider(ResourceProvider[SSMParameterAllProperties]):

    TYPE = "AWS::SSM::Parameter"

    def create(
        self,
        request: ResourceRequest[SSMParameterAllProperties],
    ) -> ProgressEvent[SSMParameterAllProperties]:
        """
        Create a new resource.
        """
        model = request.desired_state

        # TODO: validations
        assert model.Type is not None
        assert model.Value is not None

        # defaults
        if model.DataType is None:
            model.DataType = "text"

        if model.Name is None:
            model.Name = f"param-{short_uid()}"

        # idempotency
        try:
            request.aws_client_factory.ssm.get_parameter(Name=model.Name)
        except request.aws_client_factory.ssm.exceptions.ParameterNotFound:
            pass
        else:
            # the resource already exists
            # for now raise an exception
            # TODO: return progress event
            raise RuntimeError(f"opensearch domain {model.Name} already exists")

        # create the parameter
        res = request.aws_client_factory.ssm.put_parameter(
            Name=model.Name,
            Type=model.Type,
            Value=model.Value,
        )

        model.Tier = res.get("Tier", "Standard")

        model.physical_resource_id = "my-ssm-parameter"

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

    def delete(
        self,
        request: ResourceRequest[SSMParameterAllProperties],
    ) -> ProgressEvent[SSMParameterAllProperties]:
        name = request.desired_state.Name
        request.aws_client_factory.ssm.delete_parameter(Name=name)
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=request.desired_state)

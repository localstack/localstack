from typing import Optional, TypedDict

from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
    register_resource_provider,
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


class SSMParameterAllProperties(SSMParameterProperties):
    physical_resource_id: Optional[str]


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
        assert model["Type"] in {"String", "SecureString", "StringList"}
        assert model["Value"] is not None

        # defaults
        if model.get("DataType") is None:
            model["DataType"] = "text"

        if model.get("Name") is None:
            model["Name"] = f"param-{short_uid()}"

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

        # TODO
        model["physical_resource_id"] = "my-ssm-parameter"

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

    def delete(
        self,
        request: ResourceRequest[SSMParameterAllProperties],
    ) -> ProgressEvent[SSMParameterAllProperties]:
        name = request.desired_state["Name"]
        request.aws_client_factory.ssm.delete_parameter(Name=name)
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=request.desired_state)

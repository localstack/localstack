from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
    register_resource_provider,
)


@dataclass
class TracingConfig:
    Mode: Optional[str] = None


@dataclass
class VpcConfig:
    SecurityGroupIds: Optional[list] = None
    SubnetIds: Optional[list] = None


@dataclass
class RuntimeManagementConfig:
    RuntimeVersionArn: Optional[str] = None
    UpdateRuntimeOn: Optional[str] = None


@dataclass
class SnapStart:
    ApplyOn: Optional[str] = None


@dataclass
class ImageConfig:
    Command: Optional[list] = None
    EntryPoint: Optional[list] = None
    WorkingDirectory: Optional[str] = None


@dataclass
class DeadLetterConfig:
    TargetArn: Optional[str] = None


@dataclass
class SnapStartResponse:
    ApplyOn: Optional[str] = None
    OptimizationStatus: Optional[str] = None


@dataclass
class Code:
    ImageUri: Optional[str] = None
    S3Bucket: Optional[str] = None
    S3Key: Optional[str] = None
    S3ObjectVersion: Optional[str] = None
    ZipFile: Optional[str] = None


@dataclass
class Environment:
    Variables: Optional[dict] = None


@dataclass
class EphemeralStorage:
    Size: Optional[int] = None


@dataclass
class LambdaFunctionProperties:
    Code: Code
    Role: str
    Architectures: Optional[list] = None
    Arn: Optional[str] = None
    CodeSigningConfigArn: Optional[str] = None
    DeadLetterConfig: Optional[DeadLetterConfig] = None
    Description: Optional[str] = None
    Environment: Optional[Environment] = None
    EphemeralStorage: Optional[EphemeralStorage] = None
    FileSystemConfigs: Optional[list] = None
    FunctionName: Optional[str] = None
    Handler: Optional[str] = None
    ImageConfig: Optional[ImageConfig] = None
    KmsKeyArn: Optional[str] = None
    Layers: Optional[list] = None
    MemorySize: Optional[int] = None
    PackageType: Optional[str] = None
    ReservedConcurrentExecutions: Optional[int] = None
    Runtime: Optional[str] = None
    RuntimeManagementConfig: Optional[RuntimeManagementConfig] = None
    SnapStart: Optional[SnapStart] = None
    SnapStartResponse: Optional[SnapStartResponse] = None
    Tags: Optional[list] = None
    Timeout: Optional[int] = None
    TracingConfig: Optional[TracingConfig] = None
    VpcConfig: Optional[VpcConfig] = None


class LambdaFunctionAllProperties(LambdaFunctionProperties):
    physical_resource_id: Optional[str] = None


@register_resource_provider
class LambdaFunctionProvider(ResourceProvider[LambdaFunctionAllProperties]):

    TYPE = "AWS::Lambda::Function"

    def create(
        self,
        request: ResourceRequest[LambdaFunctionAllProperties],
    ) -> ProgressEvent[LambdaFunctionAllProperties]:
        """
        Create a new resource.
        """
        model = request.desired_state

        # Validation
        assert model.FunctionName is not None
        # TODO: more input parameter validations

        if model.physical_resource_id is None:
            # this is the first time this callback is invoked
            # TODO: defaults
            # TODO: What are these defaults?

            # Idempotency
            # TODO: idempotency
            # try:
            # request.aws_client_factory.awslambda.get_function(...)
            # except request.aws_client_factory.awslambda.exceptions.ResourceNotFoundException:
            #     pass
            # else:
            # the resource already exists, raise exception
            # raise RuntimeError(f"lambda function {model.FunctionName} already exists")

            # TODO: actually create the resource
            # res = request.aws_client_factory.awslambda.create_function(...)

            # TODO: set model.physical_resource_id
            model.physical_resource_id = "my-lambda-function"  # model.FunctionName
            return ProgressEvent(status=OperationStatus.IN_PROGRESS, resource_model=model)

        # TODO: check the status of the resource
        # aws lambda get-function --function-name my-function --query 'Configuration.[State, LastUpdateStatus]'
        # - if finished, update the model with all fields and return success event:
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)
        # - else
        #   return ProgressEvent(status=OperationStatus.IN_PROGRESS, resource_model=model)

    def delete(
        self,
        request: ResourceRequest[LambdaFunctionAllProperties],
    ) -> ProgressEvent[LambdaFunctionAllProperties]:
        # TODO: impl
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=request.desired_state)

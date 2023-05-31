from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

from localstack.aws.api.lambda_ import Runtime, State
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
    register_resource_provider,
)
from localstack.utils.testutil import create_lambda_archive


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
# TODO: how to instantiate this type? Should this be a (TypedDict, total=False)
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


LOG = logging.getLogger(__name__)

PYTHON_RUNTIMES = [Runtime.python3_7, Runtime.python3_8, Runtime.python3_9, Runtime.python3_10]
NODEJS_RUNTIMES = [Runtime.nodejs12_x, Runtime.nodejs14_x, Runtime.nodejs16_x, Runtime.nodejs18_x]
INLINE_CODE_RUNTIMES = [*PYTHON_RUNTIMES, *NODEJS_RUNTIMES]


@register_resource_provider
class LambdaFunctionProvider(ResourceProvider[LambdaFunctionAllProperties]):

    TYPE = "AWS::Lambda::Function"

    def create(
        self,
        request: ResourceRequest[LambdaFunctionAllProperties],
    ) -> ProgressEvent[LambdaFunctionAllProperties]:
        model = request.desired_state

        # Validation
        assert model.FunctionName is not None
        assert model.Role is not None
        # TODO: more input parameter validations. Re-use from Lambda provider or boto-spec based validation possible?

        if model.physical_resource_id is None:
            # this is the first time this callback is invoked
            # TODO: defaults
            # TODO: What are these defaults?

            # Idempotency
            try:
                request.aws_client_factory.awslambda.get_function(FunctionName=model.FunctionName)
            except request.aws_client_factory.awslambda.exceptions.ResourceNotFoundException:
                pass
            else:
                # the resource already exists
                # for now raise an exception
                raise RuntimeError(f"Lambda function {model.FunctionName} already exists")

            zip_file = model.Code.get("ZipFile")
            zip_file_exists = os.path.isfile(zip_file)
            # Handle inline ZipFile supported for Node.js and Python
            if not zip_file_exists and model.Runtime in INLINE_CODE_RUNTIMES:
                # TODO: extract functionality, do not misuse testutils !!!
                inline_zip_file = create_lambda_archive(
                    zip_file,
                    get_content=True,
                    runtime=model.Runtime,
                )
                model.Code = {"ZipFile": inline_zip_file}
            # TODO: add cfn-response dependency for Node.js and Python for interaction with custom CF resource:
            # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-function-code.html

            # create the function
            # TODO: handle many more parameters and configuration combinations
            response = request.aws_client_factory.awslambda.create_function(
                FunctionName=model.FunctionName,
                Code=model.Code,
                Role=model.Role,
                Runtime=model.Runtime,
            )

            model.physical_resource_id = model.FunctionName
            return ProgressEvent(status=OperationStatus.IN_PROGRESS, resource_model=model)

        # MAYBE: optimize query to only return the state like --query 'Configuration.[State, LastUpdateStatus]'
        response = request.aws_client_factory.awslambda.get_function(
            FunctionName=model.FunctionName
        )
        function_state = response["Configuration"]["State"]
        if function_state == State.Pending:
            return ProgressEvent(status=OperationStatus.IN_PROGRESS, resource_model=model)
        elif function_state == State.Active:
            return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)
        elif function_state == State.Inactive:
            # This might happen when setting LAMBDA_KEEPALIVE_MS=0
            LOG.warning(
                f"Lambda function {model.FunctionName} is in Inactive state during deployment"
            )
            return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)
        elif function_state == State.Failed:
            return ProgressEvent(status=OperationStatus.FAILED, resource_model=model)
        else:
            LOG.warning(
                f"Lambda function {model.FunctionName} is in invalid function state {function_state}"
            )

    def delete(
        self,
        request: ResourceRequest[LambdaFunctionAllProperties],
    ) -> ProgressEvent[LambdaFunctionAllProperties]:
        function_name = request.desired_state.FunctionName
        try:
            request.aws_client_factory.awslambda.get_function(FunctionName=function_name)
            request.aws_client_factory.awslambda.delete_function(FunctionName=function_name)
            # We assume that function deletion happens instantly at API level. The background task to stop any running
            # function containers might take longer.
        except request.aws_client_factory.awslambda.exceptions.ResourceNotFoundException:
            # Function already deleted
            pass

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=request.desired_state)

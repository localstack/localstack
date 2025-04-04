# LocalStack Resource Provider Scaffolding v2
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, TypedDict

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)
from localstack.services.lambda_.lambda_utils import get_handler_file_from_name
from localstack.utils.archives import is_zip_file
from localstack.utils.files import mkdir, new_tmp_dir, rm_rf, save_file
from localstack.utils.strings import is_base64, to_bytes
from localstack.utils.testutil import create_zip_file


class LambdaFunctionProperties(TypedDict):
    Code: Optional[Code]
    Role: Optional[str]
    Architectures: Optional[list[str]]
    Arn: Optional[str]
    CodeSigningConfigArn: Optional[str]
    DeadLetterConfig: Optional[DeadLetterConfig]
    Description: Optional[str]
    Environment: Optional[Environment]
    EphemeralStorage: Optional[EphemeralStorage]
    FileSystemConfigs: Optional[list[FileSystemConfig]]
    FunctionName: Optional[str]
    Handler: Optional[str]
    ImageConfig: Optional[ImageConfig]
    KmsKeyArn: Optional[str]
    Layers: Optional[list[str]]
    MemorySize: Optional[int]
    PackageType: Optional[str]
    ReservedConcurrentExecutions: Optional[int]
    Runtime: Optional[str]
    RuntimeManagementConfig: Optional[RuntimeManagementConfig]
    SnapStart: Optional[SnapStart]
    SnapStartResponse: Optional[SnapStartResponse]
    Tags: Optional[list[Tag]]
    Timeout: Optional[int]
    TracingConfig: Optional[TracingConfig]
    VpcConfig: Optional[VpcConfig]


class TracingConfig(TypedDict):
    Mode: Optional[str]


class VpcConfig(TypedDict):
    SecurityGroupIds: Optional[list[str]]
    SubnetIds: Optional[list[str]]


class RuntimeManagementConfig(TypedDict):
    UpdateRuntimeOn: Optional[str]
    RuntimeVersionArn: Optional[str]


class SnapStart(TypedDict):
    ApplyOn: Optional[str]


class FileSystemConfig(TypedDict):
    Arn: Optional[str]
    LocalMountPath: Optional[str]


class Tag(TypedDict):
    Key: Optional[str]
    Value: Optional[str]


class ImageConfig(TypedDict):
    Command: Optional[list[str]]
    EntryPoint: Optional[list[str]]
    WorkingDirectory: Optional[str]


class DeadLetterConfig(TypedDict):
    TargetArn: Optional[str]


class SnapStartResponse(TypedDict):
    ApplyOn: Optional[str]
    OptimizationStatus: Optional[str]


class Code(TypedDict):
    ImageUri: Optional[str]
    S3Bucket: Optional[str]
    S3Key: Optional[str]
    S3ObjectVersion: Optional[str]
    ZipFile: Optional[str]


class LoggingConfig(TypedDict):
    ApplicationLogLevel: Optional[str]
    LogFormat: Optional[str]
    LogGroup: Optional[str]
    SystemLogLevel: Optional[str]


class Environment(TypedDict):
    Variables: Optional[dict]


class EphemeralStorage(TypedDict):
    Size: Optional[int]


REPEATED_INVOCATION = "repeated_invocation"

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-lambda-function-code-cfnresponsemodule.html
PYTHON_CFN_RESPONSE_CONTENT = """
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from __future__ import print_function
import urllib3
import json

SUCCESS = "SUCCESS"
FAILED = "FAILED"

http = urllib3.PoolManager()


def send(event, context, responseStatus, responseData, physicalResourceId=None, noEcho=False, reason=None):
    responseUrl = event['ResponseURL']

    print(responseUrl)

    responseBody = {
        'Status' : responseStatus,
        'Reason' : reason or "See the details in CloudWatch Log Stream: {}".format(context.log_stream_name),
        'PhysicalResourceId' : physicalResourceId or context.log_stream_name,
        'StackId' : event['StackId'],
        'RequestId' : event['RequestId'],
        'LogicalResourceId' : event['LogicalResourceId'],
        'NoEcho' : noEcho,
        'Data' : responseData
    }

    json_responseBody = json.dumps(responseBody)

    print("Response body:")
    print(json_responseBody)

    headers = {
        'content-type' : '',
        'content-length' : str(len(json_responseBody))
    }

    try:
        response = http.request('PUT', responseUrl, headers=headers, body=json_responseBody)
        print("Status code:", response.status)


    except Exception as e:

        print("send(..) failed executing http.request(..):", e)
"""

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-lambda-function-code-cfnresponsemodule.html
NODEJS_CFN_RESPONSE_CONTENT = r"""
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

exports.SUCCESS = "SUCCESS";
exports.FAILED = "FAILED";

exports.send = function(event, context, responseStatus, responseData, physicalResourceId, noEcho) {

    var responseBody = JSON.stringify({
        Status: responseStatus,
        Reason: "See the details in CloudWatch Log Stream: " + context.logStreamName,
        PhysicalResourceId: physicalResourceId || context.logStreamName,
        StackId: event.StackId,
        RequestId: event.RequestId,
        LogicalResourceId: event.LogicalResourceId,
        NoEcho: noEcho || false,
        Data: responseData
    });

    console.log("Response body:\n", responseBody);

    var https = require("https");
    var url = require("url");

    var parsedUrl = url.parse(event.ResponseURL);
    var options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port, // Modified line: LS uses port 4566 for https; hard coded 443 causes error
        path: parsedUrl.path,
        method: "PUT",
        headers: {
            "content-type": "",
            "content-length": responseBody.length
        }
    };

    var request = https.request(options, function(response) {
        console.log("Status code: " + parseInt(response.statusCode));
        context.done();
    });

    request.on("error", function(error) {
        console.log("send(..) failed executing https.request(..): " + error);
        context.done();
    });

    request.write(responseBody);
    request.end();
}
"""


def _runtime_supports_inline_code(runtime: str) -> bool:
    return runtime.startswith("python") or runtime.startswith("node")


def _get_lambda_code_param(
    properties: LambdaFunctionProperties,
    _include_arch=False,
):
    # code here is mostly taken directly from legacy implementation
    code = properties.get("Code", {}).copy()

    # TODO: verify only one of "ImageUri" | "S3Bucket" | "ZipFile" is set
    zip_file = code.get("ZipFile")
    if zip_file and not _runtime_supports_inline_code(properties["Runtime"]):
        raise Exception(
            f"Runtime {properties['Runtime']} doesn't support inlining code via the 'ZipFile' property."
        )  # TODO: message not validated
    if zip_file and not is_base64(zip_file) and not is_zip_file(to_bytes(zip_file)):
        tmp_dir = new_tmp_dir()
        try:
            handler_file = get_handler_file_from_name(
                properties["Handler"], runtime=properties["Runtime"]
            )
            tmp_file = os.path.join(tmp_dir, handler_file)
            save_file(tmp_file, zip_file)

            # CloudFormation only includes cfn-response libs if an import is detected
            # TODO: add snapshots for this behavior
            # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-lambda-function-code-cfnresponsemodule.html
            if properties["Runtime"].lower().startswith("node") and (
                "require('cfn-response')" in zip_file or 'require("cfn-response")' in zip_file
            ):
                # the check if cfn-response is used is pretty simplistic and apparently based on simple string matching
                # having the import commented out will also lead to cfn-response.js being injected
                # this is added under both cfn-response.js and node_modules/cfn-response.js
                cfn_response_mod_dir = os.path.join(tmp_dir, "node_modules")
                mkdir(cfn_response_mod_dir)
                save_file(
                    os.path.join(cfn_response_mod_dir, "cfn-response.js"),
                    NODEJS_CFN_RESPONSE_CONTENT,
                )
                save_file(os.path.join(tmp_dir, "cfn-response.js"), NODEJS_CFN_RESPONSE_CONTENT)
            elif (
                properties["Runtime"].lower().startswith("python")
                and "import cfnresponse" in zip_file
            ):
                save_file(os.path.join(tmp_dir, "cfnresponse.py"), PYTHON_CFN_RESPONSE_CONTENT)

            # create zip file
            zip_file = create_zip_file(tmp_dir, get_content=True)
            code["ZipFile"] = zip_file
        finally:
            rm_rf(tmp_dir)
    if _include_arch and "Architectures" in properties:
        code["Architectures"] = properties.get("Architectures")
    return code


def _transform_function_to_model(function):
    model_properties = [
        "MemorySize",
        "Description",
        "TracingConfig",
        "Timeout",
        "Handler",
        "SnapStartResponse",
        "Role",
        "FileSystemConfigs",
        "FunctionName",
        "Runtime",
        "PackageType",
        "LoggingConfig",
        "Environment",
        "Arn",
        "EphemeralStorage",
        "Architectures",
    ]
    response_model = util.select_attributes(function, model_properties)
    response_model["Arn"] = function["FunctionArn"]
    return response_model


class LambdaFunctionProvider(ResourceProvider[LambdaFunctionProperties]):
    TYPE = "AWS::Lambda::Function"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[LambdaFunctionProperties],
    ) -> ProgressEvent[LambdaFunctionProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/FunctionName

        Required properties:
          - Code
          - Role

        Create-only properties:
          - /properties/FunctionName

        Read-only properties:
          - /properties/Arn
          - /properties/SnapStartResponse
          - /properties/SnapStartResponse/ApplyOn
          - /properties/SnapStartResponse/OptimizationStatus

        IAM permissions required:
          - lambda:CreateFunction
          - lambda:GetFunction
          - lambda:PutFunctionConcurrency
          - iam:PassRole
          - s3:GetObject
          - s3:GetObjectVersion
          - ec2:DescribeSecurityGroups
          - ec2:DescribeSubnets
          - ec2:DescribeVpcs
          - elasticfilesystem:DescribeMountTargets
          - kms:CreateGrant
          - kms:Decrypt
          - kms:Encrypt
          - kms:GenerateDataKey
          - lambda:GetCodeSigningConfig
          - lambda:GetFunctionCodeSigningConfig
          - lambda:GetLayerVersion
          - lambda:GetRuntimeManagementConfig
          - lambda:PutRuntimeManagementConfig
          - lambda:TagResource
          - lambda:GetPolicy
          - lambda:AddPermission
          - lambda:RemovePermission
          - lambda:GetResourcePolicy
          - lambda:PutResourcePolicy

        """
        model = request.desired_state
        lambda_client = request.aws_client_factory.lambda_

        if not request.custom_context.get(REPEATED_INVOCATION):
            request.custom_context[REPEATED_INVOCATION] = True

            name = model.get("FunctionName")
            if not name:
                name = util.generate_default_name(request.stack_name, request.logical_resource_id)
                model["FunctionName"] = name

            kwargs = util.select_attributes(
                model,
                [
                    "Architectures",
                    "DeadLetterConfig",
                    "Description",
                    "FunctionName",
                    "Handler",
                    "ImageConfig",
                    "PackageType",
                    "Layers",
                    "MemorySize",
                    "Runtime",
                    "Role",
                    "Timeout",
                    "TracingConfig",
                    "VpcConfig",
                    "LoggingConfig",
                ],
            )
            if "Timeout" in kwargs:
                kwargs["Timeout"] = int(kwargs["Timeout"])
            if "MemorySize" in kwargs:
                kwargs["MemorySize"] = int(kwargs["MemorySize"])
            if model_tags := model.get("Tags"):
                tags = {}
                for tag in model_tags:
                    tags[tag["Key"]] = tag["Value"]
                kwargs["Tags"] = tags

            # botocore/data/lambda/2015-03-31/service-2.json:1161 (EnvironmentVariableValue)
            # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-function-environment.html
            if "Environment" in model:
                environment_variables = model["Environment"].get("Variables", {})
                kwargs["Environment"] = {
                    "Variables": {k: str(v) for k, v in environment_variables.items()}
                }

            kwargs["Code"] = _get_lambda_code_param(model)
            create_response = lambda_client.create_function(**kwargs)
            model["Arn"] = create_response["FunctionArn"]

        get_fn_response = lambda_client.get_function(FunctionName=model["Arn"])
        match get_fn_response["Configuration"]["State"]:
            case "Pending":
                return ProgressEvent(
                    status=OperationStatus.IN_PROGRESS,
                    resource_model=model,
                    custom_context=request.custom_context,
                )
            case "Active":
                return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)
            case "Inactive":
                # This might happen when setting LAMBDA_KEEPALIVE_MS=0
                return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)
            case "Failed":
                return ProgressEvent(
                    status=OperationStatus.FAILED,
                    resource_model=model,
                    error_code=get_fn_response["Configuration"].get("StateReasonCode", "unknown"),
                    message=get_fn_response["Configuration"].get("StateReason", "unknown"),
                )
            case unknown_state:  # invalid state, should technically never happen
                return ProgressEvent(
                    status=OperationStatus.FAILED,
                    resource_model=model,
                    error_code="InternalException",
                    message=f"Invalid state returned: {unknown_state}",
                )

    def read(
        self,
        request: ResourceRequest[LambdaFunctionProperties],
    ) -> ProgressEvent[LambdaFunctionProperties]:
        """
        Fetch resource information

        IAM permissions required:
          - lambda:GetFunction
          - lambda:GetFunctionCodeSigningConfig
        """
        function_name = request.desired_state["FunctionName"]
        lambda_client = request.aws_client_factory.lambda_
        get_fn_response = lambda_client.get_function(FunctionName=function_name)

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=_transform_function_to_model(get_fn_response["Configuration"]),
        )

    def delete(
        self,
        request: ResourceRequest[LambdaFunctionProperties],
    ) -> ProgressEvent[LambdaFunctionProperties]:
        """
        Delete a resource

        IAM permissions required:
          - lambda:DeleteFunction
          - ec2:DescribeNetworkInterfaces
        """
        try:
            lambda_client = request.aws_client_factory.lambda_
            lambda_client.delete_function(FunctionName=request.previous_state["FunctionName"])
        except request.aws_client_factory.lambda_.exceptions.ResourceNotFoundException:
            pass
        # any other exception will be propagated
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model={})

    def update(
        self,
        request: ResourceRequest[LambdaFunctionProperties],
    ) -> ProgressEvent[LambdaFunctionProperties]:
        """
        Update a resource

        IAM permissions required:
          - lambda:DeleteFunctionConcurrency
          - lambda:GetFunction
          - lambda:PutFunctionConcurrency
          - lambda:ListTags
          - lambda:TagResource
          - lambda:UntagResource
          - lambda:UpdateFunctionConfiguration
          - lambda:UpdateFunctionCode
          - iam:PassRole
          - s3:GetObject
          - s3:GetObjectVersion
          - ec2:DescribeSecurityGroups
          - ec2:DescribeSubnets
          - ec2:DescribeVpcs
          - elasticfilesystem:DescribeMountTargets
          - kms:CreateGrant
          - kms:Decrypt
          - kms:GenerateDataKey
          - lambda:GetRuntimeManagementConfig
          - lambda:PutRuntimeManagementConfig
          - lambda:PutFunctionCodeSigningConfig
          - lambda:DeleteFunctionCodeSigningConfig
          - lambda:GetCodeSigningConfig
          - lambda:GetFunctionCodeSigningConfig
          - lambda:GetPolicy
          - lambda:AddPermission
          - lambda:RemovePermission
          - lambda:GetResourcePolicy
          - lambda:PutResourcePolicy
          - lambda:DeleteResourcePolicy
        """
        client = request.aws_client_factory.lambda_

        # TODO: handle defaults properly
        old_name = request.previous_state["FunctionName"]
        new_name = request.desired_state.get("FunctionName")
        if new_name and old_name != new_name:
            # replacement (!) => shouldn't be handled here but in the engine
            self.delete(request)
            return self.create(request)

        config_keys = [
            "Description",
            "DeadLetterConfig",
            "Environment",
            "Handler",
            "ImageConfig",
            "Layers",
            "MemorySize",
            "Role",
            "Runtime",
            "Timeout",
            "TracingConfig",
            "VpcConfig",
            "LoggingConfig",
        ]
        update_config_props = util.select_attributes(request.desired_state, config_keys)
        function_name = request.previous_state["FunctionName"]
        update_config_props["FunctionName"] = function_name

        if "Timeout" in update_config_props:
            update_config_props["Timeout"] = int(update_config_props["Timeout"])
        if "MemorySize" in update_config_props:
            update_config_props["MemorySize"] = int(update_config_props["MemorySize"])
        if "Code" in request.desired_state:
            code = request.desired_state["Code"] or {}
            if not code.get("ZipFile"):
                request.logger.debug(
                    'Updating code for Lambda "%s" from location: %s', function_name, code
                )
            code = _get_lambda_code_param(
                request.desired_state,
                _include_arch=True,
            )
            client.update_function_code(FunctionName=function_name, **code)
            client.get_waiter("function_updated_v2").wait(FunctionName=function_name)
        if "Environment" in update_config_props:
            environment_variables = update_config_props["Environment"].get("Variables", {})
            update_config_props["Environment"]["Variables"] = {
                k: str(v) for k, v in environment_variables.items()
            }
        client.update_function_configuration(**update_config_props)
        client.get_waiter("function_updated_v2").wait(FunctionName=function_name)
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model={**request.previous_state, **request.desired_state},
        )

    def list(
        self,
        request: ResourceRequest[LambdaFunctionProperties],
    ) -> ProgressEvent[LambdaFunctionProperties]:
        functions = request.aws_client_factory.lambda_.list_functions()
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_models=[_transform_function_to_model(fn) for fn in functions["Functions"]],
        )

# LocalStack Resource Provider Scaffolding v2
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, TypedDict

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)
from localstack.utils.objects import keys_to_lower
from localstack.utils.strings import to_bytes


class ApiGatewayRestApiProperties(TypedDict):
    ApiKeySourceType: Optional[str]
    BinaryMediaTypes: Optional[list[str]]
    Body: Optional[dict | str]
    BodyS3Location: Optional[S3Location]
    CloneFrom: Optional[str]
    Description: Optional[str]
    DisableExecuteApiEndpoint: Optional[bool]
    EndpointConfiguration: Optional[EndpointConfiguration]
    FailOnWarnings: Optional[bool]
    MinimumCompressionSize: Optional[int]
    Mode: Optional[str]
    Name: Optional[str]
    Parameters: Optional[dict | str]
    Policy: Optional[dict | str]
    RestApiId: Optional[str]
    RootResourceId: Optional[str]
    Tags: Optional[list[Tag]]


class S3Location(TypedDict):
    Bucket: Optional[str]
    ETag: Optional[str]
    Key: Optional[str]
    Version: Optional[str]


class EndpointConfiguration(TypedDict):
    Types: Optional[list[str]]
    VpcEndpointIds: Optional[list[str]]


class Tag(TypedDict):
    Key: Optional[str]
    Value: Optional[str]


REPEATED_INVOCATION = "repeated_invocation"


class ApiGatewayRestApiProvider(ResourceProvider[ApiGatewayRestApiProperties]):

    TYPE = "AWS::ApiGateway::RestApi"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[ApiGatewayRestApiProperties],
    ) -> ProgressEvent[ApiGatewayRestApiProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/RestApiId


        Read-only properties:
          - /properties/RestApiId
          - /properties/RootResourceId

        IAM permissions required:
          - apigateway:GET
          - apigateway:POST
          - apigateway:UpdateRestApiPolicy
          - s3:GetObject
          - iam:PassRole

        """
        model = request.desired_state
        api = request.aws_client_factory.apigateway

        # FIXME: this is only when Body or BodyS3Location is set, otherwise the deployment should fail without a name
        role_name = model.get("Name")
        if not role_name:
            model["Name"] = util.generate_default_name(
                request.stack_name, request.logical_resource_id
            )
        params = util.select_attributes(
            model,
            [
                "Name",
                "Description",
                "Version",
                "CloneFrom",
                "BinaryMediaTypes",
                "MinimumCompressionSize",
                "ApiKeySource",
                "EndpointConfiguration",
                "Policy",
                "Tags",
                "DisableExecuteApiEndpoint",
            ],
        )
        params = keys_to_lower(params, skip_children_of=["policy"])
        params["tags"] = {tag["key"]: tag["value"] for tag in params.get("tags", [])}

        cfn_client = request.aws_client_factory.cloudformation
        stack_id = cfn_client.describe_stacks(StackName=request.stack_name)["Stacks"][0]["StackId"]
        params["tags"].update(
            {
                "aws:cloudformation:logical-id": request.logical_resource_id,
                "aws:cloudformation:stack-name": request.stack_name,
                "aws:cloudformation:stack-id": stack_id,
            }
        )
        if isinstance(params.get("policy"), dict):
            params["policy"] = json.dumps(params["policy"])

        result = api.create_rest_api(**params)
        model["RestApiId"] = result["id"]

        body = model.get("Body")
        s3_body_location = model.get("BodyS3Location")
        if body or s3_body_location:
            # the default behavior for imports via CFn is basepath=ignore (validated against AWS)
            import_parameters = model.get("Parameters", {})
            import_parameters.setdefault("basepath", "ignore")

            if body:
                body = json.dumps(body) if isinstance(body, dict) else body
            else:
                get_obj_kwargs = {}
                if version_id := s3_body_location.get("Version"):
                    get_obj_kwargs["VersionId"] = version_id

                # what is the approach when client call fail? Do we bubble it up?
                s3_client = request.aws_client_factory.s3
                get_obj_req = s3_client.get_object(
                    Bucket=s3_body_location.get("Bucket"),
                    Key=s3_body_location.get("Key"),
                    **get_obj_kwargs,
                )
                if etag := s3_body_location.get("ETag"):
                    if etag != get_obj_req["ETag"]:
                        # TODO: validate the exception message
                        raise Exception(
                            "The ETag provided for the S3BodyLocation does not match the S3 Object"
                        )
                body = get_obj_req["Body"].read()

            put_kwargs = {}
            if import_mode := model.get("Mode"):
                put_kwargs["mode"] = import_mode
            if fail_on_warnings_mode := model.get("FailOnWarnings"):
                put_kwargs["failOnWarnings"] = fail_on_warnings_mode

            api.put_rest_api(
                restApiId=result["id"],
                body=to_bytes(body),
                parameters=import_parameters,
                **put_kwargs,
            )

        resources = api.get_resources(restApiId=result["id"])["items"]
        for res in resources:
            if res["path"] == "/" and not res.get("parentId"):
                model["RootResourceId"] = res["id"]

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def read(
        self,
        request: ResourceRequest[ApiGatewayRestApiProperties],
    ) -> ProgressEvent[ApiGatewayRestApiProperties]:
        """
        Fetch resource information

        IAM permissions required:
          - apigateway:GET
        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[ApiGatewayRestApiProperties],
    ) -> ProgressEvent[ApiGatewayRestApiProperties]:
        """
        Delete a resource

        IAM permissions required:
          - apigateway:DELETE
        """
        model = request.desired_state
        api = request.aws_client_factory.apigateway

        api.delete_rest_api(restApiId=model["RestApiId"])

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def update(
        self,
        request: ResourceRequest[ApiGatewayRestApiProperties],
    ) -> ProgressEvent[ApiGatewayRestApiProperties]:
        """
        Update a resource

        IAM permissions required:
          - apigateway:GET
          - apigateway:DELETE
          - apigateway:PATCH
          - apigateway:PUT
          - apigateway:UpdateRestApiPolicy
          - s3:GetObject
          - iam:PassRole
        """
        raise NotImplementedError

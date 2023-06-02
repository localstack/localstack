from __future__ import annotations

import json
from typing import Optional, TypedDict

from localstack.services.cloudformation.deployment_utils import generate_default_name
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
    register_resource_provider,
)
from localstack.utils.collections import select_attributes
from localstack.utils.objects import keys_to_lower
from localstack.utils.strings import to_bytes


class BodyS3Location(TypedDict, total=False):
    Bucket: Optional[str]
    ETag: Optional[str]
    Key: Optional[str]
    Version: Optional[str]


class EndpointConfiguration(TypedDict, total=False):
    Types: Optional[list]
    VpcEndpointIds: Optional[list]


class ApiGatewayRestApiProperties(TypedDict, total=False):
    ApiKeySourceType: Optional[str]
    BinaryMediaTypes: Optional[list]
    Body: Optional[dict[str, str]]
    BodyS3Location: Optional[BodyS3Location]
    CloneFrom: Optional[str]
    Description: Optional[str]
    DisableExecuteApiEndpoint: Optional[bool]
    EndpointConfiguration: Optional[EndpointConfiguration]
    FailOnWarnings: Optional[bool]
    MinimumCompressionSize: Optional[int]
    Mode: Optional[str]
    Name: Optional[str]
    Parameters: Optional[dict[str, str]]
    Policy: Optional[dict[str, str]]
    RestApiId: Optional[str]
    RootResourceId: Optional[str]
    Tags: Optional[list]


class ApiGatewayRestApiAllProperties(ApiGatewayRestApiProperties, total=False):
    physical_resource_id: Optional[str]


@register_resource_provider
class ApiGatewayRestApiProvider(ResourceProvider[ApiGatewayRestApiAllProperties]):

    TYPE = "AWS::ApiGateway::RestApi"

    def create(
        self,
        request: ResourceRequest[ApiGatewayRestApiAllProperties],
    ) -> ProgressEvent[ApiGatewayRestApiAllProperties]:
        """
        Create a new resource.
        """
        model = request.desired_state

        # TODO: validations

        # TODO: defaults
        # this will need to be tested if the Cfn default are different than the regular client call default
        # for sub-resources of API Gateway, we know some defaults are different, but this needs AWS testing

        # TODO: big question regarding CloudFormation and API Gateway
        # if we're importing an API, do the other parameters matters? Does AWS first create the API with the provided
        # parameters, then update it? or do they use internally ImportRestApi, which don't care about the other
        # parameters set? this is outside the scope of this PR, but this needs to be addressed.
        body = model.get("Body")
        body_s3_location = model.get("BodyS3Location")
        is_import = body is not None or body_s3_location is not None
        if is_import and not model.get("Name"):
            # as we first create the API then update it, we need a placeholder name for that time
            # AWS does not accept a RestAPI with no name if not importing
            model["Name"] = generate_default_name(request.stack_name, request.logical_resource_id)

        create_kwargs = select_attributes(
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

        create_kwargs["tags"] = (
            {tag["Key"]: tag["Value"] for tag in tags} if (tags := model.get("Tags")) else {}
        )
        create_kwargs["tags"].update(
            {
                "aws:cloudformation:logical-id": request.logical_resource_id,
                "aws:cloudformation:stack-name": request.stack_name,
                "aws:cloudformation:stack-id": request.stack_id,
            }
        )
        create_kwargs = keys_to_lower(create_kwargs, skip_children_of=["policy"])
        if isinstance(model.get("Policy"), dict):
            create_kwargs["policy"] = json.dumps(create_kwargs["policy"])

        # FIXME: this is a workaround because the client won't accept some fields set to None
        # create_kwargs = {prop: value for prop, value in create_kwargs.items() if value is not None}

        # TODO: idempotency
        # no need to check for idempotency, as the client call will raise an exception for us? need to be retrieved
        # by ApiId, which we don't have?

        # create the resource
        rest_api_response = request.aws_client_factory.apigateway.create_rest_api(**create_kwargs)
        rest_api_id = rest_api_response["id"]

        if is_import:
            # add defaults again

            # the default behavior for imports via CFn is basepath=ignore (validated against AWS)
            model.setdefault("Parameters", {}).setdefault("basepath", "ignore")

            if body:
                # not sure about the type of body here, if it's been decoded already
                body = json.dumps(body) if isinstance(body, dict) else body
            else:
                get_obj_kwargs = {}
                body_s3_location = body_s3_location or {}
                if version_id := body_s3_location.get("Version"):
                    get_obj_kwargs["VersionId"] = version_id

                # what is the approach when client call fail? Do we bubble it up?
                get_obj_req = request.aws_client_factory.s3.get_object(
                    Bucket=body_s3_location.get("Bucket"),
                    Key=body_s3_location.get("Key"),
                    **get_obj_kwargs,
                )
                if etag := body_s3_location.get("ETag"):
                    assert etag == get_obj_req["ETag"]
                body = get_obj_req["Body"].read()

            put_kwargs = {}
            if mode := model.get("Mode"):
                put_kwargs["mode"] = mode
            if fail_on_warnings := model.get("FailOnWarnings"):
                put_kwargs["failOnWarnings"] = fail_on_warnings

            request.aws_client_factory.apigateway.put_rest_api(
                restApiId=rest_api_id,
                body=to_bytes(body),
                parameters=model["Parameters"],
                **put_kwargs,
            )

        model["RestApiId"] = model["physical_resource_id"] = rest_api_id
        resources = request.aws_client_factory.apigateway.get_resources(restApiId=rest_api_id)
        root_id = next(item for item in resources["items"] if item["path"] == "/")["id"]
        model["RootResourceId"] = root_id

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

    def delete(
        self,
        request: ResourceRequest[ApiGatewayRestApiAllProperties],
    ) -> ProgressEvent[ApiGatewayRestApiAllProperties]:
        rest_api_id = request.desired_state.get("RestApiId")
        request.aws_client_factory.apigateway.delete_rest_api(restApiId=rest_api_id)
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=request.desired_state)

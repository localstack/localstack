from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Optional

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


@dataclass
class BodyS3Location:
    Bucket: Optional[str] = None
    ETag: Optional[str] = None
    Key: Optional[str] = None
    Version: Optional[str] = None


@dataclass
class EndpointConfiguration:
    Types: Optional[list] = None
    VpcEndpointIds: Optional[list] = None


@dataclass
class ApiGatewayRestApiProperties:
    ApiKeySourceType: Optional[str] = None
    BinaryMediaTypes: Optional[list] = None
    Body: Optional[dict[str, str]] = None
    BodyS3Location: Optional[BodyS3Location] = None
    CloneFrom: Optional[str] = None
    Description: Optional[str] = None
    DisableExecuteApiEndpoint: Optional[bool] = None
    EndpointConfiguration: Optional[EndpointConfiguration] = None
    FailOnWarnings: Optional[bool] = None
    MinimumCompressionSize: Optional[int] = None
    Mode: Optional[str] = None
    Name: Optional[str] = None
    Parameters: Optional[dict[str, str]] = None
    Policy: Optional[dict[str, str]] = None
    RestApiId: Optional[str] = None
    RootResourceId: Optional[str] = None
    Tags: Optional[list] = None


class ApiGatewayRestApiAllProperties(ApiGatewayRestApiProperties):
    physical_resource_id: Optional[str] = None


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

        is_import = model.Body is not None or model.BodyS3Location is not None
        if is_import and not model.Name:
            # as we first create the API then update it, we need a placeholder name for that time
            # AWS does not accept a RestAPI with no name if not importing
            model.Name = generate_default_name(request.stack_name, request.logical_resource_id)

        model.Tags = {tag["Key"]: tag["Value"] for tag in model.Tags} if model.Tags else {}
        model.Tags.update(
            {
                "aws:cloudformation:logical-id": request.logical_resource_id,
                "aws:cloudformation:stack-name": request.stack_name,
                "aws:cloudformation:stack-id": request.stack_id,
            }
        )

        if model.EndpointConfiguration:
            model.EndpointConfiguration = asdict(model.EndpointConfiguration)

        create_kwargs = select_attributes(
            asdict(model),
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
        create_kwargs = keys_to_lower(create_kwargs, skip_children_of=["policy"])
        if isinstance(model.Policy, dict):
            create_kwargs["policy"] = json.dumps(create_kwargs["policy"])

        # FIXME: this is a workaround because the client won't accept some fields set to None
        create_kwargs = {prop: value for prop, value in create_kwargs.items() if value is not None}

        # TODO: idempotency
        # no need to check for idempotency, as the client call will raise an exception for us? need to be retrieved
        # by ApiId, which we don't have?

        # create the resource
        rest_api_response = request.aws_client_factory.apigateway.create_rest_api(**create_kwargs)
        rest_api_id = rest_api_response["id"]

        if is_import:
            # add defaults again

            # the default behavior for imports via CFn is basepath=ignore (validated against AWS)
            model.Parameters = {} if model.Parameters is None else model.Parameters
            model.Parameters.setdefault("basepath", "ignore")

            if model.Body:
                # not sure about the type of body here, if it's been decoded already
                body = json.dumps(model.Body) if isinstance(model.Body, dict) else model.Body
            else:
                get_obj_kwargs = {}
                if version_id := model.BodyS3Location.Version:
                    get_obj_kwargs["VersionId"] = version_id

                # what is the approach when client call fail? Do we bubble it up?
                get_obj_req = request.aws_client_factory.s3.get_object(
                    Bucket=model.BodyS3Location.Bucket,
                    Key=model.BodyS3Location.Key,
                    **get_obj_kwargs,
                )
                if etag := model.BodyS3Location.ETag:
                    assert etag == get_obj_req["ETag"]
                body = get_obj_req["Body"].read()

            put_kwargs = {}
            if model.Mode is not None:
                put_kwargs["mode"] = model.Mode
            if model.FailOnWarnings is not None:
                put_kwargs["failOnWarnings"] = model.FailOnWarnings

            request.aws_client_factory.apigateway.put_rest_api(
                restApiId=rest_api_id,
                body=to_bytes(body),
                parameters=model.Parameters,
                **put_kwargs,
            )

        model.RestApiId = model.physical_resource_id = rest_api_id
        resources = request.aws_client_factory.apigateway.get_resources(restApiId=rest_api_id)
        root_id = next(item for item in resources["items"] if item["path"] == "/")["id"]
        model.RootResourceId = root_id

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

    def delete(
        self,
        request: ResourceRequest[ApiGatewayRestApiAllProperties],
    ) -> ProgressEvent[ApiGatewayRestApiAllProperties]:
        rest_api_id = request.desired_state.RestApiId
        request.aws_client_factory.apigateway.delete_rest_api(restApiId=rest_api_id)
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=request.desired_state)

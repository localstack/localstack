# LocalStack Resource Provider Scaffolding v2
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Optional, TypedDict
from urllib.parse import urlparse

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)
from localstack.utils.objects import keys_to_lower


class ApiGatewayMethodProperties(TypedDict):
    HttpMethod: Optional[str]
    ResourceId: Optional[str]
    RestApiId: Optional[str]
    ApiKeyRequired: Optional[bool]
    AuthorizationScopes: Optional[list[str]]
    AuthorizationType: Optional[str]
    AuthorizerId: Optional[str]
    Integration: Optional[Integration]
    MethodResponses: Optional[list[MethodResponse]]
    OperationName: Optional[str]
    RequestModels: Optional[dict]
    RequestParameters: Optional[dict]
    RequestValidatorId: Optional[str]


class IntegrationResponse(TypedDict):
    StatusCode: Optional[str]
    ContentHandling: Optional[str]
    ResponseParameters: Optional[dict]
    ResponseTemplates: Optional[dict]
    SelectionPattern: Optional[str]


class Integration(TypedDict):
    Type: Optional[str]
    CacheKeyParameters: Optional[list[str]]
    CacheNamespace: Optional[str]
    ConnectionId: Optional[str]
    ConnectionType: Optional[str]
    ContentHandling: Optional[str]
    Credentials: Optional[str]
    IntegrationHttpMethod: Optional[str]
    IntegrationResponses: Optional[list[IntegrationResponse]]
    PassthroughBehavior: Optional[str]
    RequestParameters: Optional[dict]
    RequestTemplates: Optional[dict]
    TimeoutInMillis: Optional[int]
    Uri: Optional[str]


class MethodResponse(TypedDict):
    StatusCode: Optional[str]
    ResponseModels: Optional[dict]
    ResponseParameters: Optional[dict]


REPEATED_INVOCATION = "repeated_invocation"


class ApiGatewayMethodProvider(ResourceProvider[ApiGatewayMethodProperties]):
    TYPE = "AWS::ApiGateway::Method"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[ApiGatewayMethodProperties],
    ) -> ProgressEvent[ApiGatewayMethodProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/RestApiId
          - /properties/ResourceId
          - /properties/HttpMethod

        Required properties:
          - RestApiId
          - ResourceId
          - HttpMethod

        Create-only properties:
          - /properties/RestApiId
          - /properties/ResourceId
          - /properties/HttpMethod



        IAM permissions required:
          - apigateway:PUT
          - apigateway:GET

        """
        model = request.desired_state
        apigw = request.aws_client_factory.apigateway

        # key_to_lower makes in-place changes which will cause crash
        # when we try to use model outside of this function
        # for example generating composite physical id
        params = keys_to_lower(deepcopy(model))
        param_names = [
            "restApiId",
            "resourceId",
            "httpMethod",
            "apiKeyRequired",
            "authorizationType",
            "authorizerId",
            "requestParameters",
            "requestModels",
            "requestValidatorId",
            "operationName",
        ]
        params = util.select_attributes(params, param_names)
        params["requestModels"] = params.get("requestModels") or {}
        params["requestParameters"] = params.get("requestParameters") or {}

        apigw.put_method(**params)

        # setting up integrations
        integration = model.get("Integration")
        if integration:
            api_id = model["RestApiId"]
            res_id = model["ResourceId"]

            kwargs = keys_to_lower(deepcopy(integration))
            if uri := integration.get("Uri"):
                # Moto has a validate method on Uri for integration_type "HTTP" | "HTTP_PROXY" that does not accept
                # Uri value without path, we need to add path ("/") if not exists
                if integration.get("Type") in ["HTTP", "HTTP_PROXY"]:
                    rs = urlparse(uri)
                    if not rs.path:
                        uri = "{}/".format(uri)

                kwargs["uri"] = uri

            integration_responses = kwargs.pop("integrationResponses", [])
            method = model.get("HttpMethod")

            kwargs["requestParameters"] = kwargs.get("requestParameters") or {}
            kwargs["requestTemplates"] = kwargs.get("requestTemplates") or {}

            apigw.put_integration(
                restApiId=api_id,
                resourceId=res_id,
                httpMethod=method,
                **kwargs,
            )
            default_params = (
                "responseParameters",
                "responseTemplates",
            )
            for integration_response in integration_responses:
                integration_response["statusCode"] = str(integration_response["statusCode"])
                for param in default_params:
                    integration_response[param] = integration_response.get(param) or {}
                apigw.put_integration_response(
                    restApiId=api_id,
                    resourceId=res_id,
                    httpMethod=method,
                    **keys_to_lower(integration_response),
                )

        responses = model.get("MethodResponses") or []
        for response in responses:
            api_id = model["RestApiId"]
            res_id = model["ResourceId"]
            apigw.put_method_response(
                restApiId=api_id,
                resourceId=res_id,
                httpMethod=model["HttpMethod"],
                statusCode=str(response["statusCode"]),
                responseParameters=response.get("responseParameters") or {},
                responseModels=response.get("responseModels") or {},
            )

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def read(
        self,
        request: ResourceRequest[ApiGatewayMethodProperties],
    ) -> ProgressEvent[ApiGatewayMethodProperties]:
        """
        Fetch resource information

        IAM permissions required:
          - apigateway:GET
        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[ApiGatewayMethodProperties],
    ) -> ProgressEvent[ApiGatewayMethodProperties]:
        """
        Delete a resource

        IAM permissions required:
          - apigateway:DELETE
        """

        # FIXME we sometimes get warnings when calling this method, probably because
        #  restAPI or resource has been already deleted
        model = request.desired_state
        apigw = request.aws_client_factory.apigateway

        try:
            apigw.delete_method(
                restApiId=model["RestApiId"],
                resourceId=model["ResourceId"],
                httpMethod=model["HttpMethod"],
            )
        except apigw.exceptions.NotFoundException:
            pass

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def update(
        self,
        request: ResourceRequest[ApiGatewayMethodProperties],
    ) -> ProgressEvent[ApiGatewayMethodProperties]:
        """
        Update a resource

        IAM permissions required:
          - apigateway:GET
          - apigateway:DELETE
          - apigateway:PUT
        """
        model = request.desired_state
        apigw = request.aws_client_factory.apigateway

        params = keys_to_lower(deepcopy(model))
        param_names = [
            "restApiId",
            "resourceId",
            "httpMethod",
            "requestParameters",
        ]
        params = util.select_attributes(params, param_names)

        if integration := model.get("Integration"):
            params["type"] = integration["Type"]
            if integration.get("IntegrationHttpMethod"):
                params["integrationHttpMethod"] = integration.get("IntegrationHttpMethod")
            if integration.get("Uri"):
                params["uri"] = integration.get("Uri")
            params["requestParameters"] = integration.get("RequestParameters") or {}
            params["requestTemplates"] = integration.get("RequestTemplates") or {}

            apigw.put_integration(**params)

        else:
            params["authorizationType"] = model.get("AuthorizationType")
            apigw.put_method(**params)

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

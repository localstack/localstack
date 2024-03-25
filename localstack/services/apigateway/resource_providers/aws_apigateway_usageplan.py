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
from localstack.utils.strings import first_char_to_lower


class ApiGatewayUsagePlanProperties(TypedDict):
    ApiStages: Optional[list[ApiStage]]
    Description: Optional[str]
    Id: Optional[str]
    Quota: Optional[QuotaSettings]
    Tags: Optional[list[Tag]]
    Throttle: Optional[ThrottleSettings]
    UsagePlanName: Optional[str]


class ApiStage(TypedDict):
    ApiId: Optional[str]
    Stage: Optional[str]
    Throttle: Optional[dict]


class QuotaSettings(TypedDict):
    Limit: Optional[int]
    Offset: Optional[int]
    Period: Optional[str]


class Tag(TypedDict):
    Key: Optional[str]
    Value: Optional[str]


class ThrottleSettings(TypedDict):
    BurstLimit: Optional[int]
    RateLimit: Optional[float]


REPEATED_INVOCATION = "repeated_invocation"


class ApiGatewayUsagePlanProvider(ResourceProvider[ApiGatewayUsagePlanProperties]):
    TYPE = "AWS::ApiGateway::UsagePlan"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[ApiGatewayUsagePlanProperties],
    ) -> ProgressEvent[ApiGatewayUsagePlanProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/Id

        Read-only properties:
          - /properties/Id

        IAM permissions required:
          - apigateway:POST
          - apigateway:GET

        """
        model = request.desired_state
        apigw = request.aws_client_factory.apigateway

        plan_name = model.get("UsagePlanName")
        if not plan_name:
            model["UsagePlanName"] = util.generate_default_name(
                request.stack_name, request.logical_resource_id
            )

        params = util.select_attributes(model, ["Description", "ApiStages", "Quota", "Throttle"])
        params = keys_to_lower(params.copy())
        params["name"] = model["UsagePlanName"]

        if model.get("Tags"):
            params["tags"] = {tag["Key"]: tag["Value"] for tag in model["Tags"]}

        # set int and float types
        if params.get("quota"):
            params["quota"]["limit"] = int(params["quota"]["limit"])

        if params.get("throttle"):
            params["throttle"]["burstLimit"] = int(params["throttle"]["burstLimit"])
            params["throttle"]["rateLimit"] = float(params["throttle"]["rateLimit"])

        response = apigw.create_usage_plan(**params)

        model["Id"] = response["id"]
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def read(
        self,
        request: ResourceRequest[ApiGatewayUsagePlanProperties],
    ) -> ProgressEvent[ApiGatewayUsagePlanProperties]:
        """
        Fetch resource information

        IAM permissions required:
          - apigateway:GET
        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[ApiGatewayUsagePlanProperties],
    ) -> ProgressEvent[ApiGatewayUsagePlanProperties]:
        """
        Delete a resource

        IAM permissions required:
          - apigateway:DELETE
        """
        model = request.desired_state
        apigw = request.aws_client_factory.apigateway

        apigw.delete_usage_plan(usagePlanId=model["Id"])
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def update(
        self,
        request: ResourceRequest[ApiGatewayUsagePlanProperties],
    ) -> ProgressEvent[ApiGatewayUsagePlanProperties]:
        """
        Update a resource

        IAM permissions required:
          - apigateway:GET
          - apigateway:DELETE
          - apigateway:PATCH
          - apigateway:PUT
        """
        model = request.desired_state
        apigw = request.aws_client_factory.apigateway

        parameters_to_select = [
            "UsagePlanName",
            "Description",
            "ApiStages",
            "Quota",
            "Throttle",
            "Tags",
        ]
        update_config_props = util.select_attributes(model, parameters_to_select)

        if "Tags" in update_config_props:
            tags_dict = {}
            for tag in update_config_props:
                tags_dict.update({tag["Key"]: tag["Value"]})
            update_config_props["Tags"] = tags_dict

        usage_plan_id = request.previous_state["Id"]

        patch_operations = []

        for parameter in update_config_props:
            value = update_config_props[parameter]
            if parameter == "ApiStages":
                for stage in value:
                    patch_operations.append(
                        {
                            "op": "replace",
                            "path": f"/{first_char_to_lower(parameter)}",
                            "value": f'{stage["ApiId"]}:{stage["Stage"]}',
                        }
                    )

                    if "Throttle" in stage:
                        patch_operations.append(
                            {
                                "op": "replace",
                                "path": f'/{first_char_to_lower(parameter)}/{stage["ApiId"]}:{stage["Stage"]}',
                                "value": json.dumps(stage["Throttle"]),
                            }
                        )

            elif isinstance(value, dict):
                for item in value:
                    last_value = value[item]
                    path = f"/{first_char_to_lower(parameter)}/{first_char_to_lower(item)}"
                    patch_operations.append({"op": "replace", "path": path, "value": last_value})
            else:
                patch_operations.append(
                    {"op": "replace", "path": f"/{first_char_to_lower(parameter)}", "value": value}
                )
        apigw.update_usage_plan(usagePlanId=usage_plan_id, patchOperations=patch_operations)

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

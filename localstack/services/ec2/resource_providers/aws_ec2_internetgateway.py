# LocalStack Resource Provider Scaffolding v2
from __future__ import annotations

from pathlib import Path
from typing import Optional, TypedDict

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)


class EC2InternetGatewayProperties(TypedDict):
    InternetGatewayId: Optional[str]
    Tags: Optional[list[Tag]]


class Tag(TypedDict):
    Key: Optional[str]
    Value: Optional[str]


REPEATED_INVOCATION = "repeated_invocation"


class EC2InternetGatewayProvider(ResourceProvider[EC2InternetGatewayProperties]):

    TYPE = "AWS::EC2::InternetGateway"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[EC2InternetGatewayProperties],
    ) -> ProgressEvent[EC2InternetGatewayProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/InternetGatewayId

        Read-only properties:
          - /properties/InternetGatewayId

        IAM permissions required:
          - ec2:CreateInternetGateway
          - ec2:CreateTags

        """
        model = request.desired_state
        ec2 = request.aws_client_factory.ec2

        tags = [{"ResourceType": "'internet-gateway'", "Tags": model.get("Tags", [])}]

        response = ec2.create_internet_gateway(TagSpecifications=tags)
        model["InternetGatewayId"] = response["InternetGateway"]["InternetGatewayId"]

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def read(
        self,
        request: ResourceRequest[EC2InternetGatewayProperties],
    ) -> ProgressEvent[EC2InternetGatewayProperties]:
        """
        Fetch resource information

        IAM permissions required:
          - ec2:DescribeInternetGateways
        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[EC2InternetGatewayProperties],
    ) -> ProgressEvent[EC2InternetGatewayProperties]:
        """
        Delete a resource

        IAM permissions required:
          - ec2:DeleteInternetGateway
        """
        model = request.desired_state
        ec2 = request.aws_client_factory.ec2

        # detach it first before deleting it
        response = ec2.describe_internet_gateways(InternetGatewayIds=[model["InternetGatewayId"]])

        for gateway in response.get("InternetGateways", []):
            for attachment in gateway.get("Attachments", []):
                ec2.detach_internet_gateway(
                    InternetGatewayId=model["InternetGatewayId"], VpcId=attachment["VpcId"]
                )
        ec2.delete_internet_gateway(InternetGatewayId=model["InternetGatewayId"])
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def update(
        self,
        request: ResourceRequest[EC2InternetGatewayProperties],
    ) -> ProgressEvent[EC2InternetGatewayProperties]:
        """
        Update a resource

        IAM permissions required:
          - ec2:DeleteTags
          - ec2:CreateTags
        """
        raise NotImplementedError

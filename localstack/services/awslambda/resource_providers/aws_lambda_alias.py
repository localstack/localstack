# LocalStack Resource Provider Scaffolding v2
from __future__ import annotations

from pathlib import Path
from typing import Optional, Type, TypedDict

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)


class LambdaAliasProperties(TypedDict):
    FunctionName: Optional[str]
    FunctionVersion: Optional[str]
    Name: Optional[str]
    Description: Optional[str]
    Id: Optional[str]
    ProvisionedConcurrencyConfig: Optional[ProvisionedConcurrencyConfiguration]
    RoutingConfig: Optional[AliasRoutingConfiguration]


class ProvisionedConcurrencyConfiguration(TypedDict):
    ProvisionedConcurrentExecutions: Optional[int]


class VersionWeight(TypedDict):
    FunctionVersion: Optional[str]
    FunctionWeight: Optional[float]


class AliasRoutingConfiguration(TypedDict):
    AdditionalVersionWeights: Optional[list[VersionWeight]]


REPEATED_INVOCATION = "repeated_invocation"


class LambdaAliasProvider(ResourceProvider[LambdaAliasProperties]):

    TYPE = "AWS::Lambda::Alias"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[LambdaAliasProperties],
    ) -> ProgressEvent[LambdaAliasProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/Id

        Required properties:
          - FunctionName
          - FunctionVersion
          - Name

        Create-only properties:
          - /properties/Name
          - /properties/FunctionName

        Read-only properties:
          - /properties/Id



        """
        model = request.desired_state
        lambda_ = request.aws_client_factory.lambda_

        create_params = util.select_attributes(
            model, ["FunctionName", "FunctionVersion", "Name", "Description", "RoutingConfig"]
        )

        ctx = request.custom_context
        if not ctx.get(REPEATED_INVOCATION):
            result = lambda_.create_alias(**create_params)
            model["Id"] = result["AliasArn"]
            ctx[REPEATED_INVOCATION] = True

            if model.get("ProvisionedConcurrencyConfig"):
                lambda_.put_provisioned_concurrency_config(
                    FunctionName=model["FunctionName"],
                    Qualifier=model["Id"].split(":")[-1],
                    ProvisionedConcurrentExecutions=model["ProvisionedConcurrencyConfig"][
                        "ProvisionedConcurrentExecutions"
                    ],
                )

            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
            )

        if ctx.get(REPEATED_INVOCATION) and model.get("ProvisionedConcurrencyConfig"):
            # get provisioned config status
            result = lambda_.get_provisioned_concurrency_config(
                FunctionName=model["FunctionName"],
                Qualifier=model["Id"].split(":")[-1],
            )
            if result["Status"] == "IN_PROGRESS":
                return ProgressEvent(
                    status=OperationStatus.IN_PROGRESS,
                    resource_model=model,
                )

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
        )

    def read(
        self,
        request: ResourceRequest[LambdaAliasProperties],
    ) -> ProgressEvent[LambdaAliasProperties]:
        """
        Fetch resource information


        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[LambdaAliasProperties],
    ) -> ProgressEvent[LambdaAliasProperties]:
        """
        Delete a resource


        """
        model = request.desired_state
        lambda_ = request.aws_client_factory.lambda_

        try:
            lambda_.delete_alias(
                FunctionName=model["FunctionName"],
                Name=model["Name"],
            )
        except lambda_.exceptions.ResourceNotFoundException:
            pass

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=None,
        )

    def update(
        self,
        request: ResourceRequest[LambdaAliasProperties],
    ) -> ProgressEvent[LambdaAliasProperties]:
        """
        Update a resource


        """
        raise NotImplementedError


class LambdaAliasProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Lambda::Alias"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        self.factory = LambdaAliasProvider

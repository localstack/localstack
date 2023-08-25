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


class IAMPolicyProperties(TypedDict):
    PolicyDocument: Optional[dict]
    PolicyName: Optional[str]
    Groups: Optional[list[str]]
    Id: Optional[str]
    Roles: Optional[list[str]]
    Users: Optional[list[str]]


REPEATED_INVOCATION = "repeated_invocation"


class IAMPolicyProvider(ResourceProvider[IAMPolicyProperties]):

    TYPE = "AWS::IAM::Policy"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[IAMPolicyProperties],
    ) -> ProgressEvent[IAMPolicyProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/Id

        Required properties:
          - PolicyDocument
          - PolicyName



        Read-only properties:
          - /properties/Id



        """
        model = request.desired_state

        # TODO: validations

        if not request.custom_context.get(REPEATED_INVOCATION):
            # this is the first time this callback is invoked
            # TODO: defaults
            # TODO: idempotency
            # TODO: actually create the resource
            request.custom_context[REPEATED_INVOCATION] = True
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context=request.custom_context,
            )

        # TODO: check the status of the resource
        # - if finished, update the model with all fields and return success event:
        #   return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)
        # - else
        #   return ProgressEvent(status=OperationStatus.IN_PROGRESS, resource_model=model)

        raise NotImplementedError

    def read(
        self,
        request: ResourceRequest[IAMPolicyProperties],
    ) -> ProgressEvent[IAMPolicyProperties]:
        """
        Fetch resource information


        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[IAMPolicyProperties],
    ) -> ProgressEvent[IAMPolicyProperties]:
        """
        Delete a resource


        """
        raise NotImplementedError

    def update(
        self,
        request: ResourceRequest[IAMPolicyProperties],
    ) -> ProgressEvent[IAMPolicyProperties]:
        """
        Update a resource


        """
        raise NotImplementedError


class IAMPolicyProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::IAM::Policy"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        self.factory = IAMPolicyProvider

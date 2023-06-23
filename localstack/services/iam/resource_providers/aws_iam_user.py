from __future__ import annotations

from typing import Optional, TypedDict

from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
    register_resource_provider,
)


class LoginProfile(TypedDict):
    Password: Optional[str]
    PasswordResetRequired: Optional[bool]


class IAMUserProperties(TypedDict):
    Arn: Optional[str]
    Groups: Optional[list]
    Id: Optional[str]
    LoginProfile: Optional[LoginProfile]
    ManagedPolicyArns: Optional[list]
    Path: Optional[str]
    PermissionsBoundary: Optional[str]
    Policies: Optional[list]
    Tags: Optional[list]
    UserName: Optional[str]


class IAMUserAllProperties(IAMUserProperties):
    physical_resource_id: Optional[str] = None


@register_resource_provider
class IAMUserProvider(ResourceProvider[IAMUserAllProperties]):

    TYPE = "AWS::IAM::User"

    def create(
        self,
        request: ResourceRequest[IAMUserAllProperties],
    ) -> ProgressEvent[IAMUserAllProperties]:
        """
        Create a new resource.
        """
        raise NotImplementedError
        model = request.desired_state

        # TODO: validations

        if model.physical_resource_id is None:
            # this is the first time this callback is invoked
            # TODO: defaults
            # TODO: idempotency
            # TODO: actually create the resource
            # TODO: set model.physical_resource_id
            return ProgressEvent(status=OperationStatus.IN_PROGRESS, resource_model=model)

        # TODO: check the status of the resource
        # - if finished, update the model with all fields and return success event:
        #   return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)
        # - else
        #   return ProgressEvent(status=OperationStatus.IN_PROGRESS, resource_model=model)

        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[IAMUserAllProperties],
    ) -> ProgressEvent[IAMUserAllProperties]:
        raise NotImplementedError

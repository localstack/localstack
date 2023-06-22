from __future__ import annotations

from typing import Optional, TypedDict, Type

from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
    CloudFormationResourceProviderPlugin,
    # register_resource_provider,
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

# @register_resource_provider
class IAMUserProvider(ResourceProvider[IAMUserProperties]):

    TYPE = "AWS::IAM::User"

    def create(
        self,
        request: ResourceRequest[IAMUserProperties],
    ) -> ProgressEvent[IAMUserProperties]:
        """
        Create a new resource.
        """

        model = request.desired_state

        # TODO: validations

        if model['UserName'] is None:
            model['UserName'] = "hello"

        model['Id'] = model['UserName']

        create_result = request.aws_client_factory.iam.create_user(
            UserName=model['UserName']
        )

        model['Arn'] = create_result['User']['Arn']

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)
        #
        #     # this is the first time this callback is invoked
        #     # TODO: defaults
        #     # TODO: idempotency
        #     # TODO: actually create the resource
        #     # TODO: set model.physical_resource_id
        #     # return ProgressEvent(status=OperationStatus.IN_PROGRESS, resource_model=model)
        #
        # # TODO: check the status of the resource
        # # - if finished, update the model with all fields and return success event:
        # #   return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)
        # # - else
        # #   return ProgressEvent(status=OperationStatus.IN_PROGRESS, resource_model=model)
        #
        # raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[IAMUserProperties],
    ) -> ProgressEvent[IAMUserProperties]:
        request.aws_client_factory.iam.delete_user(UserName=request.desired_state['Id'])
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model={})


class IamUserProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::IAM::User"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        self.factory = IAMUserProvider

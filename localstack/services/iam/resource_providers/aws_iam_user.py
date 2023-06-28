# LocalStack Resource Provider Scaffolding v1
from __future__ import annotations

from typing import Optional, Type, TypedDict

from localstack.services.cloudformation.provider_utils import generate_default_name
from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)


class LoginProfile(TypedDict):
    Password: Optional[str]
    PasswordResetRequired: Optional[bool]


# FIXME
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


REPEATED_INVOCATION = "repeated_invocation"


class IAMUserProvider(ResourceProvider[IAMUserProperties]):

    TYPE = "AWS::IAM::User"

    def create(
        self,
        request: ResourceRequest[IAMUserProperties],
    ) -> ProgressEvent[IAMUserProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/Id

        Create-only properties:
          - /properties/UserName

        Read-only properties:
          - /properties/Id
          - /properties/Arn
        """
        model = request.desired_state
        iam_client = request.aws_client_factory.iam
        # TODO: validations
        # TODO: idempotency

        if not request.custom_context.get(REPEATED_INVOCATION):
            # this is the first time this callback is invoked

            # Set defaults
            if not model.get("UserName"):
                model["UserName"] = generate_default_name(
                    request.stack_name, request.logical_resource_id
                )

            # actually create the resource
            # note: technically we could make this synchronous, but for the sake of this being an example it is intentionally "asynchronous" and returns IN_PROGRESS
            iam_client.create_user(
                UserName=model["UserName"],
                Path=model["Path"],
                PermissionsBoundary=model["PermissionsBoundary"],
                Tags=model["Tags"],
            )

            # for group in model["Groups"]:
            #     group
            # iam_client.add_user_to_group()

            request.custom_context[REPEATED_INVOCATION] = True
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context=request.custom_context,
            )

        get_response = iam_client.get_user(UserName=model["UserName"])
        model["Id"] = get_response["User"]["UserName"]  # this is the ref / physical resource id
        model["Arn"] = get_response["User"]["Arn"]

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

    def read(
        self,
        request: ResourceRequest[IAMUserProperties],
    ) -> ProgressEvent[IAMUserProperties]:
        """
        Fetch resource information
        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[IAMUserProperties],
    ) -> ProgressEvent[IAMUserProperties]:
        """
        Delete a resource
        """
        iam_client = request.aws_client_factory.iam
        iam_client.delete_user(UserName=request.desired_state["Id"])
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=None)

    def update(
        self,
        request: ResourceRequest[IAMUserProperties],
    ) -> ProgressEvent[IAMUserProperties]:
        """
        Update a resource
        """
        raise NotImplementedError


class IAMUserProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::IAM::User"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        self.factory = IAMUserProvider

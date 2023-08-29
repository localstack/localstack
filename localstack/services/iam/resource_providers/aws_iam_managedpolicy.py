# LocalStack Resource Provider Scaffolding v2
from __future__ import annotations

import json
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


class IAMManagedPolicyProperties(TypedDict):
    PolicyDocument: Optional[dict]
    Description: Optional[str]
    Groups: Optional[list[str]]
    Id: Optional[str]
    ManagedPolicyName: Optional[str]
    Path: Optional[str]
    Roles: Optional[list[str]]
    Users: Optional[list[str]]


REPEATED_INVOCATION = "repeated_invocation"


class IAMManagedPolicyProvider(ResourceProvider[IAMManagedPolicyProperties]):

    TYPE = "AWS::IAM::ManagedPolicy"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[IAMManagedPolicyProperties],
    ) -> ProgressEvent[IAMManagedPolicyProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/Id

        Required properties:
          - PolicyDocument

        Create-only properties:
          - /properties/ManagedPolicyName
          - /properties/Description
          - /properties/Path

        Read-only properties:
          - /properties/Id

        """
        model = request.desired_state
        iam_client = request.aws_client_factory.iam
        group_name = model.get("ManagedPolicyName")
        if not group_name:
            group_name = util.generate_default_name(request.stack_name, request.logical_resource_id)
            model["ManagedPolicyName"] = group_name

        policy_doc = json.dumps(util.remove_none_values(model["PolicyDocument"]))
        policy = iam_client.create_policy(
            PolicyName=model["ManagedPolicyName"], PolicyDocument=policy_doc
        )
        model["Id"] = policy["Policy"]["Arn"]
        policy_arn = policy["Policy"]["Arn"]
        for role in model.get("Roles", []):
            iam_client.attach_role_policy(RoleName=role, PolicyArn=policy_arn)
        for user in model.get("Users", []):
            iam_client.attach_user_policy(UserName=user, PolicyArn=policy_arn)
        for group in model.get("Groups", []):
            iam_client.attach_group_policy(GroupName=group, PolicyArn=policy_arn)
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

    def read(
        self,
        request: ResourceRequest[IAMManagedPolicyProperties],
    ) -> ProgressEvent[IAMManagedPolicyProperties]:
        """
        Fetch resource information


        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[IAMManagedPolicyProperties],
    ) -> ProgressEvent[IAMManagedPolicyProperties]:
        """
        Delete a resource
        """
        iam_client = request.aws_client_factory.iam
        model = request.previous_state

        for role in model.get("Roles", []):
            iam_client.detach_role_policy(RoleName=role, PolicyArn=model["Id"])
        for user in model.get("Users", []):
            iam_client.detach_user_policy(UserName=user, PolicyArn=model["Id"])
        for group in model.get("Groups", []):
            iam_client.detach_group_policy(GroupName=group, PolicyArn=model["Id"])

        iam_client.delete_policy(PolicyArn=model["Id"])

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

    def update(
        self,
        request: ResourceRequest[IAMManagedPolicyProperties],
    ) -> ProgressEvent[IAMManagedPolicyProperties]:
        """
        Update a resource
        """
        raise NotImplementedError


class IAMManagedPolicyProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::IAM::ManagedPolicy"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        self.factory = IAMManagedPolicyProvider

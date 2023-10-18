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


class IAMGroupProperties(TypedDict):
    Arn: Optional[str]
    GroupName: Optional[str]
    Id: Optional[str]
    ManagedPolicyArns: Optional[list[str]]
    Path: Optional[str]
    Policies: Optional[list[Policy]]


class Policy(TypedDict):
    PolicyDocument: Optional[dict]
    PolicyName: Optional[str]


REPEATED_INVOCATION = "repeated_invocation"


class IAMGroupProvider(ResourceProvider[IAMGroupProperties]):

    TYPE = "AWS::IAM::Group"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[IAMGroupProperties],
    ) -> ProgressEvent[IAMGroupProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/Id

        Create-only properties:
          - /properties/GroupName

        Read-only properties:
          - /properties/Arn
          - /properties/Id
        """
        model = request.desired_state
        iam_client = request.aws_client_factory.iam

        group_name = model.get("GroupName")
        if not group_name:
            group_name = util.generate_default_name(request.stack_name, request.logical_resource_id)
            model["GroupName"] = group_name

        create_group_result = iam_client.create_group(
            **util.select_attributes(model, ["GroupName", "Path"])
        )
        model["Id"] = create_group_result["Group"][
            "GroupName"
        ]  # a bit weird that this is not the GroupId
        model["Arn"] = create_group_result["Group"]["Arn"]

        for managed_policy in model.get("ManagedPolicyArns", []):
            iam_client.attach_group_policy(GroupName=group_name, PolicyArn=managed_policy)

        for inline_policy in model.get("Policies", []):
            doc = json.dumps(inline_policy.get("PolicyDocument"))
            iam_client.put_group_policy(
                GroupName=group_name,
                PolicyName=inline_policy.get("PolicyName"),
                PolicyDocument=doc,
            )
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def read(
        self,
        request: ResourceRequest[IAMGroupProperties],
    ) -> ProgressEvent[IAMGroupProperties]:
        """
        Fetch resource information


        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[IAMGroupProperties],
    ) -> ProgressEvent[IAMGroupProperties]:
        """
        Delete a resource
        """
        model = request.desired_state
        iam_client = request.aws_client_factory.iam

        # first we need to detach and delete any attached policies
        for managed_policy in model.get("ManagedPolicyArns", []):
            iam_client.detach_group_policy(GroupName=model["GroupName"], PolicyArn=managed_policy)

        for inline_policy in model.get("Policies", []):
            iam_client.delete_group_policy(
                GroupName=model["GroupName"],
                PolicyName=inline_policy.get("PolicyName"),
            )

        # now we can delete the actual group
        iam_client.delete_group(GroupName=model["GroupName"])

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model={},
        )

    def update(
        self,
        request: ResourceRequest[IAMGroupProperties],
    ) -> ProgressEvent[IAMGroupProperties]:
        """
        Update a resource
        """
        # TODO: note: while the resource implemented "update_resource" previously, it didn't actually work
        #  so leaving it out here for now
        # iam.update_group(
        #     GroupName=props.get("GroupName"),
        #     NewPath=props.get("NewPath") or "",
        #     NewGroupName=props.get("NewGroupName") or "",
        # )
        raise NotImplementedError

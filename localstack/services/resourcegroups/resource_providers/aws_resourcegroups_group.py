# LocalStack Resource Provider Scaffolding v1
from __future__ import annotations

from typing import Optional, Type, TypedDict

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)


class ResourceGroupsGroupProperties(TypedDict):
    Name: Optional[str]
    Arn: Optional[str]
    Configuration: Optional[list[ConfigurationItem]]
    Description: Optional[str]
    ResourceQuery: Optional[ResourceQuery]
    Resources: Optional[list[str]]
    Tags: Optional[list[Tag]]


class TagFilter(TypedDict):
    Key: Optional[str]
    Values: Optional[list[str]]


class Query(TypedDict):
    ResourceTypeFilters: Optional[list[str]]
    StackIdentifier: Optional[str]
    TagFilters: Optional[list[TagFilter]]


class ResourceQuery(TypedDict):
    Query: Optional[Query]
    Type: Optional[str]


class Tag(TypedDict):
    Key: Optional[str]
    Value: Optional[str]


class ConfigurationParameter(TypedDict):
    Name: Optional[str]
    Values: Optional[list[str]]


class ConfigurationItem(TypedDict):
    Parameters: Optional[list[ConfigurationParameter]]
    Type: Optional[str]


REPEATED_INVOCATION = "repeated_invocation"


class ResourceGroupsGroupProvider(ResourceProvider[ResourceGroupsGroupProperties]):

    TYPE = "AWS::ResourceGroups::Group"

    def create(
        self,
        request: ResourceRequest[ResourceGroupsGroupProperties],
    ) -> ProgressEvent[ResourceGroupsGroupProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/Name

        Required properties:
          - Name

        Create-only properties:
          - /properties/Name

        Read-only properties:
          - /properties/Arn

        IAM permissions required:
          - resource-groups:CreateGroup
          - resource-groups:Tag
          - cloudformation:DescribeStacks
          - cloudformation:ListStackResources
          - resource-groups:ListGroupResources
          - resource-groups:GroupResources

        """
        model = request.desired_state
        if not model.get("Name"):
            return ProgressEvent(
                status=OperationStatus.FAILED,
                message="Name attribute is required",
                resource_model=model,
            )

        if model.get("Configuration") and model.get("ResourceQuery"):
            return ProgressEvent(
                status=OperationStatus.FAILED,
                message="Configuration and ResourceQuery are mutually exclusive",
                resource_model=model,
            )

        if model.get("ResourceQuery") and model.get("Resources"):
            return ProgressEvent(
                status=OperationStatus.FAILED,
                message="ResourceQuery and Resources are mutually exclusive",
                resource_model=model,
            )

        # TODO: validations

        if not request.custom_context.get(REPEATED_INVOCATION):
            # this is the first time this callback is invoked
            # TODO: idempotency
            # TODO: actually create the resource
            request.custom_context[REPEATED_INVOCATION] = True

            try:
                response = request.aws_client_factory.resource_groups.create_group(
                    Name=model.get("Name"),
                    Description=model.get("Description"),
                    ResourceQuery=model.get("ResourceQuery"),
                    Tags=model.get("Tags"),
                    Configuration=model.get("Configuration"),
                )
                model["Arn"] = response["Group"]["Arn"]

            except Exception as e:
                if "GroupAlreadyExistsException" in str(e):
                    return ProgressEvent(
                        status=OperationStatus.FAILED,
                        message="Group already exists",
                        resource_model=model,
                    )

            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context=request.custom_context,
            )

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

    def read(
        self,
        request: ResourceRequest[ResourceGroupsGroupProperties],
    ) -> ProgressEvent[ResourceGroupsGroupProperties]:
        """
        Fetch resource information

        IAM permissions required:
          - resource-groups:GetGroup
          - resource-groups:GetGroupQuery
          - resource-groups:GetTags
          - resource-groups:GetGroupConfiguration
          - resource-groups:ListGroupResources
        """
        model = request.desired_state

        name = model.get("Name")
        description = request.aws_client_factory.resource_groups.get_group(Name=name)["Group"]
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=description)

    def delete(
        self,
        request: ResourceRequest[ResourceGroupsGroupProperties],
    ) -> ProgressEvent[ResourceGroupsGroupProperties]:
        """
        Delete a resource

        IAM permissions required:
          - resource-groups:DeleteGroup
          - resource-groups:UnGroupResources
        """
        model = request.desired_state
        name = model.get("Name")
        request.aws_client_factory.resource_groups.delete_group(Name=name)
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

    def update(
        self,
        request: ResourceRequest[ResourceGroupsGroupProperties],
    ) -> ProgressEvent[ResourceGroupsGroupProperties]:
        """
        Update a resource

        IAM permissions required:
          - resource-groups:UpdateGroup
          - resource-groups:GetTags
          - resource-groups:GetGroupQuery
          - resource-groups:UpdateGroupQuery
          - resource-groups:Tag
          - resource-groups:Untag
          - resource-groups:PutGroupConfiguration
          - resource-groups:GetGroupConfiguration
          - resource-groups:ListGroupResources
          - resource-groups:GroupResources
          - resource-groups:UnGroupResources
        """
        if request.previous_state.get("Name") != request.desired_state.get("Name"):
            request.aws_client_factory.resource_groups.delete_group(
                Name=request.previous_state.get("Name")
            )
            request.aws_client_factory.resource_groups.create_group(
                Name=request.desired_state.get("Name"),
                Description=request.desired_state.get("Description"),
                ResourceQuery=request.desired_state.get("ResourceQuery"),
                Tags=request.desired_state.get("Tags"),
                Configuration=request.desired_state.get("Configuration"),
            )
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS, resource_model=request.desired_state
            )

        request.aws_client_factory.resource_groups.update_group(
            Name=request.desired_state.get("Name"),
            Description=request.desired_state.get("Description"),
            ResourceQuery=request.desired_state.get("ResourceQuery"),
            Tags=request.desired_state.get("Tags"),
            Configuration=request.desired_state.get("Configuration"),
        )
        return ProgressEvent(
            status=OperationStatus.IN_PROGRESS, resource_model=request.desired_state
        )


class ResourceGroupsGroupProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ResourceGroups::Group"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        self.factory = ResourceGroupsGroupProvider

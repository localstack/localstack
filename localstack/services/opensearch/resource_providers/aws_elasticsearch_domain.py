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


class ElasticsearchDomainProperties(TypedDict):
    AccessPolicies: Optional[dict]
    AdvancedOptions: Optional[dict]
    AdvancedSecurityOptions: Optional[AdvancedSecurityOptionsInput]
    Arn: Optional[str]
    CognitoOptions: Optional[CognitoOptions]
    DomainArn: Optional[str]
    DomainEndpoint: Optional[str]
    DomainEndpointOptions: Optional[DomainEndpointOptions]
    DomainName: Optional[str]
    EBSOptions: Optional[EBSOptions]
    ElasticsearchClusterConfig: Optional[ElasticsearchClusterConfig]
    ElasticsearchVersion: Optional[str]
    EncryptionAtRestOptions: Optional[EncryptionAtRestOptions]
    Id: Optional[str]
    LogPublishingOptions: Optional[dict]
    NodeToNodeEncryptionOptions: Optional[NodeToNodeEncryptionOptions]
    SnapshotOptions: Optional[SnapshotOptions]
    Tags: Optional[list[Tag]]
    VPCOptions: Optional[VPCOptions]


class ZoneAwarenessConfig(TypedDict):
    AvailabilityZoneCount: Optional[int]


class ColdStorageOptions(TypedDict):
    Enabled: Optional[bool]


class ElasticsearchClusterConfig(TypedDict):
    ColdStorageOptions: Optional[ColdStorageOptions]
    DedicatedMasterCount: Optional[int]
    DedicatedMasterEnabled: Optional[bool]
    DedicatedMasterType: Optional[str]
    InstanceCount: Optional[int]
    InstanceType: Optional[str]
    WarmCount: Optional[int]
    WarmEnabled: Optional[bool]
    WarmType: Optional[str]
    ZoneAwarenessConfig: Optional[ZoneAwarenessConfig]
    ZoneAwarenessEnabled: Optional[bool]


class SnapshotOptions(TypedDict):
    AutomatedSnapshotStartHour: Optional[int]


class VPCOptions(TypedDict):
    SecurityGroupIds: Optional[list[str]]
    SubnetIds: Optional[list[str]]


class NodeToNodeEncryptionOptions(TypedDict):
    Enabled: Optional[bool]


class DomainEndpointOptions(TypedDict):
    CustomEndpoint: Optional[str]
    CustomEndpointCertificateArn: Optional[str]
    CustomEndpointEnabled: Optional[bool]
    EnforceHTTPS: Optional[bool]
    TLSSecurityPolicy: Optional[str]


class CognitoOptions(TypedDict):
    Enabled: Optional[bool]
    IdentityPoolId: Optional[str]
    RoleArn: Optional[str]
    UserPoolId: Optional[str]


class MasterUserOptions(TypedDict):
    MasterUserARN: Optional[str]
    MasterUserName: Optional[str]
    MasterUserPassword: Optional[str]


class AdvancedSecurityOptionsInput(TypedDict):
    AnonymousAuthEnabled: Optional[bool]
    Enabled: Optional[bool]
    InternalUserDatabaseEnabled: Optional[bool]
    MasterUserOptions: Optional[MasterUserOptions]


class EBSOptions(TypedDict):
    EBSEnabled: Optional[bool]
    Iops: Optional[int]
    VolumeSize: Optional[int]
    VolumeType: Optional[str]


class EncryptionAtRestOptions(TypedDict):
    Enabled: Optional[bool]
    KmsKeyId: Optional[str]


class Tag(TypedDict):
    Key: Optional[str]
    Value: Optional[str]


REPEATED_INVOCATION = "repeated_invocation"


class ElasticsearchDomainProvider(ResourceProvider[ElasticsearchDomainProperties]):
    TYPE = "AWS::Elasticsearch::Domain"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[ElasticsearchDomainProperties],
    ) -> ProgressEvent[ElasticsearchDomainProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/Id



        Create-only properties:
          - /properties/DomainName

        Read-only properties:
          - /properties/Id
          - /properties/DomainArn
          - /properties/DomainEndpoint
          - /properties/Arn



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
        request: ResourceRequest[ElasticsearchDomainProperties],
    ) -> ProgressEvent[ElasticsearchDomainProperties]:
        """
        Fetch resource information


        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[ElasticsearchDomainProperties],
    ) -> ProgressEvent[ElasticsearchDomainProperties]:
        """
        Delete a resource


        """
        raise NotImplementedError

    def update(
        self,
        request: ResourceRequest[ElasticsearchDomainProperties],
    ) -> ProgressEvent[ElasticsearchDomainProperties]:
        """
        Update a resource


        """
        raise NotImplementedError

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


class OpenSearchServiceDomainProperties(TypedDict):
    AccessPolicies: Optional[dict]
    AdvancedOptions: Optional[dict]
    AdvancedSecurityOptions: Optional[AdvancedSecurityOptionsInput]
    Arn: Optional[str]
    ClusterConfig: Optional[ClusterConfig]
    CognitoOptions: Optional[CognitoOptions]
    DomainArn: Optional[str]
    DomainEndpoint: Optional[str]
    DomainEndpointOptions: Optional[DomainEndpointOptions]
    DomainEndpoints: Optional[dict]
    DomainName: Optional[str]
    EBSOptions: Optional[EBSOptions]
    EncryptionAtRestOptions: Optional[EncryptionAtRestOptions]
    EngineVersion: Optional[str]
    Id: Optional[str]
    LogPublishingOptions: Optional[dict]
    NodeToNodeEncryptionOptions: Optional[NodeToNodeEncryptionOptions]
    OffPeakWindowOptions: Optional[OffPeakWindowOptions]
    ServiceSoftwareOptions: Optional[ServiceSoftwareOptions]
    SnapshotOptions: Optional[SnapshotOptions]
    SoftwareUpdateOptions: Optional[SoftwareUpdateOptions]
    Tags: Optional[list[Tag]]
    VPCOptions: Optional[VPCOptions]


class ZoneAwarenessConfig(TypedDict):
    AvailabilityZoneCount: Optional[int]


class ClusterConfig(TypedDict):
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


class Idp(TypedDict):
    EntityId: Optional[str]
    MetadataContent: Optional[str]


class SAMLOptions(TypedDict):
    Enabled: Optional[bool]
    Idp: Optional[Idp]
    MasterBackendRole: Optional[str]
    MasterUserName: Optional[str]
    RolesKey: Optional[str]
    SessionTimeoutMinutes: Optional[int]
    SubjectKey: Optional[str]


class AdvancedSecurityOptionsInput(TypedDict):
    AnonymousAuthDisableDate: Optional[str]
    AnonymousAuthEnabled: Optional[bool]
    Enabled: Optional[bool]
    InternalUserDatabaseEnabled: Optional[bool]
    MasterUserOptions: Optional[MasterUserOptions]
    SAMLOptions: Optional[SAMLOptions]


class EBSOptions(TypedDict):
    EBSEnabled: Optional[bool]
    Iops: Optional[int]
    Throughput: Optional[int]
    VolumeSize: Optional[int]
    VolumeType: Optional[str]


class EncryptionAtRestOptions(TypedDict):
    Enabled: Optional[bool]
    KmsKeyId: Optional[str]


class Tag(TypedDict):
    Key: Optional[str]
    Value: Optional[str]


class ServiceSoftwareOptions(TypedDict):
    AutomatedUpdateDate: Optional[str]
    Cancellable: Optional[bool]
    CurrentVersion: Optional[str]
    Description: Optional[str]
    NewVersion: Optional[str]
    OptionalDeployment: Optional[bool]
    UpdateAvailable: Optional[bool]
    UpdateStatus: Optional[str]


class WindowStartTime(TypedDict):
    Hours: Optional[int]
    Minutes: Optional[int]


class OffPeakWindow(TypedDict):
    WindowStartTime: Optional[WindowStartTime]


class OffPeakWindowOptions(TypedDict):
    Enabled: Optional[bool]
    OffPeakWindow: Optional[OffPeakWindow]


class SoftwareUpdateOptions(TypedDict):
    AutoSoftwareUpdateEnabled: Optional[bool]


REPEATED_INVOCATION = "repeated_invocation"


class OpenSearchServiceDomainProvider(ResourceProvider[OpenSearchServiceDomainProperties]):

    TYPE = "AWS::OpenSearchService::Domain"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[OpenSearchServiceDomainProperties],
    ) -> ProgressEvent[OpenSearchServiceDomainProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/DomainName

        Create-only properties:
          - /properties/DomainName

        Read-only properties:
          - /properties/Id
          - /properties/Arn
          - /properties/DomainArn
          - /properties/DomainEndpoint
          - /properties/DomainEndpoints
          - /properties/ServiceSoftwareOptions
          - /properties/AdvancedSecurityOptions/AnonymousAuthDisableDate

        IAM permissions required:
          - es:CreateDomain
          - es:DescribeDomain
          - es:AddTags
          - es:ListTags

        """
        model = request.desired_state

        # Validations
        assert model["DomainName"]

        if model["physical_resource_id"] is None:
            # resource is not ready

            # Defaults

            # Idempotency
            try:
                request.aws_client_factory.opensearch.describe_domain(
                    DomainName=model["DomainName"]
                )
            except request.aws_client_factory.opensearch.exceptions.ResourceNotFoundException:
                pass
            else:
                # the resource already exists
                # for now raise an exception
                # TODO: return progress event
                raise RuntimeError(f"opensearch domain {model['DomainName']} already exists")

            # Create resource
            res = request.aws_client_factory.opensearch.create_domain(
                DomainName=model["DomainName"]
            )
            model["physical_resource_id"] = res["DomainStatus"]["ARN"]
            return ProgressEvent(status=OperationStatus.IN_PROGRESS, resource_model=model)

        # check on the status of the domain to see if it has been created yet or not
        res = request.aws_client_factory.opensearch.describe_domain(DomainName=model["DomainName"])
        if res["DomainStatus"]["Processing"] is False:
            return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)
        else:
            return ProgressEvent(status=OperationStatus.IN_PROGRESS, resource_model=model)

    def read(
        self,
        request: ResourceRequest[OpenSearchServiceDomainProperties],
    ) -> ProgressEvent[OpenSearchServiceDomainProperties]:
        """
        Fetch resource information

        IAM permissions required:
          - es:DescribeDomain
          - es:ListTags
        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[OpenSearchServiceDomainProperties],
    ) -> ProgressEvent[OpenSearchServiceDomainProperties]:
        """
        Delete a resource

        IAM permissions required:
          - es:DeleteDomain
          - es:DescribeDomain
        """
        name = request.desired_state["DomainName"]
        # LOG.warning(f"deleting domain {request.custom_context=}")
        assert name is not None
        if not request.custom_context.get("started", False):
            # first time in the loop
            request.aws_client_factory.opensearch.delete_domain(DomainName=name)
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=request.desired_state,
                custom_context={"started": True},
            )

        # we have entered the loop again so check the resource status
        try:
            request.aws_client_factory.opensearch.describe_domain(DomainName=name)
            return ProgressEvent(
                status=OperationStatus.SUCCESS, resource_model=request.desired_state
            )
        except request.aws_client_factory.opensearch.exceptions.ResourceNotFoundException:
            return ProgressEvent(
                status=OperationStatus.SUCCESS, resource_model=request.desired_state
            )

    def update(
        self,
        request: ResourceRequest[OpenSearchServiceDomainProperties],
    ) -> ProgressEvent[OpenSearchServiceDomainProperties]:
        """
        Update a resource

        IAM permissions required:
          - es:UpdateDomain
          - es:UpgradeDomain
          - es:DescribeDomain
          - es:AddTags
          - es:RemoveTags
          - es:ListTags
        """
        raise NotImplementedError


class OpenSearchServiceDomainProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::OpenSearchService::Domain"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        self.factory = OpenSearchServiceDomainProvider

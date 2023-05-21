from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
    register_resource_provider,
)

LOG = logging.getLogger(__name__)


@dataclass
class ZoneAwarenessConfig:
    AvailabilityZoneCount: Optional[int] = None


@dataclass
class ClusterConfig:
    DedicatedMasterCount: Optional[int] = None
    DedicatedMasterEnabled: Optional[bool] = None
    DedicatedMasterType: Optional[str] = None
    InstanceCount: Optional[int] = None
    InstanceType: Optional[str] = None
    WarmCount: Optional[int] = None
    WarmEnabled: Optional[bool] = None
    WarmType: Optional[str] = None
    ZoneAwarenessConfig: Optional[ZoneAwarenessConfig] = None
    ZoneAwarenessEnabled: Optional[bool] = None


@dataclass
class SnapshotOptions:
    AutomatedSnapshotStartHour: Optional[int] = None


@dataclass
class VPCOptions:
    SecurityGroupIds: Optional[list] = None
    SubnetIds: Optional[list] = None


@dataclass
class NodeToNodeEncryptionOptions:
    Enabled: Optional[bool] = None


@dataclass
class DomainEndpointOptions:
    CustomEndpoint: Optional[str] = None
    CustomEndpointCertificateArn: Optional[str] = None
    CustomEndpointEnabled: Optional[bool] = None
    EnforceHTTPS: Optional[bool] = None
    TLSSecurityPolicy: Optional[str] = None


@dataclass
class CognitoOptions:
    Enabled: Optional[bool] = None
    IdentityPoolId: Optional[str] = None
    RoleArn: Optional[str] = None
    UserPoolId: Optional[str] = None


@dataclass
class MasterUserOptions:
    MasterUserARN: Optional[str] = None
    MasterUserName: Optional[str] = None
    MasterUserPassword: Optional[str] = None


@dataclass
class Idp:
    EntityId: Optional[str] = None
    MetadataContent: Optional[str] = None


@dataclass
class SAMLOptions:
    Enabled: Optional[bool] = None
    Idp: Optional[Idp] = None
    MasterBackendRole: Optional[str] = None
    MasterUserName: Optional[str] = None
    RolesKey: Optional[str] = None
    SessionTimeoutMinutes: Optional[int] = None
    SubjectKey: Optional[str] = None


@dataclass
class AdvancedSecurityOptions:
    AnonymousAuthDisableDate: Optional[str] = None
    AnonymousAuthEnabled: Optional[bool] = None
    Enabled: Optional[bool] = None
    InternalUserDatabaseEnabled: Optional[bool] = None
    MasterUserOptions: Optional[MasterUserOptions] = None
    SAMLOptions: Optional[SAMLOptions] = None


@dataclass
class EBSOptions:
    EBSEnabled: Optional[bool] = None
    Iops: Optional[int] = None
    Throughput: Optional[int] = None
    VolumeSize: Optional[int] = None
    VolumeType: Optional[str] = None


@dataclass
class EncryptionAtRestOptions:
    Enabled: Optional[bool] = None
    KmsKeyId: Optional[str] = None


@dataclass
class ServiceSoftwareOptions:
    AutomatedUpdateDate: Optional[str] = None
    Cancellable: Optional[bool] = None
    CurrentVersion: Optional[str] = None
    Description: Optional[str] = None
    NewVersion: Optional[str] = None
    OptionalDeployment: Optional[bool] = None
    UpdateAvailable: Optional[bool] = None
    UpdateStatus: Optional[str] = None


@dataclass
class WindowStartTime:
    Hours: Optional[int] = None
    Minutes: Optional[int] = None


@dataclass
class OffPeakWindow:
    WindowStartTime: Optional[WindowStartTime] = None


@dataclass
class OffPeakWindowOptions:
    Enabled: Optional[bool] = None
    OffPeakWindow: Optional[OffPeakWindow] = None


@dataclass
class SoftwareUpdateOptions:
    AutoSoftwareUpdateEnabled: Optional[bool] = None


@dataclass
class OpenSearchDomainProperties:
    AccessPolicies: Optional[dict] = None
    AdvancedOptions: Optional[dict] = None
    AdvancedSecurityOptions: Optional[AdvancedSecurityOptions] = None
    Arn: Optional[str] = None
    ClusterConfig: Optional[ClusterConfig] = None
    CognitoOptions: Optional[CognitoOptions] = None
    DomainArn: Optional[str] = None
    DomainEndpoint: Optional[str] = None
    DomainEndpointOptions: Optional[DomainEndpointOptions] = None
    DomainEndpoints: Optional[dict] = None
    DomainName: Optional[str] = None
    EBSOptions: Optional[EBSOptions] = None
    EncryptionAtRestOptions: Optional[EncryptionAtRestOptions] = None
    EngineVersion: Optional[str] = None
    Id: Optional[str] = None
    LogPublishingOptions: Optional[dict] = None
    NodeToNodeEncryptionOptions: Optional[NodeToNodeEncryptionOptions] = None
    OffPeakWindowOptions: Optional[OffPeakWindowOptions] = None
    ServiceSoftwareOptions: Optional[ServiceSoftwareOptions] = None
    SnapshotOptions: Optional[SnapshotOptions] = None
    SoftwareUpdateOptions: Optional[SoftwareUpdateOptions] = None
    Tags: Optional[list] = None
    VPCOptions: Optional[VPCOptions] = None


class OpenSearchDomainAllProperties(OpenSearchDomainProperties):
    physical_resource_id: Optional[str] = None


@register_resource_provider
class OpenSearchDomainProvider(ResourceProvider[OpenSearchDomainAllProperties]):
    TYPE = "AWS::OpenSearchService::Domain"

    def create(
        self,
        request: ResourceRequest[OpenSearchDomainAllProperties],
    ) -> ProgressEvent[OpenSearchDomainAllProperties]:
        model = request.desired_state

        # Validations
        assert model.DomainName

        if model.physical_resource_id is None:
            # resource is not ready

            # Defaults

            # Idempotency
            try:
                request.aws_client_factory.opensearch.describe_domain(DomainName=model.DomainName)
            except request.aws_client_factory.opensearch.exceptions.ResourceNotFoundException:
                pass
            else:
                # the resource already exists
                # for now raise an exception
                # TODO: return progress event
                raise RuntimeError(f"opensearch domain {model.DomainName} already exists")

            # Create resource
            res = request.aws_client_factory.opensearch.create_domain(DomainName=model.DomainName)
            model.physical_resource_id = res["DomainStatus"]["ARN"]
            return ProgressEvent(status=OperationStatus.IN_PROGRESS, resource_model=model)

        # check on the status of the domain to see if it has been created yet or not
        res = request.aws_client_factory.opensearch.describe_domain(DomainName=model.DomainName)
        if res["DomainStatus"]["Processing"] is False:
            return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)
        else:
            return ProgressEvent(status=OperationStatus.IN_PROGRESS, resource_model=model)

    def delete(
        self,
        request: ResourceRequest[OpenSearchDomainAllProperties],
    ) -> ProgressEvent[OpenSearchDomainAllProperties]:
        name = request.desired_state.DomainName
        LOG.warning(f"deleting domain {request.custom_context=}")
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

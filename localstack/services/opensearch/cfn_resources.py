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
    InstanceCount: Optional[int] = None
    WarmEnabled: Optional[bool] = None
    WarmCount: Optional[int] = None
    DedicatedMasterEnabled: Optional[bool] = None
    ZoneAwarenessConfig: Optional[ZoneAwarenessConfig] = None
    DedicatedMasterCount: Optional[int] = None
    InstanceType: Optional[str] = None
    WarmType: Optional[str] = None
    ZoneAwarenessEnabled: Optional[bool] = None
    DedicatedMasterType: Optional[str] = None


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
    CustomEndpointCertificateArn: Optional[str] = None
    CustomEndpointEnabled: Optional[bool] = None
    EnforceHTTPS: Optional[bool] = None
    CustomEndpoint: Optional[str] = None
    TLSSecurityPolicy: Optional[str] = None


@dataclass
class CognitoOptions:
    Enabled: Optional[bool] = None
    IdentityPoolId: Optional[str] = None
    UserPoolId: Optional[str] = None
    RoleArn: Optional[str] = None


@dataclass
class MasterUserOptions:
    MasterUserPassword: Optional[str] = None
    MasterUserName: Optional[str] = None
    MasterUserARN: Optional[str] = None


@dataclass
class Idp:
    MetadataContent: Optional[str] = None
    EntityId: Optional[str] = None


@dataclass
class SAMLOptions:
    Enabled: Optional[bool] = None
    Idp: Optional[Idp] = None
    MasterUserName: Optional[str] = None
    MasterBackendRole: Optional[str] = None
    SubjectKey: Optional[str] = None
    RolesKey: Optional[str] = None
    SessionTimeoutMinutes: Optional[int] = None


@dataclass
class AdvancedSecurityOptions:
    Enabled: Optional[bool] = None
    MasterUserOptions: Optional[MasterUserOptions] = None
    InternalUserDatabaseEnabled: Optional[bool] = None
    AnonymousAuthEnabled: Optional[bool] = None
    SAMLOptions: Optional[SAMLOptions] = None
    AnonymousAuthDisableDate: Optional[str] = None


@dataclass
class EBSOptions:
    EBSEnabled: Optional[bool] = None
    VolumeType: Optional[str] = None
    Iops: Optional[int] = None
    VolumeSize: Optional[int] = None
    Throughput: Optional[int] = None


@dataclass
class EncryptionAtRestOptions:
    KmsKeyId: Optional[str] = None
    Enabled: Optional[bool] = None


@dataclass
class ServiceSoftwareOptions:
    CurrentVersion: Optional[str] = None
    NewVersion: Optional[str] = None
    UpdateAvailable: Optional[bool] = None
    Cancellable: Optional[bool] = None
    UpdateStatus: Optional[str] = None
    Description: Optional[str] = None
    AutomatedUpdateDate: Optional[str] = None
    OptionalDeployment: Optional[bool] = None


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
class OpenSearchServiceDomainProperties:
    ClusterConfig: Optional[ClusterConfig] = None
    DomainName: Optional[str] = None
    AccessPolicies: Optional[dict] = None
    EngineVersion: Optional[str] = None
    AdvancedOptions: Optional[dict] = None
    LogPublishingOptions: Optional[dict] = None
    SnapshotOptions: Optional[SnapshotOptions] = None
    VPCOptions: Optional[VPCOptions] = None
    NodeToNodeEncryptionOptions: Optional[NodeToNodeEncryptionOptions] = None
    DomainEndpointOptions: Optional[DomainEndpointOptions] = None
    CognitoOptions: Optional[CognitoOptions] = None
    AdvancedSecurityOptions: Optional[AdvancedSecurityOptions] = None
    DomainEndpoint: Optional[str] = None
    DomainEndpoints: Optional[dict] = None
    EBSOptions: Optional[EBSOptions] = None
    Id: Optional[str] = None
    Arn: Optional[str] = None
    DomainArn: Optional[str] = None
    EncryptionAtRestOptions: Optional[EncryptionAtRestOptions] = None
    Tags: Optional[list] = None
    ServiceSoftwareOptions: Optional[ServiceSoftwareOptions] = None
    OffPeakWindowOptions: Optional[OffPeakWindowOptions] = None
    SoftwareUpdateOptions: Optional[SoftwareUpdateOptions] = None


class OpenSearchServiceDomainAllProperties(OpenSearchServiceDomainProperties):
    physical_resource_id: Optional[str] = None


@register_resource_provider
class OpenSearchServiceDomainProvider(ResourceProvider[OpenSearchServiceDomainAllProperties]):
    TYPE = "AWS::OpenSearchService::Domain"

    def create(
        self,
        request: ResourceRequest[OpenSearchServiceDomainAllProperties],
    ) -> ProgressEvent[OpenSearchServiceDomainAllProperties]:
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
        self, request: ResourceRequest[OpenSearchServiceDomainAllProperties]
    ) -> ProgressEvent[OpenSearchServiceDomainAllProperties]:
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

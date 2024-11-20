from datetime import datetime
from enum import StrEnum
from typing import List, Optional, TypedDict

from localstack.aws.api import (
    RequestContext,
    ServiceRequest,
    handler,
)
from localstack.aws.api import (
    ServiceException as ServiceException,
)

AccountID = str
AddressMaxResults = int
AllocationId = str
AllowedInstanceType = str
AssetId = str
AutoRecoveryFlag = bool
AvailabilityZoneId = str
AvailabilityZoneName = str
BareMetalFlag = bool
BaselineBandwidthInGbps = float
BaselineBandwidthInMbps = int
BaselineIops = int
BaselineThroughputInMBps = float
Boolean = bool
BoxedDouble = float
BoxedInteger = int
BundleId = str
BurstablePerformanceFlag = bool
CancelCapacityReservationFleetErrorCode = str
CancelCapacityReservationFleetErrorMessage = str
CapacityReservationFleetId = str
CapacityReservationId = str
CarrierGatewayId = str
CarrierGatewayMaxResults = int
CertificateArn = str
CertificateId = str
ClientSecretType = str
ClientVpnEndpointId = str
CloudWatchLogGroupArn = str
CoipPoolId = str
CoipPoolMaxResults = int
ComponentAccount = str
ComponentRegion = str
ConnectionNotificationId = str
ConversionTaskId = str
CoolOffPeriodRequestHours = int
CoolOffPeriodResponseHours = int
CopySnapshotRequestPSU = str
CoreCount = int
CoreNetworkArn = str
CpuManufacturerName = str
CurrentGenerationFlag = bool
CustomerGatewayId = str
DITMaxResults = int
DITOMaxResults = int
DedicatedHostFlag = bool
DedicatedHostId = str
DefaultNetworkCardIndex = int
DefaultingDhcpOptionsId = str
DescribeAddressTransfersMaxResults = int
DescribeByoipCidrsMaxResults = int
DescribeCapacityBlockOfferingsMaxResults = int
DescribeCapacityReservationBillingRequestsRequestMaxResults = int
DescribeCapacityReservationFleetsMaxResults = int
DescribeCapacityReservationsMaxResults = int
DescribeClassicLinkInstancesMaxResults = int
DescribeClientVpnAuthorizationRulesMaxResults = int
DescribeClientVpnConnectionsMaxResults = int
DescribeClientVpnEndpointMaxResults = int
DescribeClientVpnRoutesMaxResults = int
DescribeClientVpnTargetNetworksMaxResults = int
DescribeDhcpOptionsMaxResults = int
DescribeEgressOnlyInternetGatewaysMaxResults = int
DescribeElasticGpusMaxResults = int
DescribeExportImageTasksMaxResults = int
DescribeFastLaunchImagesRequestMaxResults = int
DescribeFastSnapshotRestoresMaxResults = int
DescribeFpgaImagesMaxResults = int
DescribeHostReservationsMaxResults = int
DescribeIamInstanceProfileAssociationsMaxResults = int
DescribeInstanceCreditSpecificationsMaxResults = int
DescribeInstanceImageMetadataMaxResults = int
DescribeInstanceTopologyMaxResults = int
DescribeInternetGatewaysMaxResults = int
DescribeIpamByoasnMaxResults = int
DescribeLaunchTemplatesMaxResults = int
DescribeLockedSnapshotsMaxResults = int
DescribeMacHostsRequestMaxResults = int
DescribeMovingAddressesMaxResults = int
DescribeNatGatewaysMaxResults = int
DescribeNetworkAclsMaxResults = int
DescribeNetworkInterfacePermissionsMaxResults = int
DescribeNetworkInterfacesMaxResults = int
DescribePrincipalIdFormatMaxResults = int
DescribeReplaceRootVolumeTasksMaxResults = int
DescribeRouteTablesMaxResults = int
DescribeScheduledInstanceAvailabilityMaxResults = int
DescribeSecurityGroupRulesMaxResults = int
DescribeSecurityGroupVpcAssociationsMaxResults = int
DescribeSecurityGroupsMaxResults = int
DescribeSnapshotTierStatusMaxResults = int
DescribeSpotFleetInstancesMaxResults = int
DescribeSpotFleetRequestHistoryMaxResults = int
DescribeStaleSecurityGroupsMaxResults = int
DescribeStaleSecurityGroupsNextToken = str
DescribeStoreImageTasksRequestMaxResults = int
DescribeSubnetsMaxResults = int
DescribeTrunkInterfaceAssociationsMaxResults = int
DescribeVerifiedAccessEndpointsMaxResults = int
DescribeVerifiedAccessGroupMaxResults = int
DescribeVerifiedAccessInstanceLoggingConfigurationsMaxResults = int
DescribeVerifiedAccessInstancesMaxResults = int
DescribeVerifiedAccessTrustProvidersMaxResults = int
DescribeVpcClassicLinkDnsSupportMaxResults = int
DescribeVpcClassicLinkDnsSupportNextToken = str
DescribeVpcPeeringConnectionsMaxResults = int
DescribeVpcsMaxResults = int
DhcpOptionsId = str
DisassociateSecurityGroupVpcSecurityGroupId = str
DiskCount = int
Double = float
DoubleWithConstraints = float
DrainSeconds = int
EfaSupportedFlag = bool
EgressOnlyInternetGatewayId = str
EipAllocationPublicIp = str
EkPubKeyValue = str
ElasticGpuId = str
ElasticInferenceAcceleratorCount = int
ElasticIpAssociationId = str
EnaSrdSupported = bool
EncryptionInTransitSupported = bool
ExcludedInstanceType = str
ExportImageTaskId = str
ExportTaskId = str
ExportVmTaskId = str
FleetId = str
Float = float
FlowLogResourceId = str
FpgaDeviceCount = int
FpgaDeviceManufacturerName = str
FpgaDeviceMemorySize = int
FpgaDeviceName = str
FpgaImageId = str
FreeTierEligibleFlag = bool
GVCDMaxResults = int
GetCapacityReservationUsageRequestMaxResults = int
GetGroupsForCapacityReservationRequestMaxResults = int
GetIpamPoolAllocationsMaxResults = int
GetManagedPrefixListAssociationsMaxResults = int
GetNetworkInsightsAccessScopeAnalysisFindingsMaxResults = int
GetSecurityGroupsForVpcRequestMaxResults = int
GetSubnetCidrReservationsMaxResults = int
GpuDeviceCount = int
GpuDeviceManufacturerName = str
GpuDeviceMemorySize = int
GpuDeviceName = str
HibernationFlag = bool
HostReservationId = str
Hour = int
IamInstanceProfileAssociationId = str
ImageId = str
ImportImageTaskId = str
ImportManifestUrl = str
ImportSnapshotTaskId = str
ImportTaskId = str
InferenceDeviceCount = int
InferenceDeviceManufacturerName = str
InferenceDeviceMemorySize = int
InferenceDeviceName = str
InstanceConnectEndpointId = str
InstanceConnectEndpointMaxResults = int
InstanceEventId = str
InstanceEventWindowCronExpression = str
InstanceEventWindowId = str
InstanceId = str
InstanceIdForResolver = str
InstanceIdWithVolumeResolver = str
InstanceStorageFlag = bool
Integer = int
IntegerWithConstraints = int
InternetGatewayId = str
IpAddress = str
IpamAddressHistoryMaxResults = int
IpamExternalResourceVerificationTokenId = str
IpamId = str
IpamMaxResults = int
IpamNetmaskLength = int
IpamPoolAllocationId = str
IpamPoolCidrId = str
IpamPoolId = str
IpamResourceDiscoveryAssociationId = str
IpamResourceDiscoveryId = str
IpamScopeId = str
Ipv4PoolCoipId = str
Ipv4PoolEc2Id = str
Ipv6Address = str
Ipv6Flag = bool
Ipv6PoolEc2Id = str
Ipv6PoolMaxResults = int
KernelId = str
KeyPairId = str
KeyPairName = str
KeyPairNameWithResolver = str
KmsKeyArn = str
KmsKeyId = str
LaunchTemplateElasticInferenceAcceleratorCount = int
LaunchTemplateId = str
LaunchTemplateName = str
ListImagesInRecycleBinMaxResults = int
ListSnapshotsInRecycleBinMaxResults = int
LoadBalancerArn = str
LocalGatewayId = str
LocalGatewayMaxResults = int
LocalGatewayRouteTableVirtualInterfaceGroupAssociationId = str
LocalGatewayRouteTableVpcAssociationId = str
LocalGatewayRoutetableId = str
LocalGatewayVirtualInterfaceGroupId = str
LocalGatewayVirtualInterfaceId = str
Location = str
MaxIpv4AddrPerInterface = int
MaxIpv6AddrPerInterface = int
MaxNetworkInterfaces = int
MaxResults = int
MaxResultsParam = int
MaximumBandwidthInMbps = int
MaximumEfaInterfaces = int
MaximumIops = int
MaximumNetworkCards = int
MaximumThroughputInMBps = float
MediaDeviceCount = int
MediaDeviceManufacturerName = str
MediaDeviceMemorySize = int
MediaDeviceName = str
NatGatewayId = str
NetmaskLength = int
NetworkAclAssociationId = str
NetworkAclId = str
NetworkCardIndex = int
NetworkInsightsAccessScopeAnalysisId = str
NetworkInsightsAccessScopeId = str
NetworkInsightsAnalysisId = str
NetworkInsightsMaxResults = int
NetworkInsightsPathId = str
NetworkInsightsResourceId = str
NetworkInterfaceAttachmentId = str
NetworkInterfaceId = str
NetworkInterfacePermissionId = str
NetworkPerformance = str
NeuronDeviceCoreCount = int
NeuronDeviceCoreVersion = int
NeuronDeviceCount = int
NeuronDeviceMemorySize = int
NeuronDeviceName = str
NextToken = str
NitroTpmSupportedVersionType = str
OfferingId = str
OutpostArn = str
PasswordData = str
PeakBandwidthInGbps = float
PlacementGroupArn = str
PlacementGroupId = str
PlacementGroupName = str
PoolMaxResults = int
Port = int
PrefixListMaxResults = int
PrefixListResourceId = str
Priority = int
PrivateIpAddressCount = int
ProcessorSustainedClockSpeed = float
ProtocolInt = int
PublicIpAddress = str
RamdiskId = str
ReplaceRootVolumeTaskId = str
ReportInstanceStatusRequestDescription = str
ReservationId = str
ReservedInstancesListingId = str
ReservedInstancesModificationId = str
ReservedInstancesOfferingId = str
ResourceArn = str
RestoreSnapshotTierRequestTemporaryRestoreDays = int
ResultRange = int
RetentionPeriodRequestDays = int
RetentionPeriodResponseDays = int
RoleId = str
RouteGatewayId = str
RouteTableAssociationId = str
RouteTableId = str
RunInstancesUserData = str
S3StorageUploadPolicy = str
S3StorageUploadPolicySignature = str
ScheduledInstanceId = str
SecurityGroupId = str
SecurityGroupName = str
SecurityGroupRuleId = str
SensitiveUrl = str
SensitiveUserData = str
SnapshotId = str
SpotFleetRequestId = str
SpotInstanceRequestId = str
SpotPlacementScoresMaxResults = int
SpotPlacementScoresTargetCapacity = int
String = str
StringType = str
SubnetCidrAssociationId = str
SubnetCidrReservationId = str
SubnetId = str
TaggableResourceId = str
ThreadsPerCore = int
TotalMediaMemory = int
TotalNeuronMemory = int
TrafficMirrorFilterId = str
TrafficMirrorFilterRuleIdWithResolver = str
TrafficMirrorSessionId = str
TrafficMirrorTargetId = str
TrafficMirroringMaxResults = int
TransitAssociationGatewayId = str
TransitGatewayAttachmentId = str
TransitGatewayConnectPeerId = str
TransitGatewayId = str
TransitGatewayMaxResults = int
TransitGatewayMulticastDomainId = str
TransitGatewayPolicyTableId = str
TransitGatewayRouteTableAnnouncementId = str
TransitGatewayRouteTableId = str
TrunkInterfaceAssociationId = str
VCpuCount = int
VerifiedAccessEndpointId = str
VerifiedAccessEndpointPortNumber = int
VerifiedAccessGroupId = str
VerifiedAccessInstanceId = str
VerifiedAccessTrustProviderId = str
VersionDescription = str
VolumeId = str
VolumeIdWithResolver = str
VpcCidrAssociationId = str
VpcEndpointId = str
VpcEndpointServiceId = str
VpcFlowLogId = str
VpcId = str
VpcPeeringConnectionId = str
VpcPeeringConnectionIdWithResolver = str
VpnConnectionDeviceSampleConfiguration = str
VpnConnectionDeviceTypeId = str
VpnConnectionId = str
VpnGatewayId = str
customerGatewayConfiguration = str
preSharedKey = str
totalFpgaMemory = int
totalGpuMemory = int
totalInferenceMemory = int


class AcceleratorManufacturer(StrEnum):
    amazon_web_services = "amazon-web-services"
    amd = "amd"
    nvidia = "nvidia"
    xilinx = "xilinx"
    habana = "habana"


class AcceleratorName(StrEnum):
    a100 = "a100"
    inferentia = "inferentia"
    k520 = "k520"
    k80 = "k80"
    m60 = "m60"
    radeon_pro_v520 = "radeon-pro-v520"
    t4 = "t4"
    vu9p = "vu9p"
    v100 = "v100"
    a10g = "a10g"
    h100 = "h100"
    t4g = "t4g"


class AcceleratorType(StrEnum):
    gpu = "gpu"
    fpga = "fpga"
    inference = "inference"


class AccountAttributeName(StrEnum):
    supported_platforms = "supported-platforms"
    default_vpc = "default-vpc"


class ActivityStatus(StrEnum):
    error = "error"
    pending_fulfillment = "pending_fulfillment"
    pending_termination = "pending_termination"
    fulfilled = "fulfilled"


class AddressAttributeName(StrEnum):
    domain_name = "domain-name"


class AddressFamily(StrEnum):
    ipv4 = "ipv4"
    ipv6 = "ipv6"


class AddressTransferStatus(StrEnum):
    pending = "pending"
    disabled = "disabled"
    accepted = "accepted"


class Affinity(StrEnum):
    default = "default"
    host = "host"


class AllocationState(StrEnum):
    available = "available"
    under_assessment = "under-assessment"
    permanent_failure = "permanent-failure"
    released = "released"
    released_permanent_failure = "released-permanent-failure"
    pending = "pending"


class AllocationStrategy(StrEnum):
    lowestPrice = "lowestPrice"
    diversified = "diversified"
    capacityOptimized = "capacityOptimized"
    capacityOptimizedPrioritized = "capacityOptimizedPrioritized"
    priceCapacityOptimized = "priceCapacityOptimized"


class AllocationType(StrEnum):
    used = "used"


class AllowsMultipleInstanceTypes(StrEnum):
    on = "on"
    off = "off"


class AmdSevSnpSpecification(StrEnum):
    enabled = "enabled"
    disabled = "disabled"


class AnalysisStatus(StrEnum):
    running = "running"
    succeeded = "succeeded"
    failed = "failed"


class ApplianceModeSupportValue(StrEnum):
    enable = "enable"
    disable = "disable"


class ArchitectureType(StrEnum):
    i386 = "i386"
    x86_64 = "x86_64"
    arm64 = "arm64"
    x86_64_mac = "x86_64_mac"
    arm64_mac = "arm64_mac"


class ArchitectureValues(StrEnum):
    i386 = "i386"
    x86_64 = "x86_64"
    arm64 = "arm64"
    x86_64_mac = "x86_64_mac"
    arm64_mac = "arm64_mac"


class AsnAssociationState(StrEnum):
    disassociated = "disassociated"
    failed_disassociation = "failed-disassociation"
    failed_association = "failed-association"
    pending_disassociation = "pending-disassociation"
    pending_association = "pending-association"
    associated = "associated"


class AsnState(StrEnum):
    deprovisioned = "deprovisioned"
    failed_deprovision = "failed-deprovision"
    failed_provision = "failed-provision"
    pending_deprovision = "pending-deprovision"
    pending_provision = "pending-provision"
    provisioned = "provisioned"


class AssociatedNetworkType(StrEnum):
    vpc = "vpc"


class AssociationStatusCode(StrEnum):
    associating = "associating"
    associated = "associated"
    association_failed = "association-failed"
    disassociating = "disassociating"
    disassociated = "disassociated"


class AttachmentStatus(StrEnum):
    attaching = "attaching"
    attached = "attached"
    detaching = "detaching"
    detached = "detached"


class AutoAcceptSharedAssociationsValue(StrEnum):
    enable = "enable"
    disable = "disable"


class AutoAcceptSharedAttachmentsValue(StrEnum):
    enable = "enable"
    disable = "disable"


class AutoPlacement(StrEnum):
    on = "on"
    off = "off"


class AvailabilityZoneOptInStatus(StrEnum):
    opt_in_not_required = "opt-in-not-required"
    opted_in = "opted-in"
    not_opted_in = "not-opted-in"


class AvailabilityZoneState(StrEnum):
    available = "available"
    information = "information"
    impaired = "impaired"
    unavailable = "unavailable"
    constrained = "constrained"


class BareMetal(StrEnum):
    included = "included"
    required = "required"
    excluded = "excluded"


class BatchState(StrEnum):
    submitted = "submitted"
    active = "active"
    cancelled = "cancelled"
    failed = "failed"
    cancelled_running = "cancelled_running"
    cancelled_terminating = "cancelled_terminating"
    modifying = "modifying"


class BgpStatus(StrEnum):
    up = "up"
    down = "down"


class BootModeType(StrEnum):
    legacy_bios = "legacy-bios"
    uefi = "uefi"


class BootModeValues(StrEnum):
    legacy_bios = "legacy-bios"
    uefi = "uefi"
    uefi_preferred = "uefi-preferred"


class BundleTaskState(StrEnum):
    pending = "pending"
    waiting_for_shutdown = "waiting-for-shutdown"
    bundling = "bundling"
    storing = "storing"
    cancelling = "cancelling"
    complete = "complete"
    failed = "failed"


class BurstablePerformance(StrEnum):
    included = "included"
    required = "required"
    excluded = "excluded"


class ByoipCidrState(StrEnum):
    advertised = "advertised"
    deprovisioned = "deprovisioned"
    failed_deprovision = "failed-deprovision"
    failed_provision = "failed-provision"
    pending_deprovision = "pending-deprovision"
    pending_provision = "pending-provision"
    provisioned = "provisioned"
    provisioned_not_publicly_advertisable = "provisioned-not-publicly-advertisable"


class CallerRole(StrEnum):
    odcr_owner = "odcr-owner"
    unused_reservation_billing_owner = "unused-reservation-billing-owner"


class CancelBatchErrorCode(StrEnum):
    fleetRequestIdDoesNotExist = "fleetRequestIdDoesNotExist"
    fleetRequestIdMalformed = "fleetRequestIdMalformed"
    fleetRequestNotInCancellableState = "fleetRequestNotInCancellableState"
    unexpectedError = "unexpectedError"


class CancelSpotInstanceRequestState(StrEnum):
    active = "active"
    open = "open"
    closed = "closed"
    cancelled = "cancelled"
    completed = "completed"


class CapacityReservationBillingRequestStatus(StrEnum):
    pending = "pending"
    accepted = "accepted"
    rejected = "rejected"
    cancelled = "cancelled"
    revoked = "revoked"
    expired = "expired"


class CapacityReservationFleetState(StrEnum):
    submitted = "submitted"
    modifying = "modifying"
    active = "active"
    partially_fulfilled = "partially_fulfilled"
    expiring = "expiring"
    expired = "expired"
    cancelling = "cancelling"
    cancelled = "cancelled"
    failed = "failed"


class CapacityReservationInstancePlatform(StrEnum):
    Linux_UNIX = "Linux/UNIX"
    Red_Hat_Enterprise_Linux = "Red Hat Enterprise Linux"
    SUSE_Linux = "SUSE Linux"
    Windows = "Windows"
    Windows_with_SQL_Server = "Windows with SQL Server"
    Windows_with_SQL_Server_Enterprise = "Windows with SQL Server Enterprise"
    Windows_with_SQL_Server_Standard = "Windows with SQL Server Standard"
    Windows_with_SQL_Server_Web = "Windows with SQL Server Web"
    Linux_with_SQL_Server_Standard = "Linux with SQL Server Standard"
    Linux_with_SQL_Server_Web = "Linux with SQL Server Web"
    Linux_with_SQL_Server_Enterprise = "Linux with SQL Server Enterprise"
    RHEL_with_SQL_Server_Standard = "RHEL with SQL Server Standard"
    RHEL_with_SQL_Server_Enterprise = "RHEL with SQL Server Enterprise"
    RHEL_with_SQL_Server_Web = "RHEL with SQL Server Web"
    RHEL_with_HA = "RHEL with HA"
    RHEL_with_HA_and_SQL_Server_Standard = "RHEL with HA and SQL Server Standard"
    RHEL_with_HA_and_SQL_Server_Enterprise = "RHEL with HA and SQL Server Enterprise"
    Ubuntu_Pro = "Ubuntu Pro"


class CapacityReservationPreference(StrEnum):
    open = "open"
    none = "none"


class CapacityReservationState(StrEnum):
    active = "active"
    expired = "expired"
    cancelled = "cancelled"
    pending = "pending"
    failed = "failed"
    scheduled = "scheduled"
    payment_pending = "payment-pending"
    payment_failed = "payment-failed"


class CapacityReservationTenancy(StrEnum):
    default = "default"
    dedicated = "dedicated"


class CapacityReservationType(StrEnum):
    default = "default"
    capacity_block = "capacity-block"


class CarrierGatewayState(StrEnum):
    pending = "pending"
    available = "available"
    deleting = "deleting"
    deleted = "deleted"


class ClientCertificateRevocationListStatusCode(StrEnum):
    pending = "pending"
    active = "active"


class ClientVpnAuthenticationType(StrEnum):
    certificate_authentication = "certificate-authentication"
    directory_service_authentication = "directory-service-authentication"
    federated_authentication = "federated-authentication"


class ClientVpnAuthorizationRuleStatusCode(StrEnum):
    authorizing = "authorizing"
    active = "active"
    failed = "failed"
    revoking = "revoking"


class ClientVpnConnectionStatusCode(StrEnum):
    active = "active"
    failed_to_terminate = "failed-to-terminate"
    terminating = "terminating"
    terminated = "terminated"


class ClientVpnEndpointAttributeStatusCode(StrEnum):
    applying = "applying"
    applied = "applied"


class ClientVpnEndpointStatusCode(StrEnum):
    pending_associate = "pending-associate"
    available = "available"
    deleting = "deleting"
    deleted = "deleted"


class ClientVpnRouteStatusCode(StrEnum):
    creating = "creating"
    active = "active"
    failed = "failed"
    deleting = "deleting"


class ConnectionNotificationState(StrEnum):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ConnectionNotificationType(StrEnum):
    Topic = "Topic"


class ConnectivityType(StrEnum):
    private = "private"
    public = "public"


class ContainerFormat(StrEnum):
    ova = "ova"


class ConversionTaskState(StrEnum):
    active = "active"
    cancelling = "cancelling"
    cancelled = "cancelled"
    completed = "completed"


class CopyTagsFromSource(StrEnum):
    volume = "volume"


class CpuManufacturer(StrEnum):
    intel = "intel"
    amd = "amd"
    amazon_web_services = "amazon-web-services"


class CurrencyCodeValues(StrEnum):
    USD = "USD"


class DatafeedSubscriptionState(StrEnum):
    Active = "Active"
    Inactive = "Inactive"


class DefaultInstanceMetadataEndpointState(StrEnum):
    disabled = "disabled"
    enabled = "enabled"
    no_preference = "no-preference"


class DefaultInstanceMetadataTagsState(StrEnum):
    disabled = "disabled"
    enabled = "enabled"
    no_preference = "no-preference"


class DefaultRouteTableAssociationValue(StrEnum):
    enable = "enable"
    disable = "disable"


class DefaultRouteTablePropagationValue(StrEnum):
    enable = "enable"
    disable = "disable"


class DefaultTargetCapacityType(StrEnum):
    spot = "spot"
    on_demand = "on-demand"
    capacity_block = "capacity-block"


class DeleteFleetErrorCode(StrEnum):
    fleetIdDoesNotExist = "fleetIdDoesNotExist"
    fleetIdMalformed = "fleetIdMalformed"
    fleetNotInDeletableState = "fleetNotInDeletableState"
    unexpectedError = "unexpectedError"


class DeleteQueuedReservedInstancesErrorCode(StrEnum):
    reserved_instances_id_invalid = "reserved-instances-id-invalid"
    reserved_instances_not_in_queued_state = "reserved-instances-not-in-queued-state"
    unexpected_error = "unexpected-error"


class DestinationFileFormat(StrEnum):
    plain_text = "plain-text"
    parquet = "parquet"


class DeviceTrustProviderType(StrEnum):
    jamf = "jamf"
    crowdstrike = "crowdstrike"
    jumpcloud = "jumpcloud"


class DeviceType(StrEnum):
    ebs = "ebs"
    instance_store = "instance-store"


class DiskImageFormat(StrEnum):
    VMDK = "VMDK"
    RAW = "RAW"
    VHD = "VHD"


class DiskType(StrEnum):
    hdd = "hdd"
    ssd = "ssd"


class DnsNameState(StrEnum):
    pendingVerification = "pendingVerification"
    verified = "verified"
    failed = "failed"


class DnsRecordIpType(StrEnum):
    ipv4 = "ipv4"
    dualstack = "dualstack"
    ipv6 = "ipv6"
    service_defined = "service-defined"


class DnsSupportValue(StrEnum):
    enable = "enable"
    disable = "disable"


class DomainType(StrEnum):
    vpc = "vpc"
    standard = "standard"


class DynamicRoutingValue(StrEnum):
    enable = "enable"
    disable = "disable"


class EbsEncryptionSupport(StrEnum):
    unsupported = "unsupported"
    supported = "supported"


class EbsNvmeSupport(StrEnum):
    unsupported = "unsupported"
    supported = "supported"
    required = "required"


class EbsOptimizedSupport(StrEnum):
    unsupported = "unsupported"
    supported = "supported"
    default = "default"


class Ec2InstanceConnectEndpointState(StrEnum):
    create_in_progress = "create-in-progress"
    create_complete = "create-complete"
    create_failed = "create-failed"
    delete_in_progress = "delete-in-progress"
    delete_complete = "delete-complete"
    delete_failed = "delete-failed"


class EkPubKeyFormat(StrEnum):
    der = "der"
    tpmt = "tpmt"


class EkPubKeyType(StrEnum):
    rsa_2048 = "rsa-2048"
    ecc_sec_p384 = "ecc-sec-p384"


class ElasticGpuState(StrEnum):
    ATTACHED = "ATTACHED"


class ElasticGpuStatus(StrEnum):
    OK = "OK"
    IMPAIRED = "IMPAIRED"


class EnaSupport(StrEnum):
    unsupported = "unsupported"
    supported = "supported"
    required = "required"


class EndDateType(StrEnum):
    unlimited = "unlimited"
    limited = "limited"


class EphemeralNvmeSupport(StrEnum):
    unsupported = "unsupported"
    supported = "supported"
    required = "required"


class EventCode(StrEnum):
    instance_reboot = "instance-reboot"
    system_reboot = "system-reboot"
    system_maintenance = "system-maintenance"
    instance_retirement = "instance-retirement"
    instance_stop = "instance-stop"


class EventType(StrEnum):
    instanceChange = "instanceChange"
    fleetRequestChange = "fleetRequestChange"
    error = "error"
    information = "information"


class ExcessCapacityTerminationPolicy(StrEnum):
    noTermination = "noTermination"
    default = "default"


class ExportEnvironment(StrEnum):
    citrix = "citrix"
    vmware = "vmware"
    microsoft = "microsoft"


class ExportTaskState(StrEnum):
    active = "active"
    cancelling = "cancelling"
    cancelled = "cancelled"
    completed = "completed"


class FastLaunchResourceType(StrEnum):
    snapshot = "snapshot"


class FastLaunchStateCode(StrEnum):
    enabling = "enabling"
    enabling_failed = "enabling-failed"
    enabled = "enabled"
    enabled_failed = "enabled-failed"
    disabling = "disabling"
    disabling_failed = "disabling-failed"


class FastSnapshotRestoreStateCode(StrEnum):
    enabling = "enabling"
    optimizing = "optimizing"
    enabled = "enabled"
    disabling = "disabling"
    disabled = "disabled"


class FindingsFound(StrEnum):
    true = "true"
    false = "false"
    unknown = "unknown"


class FleetActivityStatus(StrEnum):
    error = "error"
    pending_fulfillment = "pending_fulfillment"
    pending_termination = "pending_termination"
    fulfilled = "fulfilled"


class FleetCapacityReservationTenancy(StrEnum):
    default = "default"


class FleetCapacityReservationUsageStrategy(StrEnum):
    use_capacity_reservations_first = "use-capacity-reservations-first"


class FleetEventType(StrEnum):
    instance_change = "instance-change"
    fleet_change = "fleet-change"
    service_error = "service-error"


class FleetExcessCapacityTerminationPolicy(StrEnum):
    no_termination = "no-termination"
    termination = "termination"


class FleetInstanceMatchCriteria(StrEnum):
    open = "open"


class FleetOnDemandAllocationStrategy(StrEnum):
    lowest_price = "lowest-price"
    prioritized = "prioritized"


class FleetReplacementStrategy(StrEnum):
    launch = "launch"
    launch_before_terminate = "launch-before-terminate"


class FleetStateCode(StrEnum):
    submitted = "submitted"
    active = "active"
    deleted = "deleted"
    failed = "failed"
    deleted_running = "deleted_running"
    deleted_terminating = "deleted_terminating"
    modifying = "modifying"


class FleetType(StrEnum):
    request = "request"
    maintain = "maintain"
    instant = "instant"


class FlowLogsResourceType(StrEnum):
    VPC = "VPC"
    Subnet = "Subnet"
    NetworkInterface = "NetworkInterface"
    TransitGateway = "TransitGateway"
    TransitGatewayAttachment = "TransitGatewayAttachment"


class FpgaImageAttributeName(StrEnum):
    description = "description"
    name = "name"
    loadPermission = "loadPermission"
    productCodes = "productCodes"


class FpgaImageStateCode(StrEnum):
    pending = "pending"
    failed = "failed"
    available = "available"
    unavailable = "unavailable"


class GatewayAssociationState(StrEnum):
    associated = "associated"
    not_associated = "not-associated"
    associating = "associating"
    disassociating = "disassociating"


class GatewayType(StrEnum):
    ipsec_1 = "ipsec.1"


class HostMaintenance(StrEnum):
    on = "on"
    off = "off"


class HostRecovery(StrEnum):
    on = "on"
    off = "off"


class HostTenancy(StrEnum):
    default = "default"
    dedicated = "dedicated"
    host = "host"


class HostnameType(StrEnum):
    ip_name = "ip-name"
    resource_name = "resource-name"


class HttpTokensState(StrEnum):
    optional = "optional"
    required = "required"


class HypervisorType(StrEnum):
    ovm = "ovm"
    xen = "xen"


class IamInstanceProfileAssociationState(StrEnum):
    associating = "associating"
    associated = "associated"
    disassociating = "disassociating"
    disassociated = "disassociated"


class Igmpv2SupportValue(StrEnum):
    enable = "enable"
    disable = "disable"


class ImageAttributeName(StrEnum):
    description = "description"
    kernel = "kernel"
    ramdisk = "ramdisk"
    launchPermission = "launchPermission"
    productCodes = "productCodes"
    blockDeviceMapping = "blockDeviceMapping"
    sriovNetSupport = "sriovNetSupport"
    bootMode = "bootMode"
    tpmSupport = "tpmSupport"
    uefiData = "uefiData"
    lastLaunchedTime = "lastLaunchedTime"
    imdsSupport = "imdsSupport"
    deregistrationProtection = "deregistrationProtection"


class ImageBlockPublicAccessDisabledState(StrEnum):
    unblocked = "unblocked"


class ImageBlockPublicAccessEnabledState(StrEnum):
    block_new_sharing = "block-new-sharing"


class ImageState(StrEnum):
    pending = "pending"
    available = "available"
    invalid = "invalid"
    deregistered = "deregistered"
    transient = "transient"
    failed = "failed"
    error = "error"
    disabled = "disabled"


class ImageTypeValues(StrEnum):
    machine = "machine"
    kernel = "kernel"
    ramdisk = "ramdisk"


class ImdsSupportValues(StrEnum):
    v2_0 = "v2.0"


class InstanceAttributeName(StrEnum):
    instanceType = "instanceType"
    kernel = "kernel"
    ramdisk = "ramdisk"
    userData = "userData"
    disableApiTermination = "disableApiTermination"
    instanceInitiatedShutdownBehavior = "instanceInitiatedShutdownBehavior"
    rootDeviceName = "rootDeviceName"
    blockDeviceMapping = "blockDeviceMapping"
    productCodes = "productCodes"
    sourceDestCheck = "sourceDestCheck"
    groupSet = "groupSet"
    ebsOptimized = "ebsOptimized"
    sriovNetSupport = "sriovNetSupport"
    enaSupport = "enaSupport"
    enclaveOptions = "enclaveOptions"
    disableApiStop = "disableApiStop"


class InstanceAutoRecoveryState(StrEnum):
    disabled = "disabled"
    default = "default"


class InstanceBootModeValues(StrEnum):
    legacy_bios = "legacy-bios"
    uefi = "uefi"


class InstanceEventWindowState(StrEnum):
    creating = "creating"
    deleting = "deleting"
    active = "active"
    deleted = "deleted"


class InstanceGeneration(StrEnum):
    current = "current"
    previous = "previous"


class InstanceHealthStatus(StrEnum):
    healthy = "healthy"
    unhealthy = "unhealthy"


class InstanceInterruptionBehavior(StrEnum):
    hibernate = "hibernate"
    stop = "stop"
    terminate = "terminate"


class InstanceLifecycle(StrEnum):
    spot = "spot"
    on_demand = "on-demand"


class InstanceLifecycleType(StrEnum):
    spot = "spot"
    scheduled = "scheduled"
    capacity_block = "capacity-block"


class InstanceMatchCriteria(StrEnum):
    open = "open"
    targeted = "targeted"


class InstanceMetadataEndpointState(StrEnum):
    disabled = "disabled"
    enabled = "enabled"


class InstanceMetadataOptionsState(StrEnum):
    pending = "pending"
    applied = "applied"


class InstanceMetadataProtocolState(StrEnum):
    disabled = "disabled"
    enabled = "enabled"


class InstanceMetadataTagsState(StrEnum):
    disabled = "disabled"
    enabled = "enabled"


class InstanceStateName(StrEnum):
    pending = "pending"
    running = "running"
    shutting_down = "shutting-down"
    terminated = "terminated"
    stopping = "stopping"
    stopped = "stopped"


class InstanceStorageEncryptionSupport(StrEnum):
    unsupported = "unsupported"
    required = "required"


class InstanceType(StrEnum):
    a1_medium = "a1.medium"
    a1_large = "a1.large"
    a1_xlarge = "a1.xlarge"
    a1_2xlarge = "a1.2xlarge"
    a1_4xlarge = "a1.4xlarge"
    a1_metal = "a1.metal"
    c1_medium = "c1.medium"
    c1_xlarge = "c1.xlarge"
    c3_large = "c3.large"
    c3_xlarge = "c3.xlarge"
    c3_2xlarge = "c3.2xlarge"
    c3_4xlarge = "c3.4xlarge"
    c3_8xlarge = "c3.8xlarge"
    c4_large = "c4.large"
    c4_xlarge = "c4.xlarge"
    c4_2xlarge = "c4.2xlarge"
    c4_4xlarge = "c4.4xlarge"
    c4_8xlarge = "c4.8xlarge"
    c5_large = "c5.large"
    c5_xlarge = "c5.xlarge"
    c5_2xlarge = "c5.2xlarge"
    c5_4xlarge = "c5.4xlarge"
    c5_9xlarge = "c5.9xlarge"
    c5_12xlarge = "c5.12xlarge"
    c5_18xlarge = "c5.18xlarge"
    c5_24xlarge = "c5.24xlarge"
    c5_metal = "c5.metal"
    c5a_large = "c5a.large"
    c5a_xlarge = "c5a.xlarge"
    c5a_2xlarge = "c5a.2xlarge"
    c5a_4xlarge = "c5a.4xlarge"
    c5a_8xlarge = "c5a.8xlarge"
    c5a_12xlarge = "c5a.12xlarge"
    c5a_16xlarge = "c5a.16xlarge"
    c5a_24xlarge = "c5a.24xlarge"
    c5ad_large = "c5ad.large"
    c5ad_xlarge = "c5ad.xlarge"
    c5ad_2xlarge = "c5ad.2xlarge"
    c5ad_4xlarge = "c5ad.4xlarge"
    c5ad_8xlarge = "c5ad.8xlarge"
    c5ad_12xlarge = "c5ad.12xlarge"
    c5ad_16xlarge = "c5ad.16xlarge"
    c5ad_24xlarge = "c5ad.24xlarge"
    c5d_large = "c5d.large"
    c5d_xlarge = "c5d.xlarge"
    c5d_2xlarge = "c5d.2xlarge"
    c5d_4xlarge = "c5d.4xlarge"
    c5d_9xlarge = "c5d.9xlarge"
    c5d_12xlarge = "c5d.12xlarge"
    c5d_18xlarge = "c5d.18xlarge"
    c5d_24xlarge = "c5d.24xlarge"
    c5d_metal = "c5d.metal"
    c5n_large = "c5n.large"
    c5n_xlarge = "c5n.xlarge"
    c5n_2xlarge = "c5n.2xlarge"
    c5n_4xlarge = "c5n.4xlarge"
    c5n_9xlarge = "c5n.9xlarge"
    c5n_18xlarge = "c5n.18xlarge"
    c5n_metal = "c5n.metal"
    c6g_medium = "c6g.medium"
    c6g_large = "c6g.large"
    c6g_xlarge = "c6g.xlarge"
    c6g_2xlarge = "c6g.2xlarge"
    c6g_4xlarge = "c6g.4xlarge"
    c6g_8xlarge = "c6g.8xlarge"
    c6g_12xlarge = "c6g.12xlarge"
    c6g_16xlarge = "c6g.16xlarge"
    c6g_metal = "c6g.metal"
    c6gd_medium = "c6gd.medium"
    c6gd_large = "c6gd.large"
    c6gd_xlarge = "c6gd.xlarge"
    c6gd_2xlarge = "c6gd.2xlarge"
    c6gd_4xlarge = "c6gd.4xlarge"
    c6gd_8xlarge = "c6gd.8xlarge"
    c6gd_12xlarge = "c6gd.12xlarge"
    c6gd_16xlarge = "c6gd.16xlarge"
    c6gd_metal = "c6gd.metal"
    c6gn_medium = "c6gn.medium"
    c6gn_large = "c6gn.large"
    c6gn_xlarge = "c6gn.xlarge"
    c6gn_2xlarge = "c6gn.2xlarge"
    c6gn_4xlarge = "c6gn.4xlarge"
    c6gn_8xlarge = "c6gn.8xlarge"
    c6gn_12xlarge = "c6gn.12xlarge"
    c6gn_16xlarge = "c6gn.16xlarge"
    c6i_large = "c6i.large"
    c6i_xlarge = "c6i.xlarge"
    c6i_2xlarge = "c6i.2xlarge"
    c6i_4xlarge = "c6i.4xlarge"
    c6i_8xlarge = "c6i.8xlarge"
    c6i_12xlarge = "c6i.12xlarge"
    c6i_16xlarge = "c6i.16xlarge"
    c6i_24xlarge = "c6i.24xlarge"
    c6i_32xlarge = "c6i.32xlarge"
    c6i_metal = "c6i.metal"
    cc1_4xlarge = "cc1.4xlarge"
    cc2_8xlarge = "cc2.8xlarge"
    cg1_4xlarge = "cg1.4xlarge"
    cr1_8xlarge = "cr1.8xlarge"
    d2_xlarge = "d2.xlarge"
    d2_2xlarge = "d2.2xlarge"
    d2_4xlarge = "d2.4xlarge"
    d2_8xlarge = "d2.8xlarge"
    d3_xlarge = "d3.xlarge"
    d3_2xlarge = "d3.2xlarge"
    d3_4xlarge = "d3.4xlarge"
    d3_8xlarge = "d3.8xlarge"
    d3en_xlarge = "d3en.xlarge"
    d3en_2xlarge = "d3en.2xlarge"
    d3en_4xlarge = "d3en.4xlarge"
    d3en_6xlarge = "d3en.6xlarge"
    d3en_8xlarge = "d3en.8xlarge"
    d3en_12xlarge = "d3en.12xlarge"
    dl1_24xlarge = "dl1.24xlarge"
    f1_2xlarge = "f1.2xlarge"
    f1_4xlarge = "f1.4xlarge"
    f1_16xlarge = "f1.16xlarge"
    g2_2xlarge = "g2.2xlarge"
    g2_8xlarge = "g2.8xlarge"
    g3_4xlarge = "g3.4xlarge"
    g3_8xlarge = "g3.8xlarge"
    g3_16xlarge = "g3.16xlarge"
    g3s_xlarge = "g3s.xlarge"
    g4ad_xlarge = "g4ad.xlarge"
    g4ad_2xlarge = "g4ad.2xlarge"
    g4ad_4xlarge = "g4ad.4xlarge"
    g4ad_8xlarge = "g4ad.8xlarge"
    g4ad_16xlarge = "g4ad.16xlarge"
    g4dn_xlarge = "g4dn.xlarge"
    g4dn_2xlarge = "g4dn.2xlarge"
    g4dn_4xlarge = "g4dn.4xlarge"
    g4dn_8xlarge = "g4dn.8xlarge"
    g4dn_12xlarge = "g4dn.12xlarge"
    g4dn_16xlarge = "g4dn.16xlarge"
    g4dn_metal = "g4dn.metal"
    g5_xlarge = "g5.xlarge"
    g5_2xlarge = "g5.2xlarge"
    g5_4xlarge = "g5.4xlarge"
    g5_8xlarge = "g5.8xlarge"
    g5_12xlarge = "g5.12xlarge"
    g5_16xlarge = "g5.16xlarge"
    g5_24xlarge = "g5.24xlarge"
    g5_48xlarge = "g5.48xlarge"
    g5g_xlarge = "g5g.xlarge"
    g5g_2xlarge = "g5g.2xlarge"
    g5g_4xlarge = "g5g.4xlarge"
    g5g_8xlarge = "g5g.8xlarge"
    g5g_16xlarge = "g5g.16xlarge"
    g5g_metal = "g5g.metal"
    hi1_4xlarge = "hi1.4xlarge"
    hpc6a_48xlarge = "hpc6a.48xlarge"
    hs1_8xlarge = "hs1.8xlarge"
    h1_2xlarge = "h1.2xlarge"
    h1_4xlarge = "h1.4xlarge"
    h1_8xlarge = "h1.8xlarge"
    h1_16xlarge = "h1.16xlarge"
    i2_xlarge = "i2.xlarge"
    i2_2xlarge = "i2.2xlarge"
    i2_4xlarge = "i2.4xlarge"
    i2_8xlarge = "i2.8xlarge"
    i3_large = "i3.large"
    i3_xlarge = "i3.xlarge"
    i3_2xlarge = "i3.2xlarge"
    i3_4xlarge = "i3.4xlarge"
    i3_8xlarge = "i3.8xlarge"
    i3_16xlarge = "i3.16xlarge"
    i3_metal = "i3.metal"
    i3en_large = "i3en.large"
    i3en_xlarge = "i3en.xlarge"
    i3en_2xlarge = "i3en.2xlarge"
    i3en_3xlarge = "i3en.3xlarge"
    i3en_6xlarge = "i3en.6xlarge"
    i3en_12xlarge = "i3en.12xlarge"
    i3en_24xlarge = "i3en.24xlarge"
    i3en_metal = "i3en.metal"
    im4gn_large = "im4gn.large"
    im4gn_xlarge = "im4gn.xlarge"
    im4gn_2xlarge = "im4gn.2xlarge"
    im4gn_4xlarge = "im4gn.4xlarge"
    im4gn_8xlarge = "im4gn.8xlarge"
    im4gn_16xlarge = "im4gn.16xlarge"
    inf1_xlarge = "inf1.xlarge"
    inf1_2xlarge = "inf1.2xlarge"
    inf1_6xlarge = "inf1.6xlarge"
    inf1_24xlarge = "inf1.24xlarge"
    is4gen_medium = "is4gen.medium"
    is4gen_large = "is4gen.large"
    is4gen_xlarge = "is4gen.xlarge"
    is4gen_2xlarge = "is4gen.2xlarge"
    is4gen_4xlarge = "is4gen.4xlarge"
    is4gen_8xlarge = "is4gen.8xlarge"
    m1_small = "m1.small"
    m1_medium = "m1.medium"
    m1_large = "m1.large"
    m1_xlarge = "m1.xlarge"
    m2_xlarge = "m2.xlarge"
    m2_2xlarge = "m2.2xlarge"
    m2_4xlarge = "m2.4xlarge"
    m3_medium = "m3.medium"
    m3_large = "m3.large"
    m3_xlarge = "m3.xlarge"
    m3_2xlarge = "m3.2xlarge"
    m4_large = "m4.large"
    m4_xlarge = "m4.xlarge"
    m4_2xlarge = "m4.2xlarge"
    m4_4xlarge = "m4.4xlarge"
    m4_10xlarge = "m4.10xlarge"
    m4_16xlarge = "m4.16xlarge"
    m5_large = "m5.large"
    m5_xlarge = "m5.xlarge"
    m5_2xlarge = "m5.2xlarge"
    m5_4xlarge = "m5.4xlarge"
    m5_8xlarge = "m5.8xlarge"
    m5_12xlarge = "m5.12xlarge"
    m5_16xlarge = "m5.16xlarge"
    m5_24xlarge = "m5.24xlarge"
    m5_metal = "m5.metal"
    m5a_large = "m5a.large"
    m5a_xlarge = "m5a.xlarge"
    m5a_2xlarge = "m5a.2xlarge"
    m5a_4xlarge = "m5a.4xlarge"
    m5a_8xlarge = "m5a.8xlarge"
    m5a_12xlarge = "m5a.12xlarge"
    m5a_16xlarge = "m5a.16xlarge"
    m5a_24xlarge = "m5a.24xlarge"
    m5ad_large = "m5ad.large"
    m5ad_xlarge = "m5ad.xlarge"
    m5ad_2xlarge = "m5ad.2xlarge"
    m5ad_4xlarge = "m5ad.4xlarge"
    m5ad_8xlarge = "m5ad.8xlarge"
    m5ad_12xlarge = "m5ad.12xlarge"
    m5ad_16xlarge = "m5ad.16xlarge"
    m5ad_24xlarge = "m5ad.24xlarge"
    m5d_large = "m5d.large"
    m5d_xlarge = "m5d.xlarge"
    m5d_2xlarge = "m5d.2xlarge"
    m5d_4xlarge = "m5d.4xlarge"
    m5d_8xlarge = "m5d.8xlarge"
    m5d_12xlarge = "m5d.12xlarge"
    m5d_16xlarge = "m5d.16xlarge"
    m5d_24xlarge = "m5d.24xlarge"
    m5d_metal = "m5d.metal"
    m5dn_large = "m5dn.large"
    m5dn_xlarge = "m5dn.xlarge"
    m5dn_2xlarge = "m5dn.2xlarge"
    m5dn_4xlarge = "m5dn.4xlarge"
    m5dn_8xlarge = "m5dn.8xlarge"
    m5dn_12xlarge = "m5dn.12xlarge"
    m5dn_16xlarge = "m5dn.16xlarge"
    m5dn_24xlarge = "m5dn.24xlarge"
    m5dn_metal = "m5dn.metal"
    m5n_large = "m5n.large"
    m5n_xlarge = "m5n.xlarge"
    m5n_2xlarge = "m5n.2xlarge"
    m5n_4xlarge = "m5n.4xlarge"
    m5n_8xlarge = "m5n.8xlarge"
    m5n_12xlarge = "m5n.12xlarge"
    m5n_16xlarge = "m5n.16xlarge"
    m5n_24xlarge = "m5n.24xlarge"
    m5n_metal = "m5n.metal"
    m5zn_large = "m5zn.large"
    m5zn_xlarge = "m5zn.xlarge"
    m5zn_2xlarge = "m5zn.2xlarge"
    m5zn_3xlarge = "m5zn.3xlarge"
    m5zn_6xlarge = "m5zn.6xlarge"
    m5zn_12xlarge = "m5zn.12xlarge"
    m5zn_metal = "m5zn.metal"
    m6a_large = "m6a.large"
    m6a_xlarge = "m6a.xlarge"
    m6a_2xlarge = "m6a.2xlarge"
    m6a_4xlarge = "m6a.4xlarge"
    m6a_8xlarge = "m6a.8xlarge"
    m6a_12xlarge = "m6a.12xlarge"
    m6a_16xlarge = "m6a.16xlarge"
    m6a_24xlarge = "m6a.24xlarge"
    m6a_32xlarge = "m6a.32xlarge"
    m6a_48xlarge = "m6a.48xlarge"
    m6g_metal = "m6g.metal"
    m6g_medium = "m6g.medium"
    m6g_large = "m6g.large"
    m6g_xlarge = "m6g.xlarge"
    m6g_2xlarge = "m6g.2xlarge"
    m6g_4xlarge = "m6g.4xlarge"
    m6g_8xlarge = "m6g.8xlarge"
    m6g_12xlarge = "m6g.12xlarge"
    m6g_16xlarge = "m6g.16xlarge"
    m6gd_metal = "m6gd.metal"
    m6gd_medium = "m6gd.medium"
    m6gd_large = "m6gd.large"
    m6gd_xlarge = "m6gd.xlarge"
    m6gd_2xlarge = "m6gd.2xlarge"
    m6gd_4xlarge = "m6gd.4xlarge"
    m6gd_8xlarge = "m6gd.8xlarge"
    m6gd_12xlarge = "m6gd.12xlarge"
    m6gd_16xlarge = "m6gd.16xlarge"
    m6i_large = "m6i.large"
    m6i_xlarge = "m6i.xlarge"
    m6i_2xlarge = "m6i.2xlarge"
    m6i_4xlarge = "m6i.4xlarge"
    m6i_8xlarge = "m6i.8xlarge"
    m6i_12xlarge = "m6i.12xlarge"
    m6i_16xlarge = "m6i.16xlarge"
    m6i_24xlarge = "m6i.24xlarge"
    m6i_32xlarge = "m6i.32xlarge"
    m6i_metal = "m6i.metal"
    mac1_metal = "mac1.metal"
    p2_xlarge = "p2.xlarge"
    p2_8xlarge = "p2.8xlarge"
    p2_16xlarge = "p2.16xlarge"
    p3_2xlarge = "p3.2xlarge"
    p3_8xlarge = "p3.8xlarge"
    p3_16xlarge = "p3.16xlarge"
    p3dn_24xlarge = "p3dn.24xlarge"
    p4d_24xlarge = "p4d.24xlarge"
    r3_large = "r3.large"
    r3_xlarge = "r3.xlarge"
    r3_2xlarge = "r3.2xlarge"
    r3_4xlarge = "r3.4xlarge"
    r3_8xlarge = "r3.8xlarge"
    r4_large = "r4.large"
    r4_xlarge = "r4.xlarge"
    r4_2xlarge = "r4.2xlarge"
    r4_4xlarge = "r4.4xlarge"
    r4_8xlarge = "r4.8xlarge"
    r4_16xlarge = "r4.16xlarge"
    r5_large = "r5.large"
    r5_xlarge = "r5.xlarge"
    r5_2xlarge = "r5.2xlarge"
    r5_4xlarge = "r5.4xlarge"
    r5_8xlarge = "r5.8xlarge"
    r5_12xlarge = "r5.12xlarge"
    r5_16xlarge = "r5.16xlarge"
    r5_24xlarge = "r5.24xlarge"
    r5_metal = "r5.metal"
    r5a_large = "r5a.large"
    r5a_xlarge = "r5a.xlarge"
    r5a_2xlarge = "r5a.2xlarge"
    r5a_4xlarge = "r5a.4xlarge"
    r5a_8xlarge = "r5a.8xlarge"
    r5a_12xlarge = "r5a.12xlarge"
    r5a_16xlarge = "r5a.16xlarge"
    r5a_24xlarge = "r5a.24xlarge"
    r5ad_large = "r5ad.large"
    r5ad_xlarge = "r5ad.xlarge"
    r5ad_2xlarge = "r5ad.2xlarge"
    r5ad_4xlarge = "r5ad.4xlarge"
    r5ad_8xlarge = "r5ad.8xlarge"
    r5ad_12xlarge = "r5ad.12xlarge"
    r5ad_16xlarge = "r5ad.16xlarge"
    r5ad_24xlarge = "r5ad.24xlarge"
    r5b_large = "r5b.large"
    r5b_xlarge = "r5b.xlarge"
    r5b_2xlarge = "r5b.2xlarge"
    r5b_4xlarge = "r5b.4xlarge"
    r5b_8xlarge = "r5b.8xlarge"
    r5b_12xlarge = "r5b.12xlarge"
    r5b_16xlarge = "r5b.16xlarge"
    r5b_24xlarge = "r5b.24xlarge"
    r5b_metal = "r5b.metal"
    r5d_large = "r5d.large"
    r5d_xlarge = "r5d.xlarge"
    r5d_2xlarge = "r5d.2xlarge"
    r5d_4xlarge = "r5d.4xlarge"
    r5d_8xlarge = "r5d.8xlarge"
    r5d_12xlarge = "r5d.12xlarge"
    r5d_16xlarge = "r5d.16xlarge"
    r5d_24xlarge = "r5d.24xlarge"
    r5d_metal = "r5d.metal"
    r5dn_large = "r5dn.large"
    r5dn_xlarge = "r5dn.xlarge"
    r5dn_2xlarge = "r5dn.2xlarge"
    r5dn_4xlarge = "r5dn.4xlarge"
    r5dn_8xlarge = "r5dn.8xlarge"
    r5dn_12xlarge = "r5dn.12xlarge"
    r5dn_16xlarge = "r5dn.16xlarge"
    r5dn_24xlarge = "r5dn.24xlarge"
    r5dn_metal = "r5dn.metal"
    r5n_large = "r5n.large"
    r5n_xlarge = "r5n.xlarge"
    r5n_2xlarge = "r5n.2xlarge"
    r5n_4xlarge = "r5n.4xlarge"
    r5n_8xlarge = "r5n.8xlarge"
    r5n_12xlarge = "r5n.12xlarge"
    r5n_16xlarge = "r5n.16xlarge"
    r5n_24xlarge = "r5n.24xlarge"
    r5n_metal = "r5n.metal"
    r6g_medium = "r6g.medium"
    r6g_large = "r6g.large"
    r6g_xlarge = "r6g.xlarge"
    r6g_2xlarge = "r6g.2xlarge"
    r6g_4xlarge = "r6g.4xlarge"
    r6g_8xlarge = "r6g.8xlarge"
    r6g_12xlarge = "r6g.12xlarge"
    r6g_16xlarge = "r6g.16xlarge"
    r6g_metal = "r6g.metal"
    r6gd_medium = "r6gd.medium"
    r6gd_large = "r6gd.large"
    r6gd_xlarge = "r6gd.xlarge"
    r6gd_2xlarge = "r6gd.2xlarge"
    r6gd_4xlarge = "r6gd.4xlarge"
    r6gd_8xlarge = "r6gd.8xlarge"
    r6gd_12xlarge = "r6gd.12xlarge"
    r6gd_16xlarge = "r6gd.16xlarge"
    r6gd_metal = "r6gd.metal"
    r6i_large = "r6i.large"
    r6i_xlarge = "r6i.xlarge"
    r6i_2xlarge = "r6i.2xlarge"
    r6i_4xlarge = "r6i.4xlarge"
    r6i_8xlarge = "r6i.8xlarge"
    r6i_12xlarge = "r6i.12xlarge"
    r6i_16xlarge = "r6i.16xlarge"
    r6i_24xlarge = "r6i.24xlarge"
    r6i_32xlarge = "r6i.32xlarge"
    r6i_metal = "r6i.metal"
    t1_micro = "t1.micro"
    t2_nano = "t2.nano"
    t2_micro = "t2.micro"
    t2_small = "t2.small"
    t2_medium = "t2.medium"
    t2_large = "t2.large"
    t2_xlarge = "t2.xlarge"
    t2_2xlarge = "t2.2xlarge"
    t3_nano = "t3.nano"
    t3_micro = "t3.micro"
    t3_small = "t3.small"
    t3_medium = "t3.medium"
    t3_large = "t3.large"
    t3_xlarge = "t3.xlarge"
    t3_2xlarge = "t3.2xlarge"
    t3a_nano = "t3a.nano"
    t3a_micro = "t3a.micro"
    t3a_small = "t3a.small"
    t3a_medium = "t3a.medium"
    t3a_large = "t3a.large"
    t3a_xlarge = "t3a.xlarge"
    t3a_2xlarge = "t3a.2xlarge"
    t4g_nano = "t4g.nano"
    t4g_micro = "t4g.micro"
    t4g_small = "t4g.small"
    t4g_medium = "t4g.medium"
    t4g_large = "t4g.large"
    t4g_xlarge = "t4g.xlarge"
    t4g_2xlarge = "t4g.2xlarge"
    u_6tb1_56xlarge = "u-6tb1.56xlarge"
    u_6tb1_112xlarge = "u-6tb1.112xlarge"
    u_9tb1_112xlarge = "u-9tb1.112xlarge"
    u_12tb1_112xlarge = "u-12tb1.112xlarge"
    u_6tb1_metal = "u-6tb1.metal"
    u_9tb1_metal = "u-9tb1.metal"
    u_12tb1_metal = "u-12tb1.metal"
    u_18tb1_metal = "u-18tb1.metal"
    u_24tb1_metal = "u-24tb1.metal"
    vt1_3xlarge = "vt1.3xlarge"
    vt1_6xlarge = "vt1.6xlarge"
    vt1_24xlarge = "vt1.24xlarge"
    x1_16xlarge = "x1.16xlarge"
    x1_32xlarge = "x1.32xlarge"
    x1e_xlarge = "x1e.xlarge"
    x1e_2xlarge = "x1e.2xlarge"
    x1e_4xlarge = "x1e.4xlarge"
    x1e_8xlarge = "x1e.8xlarge"
    x1e_16xlarge = "x1e.16xlarge"
    x1e_32xlarge = "x1e.32xlarge"
    x2iezn_2xlarge = "x2iezn.2xlarge"
    x2iezn_4xlarge = "x2iezn.4xlarge"
    x2iezn_6xlarge = "x2iezn.6xlarge"
    x2iezn_8xlarge = "x2iezn.8xlarge"
    x2iezn_12xlarge = "x2iezn.12xlarge"
    x2iezn_metal = "x2iezn.metal"
    x2gd_medium = "x2gd.medium"
    x2gd_large = "x2gd.large"
    x2gd_xlarge = "x2gd.xlarge"
    x2gd_2xlarge = "x2gd.2xlarge"
    x2gd_4xlarge = "x2gd.4xlarge"
    x2gd_8xlarge = "x2gd.8xlarge"
    x2gd_12xlarge = "x2gd.12xlarge"
    x2gd_16xlarge = "x2gd.16xlarge"
    x2gd_metal = "x2gd.metal"
    z1d_large = "z1d.large"
    z1d_xlarge = "z1d.xlarge"
    z1d_2xlarge = "z1d.2xlarge"
    z1d_3xlarge = "z1d.3xlarge"
    z1d_6xlarge = "z1d.6xlarge"
    z1d_12xlarge = "z1d.12xlarge"
    z1d_metal = "z1d.metal"
    x2idn_16xlarge = "x2idn.16xlarge"
    x2idn_24xlarge = "x2idn.24xlarge"
    x2idn_32xlarge = "x2idn.32xlarge"
    x2iedn_xlarge = "x2iedn.xlarge"
    x2iedn_2xlarge = "x2iedn.2xlarge"
    x2iedn_4xlarge = "x2iedn.4xlarge"
    x2iedn_8xlarge = "x2iedn.8xlarge"
    x2iedn_16xlarge = "x2iedn.16xlarge"
    x2iedn_24xlarge = "x2iedn.24xlarge"
    x2iedn_32xlarge = "x2iedn.32xlarge"
    c6a_large = "c6a.large"
    c6a_xlarge = "c6a.xlarge"
    c6a_2xlarge = "c6a.2xlarge"
    c6a_4xlarge = "c6a.4xlarge"
    c6a_8xlarge = "c6a.8xlarge"
    c6a_12xlarge = "c6a.12xlarge"
    c6a_16xlarge = "c6a.16xlarge"
    c6a_24xlarge = "c6a.24xlarge"
    c6a_32xlarge = "c6a.32xlarge"
    c6a_48xlarge = "c6a.48xlarge"
    c6a_metal = "c6a.metal"
    m6a_metal = "m6a.metal"
    i4i_large = "i4i.large"
    i4i_xlarge = "i4i.xlarge"
    i4i_2xlarge = "i4i.2xlarge"
    i4i_4xlarge = "i4i.4xlarge"
    i4i_8xlarge = "i4i.8xlarge"
    i4i_16xlarge = "i4i.16xlarge"
    i4i_32xlarge = "i4i.32xlarge"
    i4i_metal = "i4i.metal"
    x2idn_metal = "x2idn.metal"
    x2iedn_metal = "x2iedn.metal"
    c7g_medium = "c7g.medium"
    c7g_large = "c7g.large"
    c7g_xlarge = "c7g.xlarge"
    c7g_2xlarge = "c7g.2xlarge"
    c7g_4xlarge = "c7g.4xlarge"
    c7g_8xlarge = "c7g.8xlarge"
    c7g_12xlarge = "c7g.12xlarge"
    c7g_16xlarge = "c7g.16xlarge"
    mac2_metal = "mac2.metal"
    c6id_large = "c6id.large"
    c6id_xlarge = "c6id.xlarge"
    c6id_2xlarge = "c6id.2xlarge"
    c6id_4xlarge = "c6id.4xlarge"
    c6id_8xlarge = "c6id.8xlarge"
    c6id_12xlarge = "c6id.12xlarge"
    c6id_16xlarge = "c6id.16xlarge"
    c6id_24xlarge = "c6id.24xlarge"
    c6id_32xlarge = "c6id.32xlarge"
    c6id_metal = "c6id.metal"
    m6id_large = "m6id.large"
    m6id_xlarge = "m6id.xlarge"
    m6id_2xlarge = "m6id.2xlarge"
    m6id_4xlarge = "m6id.4xlarge"
    m6id_8xlarge = "m6id.8xlarge"
    m6id_12xlarge = "m6id.12xlarge"
    m6id_16xlarge = "m6id.16xlarge"
    m6id_24xlarge = "m6id.24xlarge"
    m6id_32xlarge = "m6id.32xlarge"
    m6id_metal = "m6id.metal"
    r6id_large = "r6id.large"
    r6id_xlarge = "r6id.xlarge"
    r6id_2xlarge = "r6id.2xlarge"
    r6id_4xlarge = "r6id.4xlarge"
    r6id_8xlarge = "r6id.8xlarge"
    r6id_12xlarge = "r6id.12xlarge"
    r6id_16xlarge = "r6id.16xlarge"
    r6id_24xlarge = "r6id.24xlarge"
    r6id_32xlarge = "r6id.32xlarge"
    r6id_metal = "r6id.metal"
    r6a_large = "r6a.large"
    r6a_xlarge = "r6a.xlarge"
    r6a_2xlarge = "r6a.2xlarge"
    r6a_4xlarge = "r6a.4xlarge"
    r6a_8xlarge = "r6a.8xlarge"
    r6a_12xlarge = "r6a.12xlarge"
    r6a_16xlarge = "r6a.16xlarge"
    r6a_24xlarge = "r6a.24xlarge"
    r6a_32xlarge = "r6a.32xlarge"
    r6a_48xlarge = "r6a.48xlarge"
    r6a_metal = "r6a.metal"
    p4de_24xlarge = "p4de.24xlarge"
    u_3tb1_56xlarge = "u-3tb1.56xlarge"
    u_18tb1_112xlarge = "u-18tb1.112xlarge"
    u_24tb1_112xlarge = "u-24tb1.112xlarge"
    trn1_2xlarge = "trn1.2xlarge"
    trn1_32xlarge = "trn1.32xlarge"
    hpc6id_32xlarge = "hpc6id.32xlarge"
    c6in_large = "c6in.large"
    c6in_xlarge = "c6in.xlarge"
    c6in_2xlarge = "c6in.2xlarge"
    c6in_4xlarge = "c6in.4xlarge"
    c6in_8xlarge = "c6in.8xlarge"
    c6in_12xlarge = "c6in.12xlarge"
    c6in_16xlarge = "c6in.16xlarge"
    c6in_24xlarge = "c6in.24xlarge"
    c6in_32xlarge = "c6in.32xlarge"
    m6in_large = "m6in.large"
    m6in_xlarge = "m6in.xlarge"
    m6in_2xlarge = "m6in.2xlarge"
    m6in_4xlarge = "m6in.4xlarge"
    m6in_8xlarge = "m6in.8xlarge"
    m6in_12xlarge = "m6in.12xlarge"
    m6in_16xlarge = "m6in.16xlarge"
    m6in_24xlarge = "m6in.24xlarge"
    m6in_32xlarge = "m6in.32xlarge"
    m6idn_large = "m6idn.large"
    m6idn_xlarge = "m6idn.xlarge"
    m6idn_2xlarge = "m6idn.2xlarge"
    m6idn_4xlarge = "m6idn.4xlarge"
    m6idn_8xlarge = "m6idn.8xlarge"
    m6idn_12xlarge = "m6idn.12xlarge"
    m6idn_16xlarge = "m6idn.16xlarge"
    m6idn_24xlarge = "m6idn.24xlarge"
    m6idn_32xlarge = "m6idn.32xlarge"
    r6in_large = "r6in.large"
    r6in_xlarge = "r6in.xlarge"
    r6in_2xlarge = "r6in.2xlarge"
    r6in_4xlarge = "r6in.4xlarge"
    r6in_8xlarge = "r6in.8xlarge"
    r6in_12xlarge = "r6in.12xlarge"
    r6in_16xlarge = "r6in.16xlarge"
    r6in_24xlarge = "r6in.24xlarge"
    r6in_32xlarge = "r6in.32xlarge"
    r6idn_large = "r6idn.large"
    r6idn_xlarge = "r6idn.xlarge"
    r6idn_2xlarge = "r6idn.2xlarge"
    r6idn_4xlarge = "r6idn.4xlarge"
    r6idn_8xlarge = "r6idn.8xlarge"
    r6idn_12xlarge = "r6idn.12xlarge"
    r6idn_16xlarge = "r6idn.16xlarge"
    r6idn_24xlarge = "r6idn.24xlarge"
    r6idn_32xlarge = "r6idn.32xlarge"
    c7g_metal = "c7g.metal"
    m7g_medium = "m7g.medium"
    m7g_large = "m7g.large"
    m7g_xlarge = "m7g.xlarge"
    m7g_2xlarge = "m7g.2xlarge"
    m7g_4xlarge = "m7g.4xlarge"
    m7g_8xlarge = "m7g.8xlarge"
    m7g_12xlarge = "m7g.12xlarge"
    m7g_16xlarge = "m7g.16xlarge"
    m7g_metal = "m7g.metal"
    r7g_medium = "r7g.medium"
    r7g_large = "r7g.large"
    r7g_xlarge = "r7g.xlarge"
    r7g_2xlarge = "r7g.2xlarge"
    r7g_4xlarge = "r7g.4xlarge"
    r7g_8xlarge = "r7g.8xlarge"
    r7g_12xlarge = "r7g.12xlarge"
    r7g_16xlarge = "r7g.16xlarge"
    r7g_metal = "r7g.metal"
    c6in_metal = "c6in.metal"
    m6in_metal = "m6in.metal"
    m6idn_metal = "m6idn.metal"
    r6in_metal = "r6in.metal"
    r6idn_metal = "r6idn.metal"
    inf2_xlarge = "inf2.xlarge"
    inf2_8xlarge = "inf2.8xlarge"
    inf2_24xlarge = "inf2.24xlarge"
    inf2_48xlarge = "inf2.48xlarge"
    trn1n_32xlarge = "trn1n.32xlarge"
    i4g_large = "i4g.large"
    i4g_xlarge = "i4g.xlarge"
    i4g_2xlarge = "i4g.2xlarge"
    i4g_4xlarge = "i4g.4xlarge"
    i4g_8xlarge = "i4g.8xlarge"
    i4g_16xlarge = "i4g.16xlarge"
    hpc7g_4xlarge = "hpc7g.4xlarge"
    hpc7g_8xlarge = "hpc7g.8xlarge"
    hpc7g_16xlarge = "hpc7g.16xlarge"
    c7gn_medium = "c7gn.medium"
    c7gn_large = "c7gn.large"
    c7gn_xlarge = "c7gn.xlarge"
    c7gn_2xlarge = "c7gn.2xlarge"
    c7gn_4xlarge = "c7gn.4xlarge"
    c7gn_8xlarge = "c7gn.8xlarge"
    c7gn_12xlarge = "c7gn.12xlarge"
    c7gn_16xlarge = "c7gn.16xlarge"
    p5_48xlarge = "p5.48xlarge"
    m7i_large = "m7i.large"
    m7i_xlarge = "m7i.xlarge"
    m7i_2xlarge = "m7i.2xlarge"
    m7i_4xlarge = "m7i.4xlarge"
    m7i_8xlarge = "m7i.8xlarge"
    m7i_12xlarge = "m7i.12xlarge"
    m7i_16xlarge = "m7i.16xlarge"
    m7i_24xlarge = "m7i.24xlarge"
    m7i_48xlarge = "m7i.48xlarge"
    m7i_flex_large = "m7i-flex.large"
    m7i_flex_xlarge = "m7i-flex.xlarge"
    m7i_flex_2xlarge = "m7i-flex.2xlarge"
    m7i_flex_4xlarge = "m7i-flex.4xlarge"
    m7i_flex_8xlarge = "m7i-flex.8xlarge"
    m7a_medium = "m7a.medium"
    m7a_large = "m7a.large"
    m7a_xlarge = "m7a.xlarge"
    m7a_2xlarge = "m7a.2xlarge"
    m7a_4xlarge = "m7a.4xlarge"
    m7a_8xlarge = "m7a.8xlarge"
    m7a_12xlarge = "m7a.12xlarge"
    m7a_16xlarge = "m7a.16xlarge"
    m7a_24xlarge = "m7a.24xlarge"
    m7a_32xlarge = "m7a.32xlarge"
    m7a_48xlarge = "m7a.48xlarge"
    m7a_metal_48xl = "m7a.metal-48xl"
    hpc7a_12xlarge = "hpc7a.12xlarge"
    hpc7a_24xlarge = "hpc7a.24xlarge"
    hpc7a_48xlarge = "hpc7a.48xlarge"
    hpc7a_96xlarge = "hpc7a.96xlarge"
    c7gd_medium = "c7gd.medium"
    c7gd_large = "c7gd.large"
    c7gd_xlarge = "c7gd.xlarge"
    c7gd_2xlarge = "c7gd.2xlarge"
    c7gd_4xlarge = "c7gd.4xlarge"
    c7gd_8xlarge = "c7gd.8xlarge"
    c7gd_12xlarge = "c7gd.12xlarge"
    c7gd_16xlarge = "c7gd.16xlarge"
    m7gd_medium = "m7gd.medium"
    m7gd_large = "m7gd.large"
    m7gd_xlarge = "m7gd.xlarge"
    m7gd_2xlarge = "m7gd.2xlarge"
    m7gd_4xlarge = "m7gd.4xlarge"
    m7gd_8xlarge = "m7gd.8xlarge"
    m7gd_12xlarge = "m7gd.12xlarge"
    m7gd_16xlarge = "m7gd.16xlarge"
    r7gd_medium = "r7gd.medium"
    r7gd_large = "r7gd.large"
    r7gd_xlarge = "r7gd.xlarge"
    r7gd_2xlarge = "r7gd.2xlarge"
    r7gd_4xlarge = "r7gd.4xlarge"
    r7gd_8xlarge = "r7gd.8xlarge"
    r7gd_12xlarge = "r7gd.12xlarge"
    r7gd_16xlarge = "r7gd.16xlarge"
    r7a_medium = "r7a.medium"
    r7a_large = "r7a.large"
    r7a_xlarge = "r7a.xlarge"
    r7a_2xlarge = "r7a.2xlarge"
    r7a_4xlarge = "r7a.4xlarge"
    r7a_8xlarge = "r7a.8xlarge"
    r7a_12xlarge = "r7a.12xlarge"
    r7a_16xlarge = "r7a.16xlarge"
    r7a_24xlarge = "r7a.24xlarge"
    r7a_32xlarge = "r7a.32xlarge"
    r7a_48xlarge = "r7a.48xlarge"
    c7i_large = "c7i.large"
    c7i_xlarge = "c7i.xlarge"
    c7i_2xlarge = "c7i.2xlarge"
    c7i_4xlarge = "c7i.4xlarge"
    c7i_8xlarge = "c7i.8xlarge"
    c7i_12xlarge = "c7i.12xlarge"
    c7i_16xlarge = "c7i.16xlarge"
    c7i_24xlarge = "c7i.24xlarge"
    c7i_48xlarge = "c7i.48xlarge"
    mac2_m2pro_metal = "mac2-m2pro.metal"
    r7iz_large = "r7iz.large"
    r7iz_xlarge = "r7iz.xlarge"
    r7iz_2xlarge = "r7iz.2xlarge"
    r7iz_4xlarge = "r7iz.4xlarge"
    r7iz_8xlarge = "r7iz.8xlarge"
    r7iz_12xlarge = "r7iz.12xlarge"
    r7iz_16xlarge = "r7iz.16xlarge"
    r7iz_32xlarge = "r7iz.32xlarge"
    c7a_medium = "c7a.medium"
    c7a_large = "c7a.large"
    c7a_xlarge = "c7a.xlarge"
    c7a_2xlarge = "c7a.2xlarge"
    c7a_4xlarge = "c7a.4xlarge"
    c7a_8xlarge = "c7a.8xlarge"
    c7a_12xlarge = "c7a.12xlarge"
    c7a_16xlarge = "c7a.16xlarge"
    c7a_24xlarge = "c7a.24xlarge"
    c7a_32xlarge = "c7a.32xlarge"
    c7a_48xlarge = "c7a.48xlarge"
    c7a_metal_48xl = "c7a.metal-48xl"
    r7a_metal_48xl = "r7a.metal-48xl"
    r7i_large = "r7i.large"
    r7i_xlarge = "r7i.xlarge"
    r7i_2xlarge = "r7i.2xlarge"
    r7i_4xlarge = "r7i.4xlarge"
    r7i_8xlarge = "r7i.8xlarge"
    r7i_12xlarge = "r7i.12xlarge"
    r7i_16xlarge = "r7i.16xlarge"
    r7i_24xlarge = "r7i.24xlarge"
    r7i_48xlarge = "r7i.48xlarge"
    dl2q_24xlarge = "dl2q.24xlarge"
    mac2_m2_metal = "mac2-m2.metal"
    i4i_12xlarge = "i4i.12xlarge"
    i4i_24xlarge = "i4i.24xlarge"
    c7i_metal_24xl = "c7i.metal-24xl"
    c7i_metal_48xl = "c7i.metal-48xl"
    m7i_metal_24xl = "m7i.metal-24xl"
    m7i_metal_48xl = "m7i.metal-48xl"
    r7i_metal_24xl = "r7i.metal-24xl"
    r7i_metal_48xl = "r7i.metal-48xl"
    r7iz_metal_16xl = "r7iz.metal-16xl"
    r7iz_metal_32xl = "r7iz.metal-32xl"
    c7gd_metal = "c7gd.metal"
    m7gd_metal = "m7gd.metal"
    r7gd_metal = "r7gd.metal"
    g6_xlarge = "g6.xlarge"
    g6_2xlarge = "g6.2xlarge"
    g6_4xlarge = "g6.4xlarge"
    g6_8xlarge = "g6.8xlarge"
    g6_12xlarge = "g6.12xlarge"
    g6_16xlarge = "g6.16xlarge"
    g6_24xlarge = "g6.24xlarge"
    g6_48xlarge = "g6.48xlarge"
    gr6_4xlarge = "gr6.4xlarge"
    gr6_8xlarge = "gr6.8xlarge"
    c7i_flex_large = "c7i-flex.large"
    c7i_flex_xlarge = "c7i-flex.xlarge"
    c7i_flex_2xlarge = "c7i-flex.2xlarge"
    c7i_flex_4xlarge = "c7i-flex.4xlarge"
    c7i_flex_8xlarge = "c7i-flex.8xlarge"
    u7i_12tb_224xlarge = "u7i-12tb.224xlarge"
    u7in_16tb_224xlarge = "u7in-16tb.224xlarge"
    u7in_24tb_224xlarge = "u7in-24tb.224xlarge"
    u7in_32tb_224xlarge = "u7in-32tb.224xlarge"
    u7ib_12tb_224xlarge = "u7ib-12tb.224xlarge"
    c7gn_metal = "c7gn.metal"
    r8g_medium = "r8g.medium"
    r8g_large = "r8g.large"
    r8g_xlarge = "r8g.xlarge"
    r8g_2xlarge = "r8g.2xlarge"
    r8g_4xlarge = "r8g.4xlarge"
    r8g_8xlarge = "r8g.8xlarge"
    r8g_12xlarge = "r8g.12xlarge"
    r8g_16xlarge = "r8g.16xlarge"
    r8g_24xlarge = "r8g.24xlarge"
    r8g_48xlarge = "r8g.48xlarge"
    r8g_metal_24xl = "r8g.metal-24xl"
    r8g_metal_48xl = "r8g.metal-48xl"
    mac2_m1ultra_metal = "mac2-m1ultra.metal"
    g6e_xlarge = "g6e.xlarge"
    g6e_2xlarge = "g6e.2xlarge"
    g6e_4xlarge = "g6e.4xlarge"
    g6e_8xlarge = "g6e.8xlarge"
    g6e_12xlarge = "g6e.12xlarge"
    g6e_16xlarge = "g6e.16xlarge"
    g6e_24xlarge = "g6e.24xlarge"
    g6e_48xlarge = "g6e.48xlarge"
    c8g_medium = "c8g.medium"
    c8g_large = "c8g.large"
    c8g_xlarge = "c8g.xlarge"
    c8g_2xlarge = "c8g.2xlarge"
    c8g_4xlarge = "c8g.4xlarge"
    c8g_8xlarge = "c8g.8xlarge"
    c8g_12xlarge = "c8g.12xlarge"
    c8g_16xlarge = "c8g.16xlarge"
    c8g_24xlarge = "c8g.24xlarge"
    c8g_48xlarge = "c8g.48xlarge"
    c8g_metal_24xl = "c8g.metal-24xl"
    c8g_metal_48xl = "c8g.metal-48xl"
    m8g_medium = "m8g.medium"
    m8g_large = "m8g.large"
    m8g_xlarge = "m8g.xlarge"
    m8g_2xlarge = "m8g.2xlarge"
    m8g_4xlarge = "m8g.4xlarge"
    m8g_8xlarge = "m8g.8xlarge"
    m8g_12xlarge = "m8g.12xlarge"
    m8g_16xlarge = "m8g.16xlarge"
    m8g_24xlarge = "m8g.24xlarge"
    m8g_48xlarge = "m8g.48xlarge"
    m8g_metal_24xl = "m8g.metal-24xl"
    m8g_metal_48xl = "m8g.metal-48xl"
    x8g_medium = "x8g.medium"
    x8g_large = "x8g.large"
    x8g_xlarge = "x8g.xlarge"
    x8g_2xlarge = "x8g.2xlarge"
    x8g_4xlarge = "x8g.4xlarge"
    x8g_8xlarge = "x8g.8xlarge"
    x8g_12xlarge = "x8g.12xlarge"
    x8g_16xlarge = "x8g.16xlarge"
    x8g_24xlarge = "x8g.24xlarge"
    x8g_48xlarge = "x8g.48xlarge"
    x8g_metal_24xl = "x8g.metal-24xl"
    x8g_metal_48xl = "x8g.metal-48xl"


class InstanceTypeHypervisor(StrEnum):
    nitro = "nitro"
    xen = "xen"


class InterfacePermissionType(StrEnum):
    INSTANCE_ATTACH = "INSTANCE-ATTACH"
    EIP_ASSOCIATE = "EIP-ASSOCIATE"


class InterfaceProtocolType(StrEnum):
    VLAN = "VLAN"
    GRE = "GRE"


class IpAddressType(StrEnum):
    ipv4 = "ipv4"
    dualstack = "dualstack"
    ipv6 = "ipv6"


class IpSource(StrEnum):
    amazon = "amazon"
    byoip = "byoip"
    none = "none"


class IpamAddressHistoryResourceType(StrEnum):
    eip = "eip"
    vpc = "vpc"
    subnet = "subnet"
    network_interface = "network-interface"
    instance = "instance"


class IpamAssociatedResourceDiscoveryStatus(StrEnum):
    active = "active"
    not_found = "not-found"


class IpamComplianceStatus(StrEnum):
    compliant = "compliant"
    noncompliant = "noncompliant"
    unmanaged = "unmanaged"
    ignored = "ignored"


class IpamDiscoveryFailureCode(StrEnum):
    assume_role_failure = "assume-role-failure"
    throttling_failure = "throttling-failure"
    unauthorized_failure = "unauthorized-failure"


class IpamExternalResourceVerificationTokenState(StrEnum):
    create_in_progress = "create-in-progress"
    create_complete = "create-complete"
    create_failed = "create-failed"
    delete_in_progress = "delete-in-progress"
    delete_complete = "delete-complete"
    delete_failed = "delete-failed"


class IpamManagementState(StrEnum):
    managed = "managed"
    unmanaged = "unmanaged"
    ignored = "ignored"


class IpamNetworkInterfaceAttachmentStatus(StrEnum):
    available = "available"
    in_use = "in-use"


class IpamOverlapStatus(StrEnum):
    overlapping = "overlapping"
    nonoverlapping = "nonoverlapping"
    ignored = "ignored"


class IpamPoolAllocationResourceType(StrEnum):
    ipam_pool = "ipam-pool"
    vpc = "vpc"
    ec2_public_ipv4_pool = "ec2-public-ipv4-pool"
    custom = "custom"
    subnet = "subnet"
    eip = "eip"


class IpamPoolAwsService(StrEnum):
    ec2 = "ec2"


class IpamPoolCidrFailureCode(StrEnum):
    cidr_not_available = "cidr-not-available"
    limit_exceeded = "limit-exceeded"


class IpamPoolCidrState(StrEnum):
    pending_provision = "pending-provision"
    provisioned = "provisioned"
    failed_provision = "failed-provision"
    pending_deprovision = "pending-deprovision"
    deprovisioned = "deprovisioned"
    failed_deprovision = "failed-deprovision"
    pending_import = "pending-import"
    failed_import = "failed-import"


class IpamPoolPublicIpSource(StrEnum):
    amazon = "amazon"
    byoip = "byoip"


class IpamPoolSourceResourceType(StrEnum):
    vpc = "vpc"


class IpamPoolState(StrEnum):
    create_in_progress = "create-in-progress"
    create_complete = "create-complete"
    create_failed = "create-failed"
    modify_in_progress = "modify-in-progress"
    modify_complete = "modify-complete"
    modify_failed = "modify-failed"
    delete_in_progress = "delete-in-progress"
    delete_complete = "delete-complete"
    delete_failed = "delete-failed"
    isolate_in_progress = "isolate-in-progress"
    isolate_complete = "isolate-complete"
    restore_in_progress = "restore-in-progress"


class IpamPublicAddressAssociationStatus(StrEnum):
    associated = "associated"
    disassociated = "disassociated"


class IpamPublicAddressAwsService(StrEnum):
    nat_gateway = "nat-gateway"
    database_migration_service = "database-migration-service"
    redshift = "redshift"
    elastic_container_service = "elastic-container-service"
    relational_database_service = "relational-database-service"
    site_to_site_vpn = "site-to-site-vpn"
    load_balancer = "load-balancer"
    global_accelerator = "global-accelerator"
    other = "other"


class IpamPublicAddressType(StrEnum):
    service_managed_ip = "service-managed-ip"
    service_managed_byoip = "service-managed-byoip"
    amazon_owned_eip = "amazon-owned-eip"
    amazon_owned_contig = "amazon-owned-contig"
    byoip = "byoip"
    ec2_public_ip = "ec2-public-ip"


class IpamResourceCidrIpSource(StrEnum):
    amazon = "amazon"
    byoip = "byoip"
    none = "none"


class IpamResourceDiscoveryAssociationState(StrEnum):
    associate_in_progress = "associate-in-progress"
    associate_complete = "associate-complete"
    associate_failed = "associate-failed"
    disassociate_in_progress = "disassociate-in-progress"
    disassociate_complete = "disassociate-complete"
    disassociate_failed = "disassociate-failed"
    isolate_in_progress = "isolate-in-progress"
    isolate_complete = "isolate-complete"
    restore_in_progress = "restore-in-progress"


class IpamResourceDiscoveryState(StrEnum):
    create_in_progress = "create-in-progress"
    create_complete = "create-complete"
    create_failed = "create-failed"
    modify_in_progress = "modify-in-progress"
    modify_complete = "modify-complete"
    modify_failed = "modify-failed"
    delete_in_progress = "delete-in-progress"
    delete_complete = "delete-complete"
    delete_failed = "delete-failed"
    isolate_in_progress = "isolate-in-progress"
    isolate_complete = "isolate-complete"
    restore_in_progress = "restore-in-progress"


class IpamResourceType(StrEnum):
    vpc = "vpc"
    subnet = "subnet"
    eip = "eip"
    public_ipv4_pool = "public-ipv4-pool"
    ipv6_pool = "ipv6-pool"
    eni = "eni"


class IpamScopeState(StrEnum):
    create_in_progress = "create-in-progress"
    create_complete = "create-complete"
    create_failed = "create-failed"
    modify_in_progress = "modify-in-progress"
    modify_complete = "modify-complete"
    modify_failed = "modify-failed"
    delete_in_progress = "delete-in-progress"
    delete_complete = "delete-complete"
    delete_failed = "delete-failed"
    isolate_in_progress = "isolate-in-progress"
    isolate_complete = "isolate-complete"
    restore_in_progress = "restore-in-progress"


class IpamScopeType(StrEnum):
    public = "public"
    private = "private"


class IpamState(StrEnum):
    create_in_progress = "create-in-progress"
    create_complete = "create-complete"
    create_failed = "create-failed"
    modify_in_progress = "modify-in-progress"
    modify_complete = "modify-complete"
    modify_failed = "modify-failed"
    delete_in_progress = "delete-in-progress"
    delete_complete = "delete-complete"
    delete_failed = "delete-failed"
    isolate_in_progress = "isolate-in-progress"
    isolate_complete = "isolate-complete"
    restore_in_progress = "restore-in-progress"


class IpamTier(StrEnum):
    free = "free"
    advanced = "advanced"


class Ipv6AddressAttribute(StrEnum):
    public = "public"
    private = "private"


class Ipv6SupportValue(StrEnum):
    enable = "enable"
    disable = "disable"


class KeyFormat(StrEnum):
    pem = "pem"
    ppk = "ppk"


class KeyType(StrEnum):
    rsa = "rsa"
    ed25519 = "ed25519"


class LaunchTemplateAutoRecoveryState(StrEnum):
    default = "default"
    disabled = "disabled"


class LaunchTemplateErrorCode(StrEnum):
    launchTemplateIdDoesNotExist = "launchTemplateIdDoesNotExist"
    launchTemplateIdMalformed = "launchTemplateIdMalformed"
    launchTemplateNameDoesNotExist = "launchTemplateNameDoesNotExist"
    launchTemplateNameMalformed = "launchTemplateNameMalformed"
    launchTemplateVersionDoesNotExist = "launchTemplateVersionDoesNotExist"
    unexpectedError = "unexpectedError"


class LaunchTemplateHttpTokensState(StrEnum):
    optional = "optional"
    required = "required"


class LaunchTemplateInstanceMetadataEndpointState(StrEnum):
    disabled = "disabled"
    enabled = "enabled"


class LaunchTemplateInstanceMetadataOptionsState(StrEnum):
    pending = "pending"
    applied = "applied"


class LaunchTemplateInstanceMetadataProtocolIpv6(StrEnum):
    disabled = "disabled"
    enabled = "enabled"


class LaunchTemplateInstanceMetadataTagsState(StrEnum):
    disabled = "disabled"
    enabled = "enabled"


class ListingState(StrEnum):
    available = "available"
    sold = "sold"
    cancelled = "cancelled"
    pending = "pending"


class ListingStatus(StrEnum):
    active = "active"
    pending = "pending"
    cancelled = "cancelled"
    closed = "closed"


class LocalGatewayRouteState(StrEnum):
    pending = "pending"
    active = "active"
    blackhole = "blackhole"
    deleting = "deleting"
    deleted = "deleted"


class LocalGatewayRouteTableMode(StrEnum):
    direct_vpc_routing = "direct-vpc-routing"
    coip = "coip"


class LocalGatewayRouteType(StrEnum):
    static = "static"
    propagated = "propagated"


class LocalStorage(StrEnum):
    included = "included"
    required = "required"
    excluded = "excluded"


class LocalStorageType(StrEnum):
    hdd = "hdd"
    ssd = "ssd"


class LocationType(StrEnum):
    region = "region"
    availability_zone = "availability-zone"
    availability_zone_id = "availability-zone-id"
    outpost = "outpost"


class LockMode(StrEnum):
    compliance = "compliance"
    governance = "governance"


class LockState(StrEnum):
    compliance = "compliance"
    governance = "governance"
    compliance_cooloff = "compliance-cooloff"
    expired = "expired"


class LogDestinationType(StrEnum):
    cloud_watch_logs = "cloud-watch-logs"
    s3 = "s3"
    kinesis_data_firehose = "kinesis-data-firehose"


class MarketType(StrEnum):
    spot = "spot"
    capacity_block = "capacity-block"


class MembershipType(StrEnum):
    static = "static"
    igmp = "igmp"


class MetadataDefaultHttpTokensState(StrEnum):
    optional = "optional"
    required = "required"
    no_preference = "no-preference"


class MetricType(StrEnum):
    aggregate_latency = "aggregate-latency"


class ModifyAvailabilityZoneOptInStatus(StrEnum):
    opted_in = "opted-in"
    not_opted_in = "not-opted-in"


class MonitoringState(StrEnum):
    disabled = "disabled"
    disabling = "disabling"
    enabled = "enabled"
    pending = "pending"


class MoveStatus(StrEnum):
    movingToVpc = "movingToVpc"
    restoringToClassic = "restoringToClassic"


class MulticastSupportValue(StrEnum):
    enable = "enable"
    disable = "disable"


class NatGatewayAddressStatus(StrEnum):
    assigning = "assigning"
    unassigning = "unassigning"
    associating = "associating"
    disassociating = "disassociating"
    succeeded = "succeeded"
    failed = "failed"


class NatGatewayState(StrEnum):
    pending = "pending"
    failed = "failed"
    available = "available"
    deleting = "deleting"
    deleted = "deleted"


class NetworkInterfaceAttribute(StrEnum):
    description = "description"
    groupSet = "groupSet"
    sourceDestCheck = "sourceDestCheck"
    attachment = "attachment"
    associatePublicIpAddress = "associatePublicIpAddress"


class NetworkInterfaceCreationType(StrEnum):
    efa = "efa"
    efa_only = "efa-only"
    branch = "branch"
    trunk = "trunk"


class NetworkInterfacePermissionStateCode(StrEnum):
    pending = "pending"
    granted = "granted"
    revoking = "revoking"
    revoked = "revoked"


class NetworkInterfaceStatus(StrEnum):
    available = "available"
    associated = "associated"
    attaching = "attaching"
    in_use = "in-use"
    detaching = "detaching"


class NetworkInterfaceType(StrEnum):
    interface = "interface"
    natGateway = "natGateway"
    efa = "efa"
    efa_only = "efa-only"
    trunk = "trunk"
    load_balancer = "load_balancer"
    network_load_balancer = "network_load_balancer"
    vpc_endpoint = "vpc_endpoint"
    branch = "branch"
    transit_gateway = "transit_gateway"
    lambda_ = "lambda"
    quicksight = "quicksight"
    global_accelerator_managed = "global_accelerator_managed"
    api_gateway_managed = "api_gateway_managed"
    gateway_load_balancer = "gateway_load_balancer"
    gateway_load_balancer_endpoint = "gateway_load_balancer_endpoint"
    iot_rules_managed = "iot_rules_managed"
    aws_codestar_connections_managed = "aws_codestar_connections_managed"


class NitroEnclavesSupport(StrEnum):
    unsupported = "unsupported"
    supported = "supported"


class NitroTpmSupport(StrEnum):
    unsupported = "unsupported"
    supported = "supported"


class OfferingClassType(StrEnum):
    standard = "standard"
    convertible = "convertible"


class OfferingTypeValues(StrEnum):
    Heavy_Utilization = "Heavy Utilization"
    Medium_Utilization = "Medium Utilization"
    Light_Utilization = "Light Utilization"
    No_Upfront = "No Upfront"
    Partial_Upfront = "Partial Upfront"
    All_Upfront = "All Upfront"


class OnDemandAllocationStrategy(StrEnum):
    lowestPrice = "lowestPrice"
    prioritized = "prioritized"


class OperationType(StrEnum):
    add = "add"
    remove = "remove"


class PartitionLoadFrequency(StrEnum):
    none = "none"
    daily = "daily"
    weekly = "weekly"
    monthly = "monthly"


class PayerResponsibility(StrEnum):
    ServiceOwner = "ServiceOwner"


class PaymentOption(StrEnum):
    AllUpfront = "AllUpfront"
    PartialUpfront = "PartialUpfront"
    NoUpfront = "NoUpfront"


class PeriodType(StrEnum):
    five_minutes = "five-minutes"
    fifteen_minutes = "fifteen-minutes"
    one_hour = "one-hour"
    three_hours = "three-hours"
    one_day = "one-day"
    one_week = "one-week"


class PermissionGroup(StrEnum):
    all = "all"


class PhcSupport(StrEnum):
    unsupported = "unsupported"
    supported = "supported"


class PlacementGroupState(StrEnum):
    pending = "pending"
    available = "available"
    deleting = "deleting"
    deleted = "deleted"


class PlacementGroupStrategy(StrEnum):
    cluster = "cluster"
    partition = "partition"
    spread = "spread"


class PlacementStrategy(StrEnum):
    cluster = "cluster"
    spread = "spread"
    partition = "partition"


class PlatformValues(StrEnum):
    Windows = "Windows"


class PrefixListState(StrEnum):
    create_in_progress = "create-in-progress"
    create_complete = "create-complete"
    create_failed = "create-failed"
    modify_in_progress = "modify-in-progress"
    modify_complete = "modify-complete"
    modify_failed = "modify-failed"
    restore_in_progress = "restore-in-progress"
    restore_complete = "restore-complete"
    restore_failed = "restore-failed"
    delete_in_progress = "delete-in-progress"
    delete_complete = "delete-complete"
    delete_failed = "delete-failed"


class PrincipalType(StrEnum):
    All = "All"
    Service = "Service"
    OrganizationUnit = "OrganizationUnit"
    Account = "Account"
    User = "User"
    Role = "Role"


class ProductCodeValues(StrEnum):
    devpay = "devpay"
    marketplace = "marketplace"


class Protocol(StrEnum):
    tcp = "tcp"
    udp = "udp"


class ProtocolValue(StrEnum):
    gre = "gre"


class RIProductDescription(StrEnum):
    Linux_UNIX = "Linux/UNIX"
    Linux_UNIX_Amazon_VPC_ = "Linux/UNIX (Amazon VPC)"
    Windows = "Windows"
    Windows_Amazon_VPC_ = "Windows (Amazon VPC)"


class RecurringChargeFrequency(StrEnum):
    Hourly = "Hourly"


class ReplaceRootVolumeTaskState(StrEnum):
    pending = "pending"
    in_progress = "in-progress"
    failing = "failing"
    succeeded = "succeeded"
    failed = "failed"
    failed_detached = "failed-detached"


class ReplacementStrategy(StrEnum):
    launch = "launch"
    launch_before_terminate = "launch-before-terminate"


class ReportInstanceReasonCodes(StrEnum):
    instance_stuck_in_state = "instance-stuck-in-state"
    unresponsive = "unresponsive"
    not_accepting_credentials = "not-accepting-credentials"
    password_not_available = "password-not-available"
    performance_network = "performance-network"
    performance_instance_store = "performance-instance-store"
    performance_ebs_volume = "performance-ebs-volume"
    performance_other = "performance-other"
    other = "other"


class ReportStatusType(StrEnum):
    ok = "ok"
    impaired = "impaired"


class ReservationState(StrEnum):
    payment_pending = "payment-pending"
    payment_failed = "payment-failed"
    active = "active"
    retired = "retired"


class ReservedInstanceState(StrEnum):
    payment_pending = "payment-pending"
    active = "active"
    payment_failed = "payment-failed"
    retired = "retired"
    queued = "queued"
    queued_deleted = "queued-deleted"


class ResetFpgaImageAttributeName(StrEnum):
    loadPermission = "loadPermission"


class ResetImageAttributeName(StrEnum):
    launchPermission = "launchPermission"


class ResourceType(StrEnum):
    capacity_reservation = "capacity-reservation"
    client_vpn_endpoint = "client-vpn-endpoint"
    customer_gateway = "customer-gateway"
    carrier_gateway = "carrier-gateway"
    coip_pool = "coip-pool"
    dedicated_host = "dedicated-host"
    dhcp_options = "dhcp-options"
    egress_only_internet_gateway = "egress-only-internet-gateway"
    elastic_ip = "elastic-ip"
    elastic_gpu = "elastic-gpu"
    export_image_task = "export-image-task"
    export_instance_task = "export-instance-task"
    fleet = "fleet"
    fpga_image = "fpga-image"
    host_reservation = "host-reservation"
    image = "image"
    import_image_task = "import-image-task"
    import_snapshot_task = "import-snapshot-task"
    instance = "instance"
    instance_event_window = "instance-event-window"
    internet_gateway = "internet-gateway"
    ipam = "ipam"
    ipam_pool = "ipam-pool"
    ipam_scope = "ipam-scope"
    ipv4pool_ec2 = "ipv4pool-ec2"
    ipv6pool_ec2 = "ipv6pool-ec2"
    key_pair = "key-pair"
    launch_template = "launch-template"
    local_gateway = "local-gateway"
    local_gateway_route_table = "local-gateway-route-table"
    local_gateway_virtual_interface = "local-gateway-virtual-interface"
    local_gateway_virtual_interface_group = "local-gateway-virtual-interface-group"
    local_gateway_route_table_vpc_association = "local-gateway-route-table-vpc-association"
    local_gateway_route_table_virtual_interface_group_association = (
        "local-gateway-route-table-virtual-interface-group-association"
    )
    natgateway = "natgateway"
    network_acl = "network-acl"
    network_interface = "network-interface"
    network_insights_analysis = "network-insights-analysis"
    network_insights_path = "network-insights-path"
    network_insights_access_scope = "network-insights-access-scope"
    network_insights_access_scope_analysis = "network-insights-access-scope-analysis"
    placement_group = "placement-group"
    prefix_list = "prefix-list"
    replace_root_volume_task = "replace-root-volume-task"
    reserved_instances = "reserved-instances"
    route_table = "route-table"
    security_group = "security-group"
    security_group_rule = "security-group-rule"
    snapshot = "snapshot"
    spot_fleet_request = "spot-fleet-request"
    spot_instances_request = "spot-instances-request"
    subnet = "subnet"
    subnet_cidr_reservation = "subnet-cidr-reservation"
    traffic_mirror_filter = "traffic-mirror-filter"
    traffic_mirror_session = "traffic-mirror-session"
    traffic_mirror_target = "traffic-mirror-target"
    transit_gateway = "transit-gateway"
    transit_gateway_attachment = "transit-gateway-attachment"
    transit_gateway_connect_peer = "transit-gateway-connect-peer"
    transit_gateway_multicast_domain = "transit-gateway-multicast-domain"
    transit_gateway_policy_table = "transit-gateway-policy-table"
    transit_gateway_route_table = "transit-gateway-route-table"
    transit_gateway_route_table_announcement = "transit-gateway-route-table-announcement"
    volume = "volume"
    vpc = "vpc"
    vpc_endpoint = "vpc-endpoint"
    vpc_endpoint_connection = "vpc-endpoint-connection"
    vpc_endpoint_service = "vpc-endpoint-service"
    vpc_endpoint_service_permission = "vpc-endpoint-service-permission"
    vpc_peering_connection = "vpc-peering-connection"
    vpn_connection = "vpn-connection"
    vpn_gateway = "vpn-gateway"
    vpc_flow_log = "vpc-flow-log"
    capacity_reservation_fleet = "capacity-reservation-fleet"
    traffic_mirror_filter_rule = "traffic-mirror-filter-rule"
    vpc_endpoint_connection_device_type = "vpc-endpoint-connection-device-type"
    verified_access_instance = "verified-access-instance"
    verified_access_group = "verified-access-group"
    verified_access_endpoint = "verified-access-endpoint"
    verified_access_policy = "verified-access-policy"
    verified_access_trust_provider = "verified-access-trust-provider"
    vpn_connection_device_type = "vpn-connection-device-type"
    vpc_block_public_access_exclusion = "vpc-block-public-access-exclusion"
    ipam_resource_discovery = "ipam-resource-discovery"
    ipam_resource_discovery_association = "ipam-resource-discovery-association"
    instance_connect_endpoint = "instance-connect-endpoint"
    ipam_external_resource_verification_token = "ipam-external-resource-verification-token"


class RootDeviceType(StrEnum):
    ebs = "ebs"
    instance_store = "instance-store"


class RouteOrigin(StrEnum):
    CreateRouteTable = "CreateRouteTable"
    CreateRoute = "CreateRoute"
    EnableVgwRoutePropagation = "EnableVgwRoutePropagation"


class RouteState(StrEnum):
    active = "active"
    blackhole = "blackhole"


class RouteTableAssociationStateCode(StrEnum):
    associating = "associating"
    associated = "associated"
    disassociating = "disassociating"
    disassociated = "disassociated"
    failed = "failed"


class RuleAction(StrEnum):
    allow = "allow"
    deny = "deny"


class SSEType(StrEnum):
    sse_ebs = "sse-ebs"
    sse_kms = "sse-kms"
    none = "none"


class SecurityGroupReferencingSupportValue(StrEnum):
    enable = "enable"
    disable = "disable"


class SecurityGroupVpcAssociationState(StrEnum):
    associating = "associating"
    associated = "associated"
    association_failed = "association-failed"
    disassociating = "disassociating"
    disassociated = "disassociated"
    disassociation_failed = "disassociation-failed"


class SelfServicePortal(StrEnum):
    enabled = "enabled"
    disabled = "disabled"


class ServiceConnectivityType(StrEnum):
    ipv4 = "ipv4"
    ipv6 = "ipv6"


class ServiceState(StrEnum):
    Pending = "Pending"
    Available = "Available"
    Deleting = "Deleting"
    Deleted = "Deleted"
    Failed = "Failed"


class ServiceType(StrEnum):
    Interface = "Interface"
    Gateway = "Gateway"
    GatewayLoadBalancer = "GatewayLoadBalancer"


class ShutdownBehavior(StrEnum):
    stop = "stop"
    terminate = "terminate"


class SnapshotAttributeName(StrEnum):
    productCodes = "productCodes"
    createVolumePermission = "createVolumePermission"


class SnapshotBlockPublicAccessState(StrEnum):
    block_all_sharing = "block-all-sharing"
    block_new_sharing = "block-new-sharing"
    unblocked = "unblocked"


class SnapshotState(StrEnum):
    pending = "pending"
    completed = "completed"
    error = "error"
    recoverable = "recoverable"
    recovering = "recovering"


class SpotAllocationStrategy(StrEnum):
    lowest_price = "lowest-price"
    diversified = "diversified"
    capacity_optimized = "capacity-optimized"
    capacity_optimized_prioritized = "capacity-optimized-prioritized"
    price_capacity_optimized = "price-capacity-optimized"


class SpotInstanceInterruptionBehavior(StrEnum):
    hibernate = "hibernate"
    stop = "stop"
    terminate = "terminate"


class SpotInstanceState(StrEnum):
    open = "open"
    active = "active"
    closed = "closed"
    cancelled = "cancelled"
    failed = "failed"
    disabled = "disabled"


class SpotInstanceType(StrEnum):
    one_time = "one-time"
    persistent = "persistent"


class SpreadLevel(StrEnum):
    host = "host"
    rack = "rack"


class State(StrEnum):
    PendingAcceptance = "PendingAcceptance"
    Pending = "Pending"
    Available = "Available"
    Deleting = "Deleting"
    Deleted = "Deleted"
    Rejected = "Rejected"
    Failed = "Failed"
    Expired = "Expired"


class StaticSourcesSupportValue(StrEnum):
    enable = "enable"
    disable = "disable"


class StatisticType(StrEnum):
    p50 = "p50"


class Status(StrEnum):
    MoveInProgress = "MoveInProgress"
    InVpc = "InVpc"
    InClassic = "InClassic"


class StatusName(StrEnum):
    reachability = "reachability"


class StatusType(StrEnum):
    passed = "passed"
    failed = "failed"
    insufficient_data = "insufficient-data"
    initializing = "initializing"


class StorageTier(StrEnum):
    archive = "archive"
    standard = "standard"


class SubnetCidrBlockStateCode(StrEnum):
    associating = "associating"
    associated = "associated"
    disassociating = "disassociating"
    disassociated = "disassociated"
    failing = "failing"
    failed = "failed"


class SubnetCidrReservationType(StrEnum):
    prefix = "prefix"
    explicit = "explicit"


class SubnetState(StrEnum):
    pending = "pending"
    available = "available"
    unavailable = "unavailable"


class SummaryStatus(StrEnum):
    ok = "ok"
    impaired = "impaired"
    insufficient_data = "insufficient-data"
    not_applicable = "not-applicable"
    initializing = "initializing"


class SupportedAdditionalProcessorFeature(StrEnum):
    amd_sev_snp = "amd-sev-snp"


class TargetCapacityUnitType(StrEnum):
    vcpu = "vcpu"
    memory_mib = "memory-mib"
    units = "units"


class TargetStorageTier(StrEnum):
    archive = "archive"


class TelemetryStatus(StrEnum):
    UP = "UP"
    DOWN = "DOWN"


class Tenancy(StrEnum):
    default = "default"
    dedicated = "dedicated"
    host = "host"


class TieringOperationStatus(StrEnum):
    archival_in_progress = "archival-in-progress"
    archival_completed = "archival-completed"
    archival_failed = "archival-failed"
    temporary_restore_in_progress = "temporary-restore-in-progress"
    temporary_restore_completed = "temporary-restore-completed"
    temporary_restore_failed = "temporary-restore-failed"
    permanent_restore_in_progress = "permanent-restore-in-progress"
    permanent_restore_completed = "permanent-restore-completed"
    permanent_restore_failed = "permanent-restore-failed"


class TokenState(StrEnum):
    valid = "valid"
    expired = "expired"


class TpmSupportValues(StrEnum):
    v2_0 = "v2.0"


class TrafficDirection(StrEnum):
    ingress = "ingress"
    egress = "egress"


class TrafficMirrorFilterRuleField(StrEnum):
    destination_port_range = "destination-port-range"
    source_port_range = "source-port-range"
    protocol = "protocol"
    description = "description"


class TrafficMirrorNetworkService(StrEnum):
    amazon_dns = "amazon-dns"


class TrafficMirrorRuleAction(StrEnum):
    accept = "accept"
    reject = "reject"


class TrafficMirrorSessionField(StrEnum):
    packet_length = "packet-length"
    description = "description"
    virtual_network_id = "virtual-network-id"


class TrafficMirrorTargetType(StrEnum):
    network_interface = "network-interface"
    network_load_balancer = "network-load-balancer"
    gateway_load_balancer_endpoint = "gateway-load-balancer-endpoint"


class TrafficType(StrEnum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    ALL = "ALL"


class TransitGatewayAssociationState(StrEnum):
    associating = "associating"
    associated = "associated"
    disassociating = "disassociating"
    disassociated = "disassociated"


class TransitGatewayAttachmentResourceType(StrEnum):
    vpc = "vpc"
    vpn = "vpn"
    direct_connect_gateway = "direct-connect-gateway"
    connect = "connect"
    peering = "peering"
    tgw_peering = "tgw-peering"


class TransitGatewayAttachmentState(StrEnum):
    initiating = "initiating"
    initiatingRequest = "initiatingRequest"
    pendingAcceptance = "pendingAcceptance"
    rollingBack = "rollingBack"
    pending = "pending"
    available = "available"
    modifying = "modifying"
    deleting = "deleting"
    deleted = "deleted"
    failed = "failed"
    rejected = "rejected"
    rejecting = "rejecting"
    failing = "failing"


class TransitGatewayConnectPeerState(StrEnum):
    pending = "pending"
    available = "available"
    deleting = "deleting"
    deleted = "deleted"


class TransitGatewayMulitcastDomainAssociationState(StrEnum):
    pendingAcceptance = "pendingAcceptance"
    associating = "associating"
    associated = "associated"
    disassociating = "disassociating"
    disassociated = "disassociated"
    rejected = "rejected"
    failed = "failed"


class TransitGatewayMulticastDomainState(StrEnum):
    pending = "pending"
    available = "available"
    deleting = "deleting"
    deleted = "deleted"


class TransitGatewayPolicyTableState(StrEnum):
    pending = "pending"
    available = "available"
    deleting = "deleting"
    deleted = "deleted"


class TransitGatewayPrefixListReferenceState(StrEnum):
    pending = "pending"
    available = "available"
    modifying = "modifying"
    deleting = "deleting"


class TransitGatewayPropagationState(StrEnum):
    enabling = "enabling"
    enabled = "enabled"
    disabling = "disabling"
    disabled = "disabled"


class TransitGatewayRouteState(StrEnum):
    pending = "pending"
    active = "active"
    blackhole = "blackhole"
    deleting = "deleting"
    deleted = "deleted"


class TransitGatewayRouteTableAnnouncementDirection(StrEnum):
    outgoing = "outgoing"
    incoming = "incoming"


class TransitGatewayRouteTableAnnouncementState(StrEnum):
    available = "available"
    pending = "pending"
    failing = "failing"
    failed = "failed"
    deleting = "deleting"
    deleted = "deleted"


class TransitGatewayRouteTableState(StrEnum):
    pending = "pending"
    available = "available"
    deleting = "deleting"
    deleted = "deleted"


class TransitGatewayRouteType(StrEnum):
    static = "static"
    propagated = "propagated"


class TransitGatewayState(StrEnum):
    pending = "pending"
    available = "available"
    modifying = "modifying"
    deleting = "deleting"
    deleted = "deleted"


class TransportProtocol(StrEnum):
    tcp = "tcp"
    udp = "udp"


class TrustProviderType(StrEnum):
    user = "user"
    device = "device"


class TunnelInsideIpVersion(StrEnum):
    ipv4 = "ipv4"
    ipv6 = "ipv6"


class UnlimitedSupportedInstanceFamily(StrEnum):
    t2 = "t2"
    t3 = "t3"
    t3a = "t3a"
    t4g = "t4g"


class UnsuccessfulInstanceCreditSpecificationErrorCode(StrEnum):
    InvalidInstanceID_Malformed = "InvalidInstanceID.Malformed"
    InvalidInstanceID_NotFound = "InvalidInstanceID.NotFound"
    IncorrectInstanceState = "IncorrectInstanceState"
    InstanceCreditSpecification_NotSupported = "InstanceCreditSpecification.NotSupported"


class UsageClassType(StrEnum):
    spot = "spot"
    on_demand = "on-demand"
    capacity_block = "capacity-block"


class UserTrustProviderType(StrEnum):
    iam_identity_center = "iam-identity-center"
    oidc = "oidc"


class VerificationMethod(StrEnum):
    remarks_x509 = "remarks-x509"
    dns_token = "dns-token"


class VerifiedAccessEndpointAttachmentType(StrEnum):
    vpc = "vpc"


class VerifiedAccessEndpointProtocol(StrEnum):
    http = "http"
    https = "https"


class VerifiedAccessEndpointStatusCode(StrEnum):
    pending = "pending"
    active = "active"
    updating = "updating"
    deleting = "deleting"
    deleted = "deleted"


class VerifiedAccessEndpointType(StrEnum):
    load_balancer = "load-balancer"
    network_interface = "network-interface"


class VerifiedAccessLogDeliveryStatusCode(StrEnum):
    success = "success"
    failed = "failed"


class VirtualizationType(StrEnum):
    hvm = "hvm"
    paravirtual = "paravirtual"


class VolumeAttachmentState(StrEnum):
    attaching = "attaching"
    attached = "attached"
    detaching = "detaching"
    detached = "detached"
    busy = "busy"


class VolumeAttributeName(StrEnum):
    autoEnableIO = "autoEnableIO"
    productCodes = "productCodes"


class VolumeModificationState(StrEnum):
    modifying = "modifying"
    optimizing = "optimizing"
    completed = "completed"
    failed = "failed"


class VolumeState(StrEnum):
    creating = "creating"
    available = "available"
    in_use = "in-use"
    deleting = "deleting"
    deleted = "deleted"
    error = "error"


class VolumeStatusInfoStatus(StrEnum):
    ok = "ok"
    impaired = "impaired"
    insufficient_data = "insufficient-data"


class VolumeStatusName(StrEnum):
    io_enabled = "io-enabled"
    io_performance = "io-performance"


class VolumeType(StrEnum):
    standard = "standard"
    io1 = "io1"
    io2 = "io2"
    gp2 = "gp2"
    sc1 = "sc1"
    st1 = "st1"
    gp3 = "gp3"


class VpcAttributeName(StrEnum):
    enableDnsSupport = "enableDnsSupport"
    enableDnsHostnames = "enableDnsHostnames"
    enableNetworkAddressUsageMetrics = "enableNetworkAddressUsageMetrics"


class VpcCidrBlockStateCode(StrEnum):
    associating = "associating"
    associated = "associated"
    disassociating = "disassociating"
    disassociated = "disassociated"
    failing = "failing"
    failed = "failed"


class VpcEndpointType(StrEnum):
    Interface = "Interface"
    Gateway = "Gateway"
    GatewayLoadBalancer = "GatewayLoadBalancer"


class VpcPeeringConnectionStateReasonCode(StrEnum):
    initiating_request = "initiating-request"
    pending_acceptance = "pending-acceptance"
    active = "active"
    deleted = "deleted"
    rejected = "rejected"
    failed = "failed"
    expired = "expired"
    provisioning = "provisioning"
    deleting = "deleting"


class VpcState(StrEnum):
    pending = "pending"
    available = "available"


class VpcTenancy(StrEnum):
    default = "default"


class VpnEcmpSupportValue(StrEnum):
    enable = "enable"
    disable = "disable"


class VpnProtocol(StrEnum):
    openvpn = "openvpn"


class VpnState(StrEnum):
    pending = "pending"
    available = "available"
    deleting = "deleting"
    deleted = "deleted"


class VpnStaticRouteSource(StrEnum):
    Static = "Static"


class WeekDay(StrEnum):
    sunday = "sunday"
    monday = "monday"
    tuesday = "tuesday"
    wednesday = "wednesday"
    thursday = "thursday"
    friday = "friday"
    saturday = "saturday"


class scope(StrEnum):
    Availability_Zone = "Availability Zone"
    Region = "Region"


class AcceleratorCount(TypedDict, total=False):
    Min: Optional[Integer]
    Max: Optional[Integer]


class AcceleratorCountRequest(TypedDict, total=False):
    Min: Optional[Integer]
    Max: Optional[Integer]


AcceleratorManufacturerSet = List[AcceleratorManufacturer]
AcceleratorNameSet = List[AcceleratorName]


class AcceleratorTotalMemoryMiB(TypedDict, total=False):
    Min: Optional[Integer]
    Max: Optional[Integer]


class AcceleratorTotalMemoryMiBRequest(TypedDict, total=False):
    Min: Optional[Integer]
    Max: Optional[Integer]


AcceleratorTypeSet = List[AcceleratorType]


class Tag(TypedDict, total=False):
    Key: Optional[String]
    Value: Optional[String]


TagList = List[Tag]


class TagSpecification(TypedDict, total=False):
    ResourceType: Optional[ResourceType]
    Tags: Optional[TagList]


TagSpecificationList = List[TagSpecification]


class AcceptAddressTransferRequest(ServiceRequest):
    Address: String
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


MillisecondDateTime = datetime


class AddressTransfer(TypedDict, total=False):
    PublicIp: Optional[String]
    AllocationId: Optional[String]
    TransferAccountId: Optional[String]
    TransferOfferExpirationTimestamp: Optional[MillisecondDateTime]
    TransferOfferAcceptedTimestamp: Optional[MillisecondDateTime]
    AddressTransferStatus: Optional[AddressTransferStatus]


class AcceptAddressTransferResult(TypedDict, total=False):
    AddressTransfer: Optional[AddressTransfer]


class AcceptCapacityReservationBillingOwnershipRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    CapacityReservationId: CapacityReservationId


class AcceptCapacityReservationBillingOwnershipResult(TypedDict, total=False):
    Return: Optional[Boolean]


class TargetConfigurationRequest(TypedDict, total=False):
    InstanceCount: Optional[Integer]
    OfferingId: ReservedInstancesOfferingId


TargetConfigurationRequestSet = List[TargetConfigurationRequest]
ReservedInstanceIdSet = List[ReservationId]


class AcceptReservedInstancesExchangeQuoteRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ReservedInstanceIds: ReservedInstanceIdSet
    TargetConfigurations: Optional[TargetConfigurationRequestSet]


class AcceptReservedInstancesExchangeQuoteResult(TypedDict, total=False):
    ExchangeId: Optional[String]


ValueStringList = List[String]


class AcceptTransitGatewayMulticastDomainAssociationsRequest(ServiceRequest):
    TransitGatewayMulticastDomainId: Optional[TransitGatewayMulticastDomainId]
    TransitGatewayAttachmentId: Optional[TransitGatewayAttachmentId]
    SubnetIds: Optional[ValueStringList]
    DryRun: Optional[Boolean]


class SubnetAssociation(TypedDict, total=False):
    SubnetId: Optional[String]
    State: Optional[TransitGatewayMulitcastDomainAssociationState]


SubnetAssociationList = List[SubnetAssociation]


class TransitGatewayMulticastDomainAssociations(TypedDict, total=False):
    TransitGatewayMulticastDomainId: Optional[String]
    TransitGatewayAttachmentId: Optional[String]
    ResourceId: Optional[String]
    ResourceType: Optional[TransitGatewayAttachmentResourceType]
    ResourceOwnerId: Optional[String]
    Subnets: Optional[SubnetAssociationList]


class AcceptTransitGatewayMulticastDomainAssociationsResult(TypedDict, total=False):
    Associations: Optional[TransitGatewayMulticastDomainAssociations]


class AcceptTransitGatewayPeeringAttachmentRequest(ServiceRequest):
    TransitGatewayAttachmentId: TransitGatewayAttachmentId
    DryRun: Optional[Boolean]


DateTime = datetime


class PeeringAttachmentStatus(TypedDict, total=False):
    Code: Optional[String]
    Message: Optional[String]


class TransitGatewayPeeringAttachmentOptions(TypedDict, total=False):
    DynamicRouting: Optional[DynamicRoutingValue]


class PeeringTgwInfo(TypedDict, total=False):
    TransitGatewayId: Optional[String]
    CoreNetworkId: Optional[String]
    OwnerId: Optional[String]
    Region: Optional[String]


class TransitGatewayPeeringAttachment(TypedDict, total=False):
    TransitGatewayAttachmentId: Optional[String]
    AccepterTransitGatewayAttachmentId: Optional[String]
    RequesterTgwInfo: Optional[PeeringTgwInfo]
    AccepterTgwInfo: Optional[PeeringTgwInfo]
    Options: Optional[TransitGatewayPeeringAttachmentOptions]
    Status: Optional[PeeringAttachmentStatus]
    State: Optional[TransitGatewayAttachmentState]
    CreationTime: Optional[DateTime]
    Tags: Optional[TagList]


class AcceptTransitGatewayPeeringAttachmentResult(TypedDict, total=False):
    TransitGatewayPeeringAttachment: Optional[TransitGatewayPeeringAttachment]


class AcceptTransitGatewayVpcAttachmentRequest(ServiceRequest):
    TransitGatewayAttachmentId: TransitGatewayAttachmentId
    DryRun: Optional[Boolean]


class TransitGatewayVpcAttachmentOptions(TypedDict, total=False):
    DnsSupport: Optional[DnsSupportValue]
    SecurityGroupReferencingSupport: Optional[SecurityGroupReferencingSupportValue]
    Ipv6Support: Optional[Ipv6SupportValue]
    ApplianceModeSupport: Optional[ApplianceModeSupportValue]


class TransitGatewayVpcAttachment(TypedDict, total=False):
    TransitGatewayAttachmentId: Optional[String]
    TransitGatewayId: Optional[String]
    VpcId: Optional[String]
    VpcOwnerId: Optional[String]
    State: Optional[TransitGatewayAttachmentState]
    SubnetIds: Optional[ValueStringList]
    CreationTime: Optional[DateTime]
    Options: Optional[TransitGatewayVpcAttachmentOptions]
    Tags: Optional[TagList]


class AcceptTransitGatewayVpcAttachmentResult(TypedDict, total=False):
    TransitGatewayVpcAttachment: Optional[TransitGatewayVpcAttachment]


VpcEndpointIdList = List[VpcEndpointId]


class AcceptVpcEndpointConnectionsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ServiceId: VpcEndpointServiceId
    VpcEndpointIds: VpcEndpointIdList


class UnsuccessfulItemError(TypedDict, total=False):
    Code: Optional[String]
    Message: Optional[String]


class UnsuccessfulItem(TypedDict, total=False):
    Error: Optional[UnsuccessfulItemError]
    ResourceId: Optional[String]


UnsuccessfulItemSet = List[UnsuccessfulItem]


class AcceptVpcEndpointConnectionsResult(TypedDict, total=False):
    Unsuccessful: Optional[UnsuccessfulItemSet]


class AcceptVpcPeeringConnectionRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    VpcPeeringConnectionId: VpcPeeringConnectionIdWithResolver


class VpcPeeringConnectionStateReason(TypedDict, total=False):
    Code: Optional[VpcPeeringConnectionStateReasonCode]
    Message: Optional[String]


class VpcPeeringConnectionOptionsDescription(TypedDict, total=False):
    AllowDnsResolutionFromRemoteVpc: Optional[Boolean]
    AllowEgressFromLocalClassicLinkToRemoteVpc: Optional[Boolean]
    AllowEgressFromLocalVpcToRemoteClassicLink: Optional[Boolean]


class CidrBlock(TypedDict, total=False):
    CidrBlock: Optional[String]


CidrBlockSet = List[CidrBlock]


class Ipv6CidrBlock(TypedDict, total=False):
    Ipv6CidrBlock: Optional[String]


Ipv6CidrBlockSet = List[Ipv6CidrBlock]


class VpcPeeringConnectionVpcInfo(TypedDict, total=False):
    CidrBlock: Optional[String]
    Ipv6CidrBlockSet: Optional[Ipv6CidrBlockSet]
    CidrBlockSet: Optional[CidrBlockSet]
    OwnerId: Optional[String]
    PeeringOptions: Optional[VpcPeeringConnectionOptionsDescription]
    VpcId: Optional[String]
    Region: Optional[String]


class VpcPeeringConnection(TypedDict, total=False):
    AccepterVpcInfo: Optional[VpcPeeringConnectionVpcInfo]
    ExpirationTime: Optional[DateTime]
    RequesterVpcInfo: Optional[VpcPeeringConnectionVpcInfo]
    Status: Optional[VpcPeeringConnectionStateReason]
    Tags: Optional[TagList]
    VpcPeeringConnectionId: Optional[String]


class AcceptVpcPeeringConnectionResult(TypedDict, total=False):
    VpcPeeringConnection: Optional[VpcPeeringConnection]


class PortRange(TypedDict, total=False):
    From: Optional[Integer]
    To: Optional[Integer]


PortRangeList = List[PortRange]


class FirewallStatefulRule(TypedDict, total=False):
    RuleGroupArn: Optional[ResourceArn]
    Sources: Optional[ValueStringList]
    Destinations: Optional[ValueStringList]
    SourcePorts: Optional[PortRangeList]
    DestinationPorts: Optional[PortRangeList]
    Protocol: Optional[String]
    RuleAction: Optional[String]
    Direction: Optional[String]


ProtocolIntList = List[ProtocolInt]


class FirewallStatelessRule(TypedDict, total=False):
    RuleGroupArn: Optional[ResourceArn]
    Sources: Optional[ValueStringList]
    Destinations: Optional[ValueStringList]
    SourcePorts: Optional[PortRangeList]
    DestinationPorts: Optional[PortRangeList]
    Protocols: Optional[ProtocolIntList]
    RuleAction: Optional[String]
    Priority: Optional[Priority]


class AnalysisComponent(TypedDict, total=False):
    Id: Optional[String]
    Arn: Optional[String]
    Name: Optional[String]


class TransitGatewayRouteTableRoute(TypedDict, total=False):
    DestinationCidr: Optional[String]
    State: Optional[String]
    RouteOrigin: Optional[String]
    PrefixListId: Optional[String]
    AttachmentId: Optional[String]
    ResourceId: Optional[String]
    ResourceType: Optional[String]


AnalysisComponentList = List[AnalysisComponent]


class AnalysisSecurityGroupRule(TypedDict, total=False):
    Cidr: Optional[String]
    Direction: Optional[String]
    SecurityGroupId: Optional[String]
    PortRange: Optional[PortRange]
    PrefixListId: Optional[String]
    Protocol: Optional[String]


class AnalysisRouteTableRoute(TypedDict, total=False):
    DestinationCidr: Optional[String]
    DestinationPrefixListId: Optional[String]
    EgressOnlyInternetGatewayId: Optional[String]
    GatewayId: Optional[String]
    InstanceId: Optional[String]
    NatGatewayId: Optional[String]
    NetworkInterfaceId: Optional[String]
    Origin: Optional[String]
    TransitGatewayId: Optional[String]
    VpcPeeringConnectionId: Optional[String]
    State: Optional[String]
    CarrierGatewayId: Optional[String]
    CoreNetworkArn: Optional[ResourceArn]
    LocalGatewayId: Optional[String]


StringList = List[String]


class AnalysisLoadBalancerTarget(TypedDict, total=False):
    Address: Optional[IpAddress]
    AvailabilityZone: Optional[String]
    Instance: Optional[AnalysisComponent]
    Port: Optional[Port]


class AnalysisLoadBalancerListener(TypedDict, total=False):
    LoadBalancerPort: Optional[Port]
    InstancePort: Optional[Port]


IpAddressList = List[IpAddress]


class AnalysisAclRule(TypedDict, total=False):
    Cidr: Optional[String]
    Egress: Optional[Boolean]
    PortRange: Optional[PortRange]
    Protocol: Optional[String]
    RuleAction: Optional[String]
    RuleNumber: Optional[Integer]


class Explanation(TypedDict, total=False):
    Acl: Optional[AnalysisComponent]
    AclRule: Optional[AnalysisAclRule]
    Address: Optional[IpAddress]
    Addresses: Optional[IpAddressList]
    AttachedTo: Optional[AnalysisComponent]
    AvailabilityZones: Optional[ValueStringList]
    Cidrs: Optional[ValueStringList]
    Component: Optional[AnalysisComponent]
    CustomerGateway: Optional[AnalysisComponent]
    Destination: Optional[AnalysisComponent]
    DestinationVpc: Optional[AnalysisComponent]
    Direction: Optional[String]
    ExplanationCode: Optional[String]
    IngressRouteTable: Optional[AnalysisComponent]
    InternetGateway: Optional[AnalysisComponent]
    LoadBalancerArn: Optional[ResourceArn]
    ClassicLoadBalancerListener: Optional[AnalysisLoadBalancerListener]
    LoadBalancerListenerPort: Optional[Port]
    LoadBalancerTarget: Optional[AnalysisLoadBalancerTarget]
    LoadBalancerTargetGroup: Optional[AnalysisComponent]
    LoadBalancerTargetGroups: Optional[AnalysisComponentList]
    LoadBalancerTargetPort: Optional[Port]
    ElasticLoadBalancerListener: Optional[AnalysisComponent]
    MissingComponent: Optional[String]
    NatGateway: Optional[AnalysisComponent]
    NetworkInterface: Optional[AnalysisComponent]
    PacketField: Optional[String]
    VpcPeeringConnection: Optional[AnalysisComponent]
    Port: Optional[Port]
    PortRanges: Optional[PortRangeList]
    PrefixList: Optional[AnalysisComponent]
    Protocols: Optional[StringList]
    RouteTableRoute: Optional[AnalysisRouteTableRoute]
    RouteTable: Optional[AnalysisComponent]
    SecurityGroup: Optional[AnalysisComponent]
    SecurityGroupRule: Optional[AnalysisSecurityGroupRule]
    SecurityGroups: Optional[AnalysisComponentList]
    SourceVpc: Optional[AnalysisComponent]
    State: Optional[String]
    Subnet: Optional[AnalysisComponent]
    SubnetRouteTable: Optional[AnalysisComponent]
    Vpc: Optional[AnalysisComponent]
    VpcEndpoint: Optional[AnalysisComponent]
    VpnConnection: Optional[AnalysisComponent]
    VpnGateway: Optional[AnalysisComponent]
    TransitGateway: Optional[AnalysisComponent]
    TransitGatewayRouteTable: Optional[AnalysisComponent]
    TransitGatewayRouteTableRoute: Optional[TransitGatewayRouteTableRoute]
    TransitGatewayAttachment: Optional[AnalysisComponent]
    ComponentAccount: Optional[ComponentAccount]
    ComponentRegion: Optional[ComponentRegion]
    FirewallStatelessRule: Optional[FirewallStatelessRule]
    FirewallStatefulRule: Optional[FirewallStatefulRule]


ExplanationList = List[Explanation]


class RuleOption(TypedDict, total=False):
    Keyword: Optional[String]
    Settings: Optional[StringList]


RuleOptionList = List[RuleOption]


class RuleGroupRuleOptionsPair(TypedDict, total=False):
    RuleGroupArn: Optional[ResourceArn]
    RuleOptions: Optional[RuleOptionList]


RuleGroupRuleOptionsPairList = List[RuleGroupRuleOptionsPair]


class RuleGroupTypePair(TypedDict, total=False):
    RuleGroupArn: Optional[ResourceArn]
    RuleGroupType: Optional[String]


RuleGroupTypePairList = List[RuleGroupTypePair]


class AdditionalDetail(TypedDict, total=False):
    AdditionalDetailType: Optional[String]
    Component: Optional[AnalysisComponent]
    VpcEndpointService: Optional[AnalysisComponent]
    RuleOptions: Optional[RuleOptionList]
    RuleGroupTypePairs: Optional[RuleGroupTypePairList]
    RuleGroupRuleOptionsPairs: Optional[RuleGroupRuleOptionsPairList]
    ServiceName: Optional[String]
    LoadBalancers: Optional[AnalysisComponentList]


AdditionalDetailList = List[AdditionalDetail]


class AnalysisPacketHeader(TypedDict, total=False):
    DestinationAddresses: Optional[IpAddressList]
    DestinationPortRanges: Optional[PortRangeList]
    Protocol: Optional[String]
    SourceAddresses: Optional[IpAddressList]
    SourcePortRanges: Optional[PortRangeList]


class PathComponent(TypedDict, total=False):
    SequenceNumber: Optional[Integer]
    AclRule: Optional[AnalysisAclRule]
    AttachedTo: Optional[AnalysisComponent]
    Component: Optional[AnalysisComponent]
    DestinationVpc: Optional[AnalysisComponent]
    OutboundHeader: Optional[AnalysisPacketHeader]
    InboundHeader: Optional[AnalysisPacketHeader]
    RouteTableRoute: Optional[AnalysisRouteTableRoute]
    SecurityGroupRule: Optional[AnalysisSecurityGroupRule]
    SourceVpc: Optional[AnalysisComponent]
    Subnet: Optional[AnalysisComponent]
    Vpc: Optional[AnalysisComponent]
    AdditionalDetails: Optional[AdditionalDetailList]
    TransitGateway: Optional[AnalysisComponent]
    TransitGatewayRouteTableRoute: Optional[TransitGatewayRouteTableRoute]
    Explanations: Optional[ExplanationList]
    ElasticLoadBalancerListener: Optional[AnalysisComponent]
    FirewallStatelessRule: Optional[FirewallStatelessRule]
    FirewallStatefulRule: Optional[FirewallStatefulRule]
    ServiceName: Optional[String]


PathComponentList = List[PathComponent]


class AccessScopeAnalysisFinding(TypedDict, total=False):
    NetworkInsightsAccessScopeAnalysisId: Optional[NetworkInsightsAccessScopeAnalysisId]
    NetworkInsightsAccessScopeId: Optional[NetworkInsightsAccessScopeId]
    FindingId: Optional[String]
    FindingComponents: Optional[PathComponentList]


AccessScopeAnalysisFindingList = List[AccessScopeAnalysisFinding]


class ResourceStatement(TypedDict, total=False):
    Resources: Optional[ValueStringList]
    ResourceTypes: Optional[ValueStringList]


class ThroughResourcesStatement(TypedDict, total=False):
    ResourceStatement: Optional[ResourceStatement]


ThroughResourcesStatementList = List[ThroughResourcesStatement]
ProtocolList = List[Protocol]


class PacketHeaderStatement(TypedDict, total=False):
    SourceAddresses: Optional[ValueStringList]
    DestinationAddresses: Optional[ValueStringList]
    SourcePorts: Optional[ValueStringList]
    DestinationPorts: Optional[ValueStringList]
    SourcePrefixLists: Optional[ValueStringList]
    DestinationPrefixLists: Optional[ValueStringList]
    Protocols: Optional[ProtocolList]


class PathStatement(TypedDict, total=False):
    PacketHeaderStatement: Optional[PacketHeaderStatement]
    ResourceStatement: Optional[ResourceStatement]


class AccessScopePath(TypedDict, total=False):
    Source: Optional[PathStatement]
    Destination: Optional[PathStatement]
    ThroughResources: Optional[ThroughResourcesStatementList]


AccessScopePathList = List[AccessScopePath]


class ResourceStatementRequest(TypedDict, total=False):
    Resources: Optional[ValueStringList]
    ResourceTypes: Optional[ValueStringList]


class ThroughResourcesStatementRequest(TypedDict, total=False):
    ResourceStatement: Optional[ResourceStatementRequest]


ThroughResourcesStatementRequestList = List[ThroughResourcesStatementRequest]


class PacketHeaderStatementRequest(TypedDict, total=False):
    SourceAddresses: Optional[ValueStringList]
    DestinationAddresses: Optional[ValueStringList]
    SourcePorts: Optional[ValueStringList]
    DestinationPorts: Optional[ValueStringList]
    SourcePrefixLists: Optional[ValueStringList]
    DestinationPrefixLists: Optional[ValueStringList]
    Protocols: Optional[ProtocolList]


class PathStatementRequest(TypedDict, total=False):
    PacketHeaderStatement: Optional[PacketHeaderStatementRequest]
    ResourceStatement: Optional[ResourceStatementRequest]


class AccessScopePathRequest(TypedDict, total=False):
    Source: Optional[PathStatementRequest]
    Destination: Optional[PathStatementRequest]
    ThroughResources: Optional[ThroughResourcesStatementRequestList]


AccessScopePathListRequest = List[AccessScopePathRequest]


class AccountAttributeValue(TypedDict, total=False):
    AttributeValue: Optional[String]


AccountAttributeValueList = List[AccountAttributeValue]


class AccountAttribute(TypedDict, total=False):
    AttributeName: Optional[String]
    AttributeValues: Optional[AccountAttributeValueList]


AccountAttributeList = List[AccountAttribute]
AccountAttributeNameStringList = List[AccountAttributeName]


class ActiveInstance(TypedDict, total=False):
    InstanceId: Optional[String]
    InstanceType: Optional[String]
    SpotInstanceRequestId: Optional[String]
    InstanceHealth: Optional[InstanceHealthStatus]


ActiveInstanceSet = List[ActiveInstance]


class AddIpamOperatingRegion(TypedDict, total=False):
    RegionName: Optional[String]


AddIpamOperatingRegionSet = List[AddIpamOperatingRegion]


class AddPrefixListEntry(TypedDict, total=False):
    Cidr: String
    Description: Optional[String]


AddPrefixListEntries = List[AddPrefixListEntry]


class AddedPrincipal(TypedDict, total=False):
    PrincipalType: Optional[PrincipalType]
    Principal: Optional[String]
    ServicePermissionId: Optional[String]
    ServiceId: Optional[String]


AddedPrincipalSet = List[AddedPrincipal]


class Address(TypedDict, total=False):
    AllocationId: Optional[String]
    AssociationId: Optional[String]
    Domain: Optional[DomainType]
    NetworkInterfaceId: Optional[String]
    NetworkInterfaceOwnerId: Optional[String]
    PrivateIpAddress: Optional[String]
    Tags: Optional[TagList]
    PublicIpv4Pool: Optional[String]
    NetworkBorderGroup: Optional[String]
    CustomerOwnedIp: Optional[String]
    CustomerOwnedIpv4Pool: Optional[String]
    CarrierIp: Optional[String]
    InstanceId: Optional[String]
    PublicIp: Optional[String]


class PtrUpdateStatus(TypedDict, total=False):
    Value: Optional[String]
    Status: Optional[String]
    Reason: Optional[String]


class AddressAttribute(TypedDict, total=False):
    PublicIp: Optional[PublicIpAddress]
    AllocationId: Optional[AllocationId]
    PtrRecord: Optional[String]
    PtrRecordUpdate: Optional[PtrUpdateStatus]


AddressList = List[Address]
AddressSet = List[AddressAttribute]
AddressTransferList = List[AddressTransfer]


class AdvertiseByoipCidrRequest(ServiceRequest):
    Cidr: String
    Asn: Optional[String]
    DryRun: Optional[Boolean]
    NetworkBorderGroup: Optional[String]


class AsnAssociation(TypedDict, total=False):
    Asn: Optional[String]
    Cidr: Optional[String]
    StatusMessage: Optional[String]
    State: Optional[AsnAssociationState]


AsnAssociationSet = List[AsnAssociation]


class ByoipCidr(TypedDict, total=False):
    Cidr: Optional[String]
    Description: Optional[String]
    AsnAssociations: Optional[AsnAssociationSet]
    StatusMessage: Optional[String]
    State: Optional[ByoipCidrState]
    NetworkBorderGroup: Optional[String]


class AdvertiseByoipCidrResult(TypedDict, total=False):
    ByoipCidr: Optional[ByoipCidr]


class AllocateAddressRequest(ServiceRequest):
    Domain: Optional[DomainType]
    Address: Optional[PublicIpAddress]
    PublicIpv4Pool: Optional[Ipv4PoolEc2Id]
    NetworkBorderGroup: Optional[String]
    CustomerOwnedIpv4Pool: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]
    IpamPoolId: Optional[IpamPoolId]
    DryRun: Optional[Boolean]


class AllocateAddressResult(TypedDict, total=False):
    AllocationId: Optional[String]
    PublicIpv4Pool: Optional[String]
    NetworkBorderGroup: Optional[String]
    Domain: Optional[DomainType]
    CustomerOwnedIp: Optional[String]
    CustomerOwnedIpv4Pool: Optional[String]
    CarrierIp: Optional[String]
    PublicIp: Optional[String]


AssetIdList = List[AssetId]


class AllocateHostsRequest(ServiceRequest):
    InstanceFamily: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]
    HostRecovery: Optional[HostRecovery]
    OutpostArn: Optional[String]
    HostMaintenance: Optional[HostMaintenance]
    AssetIds: Optional[AssetIdList]
    AutoPlacement: Optional[AutoPlacement]
    ClientToken: Optional[String]
    InstanceType: Optional[String]
    Quantity: Optional[Integer]
    AvailabilityZone: String


ResponseHostIdList = List[String]


class AllocateHostsResult(TypedDict, total=False):
    HostIds: Optional[ResponseHostIdList]


IpamPoolAllocationDisallowedCidrs = List[String]
IpamPoolAllocationAllowedCidrs = List[String]


class AllocateIpamPoolCidrRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamPoolId: IpamPoolId
    Cidr: Optional[String]
    NetmaskLength: Optional[Integer]
    ClientToken: Optional[String]
    Description: Optional[String]
    PreviewNextCidr: Optional[Boolean]
    AllowedCidrs: Optional[IpamPoolAllocationAllowedCidrs]
    DisallowedCidrs: Optional[IpamPoolAllocationDisallowedCidrs]


class IpamPoolAllocation(TypedDict, total=False):
    Cidr: Optional[String]
    IpamPoolAllocationId: Optional[IpamPoolAllocationId]
    Description: Optional[String]
    ResourceId: Optional[String]
    ResourceType: Optional[IpamPoolAllocationResourceType]
    ResourceRegion: Optional[String]
    ResourceOwner: Optional[String]


class AllocateIpamPoolCidrResult(TypedDict, total=False):
    IpamPoolAllocation: Optional[IpamPoolAllocation]


AllocationIdList = List[AllocationId]
AllocationIds = List[AllocationId]
AllowedInstanceTypeSet = List[AllowedInstanceType]


class AllowedPrincipal(TypedDict, total=False):
    PrincipalType: Optional[PrincipalType]
    Principal: Optional[String]
    ServicePermissionId: Optional[String]
    Tags: Optional[TagList]
    ServiceId: Optional[String]


AllowedPrincipalSet = List[AllowedPrincipal]


class AlternatePathHint(TypedDict, total=False):
    ComponentId: Optional[String]
    ComponentArn: Optional[String]


AlternatePathHintList = List[AlternatePathHint]
ClientVpnSecurityGroupIdSet = List[SecurityGroupId]


class ApplySecurityGroupsToClientVpnTargetNetworkRequest(ServiceRequest):
    ClientVpnEndpointId: ClientVpnEndpointId
    VpcId: VpcId
    SecurityGroupIds: ClientVpnSecurityGroupIdSet
    DryRun: Optional[Boolean]


class ApplySecurityGroupsToClientVpnTargetNetworkResult(TypedDict, total=False):
    SecurityGroupIds: Optional[ClientVpnSecurityGroupIdSet]


ArchitectureTypeList = List[ArchitectureType]
ArchitectureTypeSet = List[ArchitectureType]
ArnList = List[ResourceArn]


class AsnAuthorizationContext(TypedDict, total=False):
    Message: String
    Signature: String


Ipv6AddressList = List[String]
IpPrefixList = List[String]


class AssignIpv6AddressesRequest(ServiceRequest):
    Ipv6PrefixCount: Optional[Integer]
    Ipv6Prefixes: Optional[IpPrefixList]
    NetworkInterfaceId: NetworkInterfaceId
    Ipv6Addresses: Optional[Ipv6AddressList]
    Ipv6AddressCount: Optional[Integer]


class AssignIpv6AddressesResult(TypedDict, total=False):
    AssignedIpv6Addresses: Optional[Ipv6AddressList]
    AssignedIpv6Prefixes: Optional[IpPrefixList]
    NetworkInterfaceId: Optional[String]


PrivateIpAddressStringList = List[String]


class AssignPrivateIpAddressesRequest(ServiceRequest):
    Ipv4Prefixes: Optional[IpPrefixList]
    Ipv4PrefixCount: Optional[Integer]
    NetworkInterfaceId: NetworkInterfaceId
    PrivateIpAddresses: Optional[PrivateIpAddressStringList]
    SecondaryPrivateIpAddressCount: Optional[Integer]
    AllowReassignment: Optional[Boolean]


class Ipv4PrefixSpecification(TypedDict, total=False):
    Ipv4Prefix: Optional[String]


Ipv4PrefixesList = List[Ipv4PrefixSpecification]


class AssignedPrivateIpAddress(TypedDict, total=False):
    PrivateIpAddress: Optional[String]


AssignedPrivateIpAddressList = List[AssignedPrivateIpAddress]


class AssignPrivateIpAddressesResult(TypedDict, total=False):
    NetworkInterfaceId: Optional[String]
    AssignedPrivateIpAddresses: Optional[AssignedPrivateIpAddressList]
    AssignedIpv4Prefixes: Optional[Ipv4PrefixesList]


IpList = List[String]


class AssignPrivateNatGatewayAddressRequest(ServiceRequest):
    NatGatewayId: NatGatewayId
    PrivateIpAddresses: Optional[IpList]
    PrivateIpAddressCount: Optional[PrivateIpAddressCount]
    DryRun: Optional[Boolean]


class NatGatewayAddress(TypedDict, total=False):
    AllocationId: Optional[String]
    NetworkInterfaceId: Optional[String]
    PrivateIp: Optional[String]
    PublicIp: Optional[String]
    AssociationId: Optional[String]
    IsPrimary: Optional[Boolean]
    FailureMessage: Optional[String]
    Status: Optional[NatGatewayAddressStatus]


NatGatewayAddressList = List[NatGatewayAddress]


class AssignPrivateNatGatewayAddressResult(TypedDict, total=False):
    NatGatewayId: Optional[NatGatewayId]
    NatGatewayAddresses: Optional[NatGatewayAddressList]


class AssociateAddressRequest(ServiceRequest):
    AllocationId: Optional[AllocationId]
    InstanceId: Optional[InstanceId]
    PublicIp: Optional[EipAllocationPublicIp]
    DryRun: Optional[Boolean]
    NetworkInterfaceId: Optional[NetworkInterfaceId]
    PrivateIpAddress: Optional[String]
    AllowReassociation: Optional[Boolean]


class AssociateAddressResult(TypedDict, total=False):
    AssociationId: Optional[String]


class AssociateCapacityReservationBillingOwnerRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    CapacityReservationId: CapacityReservationId
    UnusedReservationBillingOwnerId: AccountID


class AssociateCapacityReservationBillingOwnerResult(TypedDict, total=False):
    Return: Optional[Boolean]


class AssociateClientVpnTargetNetworkRequest(ServiceRequest):
    ClientVpnEndpointId: ClientVpnEndpointId
    SubnetId: SubnetId
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]


class AssociationStatus(TypedDict, total=False):
    Code: Optional[AssociationStatusCode]
    Message: Optional[String]


class AssociateClientVpnTargetNetworkResult(TypedDict, total=False):
    AssociationId: Optional[String]
    Status: Optional[AssociationStatus]


class AssociateDhcpOptionsRequest(ServiceRequest):
    DhcpOptionsId: DefaultingDhcpOptionsId
    VpcId: VpcId
    DryRun: Optional[Boolean]


class AssociateEnclaveCertificateIamRoleRequest(ServiceRequest):
    CertificateArn: CertificateId
    RoleArn: RoleId
    DryRun: Optional[Boolean]


class AssociateEnclaveCertificateIamRoleResult(TypedDict, total=False):
    CertificateS3BucketName: Optional[String]
    CertificateS3ObjectKey: Optional[String]
    EncryptionKmsKeyId: Optional[String]


class IamInstanceProfileSpecification(TypedDict, total=False):
    Arn: Optional[String]
    Name: Optional[String]


class AssociateIamInstanceProfileRequest(ServiceRequest):
    IamInstanceProfile: IamInstanceProfileSpecification
    InstanceId: InstanceId


class IamInstanceProfile(TypedDict, total=False):
    Arn: Optional[String]
    Id: Optional[String]


class IamInstanceProfileAssociation(TypedDict, total=False):
    AssociationId: Optional[String]
    InstanceId: Optional[String]
    IamInstanceProfile: Optional[IamInstanceProfile]
    State: Optional[IamInstanceProfileAssociationState]
    Timestamp: Optional[DateTime]


class AssociateIamInstanceProfileResult(TypedDict, total=False):
    IamInstanceProfileAssociation: Optional[IamInstanceProfileAssociation]


DedicatedHostIdList = List[DedicatedHostId]
InstanceIdList = List[InstanceId]


class InstanceEventWindowAssociationRequest(TypedDict, total=False):
    InstanceIds: Optional[InstanceIdList]
    InstanceTags: Optional[TagList]
    DedicatedHostIds: Optional[DedicatedHostIdList]


class AssociateInstanceEventWindowRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceEventWindowId: InstanceEventWindowId
    AssociationTarget: InstanceEventWindowAssociationRequest


class InstanceEventWindowAssociationTarget(TypedDict, total=False):
    InstanceIds: Optional[InstanceIdList]
    Tags: Optional[TagList]
    DedicatedHostIds: Optional[DedicatedHostIdList]


class InstanceEventWindowTimeRange(TypedDict, total=False):
    StartWeekDay: Optional[WeekDay]
    StartHour: Optional[Hour]
    EndWeekDay: Optional[WeekDay]
    EndHour: Optional[Hour]


InstanceEventWindowTimeRangeList = List[InstanceEventWindowTimeRange]


class InstanceEventWindow(TypedDict, total=False):
    InstanceEventWindowId: Optional[InstanceEventWindowId]
    TimeRanges: Optional[InstanceEventWindowTimeRangeList]
    Name: Optional[String]
    CronExpression: Optional[InstanceEventWindowCronExpression]
    AssociationTarget: Optional[InstanceEventWindowAssociationTarget]
    State: Optional[InstanceEventWindowState]
    Tags: Optional[TagList]


class AssociateInstanceEventWindowResult(TypedDict, total=False):
    InstanceEventWindow: Optional[InstanceEventWindow]


class AssociateIpamByoasnRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Asn: String
    Cidr: String


class AssociateIpamByoasnResult(TypedDict, total=False):
    AsnAssociation: Optional[AsnAssociation]


class AssociateIpamResourceDiscoveryRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamId: IpamId
    IpamResourceDiscoveryId: IpamResourceDiscoveryId
    TagSpecifications: Optional[TagSpecificationList]
    ClientToken: Optional[String]


class IpamResourceDiscoveryAssociation(TypedDict, total=False):
    OwnerId: Optional[String]
    IpamResourceDiscoveryAssociationId: Optional[IpamResourceDiscoveryAssociationId]
    IpamResourceDiscoveryAssociationArn: Optional[String]
    IpamResourceDiscoveryId: Optional[IpamResourceDiscoveryId]
    IpamId: Optional[IpamId]
    IpamArn: Optional[ResourceArn]
    IpamRegion: Optional[String]
    IsDefault: Optional[Boolean]
    ResourceDiscoveryStatus: Optional[IpamAssociatedResourceDiscoveryStatus]
    State: Optional[IpamResourceDiscoveryAssociationState]
    Tags: Optional[TagList]


class AssociateIpamResourceDiscoveryResult(TypedDict, total=False):
    IpamResourceDiscoveryAssociation: Optional[IpamResourceDiscoveryAssociation]


class AssociateNatGatewayAddressRequest(ServiceRequest):
    NatGatewayId: NatGatewayId
    AllocationIds: AllocationIdList
    PrivateIpAddresses: Optional[IpList]
    DryRun: Optional[Boolean]


class AssociateNatGatewayAddressResult(TypedDict, total=False):
    NatGatewayId: Optional[NatGatewayId]
    NatGatewayAddresses: Optional[NatGatewayAddressList]


class AssociateRouteTableRequest(ServiceRequest):
    GatewayId: Optional[RouteGatewayId]
    DryRun: Optional[Boolean]
    SubnetId: Optional[SubnetId]
    RouteTableId: RouteTableId


class RouteTableAssociationState(TypedDict, total=False):
    State: Optional[RouteTableAssociationStateCode]
    StatusMessage: Optional[String]


class AssociateRouteTableResult(TypedDict, total=False):
    AssociationId: Optional[String]
    AssociationState: Optional[RouteTableAssociationState]


class AssociateSecurityGroupVpcRequest(ServiceRequest):
    GroupId: SecurityGroupId
    VpcId: VpcId
    DryRun: Optional[Boolean]


class AssociateSecurityGroupVpcResult(TypedDict, total=False):
    State: Optional[SecurityGroupVpcAssociationState]


class AssociateSubnetCidrBlockRequest(ServiceRequest):
    Ipv6IpamPoolId: Optional[IpamPoolId]
    Ipv6NetmaskLength: Optional[NetmaskLength]
    SubnetId: SubnetId
    Ipv6CidrBlock: Optional[String]


class SubnetCidrBlockState(TypedDict, total=False):
    State: Optional[SubnetCidrBlockStateCode]
    StatusMessage: Optional[String]


class SubnetIpv6CidrBlockAssociation(TypedDict, total=False):
    AssociationId: Optional[SubnetCidrAssociationId]
    Ipv6CidrBlock: Optional[String]
    Ipv6CidrBlockState: Optional[SubnetCidrBlockState]
    Ipv6AddressAttribute: Optional[Ipv6AddressAttribute]
    IpSource: Optional[IpSource]


class AssociateSubnetCidrBlockResult(TypedDict, total=False):
    Ipv6CidrBlockAssociation: Optional[SubnetIpv6CidrBlockAssociation]
    SubnetId: Optional[String]


TransitGatewaySubnetIdList = List[SubnetId]


class AssociateTransitGatewayMulticastDomainRequest(ServiceRequest):
    TransitGatewayMulticastDomainId: TransitGatewayMulticastDomainId
    TransitGatewayAttachmentId: TransitGatewayAttachmentId
    SubnetIds: TransitGatewaySubnetIdList
    DryRun: Optional[Boolean]


class AssociateTransitGatewayMulticastDomainResult(TypedDict, total=False):
    Associations: Optional[TransitGatewayMulticastDomainAssociations]


class AssociateTransitGatewayPolicyTableRequest(ServiceRequest):
    TransitGatewayPolicyTableId: TransitGatewayPolicyTableId
    TransitGatewayAttachmentId: TransitGatewayAttachmentId
    DryRun: Optional[Boolean]


class TransitGatewayPolicyTableAssociation(TypedDict, total=False):
    TransitGatewayPolicyTableId: Optional[TransitGatewayPolicyTableId]
    TransitGatewayAttachmentId: Optional[TransitGatewayAttachmentId]
    ResourceId: Optional[String]
    ResourceType: Optional[TransitGatewayAttachmentResourceType]
    State: Optional[TransitGatewayAssociationState]


class AssociateTransitGatewayPolicyTableResult(TypedDict, total=False):
    Association: Optional[TransitGatewayPolicyTableAssociation]


class AssociateTransitGatewayRouteTableRequest(ServiceRequest):
    TransitGatewayRouteTableId: TransitGatewayRouteTableId
    TransitGatewayAttachmentId: TransitGatewayAttachmentId
    DryRun: Optional[Boolean]


class TransitGatewayAssociation(TypedDict, total=False):
    TransitGatewayRouteTableId: Optional[TransitGatewayRouteTableId]
    TransitGatewayAttachmentId: Optional[TransitGatewayAttachmentId]
    ResourceId: Optional[String]
    ResourceType: Optional[TransitGatewayAttachmentResourceType]
    State: Optional[TransitGatewayAssociationState]


class AssociateTransitGatewayRouteTableResult(TypedDict, total=False):
    Association: Optional[TransitGatewayAssociation]


class AssociateTrunkInterfaceRequest(ServiceRequest):
    BranchInterfaceId: NetworkInterfaceId
    TrunkInterfaceId: NetworkInterfaceId
    VlanId: Optional[Integer]
    GreKey: Optional[Integer]
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]


class TrunkInterfaceAssociation(TypedDict, total=False):
    AssociationId: Optional[TrunkInterfaceAssociationId]
    BranchInterfaceId: Optional[String]
    TrunkInterfaceId: Optional[String]
    InterfaceProtocol: Optional[InterfaceProtocolType]
    VlanId: Optional[Integer]
    GreKey: Optional[Integer]
    Tags: Optional[TagList]


class AssociateTrunkInterfaceResult(TypedDict, total=False):
    InterfaceAssociation: Optional[TrunkInterfaceAssociation]
    ClientToken: Optional[String]


class AssociateVpcCidrBlockRequest(ServiceRequest):
    CidrBlock: Optional[String]
    Ipv6CidrBlockNetworkBorderGroup: Optional[String]
    Ipv6Pool: Optional[Ipv6PoolEc2Id]
    Ipv6CidrBlock: Optional[String]
    Ipv4IpamPoolId: Optional[IpamPoolId]
    Ipv4NetmaskLength: Optional[NetmaskLength]
    Ipv6IpamPoolId: Optional[IpamPoolId]
    Ipv6NetmaskLength: Optional[NetmaskLength]
    VpcId: VpcId
    AmazonProvidedIpv6CidrBlock: Optional[Boolean]


class VpcCidrBlockState(TypedDict, total=False):
    State: Optional[VpcCidrBlockStateCode]
    StatusMessage: Optional[String]


class VpcCidrBlockAssociation(TypedDict, total=False):
    AssociationId: Optional[String]
    CidrBlock: Optional[String]
    CidrBlockState: Optional[VpcCidrBlockState]


class VpcIpv6CidrBlockAssociation(TypedDict, total=False):
    AssociationId: Optional[String]
    Ipv6CidrBlock: Optional[String]
    Ipv6CidrBlockState: Optional[VpcCidrBlockState]
    NetworkBorderGroup: Optional[String]
    Ipv6Pool: Optional[String]
    Ipv6AddressAttribute: Optional[Ipv6AddressAttribute]
    IpSource: Optional[IpSource]


class AssociateVpcCidrBlockResult(TypedDict, total=False):
    Ipv6CidrBlockAssociation: Optional[VpcIpv6CidrBlockAssociation]
    CidrBlockAssociation: Optional[VpcCidrBlockAssociation]
    VpcId: Optional[String]


class AssociatedRole(TypedDict, total=False):
    AssociatedRoleArn: Optional[ResourceArn]
    CertificateS3BucketName: Optional[String]
    CertificateS3ObjectKey: Optional[String]
    EncryptionKmsKeyId: Optional[String]


AssociatedRolesList = List[AssociatedRole]


class AssociatedTargetNetwork(TypedDict, total=False):
    NetworkId: Optional[String]
    NetworkType: Optional[AssociatedNetworkType]


AssociatedTargetNetworkSet = List[AssociatedTargetNetwork]
AssociationIdList = List[IamInstanceProfileAssociationId]


class AthenaIntegration(TypedDict, total=False):
    IntegrationResultS3DestinationArn: String
    PartitionLoadFrequency: PartitionLoadFrequency
    PartitionStartDate: Optional[MillisecondDateTime]
    PartitionEndDate: Optional[MillisecondDateTime]


AthenaIntegrationsSet = List[AthenaIntegration]
GroupIdStringList = List[SecurityGroupId]


class AttachClassicLinkVpcRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceId: InstanceId
    VpcId: VpcId
    Groups: GroupIdStringList


class AttachClassicLinkVpcResult(TypedDict, total=False):
    Return: Optional[Boolean]


class AttachInternetGatewayRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InternetGatewayId: InternetGatewayId
    VpcId: VpcId


class EnaSrdUdpSpecification(TypedDict, total=False):
    EnaSrdUdpEnabled: Optional[Boolean]


class EnaSrdSpecification(TypedDict, total=False):
    EnaSrdEnabled: Optional[Boolean]
    EnaSrdUdpSpecification: Optional[EnaSrdUdpSpecification]


class AttachNetworkInterfaceRequest(ServiceRequest):
    NetworkCardIndex: Optional[Integer]
    EnaSrdSpecification: Optional[EnaSrdSpecification]
    DryRun: Optional[Boolean]
    NetworkInterfaceId: NetworkInterfaceId
    InstanceId: InstanceId
    DeviceIndex: Integer


class AttachNetworkInterfaceResult(TypedDict, total=False):
    AttachmentId: Optional[String]
    NetworkCardIndex: Optional[Integer]


class AttachVerifiedAccessTrustProviderRequest(ServiceRequest):
    VerifiedAccessInstanceId: VerifiedAccessInstanceId
    VerifiedAccessTrustProviderId: VerifiedAccessTrustProviderId
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]


class VerifiedAccessTrustProviderCondensed(TypedDict, total=False):
    VerifiedAccessTrustProviderId: Optional[String]
    Description: Optional[String]
    TrustProviderType: Optional[TrustProviderType]
    UserTrustProviderType: Optional[UserTrustProviderType]
    DeviceTrustProviderType: Optional[DeviceTrustProviderType]


VerifiedAccessTrustProviderCondensedList = List[VerifiedAccessTrustProviderCondensed]


class VerifiedAccessInstance(TypedDict, total=False):
    VerifiedAccessInstanceId: Optional[String]
    Description: Optional[String]
    VerifiedAccessTrustProviders: Optional[VerifiedAccessTrustProviderCondensedList]
    CreationTime: Optional[String]
    LastUpdatedTime: Optional[String]
    Tags: Optional[TagList]
    FipsEnabled: Optional[Boolean]


class VerifiedAccessSseSpecificationResponse(TypedDict, total=False):
    CustomerManagedKeyEnabled: Optional[Boolean]
    KmsKeyArn: Optional[KmsKeyArn]


class DeviceOptions(TypedDict, total=False):
    TenantId: Optional[String]
    PublicSigningKeyUrl: Optional[String]


class OidcOptions(TypedDict, total=False):
    Issuer: Optional[String]
    AuthorizationEndpoint: Optional[String]
    TokenEndpoint: Optional[String]
    UserInfoEndpoint: Optional[String]
    ClientId: Optional[String]
    ClientSecret: Optional[ClientSecretType]
    Scope: Optional[String]


class VerifiedAccessTrustProvider(TypedDict, total=False):
    VerifiedAccessTrustProviderId: Optional[String]
    Description: Optional[String]
    TrustProviderType: Optional[TrustProviderType]
    UserTrustProviderType: Optional[UserTrustProviderType]
    DeviceTrustProviderType: Optional[DeviceTrustProviderType]
    OidcOptions: Optional[OidcOptions]
    DeviceOptions: Optional[DeviceOptions]
    PolicyReferenceName: Optional[String]
    CreationTime: Optional[String]
    LastUpdatedTime: Optional[String]
    Tags: Optional[TagList]
    SseSpecification: Optional[VerifiedAccessSseSpecificationResponse]


class AttachVerifiedAccessTrustProviderResult(TypedDict, total=False):
    VerifiedAccessTrustProvider: Optional[VerifiedAccessTrustProvider]
    VerifiedAccessInstance: Optional[VerifiedAccessInstance]


class AttachVolumeRequest(ServiceRequest):
    Device: String
    InstanceId: InstanceId
    VolumeId: VolumeId
    DryRun: Optional[Boolean]


class AttachVpnGatewayRequest(ServiceRequest):
    VpcId: VpcId
    VpnGatewayId: VpnGatewayId
    DryRun: Optional[Boolean]


class VpcAttachment(TypedDict, total=False):
    VpcId: Optional[String]
    State: Optional[AttachmentStatus]


class AttachVpnGatewayResult(TypedDict, total=False):
    VpcAttachment: Optional[VpcAttachment]


class AttachmentEnaSrdUdpSpecification(TypedDict, total=False):
    EnaSrdUdpEnabled: Optional[Boolean]


class AttachmentEnaSrdSpecification(TypedDict, total=False):
    EnaSrdEnabled: Optional[Boolean]
    EnaSrdUdpSpecification: Optional[AttachmentEnaSrdUdpSpecification]


class AttributeBooleanValue(TypedDict, total=False):
    Value: Optional[Boolean]


class AttributeValue(TypedDict, total=False):
    Value: Optional[String]


class ClientVpnAuthorizationRuleStatus(TypedDict, total=False):
    Code: Optional[ClientVpnAuthorizationRuleStatusCode]
    Message: Optional[String]


class AuthorizationRule(TypedDict, total=False):
    ClientVpnEndpointId: Optional[String]
    Description: Optional[String]
    GroupId: Optional[String]
    AccessAll: Optional[Boolean]
    DestinationCidr: Optional[String]
    Status: Optional[ClientVpnAuthorizationRuleStatus]


AuthorizationRuleSet = List[AuthorizationRule]


class AuthorizeClientVpnIngressRequest(ServiceRequest):
    ClientVpnEndpointId: ClientVpnEndpointId
    TargetNetworkCidr: String
    AccessGroupId: Optional[String]
    AuthorizeAllGroups: Optional[Boolean]
    Description: Optional[String]
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]


class AuthorizeClientVpnIngressResult(TypedDict, total=False):
    Status: Optional[ClientVpnAuthorizationRuleStatus]


class PrefixListId(TypedDict, total=False):
    Description: Optional[String]
    PrefixListId: Optional[String]


PrefixListIdList = List[PrefixListId]


class Ipv6Range(TypedDict, total=False):
    Description: Optional[String]
    CidrIpv6: Optional[String]


Ipv6RangeList = List[Ipv6Range]


class IpRange(TypedDict, total=False):
    Description: Optional[String]
    CidrIp: Optional[String]


IpRangeList = List[IpRange]


class UserIdGroupPair(TypedDict, total=False):
    Description: Optional[String]
    UserId: Optional[String]
    GroupName: Optional[String]
    GroupId: Optional[String]
    VpcId: Optional[String]
    VpcPeeringConnectionId: Optional[String]
    PeeringStatus: Optional[String]


UserIdGroupPairList = List[UserIdGroupPair]


class IpPermission(TypedDict, total=False):
    IpProtocol: Optional[String]
    FromPort: Optional[Integer]
    ToPort: Optional[Integer]
    UserIdGroupPairs: Optional[UserIdGroupPairList]
    IpRanges: Optional[IpRangeList]
    Ipv6Ranges: Optional[Ipv6RangeList]
    PrefixListIds: Optional[PrefixListIdList]


IpPermissionList = List[IpPermission]


class AuthorizeSecurityGroupEgressRequest(ServiceRequest):
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]
    GroupId: SecurityGroupId
    SourceSecurityGroupName: Optional[String]
    SourceSecurityGroupOwnerId: Optional[String]
    IpProtocol: Optional[String]
    FromPort: Optional[Integer]
    ToPort: Optional[Integer]
    CidrIp: Optional[String]
    IpPermissions: Optional[IpPermissionList]


class ReferencedSecurityGroup(TypedDict, total=False):
    GroupId: Optional[String]
    PeeringStatus: Optional[String]
    UserId: Optional[String]
    VpcId: Optional[String]
    VpcPeeringConnectionId: Optional[String]


class SecurityGroupRule(TypedDict, total=False):
    SecurityGroupRuleId: Optional[SecurityGroupRuleId]
    GroupId: Optional[SecurityGroupId]
    GroupOwnerId: Optional[String]
    IsEgress: Optional[Boolean]
    IpProtocol: Optional[String]
    FromPort: Optional[Integer]
    ToPort: Optional[Integer]
    CidrIpv4: Optional[String]
    CidrIpv6: Optional[String]
    PrefixListId: Optional[PrefixListResourceId]
    ReferencedGroupInfo: Optional[ReferencedSecurityGroup]
    Description: Optional[String]
    Tags: Optional[TagList]
    SecurityGroupRuleArn: Optional[String]


SecurityGroupRuleList = List[SecurityGroupRule]


class AuthorizeSecurityGroupEgressResult(TypedDict, total=False):
    Return: Optional[Boolean]
    SecurityGroupRules: Optional[SecurityGroupRuleList]


class AuthorizeSecurityGroupIngressRequest(ServiceRequest):
    CidrIp: Optional[String]
    FromPort: Optional[Integer]
    GroupId: Optional[SecurityGroupId]
    GroupName: Optional[SecurityGroupName]
    IpPermissions: Optional[IpPermissionList]
    IpProtocol: Optional[String]
    SourceSecurityGroupName: Optional[String]
    SourceSecurityGroupOwnerId: Optional[String]
    ToPort: Optional[Integer]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class AuthorizeSecurityGroupIngressResult(TypedDict, total=False):
    Return: Optional[Boolean]
    SecurityGroupRules: Optional[SecurityGroupRuleList]


class AvailabilityZoneMessage(TypedDict, total=False):
    Message: Optional[String]


AvailabilityZoneMessageList = List[AvailabilityZoneMessage]


class AvailabilityZone(TypedDict, total=False):
    OptInStatus: Optional[AvailabilityZoneOptInStatus]
    Messages: Optional[AvailabilityZoneMessageList]
    RegionName: Optional[String]
    ZoneName: Optional[String]
    ZoneId: Optional[String]
    GroupName: Optional[String]
    NetworkBorderGroup: Optional[String]
    ZoneType: Optional[String]
    ParentZoneName: Optional[String]
    ParentZoneId: Optional[String]
    State: Optional[AvailabilityZoneState]


AvailabilityZoneList = List[AvailabilityZone]
AvailabilityZoneStringList = List[String]


class InstanceCapacity(TypedDict, total=False):
    AvailableCapacity: Optional[Integer]
    InstanceType: Optional[String]
    TotalCapacity: Optional[Integer]


AvailableInstanceCapacityList = List[InstanceCapacity]


class AvailableCapacity(TypedDict, total=False):
    AvailableInstanceCapacity: Optional[AvailableInstanceCapacityList]
    AvailableVCpus: Optional[Integer]


class BaselineEbsBandwidthMbps(TypedDict, total=False):
    Min: Optional[Integer]
    Max: Optional[Integer]


class BaselineEbsBandwidthMbpsRequest(TypedDict, total=False):
    Min: Optional[Integer]
    Max: Optional[Integer]


BillingProductList = List[String]
Blob = bytes


class BlobAttributeValue(TypedDict, total=False):
    Value: Optional[Blob]


class EbsBlockDevice(TypedDict, total=False):
    DeleteOnTermination: Optional[Boolean]
    Iops: Optional[Integer]
    SnapshotId: Optional[SnapshotId]
    VolumeSize: Optional[Integer]
    VolumeType: Optional[VolumeType]
    KmsKeyId: Optional[String]
    Throughput: Optional[Integer]
    OutpostArn: Optional[String]
    Encrypted: Optional[Boolean]


class BlockDeviceMapping(TypedDict, total=False):
    Ebs: Optional[EbsBlockDevice]
    NoDevice: Optional[String]
    DeviceName: Optional[String]
    VirtualName: Optional[String]


BlockDeviceMappingList = List[BlockDeviceMapping]
BlockDeviceMappingRequestList = List[BlockDeviceMapping]
BootModeTypeList = List[BootModeType]
BundleIdStringList = List[BundleId]


class S3Storage(TypedDict, total=False):
    AWSAccessKeyId: Optional[String]
    Bucket: Optional[String]
    Prefix: Optional[String]
    UploadPolicy: Optional[Blob]
    UploadPolicySignature: Optional[S3StorageUploadPolicySignature]


class Storage(TypedDict, total=False):
    S3: Optional[S3Storage]


class BundleInstanceRequest(ServiceRequest):
    InstanceId: InstanceId
    Storage: Storage
    DryRun: Optional[Boolean]


class BundleTaskError(TypedDict, total=False):
    Code: Optional[String]
    Message: Optional[String]


class BundleTask(TypedDict, total=False):
    InstanceId: Optional[String]
    BundleId: Optional[String]
    State: Optional[BundleTaskState]
    StartTime: Optional[DateTime]
    UpdateTime: Optional[DateTime]
    Storage: Optional[Storage]
    Progress: Optional[String]
    BundleTaskError: Optional[BundleTaskError]


class BundleInstanceResult(TypedDict, total=False):
    BundleTask: Optional[BundleTask]


BundleTaskList = List[BundleTask]


class Byoasn(TypedDict, total=False):
    Asn: Optional[String]
    IpamId: Optional[IpamId]
    StatusMessage: Optional[String]
    State: Optional[AsnState]


ByoasnSet = List[Byoasn]
ByoipCidrSet = List[ByoipCidr]


class CancelBundleTaskRequest(ServiceRequest):
    BundleId: BundleId
    DryRun: Optional[Boolean]


class CancelBundleTaskResult(TypedDict, total=False):
    BundleTask: Optional[BundleTask]


class CancelCapacityReservationFleetError(TypedDict, total=False):
    Code: Optional[CancelCapacityReservationFleetErrorCode]
    Message: Optional[CancelCapacityReservationFleetErrorMessage]


CapacityReservationFleetIdSet = List[CapacityReservationFleetId]


class CancelCapacityReservationFleetsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    CapacityReservationFleetIds: CapacityReservationFleetIdSet


class FailedCapacityReservationFleetCancellationResult(TypedDict, total=False):
    CapacityReservationFleetId: Optional[CapacityReservationFleetId]
    CancelCapacityReservationFleetError: Optional[CancelCapacityReservationFleetError]


FailedCapacityReservationFleetCancellationResultSet = List[
    FailedCapacityReservationFleetCancellationResult
]


class CapacityReservationFleetCancellationState(TypedDict, total=False):
    CurrentFleetState: Optional[CapacityReservationFleetState]
    PreviousFleetState: Optional[CapacityReservationFleetState]
    CapacityReservationFleetId: Optional[CapacityReservationFleetId]


CapacityReservationFleetCancellationStateSet = List[CapacityReservationFleetCancellationState]


class CancelCapacityReservationFleetsResult(TypedDict, total=False):
    SuccessfulFleetCancellations: Optional[CapacityReservationFleetCancellationStateSet]
    FailedFleetCancellations: Optional[FailedCapacityReservationFleetCancellationResultSet]


class CancelCapacityReservationRequest(ServiceRequest):
    CapacityReservationId: CapacityReservationId
    DryRun: Optional[Boolean]


class CancelCapacityReservationResult(TypedDict, total=False):
    Return: Optional[Boolean]


class CancelConversionRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ConversionTaskId: ConversionTaskId
    ReasonMessage: Optional[String]


class CancelExportTaskRequest(ServiceRequest):
    ExportTaskId: ExportVmTaskId


class CancelImageLaunchPermissionRequest(ServiceRequest):
    ImageId: ImageId
    DryRun: Optional[Boolean]


class CancelImageLaunchPermissionResult(TypedDict, total=False):
    Return: Optional[Boolean]


class CancelImportTaskRequest(ServiceRequest):
    CancelReason: Optional[String]
    DryRun: Optional[Boolean]
    ImportTaskId: Optional[ImportTaskId]


class CancelImportTaskResult(TypedDict, total=False):
    ImportTaskId: Optional[String]
    PreviousState: Optional[String]
    State: Optional[String]


class CancelReservedInstancesListingRequest(ServiceRequest):
    ReservedInstancesListingId: ReservedInstancesListingId


Long = int


class PriceSchedule(TypedDict, total=False):
    Active: Optional[Boolean]
    CurrencyCode: Optional[CurrencyCodeValues]
    Price: Optional[Double]
    Term: Optional[Long]


PriceScheduleList = List[PriceSchedule]


class InstanceCount(TypedDict, total=False):
    InstanceCount: Optional[Integer]
    State: Optional[ListingState]


InstanceCountList = List[InstanceCount]


class ReservedInstancesListing(TypedDict, total=False):
    ClientToken: Optional[String]
    CreateDate: Optional[DateTime]
    InstanceCounts: Optional[InstanceCountList]
    PriceSchedules: Optional[PriceScheduleList]
    ReservedInstancesId: Optional[String]
    ReservedInstancesListingId: Optional[String]
    Status: Optional[ListingStatus]
    StatusMessage: Optional[String]
    Tags: Optional[TagList]
    UpdateDate: Optional[DateTime]


ReservedInstancesListingList = List[ReservedInstancesListing]


class CancelReservedInstancesListingResult(TypedDict, total=False):
    ReservedInstancesListings: Optional[ReservedInstancesListingList]


class CancelSpotFleetRequestsError(TypedDict, total=False):
    Code: Optional[CancelBatchErrorCode]
    Message: Optional[String]


class CancelSpotFleetRequestsErrorItem(TypedDict, total=False):
    Error: Optional[CancelSpotFleetRequestsError]
    SpotFleetRequestId: Optional[String]


CancelSpotFleetRequestsErrorSet = List[CancelSpotFleetRequestsErrorItem]
SpotFleetRequestIdList = List[SpotFleetRequestId]


class CancelSpotFleetRequestsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    SpotFleetRequestIds: SpotFleetRequestIdList
    TerminateInstances: Boolean


class CancelSpotFleetRequestsSuccessItem(TypedDict, total=False):
    CurrentSpotFleetRequestState: Optional[BatchState]
    PreviousSpotFleetRequestState: Optional[BatchState]
    SpotFleetRequestId: Optional[String]


CancelSpotFleetRequestsSuccessSet = List[CancelSpotFleetRequestsSuccessItem]


class CancelSpotFleetRequestsResponse(TypedDict, total=False):
    SuccessfulFleetRequests: Optional[CancelSpotFleetRequestsSuccessSet]
    UnsuccessfulFleetRequests: Optional[CancelSpotFleetRequestsErrorSet]


SpotInstanceRequestIdList = List[SpotInstanceRequestId]


class CancelSpotInstanceRequestsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    SpotInstanceRequestIds: SpotInstanceRequestIdList


class CancelledSpotInstanceRequest(TypedDict, total=False):
    SpotInstanceRequestId: Optional[String]
    State: Optional[CancelSpotInstanceRequestState]


CancelledSpotInstanceRequestList = List[CancelledSpotInstanceRequest]


class CancelSpotInstanceRequestsResult(TypedDict, total=False):
    CancelledSpotInstanceRequests: Optional[CancelledSpotInstanceRequestList]


class CapacityAllocation(TypedDict, total=False):
    AllocationType: Optional[AllocationType]
    Count: Optional[Integer]


CapacityAllocations = List[CapacityAllocation]


class CapacityBlockOffering(TypedDict, total=False):
    CapacityBlockOfferingId: Optional[OfferingId]
    InstanceType: Optional[String]
    AvailabilityZone: Optional[String]
    InstanceCount: Optional[Integer]
    StartDate: Optional[MillisecondDateTime]
    EndDate: Optional[MillisecondDateTime]
    CapacityBlockDurationHours: Optional[Integer]
    UpfrontFee: Optional[String]
    CurrencyCode: Optional[String]
    Tenancy: Optional[CapacityReservationTenancy]


CapacityBlockOfferingSet = List[CapacityBlockOffering]


class CapacityReservation(TypedDict, total=False):
    CapacityReservationId: Optional[String]
    OwnerId: Optional[String]
    CapacityReservationArn: Optional[String]
    AvailabilityZoneId: Optional[String]
    InstanceType: Optional[String]
    InstancePlatform: Optional[CapacityReservationInstancePlatform]
    AvailabilityZone: Optional[String]
    Tenancy: Optional[CapacityReservationTenancy]
    TotalInstanceCount: Optional[Integer]
    AvailableInstanceCount: Optional[Integer]
    EbsOptimized: Optional[Boolean]
    EphemeralStorage: Optional[Boolean]
    State: Optional[CapacityReservationState]
    StartDate: Optional[MillisecondDateTime]
    EndDate: Optional[DateTime]
    EndDateType: Optional[EndDateType]
    InstanceMatchCriteria: Optional[InstanceMatchCriteria]
    CreateDate: Optional[DateTime]
    Tags: Optional[TagList]
    OutpostArn: Optional[OutpostArn]
    CapacityReservationFleetId: Optional[String]
    PlacementGroupArn: Optional[PlacementGroupArn]
    CapacityAllocations: Optional[CapacityAllocations]
    ReservationType: Optional[CapacityReservationType]
    UnusedReservationBillingOwnerId: Optional[AccountID]


class CapacityReservationInfo(TypedDict, total=False):
    InstanceType: Optional[String]
    AvailabilityZone: Optional[AvailabilityZoneName]
    Tenancy: Optional[CapacityReservationTenancy]


class CapacityReservationBillingRequest(TypedDict, total=False):
    CapacityReservationId: Optional[String]
    RequestedBy: Optional[String]
    UnusedReservationBillingOwnerId: Optional[AccountID]
    LastUpdateTime: Optional[MillisecondDateTime]
    Status: Optional[CapacityReservationBillingRequestStatus]
    StatusMessage: Optional[String]
    CapacityReservationInfo: Optional[CapacityReservationInfo]


CapacityReservationBillingRequestSet = List[CapacityReservationBillingRequest]


class FleetCapacityReservation(TypedDict, total=False):
    CapacityReservationId: Optional[CapacityReservationId]
    AvailabilityZoneId: Optional[String]
    InstanceType: Optional[InstanceType]
    InstancePlatform: Optional[CapacityReservationInstancePlatform]
    AvailabilityZone: Optional[String]
    TotalInstanceCount: Optional[Integer]
    FulfilledCapacity: Optional[Double]
    EbsOptimized: Optional[Boolean]
    CreateDate: Optional[MillisecondDateTime]
    Weight: Optional[DoubleWithConstraints]
    Priority: Optional[IntegerWithConstraints]


FleetCapacityReservationSet = List[FleetCapacityReservation]


class CapacityReservationFleet(TypedDict, total=False):
    CapacityReservationFleetId: Optional[CapacityReservationFleetId]
    CapacityReservationFleetArn: Optional[String]
    State: Optional[CapacityReservationFleetState]
    TotalTargetCapacity: Optional[Integer]
    TotalFulfilledCapacity: Optional[Double]
    Tenancy: Optional[FleetCapacityReservationTenancy]
    EndDate: Optional[MillisecondDateTime]
    CreateTime: Optional[MillisecondDateTime]
    InstanceMatchCriteria: Optional[FleetInstanceMatchCriteria]
    AllocationStrategy: Optional[String]
    InstanceTypeSpecifications: Optional[FleetCapacityReservationSet]
    Tags: Optional[TagList]


CapacityReservationFleetSet = List[CapacityReservationFleet]


class CapacityReservationGroup(TypedDict, total=False):
    GroupArn: Optional[String]
    OwnerId: Optional[String]


CapacityReservationGroupSet = List[CapacityReservationGroup]
CapacityReservationIdSet = List[CapacityReservationId]


class CapacityReservationOptions(TypedDict, total=False):
    UsageStrategy: Optional[FleetCapacityReservationUsageStrategy]


class CapacityReservationOptionsRequest(TypedDict, total=False):
    UsageStrategy: Optional[FleetCapacityReservationUsageStrategy]


CapacityReservationSet = List[CapacityReservation]


class CapacityReservationTarget(TypedDict, total=False):
    CapacityReservationId: Optional[CapacityReservationId]
    CapacityReservationResourceGroupArn: Optional[String]


class CapacityReservationSpecification(TypedDict, total=False):
    CapacityReservationPreference: Optional[CapacityReservationPreference]
    CapacityReservationTarget: Optional[CapacityReservationTarget]


class CapacityReservationTargetResponse(TypedDict, total=False):
    CapacityReservationId: Optional[String]
    CapacityReservationResourceGroupArn: Optional[String]


class CapacityReservationSpecificationResponse(TypedDict, total=False):
    CapacityReservationPreference: Optional[CapacityReservationPreference]
    CapacityReservationTarget: Optional[CapacityReservationTargetResponse]


class CarrierGateway(TypedDict, total=False):
    CarrierGatewayId: Optional[CarrierGatewayId]
    VpcId: Optional[VpcId]
    State: Optional[CarrierGatewayState]
    OwnerId: Optional[String]
    Tags: Optional[TagList]


CarrierGatewayIdSet = List[CarrierGatewayId]
CarrierGatewaySet = List[CarrierGateway]


class CertificateAuthentication(TypedDict, total=False):
    ClientRootCertificateChain: Optional[String]


class CertificateAuthenticationRequest(TypedDict, total=False):
    ClientRootCertificateChainArn: Optional[String]


class CidrAuthorizationContext(TypedDict, total=False):
    Message: String
    Signature: String


class ClassicLinkDnsSupport(TypedDict, total=False):
    ClassicLinkDnsSupported: Optional[Boolean]
    VpcId: Optional[String]


ClassicLinkDnsSupportList = List[ClassicLinkDnsSupport]


class GroupIdentifier(TypedDict, total=False):
    GroupId: Optional[String]
    GroupName: Optional[String]


GroupIdentifierList = List[GroupIdentifier]


class ClassicLinkInstance(TypedDict, total=False):
    Groups: Optional[GroupIdentifierList]
    InstanceId: Optional[String]
    Tags: Optional[TagList]
    VpcId: Optional[String]


ClassicLinkInstanceList = List[ClassicLinkInstance]


class ClassicLoadBalancer(TypedDict, total=False):
    Name: Optional[String]


ClassicLoadBalancers = List[ClassicLoadBalancer]


class ClassicLoadBalancersConfig(TypedDict, total=False):
    ClassicLoadBalancers: Optional[ClassicLoadBalancers]


class ClientCertificateRevocationListStatus(TypedDict, total=False):
    Code: Optional[ClientCertificateRevocationListStatusCode]
    Message: Optional[String]


class ClientConnectOptions(TypedDict, total=False):
    Enabled: Optional[Boolean]
    LambdaFunctionArn: Optional[String]


class ClientVpnEndpointAttributeStatus(TypedDict, total=False):
    Code: Optional[ClientVpnEndpointAttributeStatusCode]
    Message: Optional[String]


class ClientConnectResponseOptions(TypedDict, total=False):
    Enabled: Optional[Boolean]
    LambdaFunctionArn: Optional[String]
    Status: Optional[ClientVpnEndpointAttributeStatus]


class ClientData(TypedDict, total=False):
    Comment: Optional[String]
    UploadEnd: Optional[DateTime]
    UploadSize: Optional[Double]
    UploadStart: Optional[DateTime]


class ClientLoginBannerOptions(TypedDict, total=False):
    Enabled: Optional[Boolean]
    BannerText: Optional[String]


class ClientLoginBannerResponseOptions(TypedDict, total=False):
    Enabled: Optional[Boolean]
    BannerText: Optional[String]


class FederatedAuthentication(TypedDict, total=False):
    SamlProviderArn: Optional[String]
    SelfServiceSamlProviderArn: Optional[String]


class DirectoryServiceAuthentication(TypedDict, total=False):
    DirectoryId: Optional[String]


class ClientVpnAuthentication(TypedDict, total=False):
    Type: Optional[ClientVpnAuthenticationType]
    ActiveDirectory: Optional[DirectoryServiceAuthentication]
    MutualAuthentication: Optional[CertificateAuthentication]
    FederatedAuthentication: Optional[FederatedAuthentication]


ClientVpnAuthenticationList = List[ClientVpnAuthentication]


class FederatedAuthenticationRequest(TypedDict, total=False):
    SAMLProviderArn: Optional[String]
    SelfServiceSAMLProviderArn: Optional[String]


class DirectoryServiceAuthenticationRequest(TypedDict, total=False):
    DirectoryId: Optional[String]


class ClientVpnAuthenticationRequest(TypedDict, total=False):
    Type: Optional[ClientVpnAuthenticationType]
    ActiveDirectory: Optional[DirectoryServiceAuthenticationRequest]
    MutualAuthentication: Optional[CertificateAuthenticationRequest]
    FederatedAuthentication: Optional[FederatedAuthenticationRequest]


ClientVpnAuthenticationRequestList = List[ClientVpnAuthenticationRequest]


class ClientVpnConnectionStatus(TypedDict, total=False):
    Code: Optional[ClientVpnConnectionStatusCode]
    Message: Optional[String]


class ClientVpnConnection(TypedDict, total=False):
    ClientVpnEndpointId: Optional[String]
    Timestamp: Optional[String]
    ConnectionId: Optional[String]
    Username: Optional[String]
    ConnectionEstablishedTime: Optional[String]
    IngressBytes: Optional[String]
    EgressBytes: Optional[String]
    IngressPackets: Optional[String]
    EgressPackets: Optional[String]
    ClientIp: Optional[String]
    CommonName: Optional[String]
    Status: Optional[ClientVpnConnectionStatus]
    ConnectionEndTime: Optional[String]
    PostureComplianceStatuses: Optional[ValueStringList]


ClientVpnConnectionSet = List[ClientVpnConnection]


class ConnectionLogResponseOptions(TypedDict, total=False):
    Enabled: Optional[Boolean]
    CloudwatchLogGroup: Optional[String]
    CloudwatchLogStream: Optional[String]


class ClientVpnEndpointStatus(TypedDict, total=False):
    Code: Optional[ClientVpnEndpointStatusCode]
    Message: Optional[String]


class ClientVpnEndpoint(TypedDict, total=False):
    ClientVpnEndpointId: Optional[String]
    Description: Optional[String]
    Status: Optional[ClientVpnEndpointStatus]
    CreationTime: Optional[String]
    DeletionTime: Optional[String]
    DnsName: Optional[String]
    ClientCidrBlock: Optional[String]
    DnsServers: Optional[ValueStringList]
    SplitTunnel: Optional[Boolean]
    VpnProtocol: Optional[VpnProtocol]
    TransportProtocol: Optional[TransportProtocol]
    VpnPort: Optional[Integer]
    AssociatedTargetNetworks: Optional[AssociatedTargetNetworkSet]
    ServerCertificateArn: Optional[String]
    AuthenticationOptions: Optional[ClientVpnAuthenticationList]
    ConnectionLogOptions: Optional[ConnectionLogResponseOptions]
    Tags: Optional[TagList]
    SecurityGroupIds: Optional[ClientVpnSecurityGroupIdSet]
    VpcId: Optional[VpcId]
    SelfServicePortalUrl: Optional[String]
    ClientConnectOptions: Optional[ClientConnectResponseOptions]
    SessionTimeoutHours: Optional[Integer]
    ClientLoginBannerOptions: Optional[ClientLoginBannerResponseOptions]


ClientVpnEndpointIdList = List[ClientVpnEndpointId]


class ClientVpnRouteStatus(TypedDict, total=False):
    Code: Optional[ClientVpnRouteStatusCode]
    Message: Optional[String]


class ClientVpnRoute(TypedDict, total=False):
    ClientVpnEndpointId: Optional[String]
    DestinationCidr: Optional[String]
    TargetSubnet: Optional[String]
    Type: Optional[String]
    Origin: Optional[String]
    Status: Optional[ClientVpnRouteStatus]
    Description: Optional[String]


ClientVpnRouteSet = List[ClientVpnRoute]


class CloudWatchLogOptions(TypedDict, total=False):
    LogEnabled: Optional[Boolean]
    LogGroupArn: Optional[String]
    LogOutputFormat: Optional[String]


class CloudWatchLogOptionsSpecification(TypedDict, total=False):
    LogEnabled: Optional[Boolean]
    LogGroupArn: Optional[CloudWatchLogGroupArn]
    LogOutputFormat: Optional[String]


class CoipAddressUsage(TypedDict, total=False):
    AllocationId: Optional[String]
    AwsAccountId: Optional[String]
    AwsService: Optional[String]
    CoIp: Optional[String]


CoipAddressUsageSet = List[CoipAddressUsage]


class CoipCidr(TypedDict, total=False):
    Cidr: Optional[String]
    CoipPoolId: Optional[Ipv4PoolCoipId]
    LocalGatewayRouteTableId: Optional[String]


class CoipPool(TypedDict, total=False):
    PoolId: Optional[Ipv4PoolCoipId]
    PoolCidrs: Optional[ValueStringList]
    LocalGatewayRouteTableId: Optional[LocalGatewayRoutetableId]
    Tags: Optional[TagList]
    PoolArn: Optional[ResourceArn]


CoipPoolIdSet = List[Ipv4PoolCoipId]
CoipPoolSet = List[CoipPool]


class ConfirmProductInstanceRequest(ServiceRequest):
    InstanceId: InstanceId
    ProductCode: String
    DryRun: Optional[Boolean]


class ConfirmProductInstanceResult(TypedDict, total=False):
    Return: Optional[Boolean]
    OwnerId: Optional[String]


class ConnectionLogOptions(TypedDict, total=False):
    Enabled: Optional[Boolean]
    CloudwatchLogGroup: Optional[String]
    CloudwatchLogStream: Optional[String]


class ConnectionNotification(TypedDict, total=False):
    ConnectionNotificationId: Optional[String]
    ServiceId: Optional[String]
    VpcEndpointId: Optional[String]
    ConnectionNotificationType: Optional[ConnectionNotificationType]
    ConnectionNotificationArn: Optional[String]
    ConnectionEvents: Optional[ValueStringList]
    ConnectionNotificationState: Optional[ConnectionNotificationState]


ConnectionNotificationIdsList = List[ConnectionNotificationId]
ConnectionNotificationSet = List[ConnectionNotification]


class ConnectionTrackingConfiguration(TypedDict, total=False):
    TcpEstablishedTimeout: Optional[Integer]
    UdpStreamTimeout: Optional[Integer]
    UdpTimeout: Optional[Integer]


class ConnectionTrackingSpecification(TypedDict, total=False):
    TcpEstablishedTimeout: Optional[Integer]
    UdpTimeout: Optional[Integer]
    UdpStreamTimeout: Optional[Integer]


class ConnectionTrackingSpecificationRequest(TypedDict, total=False):
    TcpEstablishedTimeout: Optional[Integer]
    UdpStreamTimeout: Optional[Integer]
    UdpTimeout: Optional[Integer]


class ConnectionTrackingSpecificationResponse(TypedDict, total=False):
    TcpEstablishedTimeout: Optional[Integer]
    UdpStreamTimeout: Optional[Integer]
    UdpTimeout: Optional[Integer]


ConversionIdStringList = List[ConversionTaskId]


class DiskImageVolumeDescription(TypedDict, total=False):
    Id: Optional[String]
    Size: Optional[Long]


class DiskImageDescription(TypedDict, total=False):
    Checksum: Optional[String]
    Format: Optional[DiskImageFormat]
    ImportManifestUrl: Optional[ImportManifestUrl]
    Size: Optional[Long]


class ImportVolumeTaskDetails(TypedDict, total=False):
    AvailabilityZone: Optional[String]
    BytesConverted: Optional[Long]
    Description: Optional[String]
    Image: Optional[DiskImageDescription]
    Volume: Optional[DiskImageVolumeDescription]


class ImportInstanceVolumeDetailItem(TypedDict, total=False):
    AvailabilityZone: Optional[String]
    BytesConverted: Optional[Long]
    Description: Optional[String]
    Image: Optional[DiskImageDescription]
    Status: Optional[String]
    StatusMessage: Optional[String]
    Volume: Optional[DiskImageVolumeDescription]


ImportInstanceVolumeDetailSet = List[ImportInstanceVolumeDetailItem]


class ImportInstanceTaskDetails(TypedDict, total=False):
    Description: Optional[String]
    InstanceId: Optional[String]
    Platform: Optional[PlatformValues]
    Volumes: Optional[ImportInstanceVolumeDetailSet]


class ConversionTask(TypedDict, total=False):
    ConversionTaskId: Optional[String]
    ExpirationTime: Optional[String]
    ImportInstance: Optional[ImportInstanceTaskDetails]
    ImportVolume: Optional[ImportVolumeTaskDetails]
    State: Optional[ConversionTaskState]
    StatusMessage: Optional[String]
    Tags: Optional[TagList]


class CopyFpgaImageRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    SourceFpgaImageId: String
    Description: Optional[String]
    Name: Optional[String]
    SourceRegion: String
    ClientToken: Optional[String]


class CopyFpgaImageResult(TypedDict, total=False):
    FpgaImageId: Optional[String]


class CopyImageRequest(ServiceRequest):
    ClientToken: Optional[String]
    Description: Optional[String]
    Encrypted: Optional[Boolean]
    KmsKeyId: Optional[KmsKeyId]
    Name: String
    SourceImageId: String
    SourceRegion: String
    DestinationOutpostArn: Optional[String]
    CopyImageTags: Optional[Boolean]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class CopyImageResult(TypedDict, total=False):
    ImageId: Optional[String]


class CopySnapshotRequest(ServiceRequest):
    Description: Optional[String]
    DestinationOutpostArn: Optional[String]
    DestinationRegion: Optional[String]
    Encrypted: Optional[Boolean]
    KmsKeyId: Optional[KmsKeyId]
    PresignedUrl: Optional[CopySnapshotRequestPSU]
    SourceRegion: String
    SourceSnapshotId: String
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class CopySnapshotResult(TypedDict, total=False):
    Tags: Optional[TagList]
    SnapshotId: Optional[String]


CoreCountList = List[CoreCount]
CpuManufacturerSet = List[CpuManufacturer]


class CpuOptions(TypedDict, total=False):
    CoreCount: Optional[Integer]
    ThreadsPerCore: Optional[Integer]
    AmdSevSnp: Optional[AmdSevSnpSpecification]


class CpuOptionsRequest(TypedDict, total=False):
    CoreCount: Optional[Integer]
    ThreadsPerCore: Optional[Integer]
    AmdSevSnp: Optional[AmdSevSnpSpecification]


class CreateCapacityReservationBySplittingRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]
    SourceCapacityReservationId: CapacityReservationId
    InstanceCount: Integer
    TagSpecifications: Optional[TagSpecificationList]


class CreateCapacityReservationBySplittingResult(TypedDict, total=False):
    SourceCapacityReservation: Optional[CapacityReservation]
    DestinationCapacityReservation: Optional[CapacityReservation]
    InstanceCount: Optional[Integer]


class ReservationFleetInstanceSpecification(TypedDict, total=False):
    InstanceType: Optional[InstanceType]
    InstancePlatform: Optional[CapacityReservationInstancePlatform]
    Weight: Optional[DoubleWithConstraints]
    AvailabilityZone: Optional[String]
    AvailabilityZoneId: Optional[String]
    EbsOptimized: Optional[Boolean]
    Priority: Optional[IntegerWithConstraints]


ReservationFleetInstanceSpecificationList = List[ReservationFleetInstanceSpecification]


class CreateCapacityReservationFleetRequest(ServiceRequest):
    AllocationStrategy: Optional[String]
    ClientToken: Optional[String]
    InstanceTypeSpecifications: ReservationFleetInstanceSpecificationList
    Tenancy: Optional[FleetCapacityReservationTenancy]
    TotalTargetCapacity: Integer
    EndDate: Optional[MillisecondDateTime]
    InstanceMatchCriteria: Optional[FleetInstanceMatchCriteria]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class CreateCapacityReservationFleetResult(TypedDict, total=False):
    CapacityReservationFleetId: Optional[CapacityReservationFleetId]
    State: Optional[CapacityReservationFleetState]
    TotalTargetCapacity: Optional[Integer]
    TotalFulfilledCapacity: Optional[Double]
    InstanceMatchCriteria: Optional[FleetInstanceMatchCriteria]
    AllocationStrategy: Optional[String]
    CreateTime: Optional[MillisecondDateTime]
    EndDate: Optional[MillisecondDateTime]
    Tenancy: Optional[FleetCapacityReservationTenancy]
    FleetCapacityReservations: Optional[FleetCapacityReservationSet]
    Tags: Optional[TagList]


class CreateCapacityReservationRequest(ServiceRequest):
    ClientToken: Optional[String]
    InstanceType: String
    InstancePlatform: CapacityReservationInstancePlatform
    AvailabilityZone: Optional[AvailabilityZoneName]
    AvailabilityZoneId: Optional[AvailabilityZoneId]
    Tenancy: Optional[CapacityReservationTenancy]
    InstanceCount: Integer
    EbsOptimized: Optional[Boolean]
    EphemeralStorage: Optional[Boolean]
    EndDate: Optional[DateTime]
    EndDateType: Optional[EndDateType]
    InstanceMatchCriteria: Optional[InstanceMatchCriteria]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]
    OutpostArn: Optional[OutpostArn]
    PlacementGroupArn: Optional[PlacementGroupArn]


class CreateCapacityReservationResult(TypedDict, total=False):
    CapacityReservation: Optional[CapacityReservation]


class CreateCarrierGatewayRequest(ServiceRequest):
    VpcId: VpcId
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]


class CreateCarrierGatewayResult(TypedDict, total=False):
    CarrierGateway: Optional[CarrierGateway]


class CreateClientVpnEndpointRequest(ServiceRequest):
    ClientCidrBlock: String
    ServerCertificateArn: String
    AuthenticationOptions: ClientVpnAuthenticationRequestList
    ConnectionLogOptions: ConnectionLogOptions
    DnsServers: Optional[ValueStringList]
    TransportProtocol: Optional[TransportProtocol]
    VpnPort: Optional[Integer]
    Description: Optional[String]
    SplitTunnel: Optional[Boolean]
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]
    SecurityGroupIds: Optional[ClientVpnSecurityGroupIdSet]
    VpcId: Optional[VpcId]
    SelfServicePortal: Optional[SelfServicePortal]
    ClientConnectOptions: Optional[ClientConnectOptions]
    SessionTimeoutHours: Optional[Integer]
    ClientLoginBannerOptions: Optional[ClientLoginBannerOptions]


class CreateClientVpnEndpointResult(TypedDict, total=False):
    ClientVpnEndpointId: Optional[String]
    Status: Optional[ClientVpnEndpointStatus]
    DnsName: Optional[String]


class CreateClientVpnRouteRequest(ServiceRequest):
    ClientVpnEndpointId: ClientVpnEndpointId
    DestinationCidrBlock: String
    TargetVpcSubnetId: SubnetId
    Description: Optional[String]
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]


class CreateClientVpnRouteResult(TypedDict, total=False):
    Status: Optional[ClientVpnRouteStatus]


class CreateCoipCidrRequest(ServiceRequest):
    Cidr: String
    CoipPoolId: Ipv4PoolCoipId
    DryRun: Optional[Boolean]


class CreateCoipCidrResult(TypedDict, total=False):
    CoipCidr: Optional[CoipCidr]


class CreateCoipPoolRequest(ServiceRequest):
    LocalGatewayRouteTableId: LocalGatewayRoutetableId
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class CreateCoipPoolResult(TypedDict, total=False):
    CoipPool: Optional[CoipPool]


class CreateCustomerGatewayRequest(ServiceRequest):
    BgpAsn: Optional[Integer]
    PublicIp: Optional[String]
    CertificateArn: Optional[String]
    Type: GatewayType
    TagSpecifications: Optional[TagSpecificationList]
    DeviceName: Optional[String]
    IpAddress: Optional[String]
    BgpAsnExtended: Optional[Long]
    DryRun: Optional[Boolean]


class CustomerGateway(TypedDict, total=False):
    CertificateArn: Optional[String]
    DeviceName: Optional[String]
    Tags: Optional[TagList]
    BgpAsnExtended: Optional[String]
    CustomerGatewayId: Optional[String]
    State: Optional[String]
    Type: Optional[String]
    IpAddress: Optional[String]
    BgpAsn: Optional[String]


class CreateCustomerGatewayResult(TypedDict, total=False):
    CustomerGateway: Optional[CustomerGateway]


class CreateDefaultSubnetRequest(ServiceRequest):
    AvailabilityZone: AvailabilityZoneName
    DryRun: Optional[Boolean]
    Ipv6Native: Optional[Boolean]


class PrivateDnsNameOptionsOnLaunch(TypedDict, total=False):
    HostnameType: Optional[HostnameType]
    EnableResourceNameDnsARecord: Optional[Boolean]
    EnableResourceNameDnsAAAARecord: Optional[Boolean]


SubnetIpv6CidrBlockAssociationSet = List[SubnetIpv6CidrBlockAssociation]


class Subnet(TypedDict, total=False):
    AvailabilityZoneId: Optional[String]
    EnableLniAtDeviceIndex: Optional[Integer]
    MapCustomerOwnedIpOnLaunch: Optional[Boolean]
    CustomerOwnedIpv4Pool: Optional[CoipPoolId]
    OwnerId: Optional[String]
    AssignIpv6AddressOnCreation: Optional[Boolean]
    Ipv6CidrBlockAssociationSet: Optional[SubnetIpv6CidrBlockAssociationSet]
    Tags: Optional[TagList]
    SubnetArn: Optional[String]
    OutpostArn: Optional[String]
    EnableDns64: Optional[Boolean]
    Ipv6Native: Optional[Boolean]
    PrivateDnsNameOptionsOnLaunch: Optional[PrivateDnsNameOptionsOnLaunch]
    SubnetId: Optional[String]
    State: Optional[SubnetState]
    VpcId: Optional[String]
    CidrBlock: Optional[String]
    AvailableIpAddressCount: Optional[Integer]
    AvailabilityZone: Optional[String]
    DefaultForAz: Optional[Boolean]
    MapPublicIpOnLaunch: Optional[Boolean]


class CreateDefaultSubnetResult(TypedDict, total=False):
    Subnet: Optional[Subnet]


class CreateDefaultVpcRequest(ServiceRequest):
    DryRun: Optional[Boolean]


VpcCidrBlockAssociationSet = List[VpcCidrBlockAssociation]
VpcIpv6CidrBlockAssociationSet = List[VpcIpv6CidrBlockAssociation]


class Vpc(TypedDict, total=False):
    OwnerId: Optional[String]
    InstanceTenancy: Optional[Tenancy]
    Ipv6CidrBlockAssociationSet: Optional[VpcIpv6CidrBlockAssociationSet]
    CidrBlockAssociationSet: Optional[VpcCidrBlockAssociationSet]
    IsDefault: Optional[Boolean]
    Tags: Optional[TagList]
    VpcId: Optional[String]
    State: Optional[VpcState]
    CidrBlock: Optional[String]
    DhcpOptionsId: Optional[String]


class CreateDefaultVpcResult(TypedDict, total=False):
    Vpc: Optional[Vpc]


class NewDhcpConfiguration(TypedDict, total=False):
    Key: Optional[String]
    Values: Optional[ValueStringList]


NewDhcpConfigurationList = List[NewDhcpConfiguration]


class CreateDhcpOptionsRequest(ServiceRequest):
    DhcpConfigurations: NewDhcpConfigurationList
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


DhcpConfigurationValueList = List[AttributeValue]


class DhcpConfiguration(TypedDict, total=False):
    Key: Optional[String]
    Values: Optional[DhcpConfigurationValueList]


DhcpConfigurationList = List[DhcpConfiguration]


class DhcpOptions(TypedDict, total=False):
    OwnerId: Optional[String]
    Tags: Optional[TagList]
    DhcpOptionsId: Optional[String]
    DhcpConfigurations: Optional[DhcpConfigurationList]


class CreateDhcpOptionsResult(TypedDict, total=False):
    DhcpOptions: Optional[DhcpOptions]


class CreateEgressOnlyInternetGatewayRequest(ServiceRequest):
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]
    VpcId: VpcId
    TagSpecifications: Optional[TagSpecificationList]


class InternetGatewayAttachment(TypedDict, total=False):
    State: Optional[AttachmentStatus]
    VpcId: Optional[String]


InternetGatewayAttachmentList = List[InternetGatewayAttachment]


class EgressOnlyInternetGateway(TypedDict, total=False):
    Attachments: Optional[InternetGatewayAttachmentList]
    EgressOnlyInternetGatewayId: Optional[EgressOnlyInternetGatewayId]
    Tags: Optional[TagList]


class CreateEgressOnlyInternetGatewayResult(TypedDict, total=False):
    ClientToken: Optional[String]
    EgressOnlyInternetGateway: Optional[EgressOnlyInternetGateway]


class NetworkBandwidthGbps(TypedDict, total=False):
    Min: Optional[Double]
    Max: Optional[Double]


class TotalLocalStorageGB(TypedDict, total=False):
    Min: Optional[Double]
    Max: Optional[Double]


LocalStorageTypeSet = List[LocalStorageType]


class NetworkInterfaceCount(TypedDict, total=False):
    Min: Optional[Integer]
    Max: Optional[Integer]


InstanceGenerationSet = List[InstanceGeneration]
ExcludedInstanceTypeSet = List[ExcludedInstanceType]


class MemoryGiBPerVCpu(TypedDict, total=False):
    Min: Optional[Double]
    Max: Optional[Double]


class MemoryMiB(TypedDict, total=False):
    Min: Optional[Integer]
    Max: Optional[Integer]


class VCpuCountRange(TypedDict, total=False):
    Min: Optional[Integer]
    Max: Optional[Integer]


class InstanceRequirements(TypedDict, total=False):
    VCpuCount: Optional[VCpuCountRange]
    MemoryMiB: Optional[MemoryMiB]
    CpuManufacturers: Optional[CpuManufacturerSet]
    MemoryGiBPerVCpu: Optional[MemoryGiBPerVCpu]
    ExcludedInstanceTypes: Optional[ExcludedInstanceTypeSet]
    InstanceGenerations: Optional[InstanceGenerationSet]
    SpotMaxPricePercentageOverLowestPrice: Optional[Integer]
    OnDemandMaxPricePercentageOverLowestPrice: Optional[Integer]
    BareMetal: Optional[BareMetal]
    BurstablePerformance: Optional[BurstablePerformance]
    RequireHibernateSupport: Optional[Boolean]
    NetworkInterfaceCount: Optional[NetworkInterfaceCount]
    LocalStorage: Optional[LocalStorage]
    LocalStorageTypes: Optional[LocalStorageTypeSet]
    TotalLocalStorageGB: Optional[TotalLocalStorageGB]
    BaselineEbsBandwidthMbps: Optional[BaselineEbsBandwidthMbps]
    AcceleratorTypes: Optional[AcceleratorTypeSet]
    AcceleratorCount: Optional[AcceleratorCount]
    AcceleratorManufacturers: Optional[AcceleratorManufacturerSet]
    AcceleratorNames: Optional[AcceleratorNameSet]
    AcceleratorTotalMemoryMiB: Optional[AcceleratorTotalMemoryMiB]
    NetworkBandwidthGbps: Optional[NetworkBandwidthGbps]
    AllowedInstanceTypes: Optional[AllowedInstanceTypeSet]
    MaxSpotPriceAsPercentageOfOptimalOnDemandPrice: Optional[Integer]


class PlacementResponse(TypedDict, total=False):
    GroupName: Optional[PlacementGroupName]


class FleetLaunchTemplateOverrides(TypedDict, total=False):
    InstanceType: Optional[InstanceType]
    MaxPrice: Optional[String]
    SubnetId: Optional[String]
    AvailabilityZone: Optional[String]
    WeightedCapacity: Optional[Double]
    Priority: Optional[Double]
    Placement: Optional[PlacementResponse]
    InstanceRequirements: Optional[InstanceRequirements]
    ImageId: Optional[ImageId]


class FleetLaunchTemplateSpecification(TypedDict, total=False):
    LaunchTemplateId: Optional[String]
    LaunchTemplateName: Optional[LaunchTemplateName]
    Version: Optional[String]


class LaunchTemplateAndOverridesResponse(TypedDict, total=False):
    LaunchTemplateSpecification: Optional[FleetLaunchTemplateSpecification]
    Overrides: Optional[FleetLaunchTemplateOverrides]


class CreateFleetError(TypedDict, total=False):
    LaunchTemplateAndOverrides: Optional[LaunchTemplateAndOverridesResponse]
    Lifecycle: Optional[InstanceLifecycle]
    ErrorCode: Optional[String]
    ErrorMessage: Optional[String]


CreateFleetErrorsSet = List[CreateFleetError]
InstanceIdsSet = List[InstanceId]


class CreateFleetInstance(TypedDict, total=False):
    LaunchTemplateAndOverrides: Optional[LaunchTemplateAndOverridesResponse]
    Lifecycle: Optional[InstanceLifecycle]
    InstanceIds: Optional[InstanceIdsSet]
    InstanceType: Optional[InstanceType]
    Platform: Optional[PlatformValues]


CreateFleetInstancesSet = List[CreateFleetInstance]


class TargetCapacitySpecificationRequest(TypedDict, total=False):
    TotalTargetCapacity: Integer
    OnDemandTargetCapacity: Optional[Integer]
    SpotTargetCapacity: Optional[Integer]
    DefaultTargetCapacityType: Optional[DefaultTargetCapacityType]
    TargetCapacityUnitType: Optional[TargetCapacityUnitType]


class NetworkBandwidthGbpsRequest(TypedDict, total=False):
    Min: Optional[Double]
    Max: Optional[Double]


class TotalLocalStorageGBRequest(TypedDict, total=False):
    Min: Optional[Double]
    Max: Optional[Double]


class NetworkInterfaceCountRequest(TypedDict, total=False):
    Min: Optional[Integer]
    Max: Optional[Integer]


class MemoryGiBPerVCpuRequest(TypedDict, total=False):
    Min: Optional[Double]
    Max: Optional[Double]


class MemoryMiBRequest(TypedDict, total=False):
    Min: Integer
    Max: Optional[Integer]


class VCpuCountRangeRequest(TypedDict, total=False):
    Min: Integer
    Max: Optional[Integer]


class InstanceRequirementsRequest(TypedDict, total=False):
    VCpuCount: VCpuCountRangeRequest
    MemoryMiB: MemoryMiBRequest
    CpuManufacturers: Optional[CpuManufacturerSet]
    MemoryGiBPerVCpu: Optional[MemoryGiBPerVCpuRequest]
    ExcludedInstanceTypes: Optional[ExcludedInstanceTypeSet]
    InstanceGenerations: Optional[InstanceGenerationSet]
    SpotMaxPricePercentageOverLowestPrice: Optional[Integer]
    OnDemandMaxPricePercentageOverLowestPrice: Optional[Integer]
    BareMetal: Optional[BareMetal]
    BurstablePerformance: Optional[BurstablePerformance]
    RequireHibernateSupport: Optional[Boolean]
    NetworkInterfaceCount: Optional[NetworkInterfaceCountRequest]
    LocalStorage: Optional[LocalStorage]
    LocalStorageTypes: Optional[LocalStorageTypeSet]
    TotalLocalStorageGB: Optional[TotalLocalStorageGBRequest]
    BaselineEbsBandwidthMbps: Optional[BaselineEbsBandwidthMbpsRequest]
    AcceleratorTypes: Optional[AcceleratorTypeSet]
    AcceleratorCount: Optional[AcceleratorCountRequest]
    AcceleratorManufacturers: Optional[AcceleratorManufacturerSet]
    AcceleratorNames: Optional[AcceleratorNameSet]
    AcceleratorTotalMemoryMiB: Optional[AcceleratorTotalMemoryMiBRequest]
    NetworkBandwidthGbps: Optional[NetworkBandwidthGbpsRequest]
    AllowedInstanceTypes: Optional[AllowedInstanceTypeSet]
    MaxSpotPriceAsPercentageOfOptimalOnDemandPrice: Optional[Integer]


class Placement(TypedDict, total=False):
    Affinity: Optional[String]
    GroupName: Optional[PlacementGroupName]
    PartitionNumber: Optional[Integer]
    HostId: Optional[String]
    Tenancy: Optional[Tenancy]
    SpreadDomain: Optional[String]
    HostResourceGroupArn: Optional[String]
    GroupId: Optional[PlacementGroupId]
    AvailabilityZone: Optional[String]


class FleetLaunchTemplateOverridesRequest(TypedDict, total=False):
    InstanceType: Optional[InstanceType]
    MaxPrice: Optional[String]
    SubnetId: Optional[SubnetId]
    AvailabilityZone: Optional[String]
    WeightedCapacity: Optional[Double]
    Priority: Optional[Double]
    Placement: Optional[Placement]
    InstanceRequirements: Optional[InstanceRequirementsRequest]
    ImageId: Optional[ImageId]


FleetLaunchTemplateOverridesListRequest = List[FleetLaunchTemplateOverridesRequest]


class FleetLaunchTemplateSpecificationRequest(TypedDict, total=False):
    LaunchTemplateId: Optional[LaunchTemplateId]
    LaunchTemplateName: Optional[LaunchTemplateName]
    Version: Optional[String]


class FleetLaunchTemplateConfigRequest(TypedDict, total=False):
    LaunchTemplateSpecification: Optional[FleetLaunchTemplateSpecificationRequest]
    Overrides: Optional[FleetLaunchTemplateOverridesListRequest]


FleetLaunchTemplateConfigListRequest = List[FleetLaunchTemplateConfigRequest]


class OnDemandOptionsRequest(TypedDict, total=False):
    AllocationStrategy: Optional[FleetOnDemandAllocationStrategy]
    CapacityReservationOptions: Optional[CapacityReservationOptionsRequest]
    SingleInstanceType: Optional[Boolean]
    SingleAvailabilityZone: Optional[Boolean]
    MinTargetCapacity: Optional[Integer]
    MaxTotalPrice: Optional[String]


class FleetSpotCapacityRebalanceRequest(TypedDict, total=False):
    ReplacementStrategy: Optional[FleetReplacementStrategy]
    TerminationDelay: Optional[Integer]


class FleetSpotMaintenanceStrategiesRequest(TypedDict, total=False):
    CapacityRebalance: Optional[FleetSpotCapacityRebalanceRequest]


class SpotOptionsRequest(TypedDict, total=False):
    AllocationStrategy: Optional[SpotAllocationStrategy]
    MaintenanceStrategies: Optional[FleetSpotMaintenanceStrategiesRequest]
    InstanceInterruptionBehavior: Optional[SpotInstanceInterruptionBehavior]
    InstancePoolsToUseCount: Optional[Integer]
    SingleInstanceType: Optional[Boolean]
    SingleAvailabilityZone: Optional[Boolean]
    MinTargetCapacity: Optional[Integer]
    MaxTotalPrice: Optional[String]


class CreateFleetRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]
    SpotOptions: Optional[SpotOptionsRequest]
    OnDemandOptions: Optional[OnDemandOptionsRequest]
    ExcessCapacityTerminationPolicy: Optional[FleetExcessCapacityTerminationPolicy]
    LaunchTemplateConfigs: FleetLaunchTemplateConfigListRequest
    TargetCapacitySpecification: TargetCapacitySpecificationRequest
    TerminateInstancesWithExpiration: Optional[Boolean]
    Type: Optional[FleetType]
    ValidFrom: Optional[DateTime]
    ValidUntil: Optional[DateTime]
    ReplaceUnhealthyInstances: Optional[Boolean]
    TagSpecifications: Optional[TagSpecificationList]
    Context: Optional[String]


class CreateFleetResult(TypedDict, total=False):
    FleetId: Optional[FleetId]
    Errors: Optional[CreateFleetErrorsSet]
    Instances: Optional[CreateFleetInstancesSet]


class DestinationOptionsRequest(TypedDict, total=False):
    FileFormat: Optional[DestinationFileFormat]
    HiveCompatiblePartitions: Optional[Boolean]
    PerHourPartition: Optional[Boolean]


FlowLogResourceIds = List[FlowLogResourceId]


class CreateFlowLogsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]
    DeliverLogsPermissionArn: Optional[String]
    DeliverCrossAccountRole: Optional[String]
    LogGroupName: Optional[String]
    ResourceIds: FlowLogResourceIds
    ResourceType: FlowLogsResourceType
    TrafficType: Optional[TrafficType]
    LogDestinationType: Optional[LogDestinationType]
    LogDestination: Optional[String]
    LogFormat: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]
    MaxAggregationInterval: Optional[Integer]
    DestinationOptions: Optional[DestinationOptionsRequest]


class CreateFlowLogsResult(TypedDict, total=False):
    ClientToken: Optional[String]
    FlowLogIds: Optional[ValueStringList]
    Unsuccessful: Optional[UnsuccessfulItemSet]


class StorageLocation(TypedDict, total=False):
    Bucket: Optional[String]
    Key: Optional[String]


class CreateFpgaImageRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InputStorageLocation: StorageLocation
    LogsStorageLocation: Optional[StorageLocation]
    Description: Optional[String]
    Name: Optional[String]
    ClientToken: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]


class CreateFpgaImageResult(TypedDict, total=False):
    FpgaImageId: Optional[String]
    FpgaImageGlobalId: Optional[String]


class CreateImageRequest(ServiceRequest):
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]
    InstanceId: InstanceId
    Name: String
    Description: Optional[String]
    NoReboot: Optional[Boolean]
    BlockDeviceMappings: Optional[BlockDeviceMappingRequestList]


class CreateImageResult(TypedDict, total=False):
    ImageId: Optional[String]


SecurityGroupIdStringListRequest = List[SecurityGroupId]


class CreateInstanceConnectEndpointRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    SubnetId: SubnetId
    SecurityGroupIds: Optional[SecurityGroupIdStringListRequest]
    PreserveClientIp: Optional[Boolean]
    ClientToken: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]


SecurityGroupIdSet = List[SecurityGroupId]
NetworkInterfaceIdSet = List[String]


class Ec2InstanceConnectEndpoint(TypedDict, total=False):
    OwnerId: Optional[String]
    InstanceConnectEndpointId: Optional[InstanceConnectEndpointId]
    InstanceConnectEndpointArn: Optional[ResourceArn]
    State: Optional[Ec2InstanceConnectEndpointState]
    StateMessage: Optional[String]
    DnsName: Optional[String]
    FipsDnsName: Optional[String]
    NetworkInterfaceIds: Optional[NetworkInterfaceIdSet]
    VpcId: Optional[VpcId]
    AvailabilityZone: Optional[String]
    CreatedAt: Optional[MillisecondDateTime]
    SubnetId: Optional[SubnetId]
    PreserveClientIp: Optional[Boolean]
    SecurityGroupIds: Optional[SecurityGroupIdSet]
    Tags: Optional[TagList]


class CreateInstanceConnectEndpointResult(TypedDict, total=False):
    InstanceConnectEndpoint: Optional[Ec2InstanceConnectEndpoint]
    ClientToken: Optional[String]


class InstanceEventWindowTimeRangeRequest(TypedDict, total=False):
    StartWeekDay: Optional[WeekDay]
    StartHour: Optional[Hour]
    EndWeekDay: Optional[WeekDay]
    EndHour: Optional[Hour]


InstanceEventWindowTimeRangeRequestSet = List[InstanceEventWindowTimeRangeRequest]


class CreateInstanceEventWindowRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Name: Optional[String]
    TimeRanges: Optional[InstanceEventWindowTimeRangeRequestSet]
    CronExpression: Optional[InstanceEventWindowCronExpression]
    TagSpecifications: Optional[TagSpecificationList]


class CreateInstanceEventWindowResult(TypedDict, total=False):
    InstanceEventWindow: Optional[InstanceEventWindow]


class ExportToS3TaskSpecification(TypedDict, total=False):
    DiskImageFormat: Optional[DiskImageFormat]
    ContainerFormat: Optional[ContainerFormat]
    S3Bucket: Optional[String]
    S3Prefix: Optional[String]


class CreateInstanceExportTaskRequest(ServiceRequest):
    TagSpecifications: Optional[TagSpecificationList]
    Description: Optional[String]
    InstanceId: InstanceId
    TargetEnvironment: ExportEnvironment
    ExportToS3Task: ExportToS3TaskSpecification


class InstanceExportDetails(TypedDict, total=False):
    InstanceId: Optional[String]
    TargetEnvironment: Optional[ExportEnvironment]


class ExportToS3Task(TypedDict, total=False):
    ContainerFormat: Optional[ContainerFormat]
    DiskImageFormat: Optional[DiskImageFormat]
    S3Bucket: Optional[String]
    S3Key: Optional[String]


class ExportTask(TypedDict, total=False):
    Description: Optional[String]
    ExportTaskId: Optional[String]
    ExportToS3Task: Optional[ExportToS3Task]
    InstanceExportDetails: Optional[InstanceExportDetails]
    State: Optional[ExportTaskState]
    StatusMessage: Optional[String]
    Tags: Optional[TagList]


class CreateInstanceExportTaskResult(TypedDict, total=False):
    ExportTask: Optional[ExportTask]


class CreateInternetGatewayRequest(ServiceRequest):
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class InternetGateway(TypedDict, total=False):
    Attachments: Optional[InternetGatewayAttachmentList]
    InternetGatewayId: Optional[String]
    OwnerId: Optional[String]
    Tags: Optional[TagList]


class CreateInternetGatewayResult(TypedDict, total=False):
    InternetGateway: Optional[InternetGateway]


class CreateIpamExternalResourceVerificationTokenRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamId: IpamId
    TagSpecifications: Optional[TagSpecificationList]
    ClientToken: Optional[String]


class IpamExternalResourceVerificationToken(TypedDict, total=False):
    IpamExternalResourceVerificationTokenId: Optional[IpamExternalResourceVerificationTokenId]
    IpamExternalResourceVerificationTokenArn: Optional[ResourceArn]
    IpamId: Optional[IpamId]
    IpamArn: Optional[ResourceArn]
    IpamRegion: Optional[String]
    TokenValue: Optional[String]
    TokenName: Optional[String]
    NotAfter: Optional[MillisecondDateTime]
    Status: Optional[TokenState]
    Tags: Optional[TagList]
    State: Optional[IpamExternalResourceVerificationTokenState]


class CreateIpamExternalResourceVerificationTokenResult(TypedDict, total=False):
    IpamExternalResourceVerificationToken: Optional[IpamExternalResourceVerificationToken]


class IpamPoolSourceResourceRequest(TypedDict, total=False):
    ResourceId: Optional[String]
    ResourceType: Optional[IpamPoolSourceResourceType]
    ResourceRegion: Optional[String]
    ResourceOwner: Optional[String]


class RequestIpamResourceTag(TypedDict, total=False):
    Key: Optional[String]
    Value: Optional[String]


RequestIpamResourceTagList = List[RequestIpamResourceTag]


class CreateIpamPoolRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamScopeId: IpamScopeId
    Locale: Optional[String]
    SourceIpamPoolId: Optional[IpamPoolId]
    Description: Optional[String]
    AddressFamily: AddressFamily
    AutoImport: Optional[Boolean]
    PubliclyAdvertisable: Optional[Boolean]
    AllocationMinNetmaskLength: Optional[IpamNetmaskLength]
    AllocationMaxNetmaskLength: Optional[IpamNetmaskLength]
    AllocationDefaultNetmaskLength: Optional[IpamNetmaskLength]
    AllocationResourceTags: Optional[RequestIpamResourceTagList]
    TagSpecifications: Optional[TagSpecificationList]
    ClientToken: Optional[String]
    AwsService: Optional[IpamPoolAwsService]
    PublicIpSource: Optional[IpamPoolPublicIpSource]
    SourceResource: Optional[IpamPoolSourceResourceRequest]


class IpamPoolSourceResource(TypedDict, total=False):
    ResourceId: Optional[String]
    ResourceType: Optional[IpamPoolSourceResourceType]
    ResourceRegion: Optional[String]
    ResourceOwner: Optional[String]


class IpamResourceTag(TypedDict, total=False):
    Key: Optional[String]
    Value: Optional[String]


IpamResourceTagList = List[IpamResourceTag]


class IpamPool(TypedDict, total=False):
    OwnerId: Optional[String]
    IpamPoolId: Optional[IpamPoolId]
    SourceIpamPoolId: Optional[IpamPoolId]
    IpamPoolArn: Optional[ResourceArn]
    IpamScopeArn: Optional[ResourceArn]
    IpamScopeType: Optional[IpamScopeType]
    IpamArn: Optional[ResourceArn]
    IpamRegion: Optional[String]
    Locale: Optional[String]
    PoolDepth: Optional[Integer]
    State: Optional[IpamPoolState]
    StateMessage: Optional[String]
    Description: Optional[String]
    AutoImport: Optional[Boolean]
    PubliclyAdvertisable: Optional[Boolean]
    AddressFamily: Optional[AddressFamily]
    AllocationMinNetmaskLength: Optional[IpamNetmaskLength]
    AllocationMaxNetmaskLength: Optional[IpamNetmaskLength]
    AllocationDefaultNetmaskLength: Optional[IpamNetmaskLength]
    AllocationResourceTags: Optional[IpamResourceTagList]
    Tags: Optional[TagList]
    AwsService: Optional[IpamPoolAwsService]
    PublicIpSource: Optional[IpamPoolPublicIpSource]
    SourceResource: Optional[IpamPoolSourceResource]


class CreateIpamPoolResult(TypedDict, total=False):
    IpamPool: Optional[IpamPool]


class CreateIpamRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Description: Optional[String]
    OperatingRegions: Optional[AddIpamOperatingRegionSet]
    TagSpecifications: Optional[TagSpecificationList]
    ClientToken: Optional[String]
    Tier: Optional[IpamTier]
    EnablePrivateGua: Optional[Boolean]


class CreateIpamResourceDiscoveryRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Description: Optional[String]
    OperatingRegions: Optional[AddIpamOperatingRegionSet]
    TagSpecifications: Optional[TagSpecificationList]
    ClientToken: Optional[String]


class IpamOperatingRegion(TypedDict, total=False):
    RegionName: Optional[String]


IpamOperatingRegionSet = List[IpamOperatingRegion]


class IpamResourceDiscovery(TypedDict, total=False):
    OwnerId: Optional[String]
    IpamResourceDiscoveryId: Optional[IpamResourceDiscoveryId]
    IpamResourceDiscoveryArn: Optional[String]
    IpamResourceDiscoveryRegion: Optional[String]
    Description: Optional[String]
    OperatingRegions: Optional[IpamOperatingRegionSet]
    IsDefault: Optional[Boolean]
    State: Optional[IpamResourceDiscoveryState]
    Tags: Optional[TagList]


class CreateIpamResourceDiscoveryResult(TypedDict, total=False):
    IpamResourceDiscovery: Optional[IpamResourceDiscovery]


class Ipam(TypedDict, total=False):
    OwnerId: Optional[String]
    IpamId: Optional[IpamId]
    IpamArn: Optional[ResourceArn]
    IpamRegion: Optional[String]
    PublicDefaultScopeId: Optional[IpamScopeId]
    PrivateDefaultScopeId: Optional[IpamScopeId]
    ScopeCount: Optional[Integer]
    Description: Optional[String]
    OperatingRegions: Optional[IpamOperatingRegionSet]
    State: Optional[IpamState]
    Tags: Optional[TagList]
    DefaultResourceDiscoveryId: Optional[IpamResourceDiscoveryId]
    DefaultResourceDiscoveryAssociationId: Optional[IpamResourceDiscoveryAssociationId]
    ResourceDiscoveryAssociationCount: Optional[Integer]
    StateMessage: Optional[String]
    Tier: Optional[IpamTier]
    EnablePrivateGua: Optional[Boolean]


class CreateIpamResult(TypedDict, total=False):
    Ipam: Optional[Ipam]


class CreateIpamScopeRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamId: IpamId
    Description: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]
    ClientToken: Optional[String]


class IpamScope(TypedDict, total=False):
    OwnerId: Optional[String]
    IpamScopeId: Optional[IpamScopeId]
    IpamScopeArn: Optional[ResourceArn]
    IpamArn: Optional[ResourceArn]
    IpamRegion: Optional[String]
    IpamScopeType: Optional[IpamScopeType]
    IsDefault: Optional[Boolean]
    Description: Optional[String]
    PoolCount: Optional[Integer]
    State: Optional[IpamScopeState]
    Tags: Optional[TagList]


class CreateIpamScopeResult(TypedDict, total=False):
    IpamScope: Optional[IpamScope]


class CreateKeyPairRequest(ServiceRequest):
    KeyName: String
    KeyType: Optional[KeyType]
    TagSpecifications: Optional[TagSpecificationList]
    KeyFormat: Optional[KeyFormat]
    DryRun: Optional[Boolean]


class LaunchTemplateInstanceMaintenanceOptionsRequest(TypedDict, total=False):
    AutoRecovery: Optional[LaunchTemplateAutoRecoveryState]


class LaunchTemplatePrivateDnsNameOptionsRequest(TypedDict, total=False):
    HostnameType: Optional[HostnameType]
    EnableResourceNameDnsARecord: Optional[Boolean]
    EnableResourceNameDnsAAAARecord: Optional[Boolean]


class LaunchTemplateEnclaveOptionsRequest(TypedDict, total=False):
    Enabled: Optional[Boolean]


class LaunchTemplateInstanceMetadataOptionsRequest(TypedDict, total=False):
    HttpTokens: Optional[LaunchTemplateHttpTokensState]
    HttpPutResponseHopLimit: Optional[Integer]
    HttpEndpoint: Optional[LaunchTemplateInstanceMetadataEndpointState]
    HttpProtocolIpv6: Optional[LaunchTemplateInstanceMetadataProtocolIpv6]
    InstanceMetadataTags: Optional[LaunchTemplateInstanceMetadataTagsState]


class LaunchTemplateHibernationOptionsRequest(TypedDict, total=False):
    Configured: Optional[Boolean]


class LaunchTemplateLicenseConfigurationRequest(TypedDict, total=False):
    LicenseConfigurationArn: Optional[String]


LaunchTemplateLicenseSpecificationListRequest = List[LaunchTemplateLicenseConfigurationRequest]


class LaunchTemplateCapacityReservationSpecificationRequest(TypedDict, total=False):
    CapacityReservationPreference: Optional[CapacityReservationPreference]
    CapacityReservationTarget: Optional[CapacityReservationTarget]


class LaunchTemplateCpuOptionsRequest(TypedDict, total=False):
    CoreCount: Optional[Integer]
    ThreadsPerCore: Optional[Integer]
    AmdSevSnp: Optional[AmdSevSnpSpecification]


class CreditSpecificationRequest(TypedDict, total=False):
    CpuCredits: String


class LaunchTemplateSpotMarketOptionsRequest(TypedDict, total=False):
    MaxPrice: Optional[String]
    SpotInstanceType: Optional[SpotInstanceType]
    BlockDurationMinutes: Optional[Integer]
    ValidUntil: Optional[DateTime]
    InstanceInterruptionBehavior: Optional[InstanceInterruptionBehavior]


class LaunchTemplateInstanceMarketOptionsRequest(TypedDict, total=False):
    MarketType: Optional[MarketType]
    SpotOptions: Optional[LaunchTemplateSpotMarketOptionsRequest]


SecurityGroupStringList = List[SecurityGroupName]
SecurityGroupIdStringList = List[SecurityGroupId]


class LaunchTemplateElasticInferenceAccelerator(TypedDict, total=False):
    Type: String
    Count: Optional[LaunchTemplateElasticInferenceAcceleratorCount]


LaunchTemplateElasticInferenceAcceleratorList = List[LaunchTemplateElasticInferenceAccelerator]


class ElasticGpuSpecification(TypedDict, total=False):
    Type: String


ElasticGpuSpecificationList = List[ElasticGpuSpecification]


class LaunchTemplateTagSpecificationRequest(TypedDict, total=False):
    ResourceType: Optional[ResourceType]
    Tags: Optional[TagList]


LaunchTemplateTagSpecificationRequestList = List[LaunchTemplateTagSpecificationRequest]


class LaunchTemplatePlacementRequest(TypedDict, total=False):
    AvailabilityZone: Optional[String]
    Affinity: Optional[String]
    GroupName: Optional[PlacementGroupName]
    HostId: Optional[DedicatedHostId]
    Tenancy: Optional[Tenancy]
    SpreadDomain: Optional[String]
    HostResourceGroupArn: Optional[String]
    PartitionNumber: Optional[Integer]
    GroupId: Optional[PlacementGroupId]


class LaunchTemplatesMonitoringRequest(TypedDict, total=False):
    Enabled: Optional[Boolean]


class EnaSrdUdpSpecificationRequest(TypedDict, total=False):
    EnaSrdUdpEnabled: Optional[Boolean]


class EnaSrdSpecificationRequest(TypedDict, total=False):
    EnaSrdEnabled: Optional[Boolean]
    EnaSrdUdpSpecification: Optional[EnaSrdUdpSpecificationRequest]


class Ipv6PrefixSpecificationRequest(TypedDict, total=False):
    Ipv6Prefix: Optional[String]


Ipv6PrefixList = List[Ipv6PrefixSpecificationRequest]


class Ipv4PrefixSpecificationRequest(TypedDict, total=False):
    Ipv4Prefix: Optional[String]


Ipv4PrefixList = List[Ipv4PrefixSpecificationRequest]


class PrivateIpAddressSpecification(TypedDict, total=False):
    Primary: Optional[Boolean]
    PrivateIpAddress: Optional[String]


PrivateIpAddressSpecificationList = List[PrivateIpAddressSpecification]


class InstanceIpv6AddressRequest(TypedDict, total=False):
    Ipv6Address: Optional[String]


InstanceIpv6AddressListRequest = List[InstanceIpv6AddressRequest]


class LaunchTemplateInstanceNetworkInterfaceSpecificationRequest(TypedDict, total=False):
    AssociateCarrierIpAddress: Optional[Boolean]
    AssociatePublicIpAddress: Optional[Boolean]
    DeleteOnTermination: Optional[Boolean]
    Description: Optional[String]
    DeviceIndex: Optional[Integer]
    Groups: Optional[SecurityGroupIdStringList]
    InterfaceType: Optional[String]
    Ipv6AddressCount: Optional[Integer]
    Ipv6Addresses: Optional[InstanceIpv6AddressListRequest]
    NetworkInterfaceId: Optional[NetworkInterfaceId]
    PrivateIpAddress: Optional[String]
    PrivateIpAddresses: Optional[PrivateIpAddressSpecificationList]
    SecondaryPrivateIpAddressCount: Optional[Integer]
    SubnetId: Optional[SubnetId]
    NetworkCardIndex: Optional[Integer]
    Ipv4Prefixes: Optional[Ipv4PrefixList]
    Ipv4PrefixCount: Optional[Integer]
    Ipv6Prefixes: Optional[Ipv6PrefixList]
    Ipv6PrefixCount: Optional[Integer]
    PrimaryIpv6: Optional[Boolean]
    EnaSrdSpecification: Optional[EnaSrdSpecificationRequest]
    ConnectionTrackingSpecification: Optional[ConnectionTrackingSpecificationRequest]


LaunchTemplateInstanceNetworkInterfaceSpecificationRequestList = List[
    LaunchTemplateInstanceNetworkInterfaceSpecificationRequest
]


class LaunchTemplateEbsBlockDeviceRequest(TypedDict, total=False):
    Encrypted: Optional[Boolean]
    DeleteOnTermination: Optional[Boolean]
    Iops: Optional[Integer]
    KmsKeyId: Optional[KmsKeyId]
    SnapshotId: Optional[SnapshotId]
    VolumeSize: Optional[Integer]
    VolumeType: Optional[VolumeType]
    Throughput: Optional[Integer]


class LaunchTemplateBlockDeviceMappingRequest(TypedDict, total=False):
    DeviceName: Optional[String]
    VirtualName: Optional[String]
    Ebs: Optional[LaunchTemplateEbsBlockDeviceRequest]
    NoDevice: Optional[String]


LaunchTemplateBlockDeviceMappingRequestList = List[LaunchTemplateBlockDeviceMappingRequest]


class LaunchTemplateIamInstanceProfileSpecificationRequest(TypedDict, total=False):
    Arn: Optional[String]
    Name: Optional[String]


class RequestLaunchTemplateData(TypedDict, total=False):
    KernelId: Optional[KernelId]
    EbsOptimized: Optional[Boolean]
    IamInstanceProfile: Optional[LaunchTemplateIamInstanceProfileSpecificationRequest]
    BlockDeviceMappings: Optional[LaunchTemplateBlockDeviceMappingRequestList]
    NetworkInterfaces: Optional[LaunchTemplateInstanceNetworkInterfaceSpecificationRequestList]
    ImageId: Optional[ImageId]
    InstanceType: Optional[InstanceType]
    KeyName: Optional[KeyPairName]
    Monitoring: Optional[LaunchTemplatesMonitoringRequest]
    Placement: Optional[LaunchTemplatePlacementRequest]
    RamDiskId: Optional[RamdiskId]
    DisableApiTermination: Optional[Boolean]
    InstanceInitiatedShutdownBehavior: Optional[ShutdownBehavior]
    UserData: Optional[SensitiveUserData]
    TagSpecifications: Optional[LaunchTemplateTagSpecificationRequestList]
    ElasticGpuSpecifications: Optional[ElasticGpuSpecificationList]
    ElasticInferenceAccelerators: Optional[LaunchTemplateElasticInferenceAcceleratorList]
    SecurityGroupIds: Optional[SecurityGroupIdStringList]
    SecurityGroups: Optional[SecurityGroupStringList]
    InstanceMarketOptions: Optional[LaunchTemplateInstanceMarketOptionsRequest]
    CreditSpecification: Optional[CreditSpecificationRequest]
    CpuOptions: Optional[LaunchTemplateCpuOptionsRequest]
    CapacityReservationSpecification: Optional[
        LaunchTemplateCapacityReservationSpecificationRequest
    ]
    LicenseSpecifications: Optional[LaunchTemplateLicenseSpecificationListRequest]
    HibernationOptions: Optional[LaunchTemplateHibernationOptionsRequest]
    MetadataOptions: Optional[LaunchTemplateInstanceMetadataOptionsRequest]
    EnclaveOptions: Optional[LaunchTemplateEnclaveOptionsRequest]
    InstanceRequirements: Optional[InstanceRequirementsRequest]
    PrivateDnsNameOptions: Optional[LaunchTemplatePrivateDnsNameOptionsRequest]
    MaintenanceOptions: Optional[LaunchTemplateInstanceMaintenanceOptionsRequest]
    DisableApiStop: Optional[Boolean]


class CreateLaunchTemplateRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]
    LaunchTemplateName: LaunchTemplateName
    VersionDescription: Optional[VersionDescription]
    LaunchTemplateData: RequestLaunchTemplateData
    TagSpecifications: Optional[TagSpecificationList]


class ValidationError(TypedDict, total=False):
    Code: Optional[String]
    Message: Optional[String]


ErrorSet = List[ValidationError]


class ValidationWarning(TypedDict, total=False):
    Errors: Optional[ErrorSet]


class LaunchTemplate(TypedDict, total=False):
    LaunchTemplateId: Optional[String]
    LaunchTemplateName: Optional[LaunchTemplateName]
    CreateTime: Optional[DateTime]
    CreatedBy: Optional[String]
    DefaultVersionNumber: Optional[Long]
    LatestVersionNumber: Optional[Long]
    Tags: Optional[TagList]


class CreateLaunchTemplateResult(TypedDict, total=False):
    LaunchTemplate: Optional[LaunchTemplate]
    Warning: Optional[ValidationWarning]


class CreateLaunchTemplateVersionRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]
    LaunchTemplateId: Optional[LaunchTemplateId]
    LaunchTemplateName: Optional[LaunchTemplateName]
    SourceVersion: Optional[String]
    VersionDescription: Optional[VersionDescription]
    LaunchTemplateData: RequestLaunchTemplateData
    ResolveAlias: Optional[Boolean]


class LaunchTemplateInstanceMaintenanceOptions(TypedDict, total=False):
    AutoRecovery: Optional[LaunchTemplateAutoRecoveryState]


class LaunchTemplatePrivateDnsNameOptions(TypedDict, total=False):
    HostnameType: Optional[HostnameType]
    EnableResourceNameDnsARecord: Optional[Boolean]
    EnableResourceNameDnsAAAARecord: Optional[Boolean]


class LaunchTemplateEnclaveOptions(TypedDict, total=False):
    Enabled: Optional[Boolean]


class LaunchTemplateInstanceMetadataOptions(TypedDict, total=False):
    State: Optional[LaunchTemplateInstanceMetadataOptionsState]
    HttpTokens: Optional[LaunchTemplateHttpTokensState]
    HttpPutResponseHopLimit: Optional[Integer]
    HttpEndpoint: Optional[LaunchTemplateInstanceMetadataEndpointState]
    HttpProtocolIpv6: Optional[LaunchTemplateInstanceMetadataProtocolIpv6]
    InstanceMetadataTags: Optional[LaunchTemplateInstanceMetadataTagsState]


class LaunchTemplateHibernationOptions(TypedDict, total=False):
    Configured: Optional[Boolean]


class LaunchTemplateLicenseConfiguration(TypedDict, total=False):
    LicenseConfigurationArn: Optional[String]


LaunchTemplateLicenseList = List[LaunchTemplateLicenseConfiguration]


class LaunchTemplateCapacityReservationSpecificationResponse(TypedDict, total=False):
    CapacityReservationPreference: Optional[CapacityReservationPreference]
    CapacityReservationTarget: Optional[CapacityReservationTargetResponse]


class LaunchTemplateCpuOptions(TypedDict, total=False):
    CoreCount: Optional[Integer]
    ThreadsPerCore: Optional[Integer]
    AmdSevSnp: Optional[AmdSevSnpSpecification]


class CreditSpecification(TypedDict, total=False):
    CpuCredits: Optional[String]


class LaunchTemplateSpotMarketOptions(TypedDict, total=False):
    MaxPrice: Optional[String]
    SpotInstanceType: Optional[SpotInstanceType]
    BlockDurationMinutes: Optional[Integer]
    ValidUntil: Optional[DateTime]
    InstanceInterruptionBehavior: Optional[InstanceInterruptionBehavior]


class LaunchTemplateInstanceMarketOptions(TypedDict, total=False):
    MarketType: Optional[MarketType]
    SpotOptions: Optional[LaunchTemplateSpotMarketOptions]


class LaunchTemplateElasticInferenceAcceleratorResponse(TypedDict, total=False):
    Type: Optional[String]
    Count: Optional[Integer]


LaunchTemplateElasticInferenceAcceleratorResponseList = List[
    LaunchTemplateElasticInferenceAcceleratorResponse
]


class ElasticGpuSpecificationResponse(TypedDict, total=False):
    Type: Optional[String]


ElasticGpuSpecificationResponseList = List[ElasticGpuSpecificationResponse]


class LaunchTemplateTagSpecification(TypedDict, total=False):
    ResourceType: Optional[ResourceType]
    Tags: Optional[TagList]


LaunchTemplateTagSpecificationList = List[LaunchTemplateTagSpecification]


class LaunchTemplatePlacement(TypedDict, total=False):
    AvailabilityZone: Optional[String]
    Affinity: Optional[String]
    GroupName: Optional[String]
    HostId: Optional[String]
    Tenancy: Optional[Tenancy]
    SpreadDomain: Optional[String]
    HostResourceGroupArn: Optional[String]
    PartitionNumber: Optional[Integer]
    GroupId: Optional[PlacementGroupId]


class LaunchTemplatesMonitoring(TypedDict, total=False):
    Enabled: Optional[Boolean]


class LaunchTemplateEnaSrdUdpSpecification(TypedDict, total=False):
    EnaSrdUdpEnabled: Optional[Boolean]


class LaunchTemplateEnaSrdSpecification(TypedDict, total=False):
    EnaSrdEnabled: Optional[Boolean]
    EnaSrdUdpSpecification: Optional[LaunchTemplateEnaSrdUdpSpecification]


class Ipv6PrefixSpecificationResponse(TypedDict, total=False):
    Ipv6Prefix: Optional[String]


Ipv6PrefixListResponse = List[Ipv6PrefixSpecificationResponse]


class Ipv4PrefixSpecificationResponse(TypedDict, total=False):
    Ipv4Prefix: Optional[String]


Ipv4PrefixListResponse = List[Ipv4PrefixSpecificationResponse]


class InstanceIpv6Address(TypedDict, total=False):
    Ipv6Address: Optional[String]
    IsPrimaryIpv6: Optional[Boolean]


InstanceIpv6AddressList = List[InstanceIpv6Address]


class LaunchTemplateInstanceNetworkInterfaceSpecification(TypedDict, total=False):
    AssociateCarrierIpAddress: Optional[Boolean]
    AssociatePublicIpAddress: Optional[Boolean]
    DeleteOnTermination: Optional[Boolean]
    Description: Optional[String]
    DeviceIndex: Optional[Integer]
    Groups: Optional[GroupIdStringList]
    InterfaceType: Optional[String]
    Ipv6AddressCount: Optional[Integer]
    Ipv6Addresses: Optional[InstanceIpv6AddressList]
    NetworkInterfaceId: Optional[NetworkInterfaceId]
    PrivateIpAddress: Optional[String]
    PrivateIpAddresses: Optional[PrivateIpAddressSpecificationList]
    SecondaryPrivateIpAddressCount: Optional[Integer]
    SubnetId: Optional[SubnetId]
    NetworkCardIndex: Optional[Integer]
    Ipv4Prefixes: Optional[Ipv4PrefixListResponse]
    Ipv4PrefixCount: Optional[Integer]
    Ipv6Prefixes: Optional[Ipv6PrefixListResponse]
    Ipv6PrefixCount: Optional[Integer]
    PrimaryIpv6: Optional[Boolean]
    EnaSrdSpecification: Optional[LaunchTemplateEnaSrdSpecification]
    ConnectionTrackingSpecification: Optional[ConnectionTrackingSpecification]


LaunchTemplateInstanceNetworkInterfaceSpecificationList = List[
    LaunchTemplateInstanceNetworkInterfaceSpecification
]


class LaunchTemplateEbsBlockDevice(TypedDict, total=False):
    Encrypted: Optional[Boolean]
    DeleteOnTermination: Optional[Boolean]
    Iops: Optional[Integer]
    KmsKeyId: Optional[KmsKeyId]
    SnapshotId: Optional[SnapshotId]
    VolumeSize: Optional[Integer]
    VolumeType: Optional[VolumeType]
    Throughput: Optional[Integer]


class LaunchTemplateBlockDeviceMapping(TypedDict, total=False):
    DeviceName: Optional[String]
    VirtualName: Optional[String]
    Ebs: Optional[LaunchTemplateEbsBlockDevice]
    NoDevice: Optional[String]


LaunchTemplateBlockDeviceMappingList = List[LaunchTemplateBlockDeviceMapping]


class LaunchTemplateIamInstanceProfileSpecification(TypedDict, total=False):
    Arn: Optional[String]
    Name: Optional[String]


class ResponseLaunchTemplateData(TypedDict, total=False):
    KernelId: Optional[String]
    EbsOptimized: Optional[Boolean]
    IamInstanceProfile: Optional[LaunchTemplateIamInstanceProfileSpecification]
    BlockDeviceMappings: Optional[LaunchTemplateBlockDeviceMappingList]
    NetworkInterfaces: Optional[LaunchTemplateInstanceNetworkInterfaceSpecificationList]
    ImageId: Optional[String]
    InstanceType: Optional[InstanceType]
    KeyName: Optional[String]
    Monitoring: Optional[LaunchTemplatesMonitoring]
    Placement: Optional[LaunchTemplatePlacement]
    RamDiskId: Optional[String]
    DisableApiTermination: Optional[Boolean]
    InstanceInitiatedShutdownBehavior: Optional[ShutdownBehavior]
    UserData: Optional[SensitiveUserData]
    TagSpecifications: Optional[LaunchTemplateTagSpecificationList]
    ElasticGpuSpecifications: Optional[ElasticGpuSpecificationResponseList]
    ElasticInferenceAccelerators: Optional[LaunchTemplateElasticInferenceAcceleratorResponseList]
    SecurityGroupIds: Optional[ValueStringList]
    SecurityGroups: Optional[ValueStringList]
    InstanceMarketOptions: Optional[LaunchTemplateInstanceMarketOptions]
    CreditSpecification: Optional[CreditSpecification]
    CpuOptions: Optional[LaunchTemplateCpuOptions]
    CapacityReservationSpecification: Optional[
        LaunchTemplateCapacityReservationSpecificationResponse
    ]
    LicenseSpecifications: Optional[LaunchTemplateLicenseList]
    HibernationOptions: Optional[LaunchTemplateHibernationOptions]
    MetadataOptions: Optional[LaunchTemplateInstanceMetadataOptions]
    EnclaveOptions: Optional[LaunchTemplateEnclaveOptions]
    InstanceRequirements: Optional[InstanceRequirements]
    PrivateDnsNameOptions: Optional[LaunchTemplatePrivateDnsNameOptions]
    MaintenanceOptions: Optional[LaunchTemplateInstanceMaintenanceOptions]
    DisableApiStop: Optional[Boolean]


class LaunchTemplateVersion(TypedDict, total=False):
    LaunchTemplateId: Optional[String]
    LaunchTemplateName: Optional[LaunchTemplateName]
    VersionNumber: Optional[Long]
    VersionDescription: Optional[VersionDescription]
    CreateTime: Optional[DateTime]
    CreatedBy: Optional[String]
    DefaultVersion: Optional[Boolean]
    LaunchTemplateData: Optional[ResponseLaunchTemplateData]


class CreateLaunchTemplateVersionResult(TypedDict, total=False):
    LaunchTemplateVersion: Optional[LaunchTemplateVersion]
    Warning: Optional[ValidationWarning]


class CreateLocalGatewayRouteRequest(ServiceRequest):
    DestinationCidrBlock: Optional[String]
    LocalGatewayRouteTableId: LocalGatewayRoutetableId
    LocalGatewayVirtualInterfaceGroupId: Optional[LocalGatewayVirtualInterfaceGroupId]
    DryRun: Optional[Boolean]
    NetworkInterfaceId: Optional[NetworkInterfaceId]
    DestinationPrefixListId: Optional[PrefixListResourceId]


class LocalGatewayRoute(TypedDict, total=False):
    DestinationCidrBlock: Optional[String]
    LocalGatewayVirtualInterfaceGroupId: Optional[LocalGatewayVirtualInterfaceGroupId]
    Type: Optional[LocalGatewayRouteType]
    State: Optional[LocalGatewayRouteState]
    LocalGatewayRouteTableId: Optional[LocalGatewayRoutetableId]
    LocalGatewayRouteTableArn: Optional[ResourceArn]
    OwnerId: Optional[String]
    SubnetId: Optional[SubnetId]
    CoipPoolId: Optional[CoipPoolId]
    NetworkInterfaceId: Optional[NetworkInterfaceId]
    DestinationPrefixListId: Optional[PrefixListResourceId]


class CreateLocalGatewayRouteResult(TypedDict, total=False):
    Route: Optional[LocalGatewayRoute]


class CreateLocalGatewayRouteTableRequest(ServiceRequest):
    LocalGatewayId: LocalGatewayId
    Mode: Optional[LocalGatewayRouteTableMode]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class StateReason(TypedDict, total=False):
    Code: Optional[String]
    Message: Optional[String]


class LocalGatewayRouteTable(TypedDict, total=False):
    LocalGatewayRouteTableId: Optional[String]
    LocalGatewayRouteTableArn: Optional[ResourceArn]
    LocalGatewayId: Optional[LocalGatewayId]
    OutpostArn: Optional[String]
    OwnerId: Optional[String]
    State: Optional[String]
    Tags: Optional[TagList]
    Mode: Optional[LocalGatewayRouteTableMode]
    StateReason: Optional[StateReason]


class CreateLocalGatewayRouteTableResult(TypedDict, total=False):
    LocalGatewayRouteTable: Optional[LocalGatewayRouteTable]


class CreateLocalGatewayRouteTableVirtualInterfaceGroupAssociationRequest(ServiceRequest):
    LocalGatewayRouteTableId: LocalGatewayRoutetableId
    LocalGatewayVirtualInterfaceGroupId: LocalGatewayVirtualInterfaceGroupId
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class LocalGatewayRouteTableVirtualInterfaceGroupAssociation(TypedDict, total=False):
    LocalGatewayRouteTableVirtualInterfaceGroupAssociationId: Optional[
        LocalGatewayRouteTableVirtualInterfaceGroupAssociationId
    ]
    LocalGatewayVirtualInterfaceGroupId: Optional[LocalGatewayVirtualInterfaceGroupId]
    LocalGatewayId: Optional[String]
    LocalGatewayRouteTableId: Optional[LocalGatewayId]
    LocalGatewayRouteTableArn: Optional[ResourceArn]
    OwnerId: Optional[String]
    State: Optional[String]
    Tags: Optional[TagList]


class CreateLocalGatewayRouteTableVirtualInterfaceGroupAssociationResult(TypedDict, total=False):
    LocalGatewayRouteTableVirtualInterfaceGroupAssociation: Optional[
        LocalGatewayRouteTableVirtualInterfaceGroupAssociation
    ]


class CreateLocalGatewayRouteTableVpcAssociationRequest(ServiceRequest):
    LocalGatewayRouteTableId: LocalGatewayRoutetableId
    VpcId: VpcId
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class LocalGatewayRouteTableVpcAssociation(TypedDict, total=False):
    LocalGatewayRouteTableVpcAssociationId: Optional[LocalGatewayRouteTableVpcAssociationId]
    LocalGatewayRouteTableId: Optional[String]
    LocalGatewayRouteTableArn: Optional[ResourceArn]
    LocalGatewayId: Optional[String]
    VpcId: Optional[String]
    OwnerId: Optional[String]
    State: Optional[String]
    Tags: Optional[TagList]


class CreateLocalGatewayRouteTableVpcAssociationResult(TypedDict, total=False):
    LocalGatewayRouteTableVpcAssociation: Optional[LocalGatewayRouteTableVpcAssociation]


class CreateManagedPrefixListRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    PrefixListName: String
    Entries: Optional[AddPrefixListEntries]
    MaxEntries: Integer
    TagSpecifications: Optional[TagSpecificationList]
    AddressFamily: String
    ClientToken: Optional[String]


class ManagedPrefixList(TypedDict, total=False):
    PrefixListId: Optional[PrefixListResourceId]
    AddressFamily: Optional[String]
    State: Optional[PrefixListState]
    StateMessage: Optional[String]
    PrefixListArn: Optional[ResourceArn]
    PrefixListName: Optional[String]
    MaxEntries: Optional[Integer]
    Version: Optional[Long]
    Tags: Optional[TagList]
    OwnerId: Optional[String]


class CreateManagedPrefixListResult(TypedDict, total=False):
    PrefixList: Optional[ManagedPrefixList]


class CreateNatGatewayRequest(ServiceRequest):
    AllocationId: Optional[AllocationId]
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]
    SubnetId: SubnetId
    TagSpecifications: Optional[TagSpecificationList]
    ConnectivityType: Optional[ConnectivityType]
    PrivateIpAddress: Optional[String]
    SecondaryAllocationIds: Optional[AllocationIdList]
    SecondaryPrivateIpAddresses: Optional[IpList]
    SecondaryPrivateIpAddressCount: Optional[PrivateIpAddressCount]


class ProvisionedBandwidth(TypedDict, total=False):
    ProvisionTime: Optional[DateTime]
    Provisioned: Optional[String]
    RequestTime: Optional[DateTime]
    Requested: Optional[String]
    Status: Optional[String]


class NatGateway(TypedDict, total=False):
    CreateTime: Optional[DateTime]
    DeleteTime: Optional[DateTime]
    FailureCode: Optional[String]
    FailureMessage: Optional[String]
    NatGatewayAddresses: Optional[NatGatewayAddressList]
    NatGatewayId: Optional[String]
    ProvisionedBandwidth: Optional[ProvisionedBandwidth]
    State: Optional[NatGatewayState]
    SubnetId: Optional[String]
    VpcId: Optional[String]
    Tags: Optional[TagList]
    ConnectivityType: Optional[ConnectivityType]


class CreateNatGatewayResult(TypedDict, total=False):
    ClientToken: Optional[String]
    NatGateway: Optional[NatGateway]


class IcmpTypeCode(TypedDict, total=False):
    Code: Optional[Integer]
    Type: Optional[Integer]


class CreateNetworkAclEntryRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    NetworkAclId: NetworkAclId
    RuleNumber: Integer
    Protocol: String
    RuleAction: RuleAction
    Egress: Boolean
    CidrBlock: Optional[String]
    Ipv6CidrBlock: Optional[String]
    IcmpTypeCode: Optional[IcmpTypeCode]
    PortRange: Optional[PortRange]


class CreateNetworkAclRequest(ServiceRequest):
    TagSpecifications: Optional[TagSpecificationList]
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]
    VpcId: VpcId


class NetworkAclEntry(TypedDict, total=False):
    CidrBlock: Optional[String]
    Egress: Optional[Boolean]
    IcmpTypeCode: Optional[IcmpTypeCode]
    Ipv6CidrBlock: Optional[String]
    PortRange: Optional[PortRange]
    Protocol: Optional[String]
    RuleAction: Optional[RuleAction]
    RuleNumber: Optional[Integer]


NetworkAclEntryList = List[NetworkAclEntry]


class NetworkAclAssociation(TypedDict, total=False):
    NetworkAclAssociationId: Optional[String]
    NetworkAclId: Optional[String]
    SubnetId: Optional[String]


NetworkAclAssociationList = List[NetworkAclAssociation]


class NetworkAcl(TypedDict, total=False):
    Associations: Optional[NetworkAclAssociationList]
    Entries: Optional[NetworkAclEntryList]
    IsDefault: Optional[Boolean]
    NetworkAclId: Optional[String]
    Tags: Optional[TagList]
    VpcId: Optional[String]
    OwnerId: Optional[String]


class CreateNetworkAclResult(TypedDict, total=False):
    NetworkAcl: Optional[NetworkAcl]
    ClientToken: Optional[String]


class CreateNetworkInsightsAccessScopeRequest(ServiceRequest):
    MatchPaths: Optional[AccessScopePathListRequest]
    ExcludePaths: Optional[AccessScopePathListRequest]
    ClientToken: String
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class NetworkInsightsAccessScopeContent(TypedDict, total=False):
    NetworkInsightsAccessScopeId: Optional[NetworkInsightsAccessScopeId]
    MatchPaths: Optional[AccessScopePathList]
    ExcludePaths: Optional[AccessScopePathList]


class NetworkInsightsAccessScope(TypedDict, total=False):
    NetworkInsightsAccessScopeId: Optional[NetworkInsightsAccessScopeId]
    NetworkInsightsAccessScopeArn: Optional[ResourceArn]
    CreatedDate: Optional[MillisecondDateTime]
    UpdatedDate: Optional[MillisecondDateTime]
    Tags: Optional[TagList]


class CreateNetworkInsightsAccessScopeResult(TypedDict, total=False):
    NetworkInsightsAccessScope: Optional[NetworkInsightsAccessScope]
    NetworkInsightsAccessScopeContent: Optional[NetworkInsightsAccessScopeContent]


class RequestFilterPortRange(TypedDict, total=False):
    FromPort: Optional[Port]
    ToPort: Optional[Port]


class PathRequestFilter(TypedDict, total=False):
    SourceAddress: Optional[IpAddress]
    SourcePortRange: Optional[RequestFilterPortRange]
    DestinationAddress: Optional[IpAddress]
    DestinationPortRange: Optional[RequestFilterPortRange]


class CreateNetworkInsightsPathRequest(ServiceRequest):
    SourceIp: Optional[IpAddress]
    DestinationIp: Optional[IpAddress]
    Source: NetworkInsightsResourceId
    Destination: Optional[NetworkInsightsResourceId]
    Protocol: Protocol
    DestinationPort: Optional[Port]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]
    ClientToken: String
    FilterAtSource: Optional[PathRequestFilter]
    FilterAtDestination: Optional[PathRequestFilter]


class FilterPortRange(TypedDict, total=False):
    FromPort: Optional[Port]
    ToPort: Optional[Port]


class PathFilter(TypedDict, total=False):
    SourceAddress: Optional[IpAddress]
    SourcePortRange: Optional[FilterPortRange]
    DestinationAddress: Optional[IpAddress]
    DestinationPortRange: Optional[FilterPortRange]


class NetworkInsightsPath(TypedDict, total=False):
    NetworkInsightsPathId: Optional[NetworkInsightsPathId]
    NetworkInsightsPathArn: Optional[ResourceArn]
    CreatedDate: Optional[MillisecondDateTime]
    Source: Optional[String]
    Destination: Optional[String]
    SourceArn: Optional[ResourceArn]
    DestinationArn: Optional[ResourceArn]
    SourceIp: Optional[IpAddress]
    DestinationIp: Optional[IpAddress]
    Protocol: Optional[Protocol]
    DestinationPort: Optional[Integer]
    Tags: Optional[TagList]
    FilterAtSource: Optional[PathFilter]
    FilterAtDestination: Optional[PathFilter]


class CreateNetworkInsightsPathResult(TypedDict, total=False):
    NetworkInsightsPath: Optional[NetworkInsightsPath]


class CreateNetworkInterfacePermissionRequest(ServiceRequest):
    NetworkInterfaceId: NetworkInterfaceId
    AwsAccountId: Optional[String]
    AwsService: Optional[String]
    Permission: InterfacePermissionType
    DryRun: Optional[Boolean]


class NetworkInterfacePermissionState(TypedDict, total=False):
    State: Optional[NetworkInterfacePermissionStateCode]
    StatusMessage: Optional[String]


class NetworkInterfacePermission(TypedDict, total=False):
    NetworkInterfacePermissionId: Optional[String]
    NetworkInterfaceId: Optional[String]
    AwsAccountId: Optional[String]
    AwsService: Optional[String]
    Permission: Optional[InterfacePermissionType]
    PermissionState: Optional[NetworkInterfacePermissionState]


class CreateNetworkInterfacePermissionResult(TypedDict, total=False):
    InterfacePermission: Optional[NetworkInterfacePermission]


class CreateNetworkInterfaceRequest(ServiceRequest):
    Ipv4Prefixes: Optional[Ipv4PrefixList]
    Ipv4PrefixCount: Optional[Integer]
    Ipv6Prefixes: Optional[Ipv6PrefixList]
    Ipv6PrefixCount: Optional[Integer]
    InterfaceType: Optional[NetworkInterfaceCreationType]
    TagSpecifications: Optional[TagSpecificationList]
    ClientToken: Optional[String]
    EnablePrimaryIpv6: Optional[Boolean]
    ConnectionTrackingSpecification: Optional[ConnectionTrackingSpecificationRequest]
    SubnetId: SubnetId
    Description: Optional[String]
    PrivateIpAddress: Optional[String]
    Groups: Optional[SecurityGroupIdStringList]
    PrivateIpAddresses: Optional[PrivateIpAddressSpecificationList]
    SecondaryPrivateIpAddressCount: Optional[Integer]
    Ipv6Addresses: Optional[InstanceIpv6AddressList]
    Ipv6AddressCount: Optional[Integer]
    DryRun: Optional[Boolean]


class Ipv6PrefixSpecification(TypedDict, total=False):
    Ipv6Prefix: Optional[String]


Ipv6PrefixesList = List[Ipv6PrefixSpecification]


class NetworkInterfaceAssociation(TypedDict, total=False):
    AllocationId: Optional[String]
    AssociationId: Optional[String]
    IpOwnerId: Optional[String]
    PublicDnsName: Optional[String]
    PublicIp: Optional[String]
    CustomerOwnedIp: Optional[String]
    CarrierIp: Optional[String]


class NetworkInterfacePrivateIpAddress(TypedDict, total=False):
    Association: Optional[NetworkInterfaceAssociation]
    Primary: Optional[Boolean]
    PrivateDnsName: Optional[String]
    PrivateIpAddress: Optional[String]


NetworkInterfacePrivateIpAddressList = List[NetworkInterfacePrivateIpAddress]


class NetworkInterfaceIpv6Address(TypedDict, total=False):
    Ipv6Address: Optional[String]
    IsPrimaryIpv6: Optional[Boolean]


NetworkInterfaceIpv6AddressesList = List[NetworkInterfaceIpv6Address]


class NetworkInterfaceAttachment(TypedDict, total=False):
    AttachTime: Optional[DateTime]
    AttachmentId: Optional[String]
    DeleteOnTermination: Optional[Boolean]
    DeviceIndex: Optional[Integer]
    NetworkCardIndex: Optional[Integer]
    InstanceId: Optional[String]
    InstanceOwnerId: Optional[String]
    Status: Optional[AttachmentStatus]
    EnaSrdSpecification: Optional[AttachmentEnaSrdSpecification]


class NetworkInterface(TypedDict, total=False):
    Association: Optional[NetworkInterfaceAssociation]
    Attachment: Optional[NetworkInterfaceAttachment]
    AvailabilityZone: Optional[String]
    ConnectionTrackingConfiguration: Optional[ConnectionTrackingConfiguration]
    Description: Optional[String]
    Groups: Optional[GroupIdentifierList]
    InterfaceType: Optional[NetworkInterfaceType]
    Ipv6Addresses: Optional[NetworkInterfaceIpv6AddressesList]
    MacAddress: Optional[String]
    NetworkInterfaceId: Optional[String]
    OutpostArn: Optional[String]
    OwnerId: Optional[String]
    PrivateDnsName: Optional[String]
    PrivateIpAddress: Optional[String]
    PrivateIpAddresses: Optional[NetworkInterfacePrivateIpAddressList]
    Ipv4Prefixes: Optional[Ipv4PrefixesList]
    Ipv6Prefixes: Optional[Ipv6PrefixesList]
    RequesterId: Optional[String]
    RequesterManaged: Optional[Boolean]
    SourceDestCheck: Optional[Boolean]
    Status: Optional[NetworkInterfaceStatus]
    SubnetId: Optional[String]
    TagSet: Optional[TagList]
    VpcId: Optional[String]
    DenyAllIgwTraffic: Optional[Boolean]
    Ipv6Native: Optional[Boolean]
    Ipv6Address: Optional[String]


class CreateNetworkInterfaceResult(TypedDict, total=False):
    NetworkInterface: Optional[NetworkInterface]
    ClientToken: Optional[String]


class CreatePlacementGroupRequest(ServiceRequest):
    PartitionCount: Optional[Integer]
    TagSpecifications: Optional[TagSpecificationList]
    SpreadLevel: Optional[SpreadLevel]
    DryRun: Optional[Boolean]
    GroupName: Optional[String]
    Strategy: Optional[PlacementStrategy]


class PlacementGroup(TypedDict, total=False):
    GroupName: Optional[String]
    State: Optional[PlacementGroupState]
    Strategy: Optional[PlacementStrategy]
    PartitionCount: Optional[Integer]
    GroupId: Optional[String]
    Tags: Optional[TagList]
    GroupArn: Optional[String]
    SpreadLevel: Optional[SpreadLevel]


class CreatePlacementGroupResult(TypedDict, total=False):
    PlacementGroup: Optional[PlacementGroup]


class CreatePublicIpv4PoolRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    TagSpecifications: Optional[TagSpecificationList]
    NetworkBorderGroup: Optional[String]


class CreatePublicIpv4PoolResult(TypedDict, total=False):
    PoolId: Optional[Ipv4PoolEc2Id]


class CreateReplaceRootVolumeTaskRequest(ServiceRequest):
    InstanceId: InstanceId
    SnapshotId: Optional[SnapshotId]
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]
    TagSpecifications: Optional[TagSpecificationList]
    ImageId: Optional[ImageId]
    DeleteReplacedRootVolume: Optional[Boolean]


class ReplaceRootVolumeTask(TypedDict, total=False):
    ReplaceRootVolumeTaskId: Optional[ReplaceRootVolumeTaskId]
    InstanceId: Optional[String]
    TaskState: Optional[ReplaceRootVolumeTaskState]
    StartTime: Optional[String]
    CompleteTime: Optional[String]
    Tags: Optional[TagList]
    ImageId: Optional[ImageId]
    SnapshotId: Optional[SnapshotId]
    DeleteReplacedRootVolume: Optional[Boolean]


class CreateReplaceRootVolumeTaskResult(TypedDict, total=False):
    ReplaceRootVolumeTask: Optional[ReplaceRootVolumeTask]


class PriceScheduleSpecification(TypedDict, total=False):
    Term: Optional[Long]
    Price: Optional[Double]
    CurrencyCode: Optional[CurrencyCodeValues]


PriceScheduleSpecificationList = List[PriceScheduleSpecification]


class CreateReservedInstancesListingRequest(ServiceRequest):
    ReservedInstancesId: ReservationId
    InstanceCount: Integer
    PriceSchedules: PriceScheduleSpecificationList
    ClientToken: String


class CreateReservedInstancesListingResult(TypedDict, total=False):
    ReservedInstancesListings: Optional[ReservedInstancesListingList]


class CreateRestoreImageTaskRequest(ServiceRequest):
    Bucket: String
    ObjectKey: String
    Name: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class CreateRestoreImageTaskResult(TypedDict, total=False):
    ImageId: Optional[String]


class CreateRouteRequest(ServiceRequest):
    DestinationPrefixListId: Optional[PrefixListResourceId]
    VpcEndpointId: Optional[VpcEndpointId]
    TransitGatewayId: Optional[TransitGatewayId]
    LocalGatewayId: Optional[LocalGatewayId]
    CarrierGatewayId: Optional[CarrierGatewayId]
    CoreNetworkArn: Optional[CoreNetworkArn]
    DryRun: Optional[Boolean]
    RouteTableId: RouteTableId
    DestinationCidrBlock: Optional[String]
    GatewayId: Optional[RouteGatewayId]
    DestinationIpv6CidrBlock: Optional[String]
    EgressOnlyInternetGatewayId: Optional[EgressOnlyInternetGatewayId]
    InstanceId: Optional[InstanceId]
    NetworkInterfaceId: Optional[NetworkInterfaceId]
    VpcPeeringConnectionId: Optional[VpcPeeringConnectionId]
    NatGatewayId: Optional[NatGatewayId]


class CreateRouteResult(TypedDict, total=False):
    Return: Optional[Boolean]


class CreateRouteTableRequest(ServiceRequest):
    TagSpecifications: Optional[TagSpecificationList]
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]
    VpcId: VpcId


class Route(TypedDict, total=False):
    DestinationCidrBlock: Optional[String]
    DestinationIpv6CidrBlock: Optional[String]
    DestinationPrefixListId: Optional[String]
    EgressOnlyInternetGatewayId: Optional[String]
    GatewayId: Optional[String]
    InstanceId: Optional[String]
    InstanceOwnerId: Optional[String]
    NatGatewayId: Optional[String]
    TransitGatewayId: Optional[String]
    LocalGatewayId: Optional[String]
    CarrierGatewayId: Optional[CarrierGatewayId]
    NetworkInterfaceId: Optional[String]
    Origin: Optional[RouteOrigin]
    State: Optional[RouteState]
    VpcPeeringConnectionId: Optional[String]
    CoreNetworkArn: Optional[CoreNetworkArn]


RouteList = List[Route]


class PropagatingVgw(TypedDict, total=False):
    GatewayId: Optional[String]


PropagatingVgwList = List[PropagatingVgw]


class RouteTableAssociation(TypedDict, total=False):
    Main: Optional[Boolean]
    RouteTableAssociationId: Optional[String]
    RouteTableId: Optional[String]
    SubnetId: Optional[String]
    GatewayId: Optional[String]
    AssociationState: Optional[RouteTableAssociationState]


RouteTableAssociationList = List[RouteTableAssociation]


class RouteTable(TypedDict, total=False):
    Associations: Optional[RouteTableAssociationList]
    PropagatingVgws: Optional[PropagatingVgwList]
    RouteTableId: Optional[String]
    Routes: Optional[RouteList]
    Tags: Optional[TagList]
    VpcId: Optional[String]
    OwnerId: Optional[String]


class CreateRouteTableResult(TypedDict, total=False):
    RouteTable: Optional[RouteTable]
    ClientToken: Optional[String]


class CreateSecurityGroupRequest(ServiceRequest):
    Description: String
    GroupName: String
    VpcId: Optional[VpcId]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class CreateSecurityGroupResult(TypedDict, total=False):
    GroupId: Optional[String]
    Tags: Optional[TagList]
    SecurityGroupArn: Optional[String]


class CreateSnapshotRequest(ServiceRequest):
    Description: Optional[String]
    OutpostArn: Optional[String]
    VolumeId: VolumeId
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


VolumeIdStringList = List[VolumeId]


class InstanceSpecification(TypedDict, total=False):
    InstanceId: InstanceIdWithVolumeResolver
    ExcludeBootVolume: Optional[Boolean]
    ExcludeDataVolumeIds: Optional[VolumeIdStringList]


class CreateSnapshotsRequest(ServiceRequest):
    Description: Optional[String]
    InstanceSpecification: InstanceSpecification
    OutpostArn: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]
    CopyTagsFromSource: Optional[CopyTagsFromSource]


class SnapshotInfo(TypedDict, total=False):
    Description: Optional[String]
    Tags: Optional[TagList]
    Encrypted: Optional[Boolean]
    VolumeId: Optional[String]
    State: Optional[SnapshotState]
    VolumeSize: Optional[Integer]
    StartTime: Optional[MillisecondDateTime]
    Progress: Optional[String]
    OwnerId: Optional[String]
    SnapshotId: Optional[String]
    OutpostArn: Optional[String]
    SseType: Optional[SSEType]


SnapshotSet = List[SnapshotInfo]


class CreateSnapshotsResult(TypedDict, total=False):
    Snapshots: Optional[SnapshotSet]


class CreateSpotDatafeedSubscriptionRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Bucket: String
    Prefix: Optional[String]


class SpotInstanceStateFault(TypedDict, total=False):
    Code: Optional[String]
    Message: Optional[String]


class SpotDatafeedSubscription(TypedDict, total=False):
    Bucket: Optional[String]
    Fault: Optional[SpotInstanceStateFault]
    OwnerId: Optional[String]
    Prefix: Optional[String]
    State: Optional[DatafeedSubscriptionState]


class CreateSpotDatafeedSubscriptionResult(TypedDict, total=False):
    SpotDatafeedSubscription: Optional[SpotDatafeedSubscription]


class S3ObjectTag(TypedDict, total=False):
    Key: Optional[String]
    Value: Optional[String]


S3ObjectTagList = List[S3ObjectTag]


class CreateStoreImageTaskRequest(ServiceRequest):
    ImageId: ImageId
    Bucket: String
    S3ObjectTags: Optional[S3ObjectTagList]
    DryRun: Optional[Boolean]


class CreateStoreImageTaskResult(TypedDict, total=False):
    ObjectKey: Optional[String]


class CreateSubnetCidrReservationRequest(ServiceRequest):
    SubnetId: SubnetId
    Cidr: String
    ReservationType: SubnetCidrReservationType
    Description: Optional[String]
    DryRun: Optional[Boolean]
    TagSpecifications: Optional[TagSpecificationList]


class SubnetCidrReservation(TypedDict, total=False):
    SubnetCidrReservationId: Optional[SubnetCidrReservationId]
    SubnetId: Optional[SubnetId]
    Cidr: Optional[String]
    ReservationType: Optional[SubnetCidrReservationType]
    OwnerId: Optional[String]
    Description: Optional[String]
    Tags: Optional[TagList]


class CreateSubnetCidrReservationResult(TypedDict, total=False):
    SubnetCidrReservation: Optional[SubnetCidrReservation]


class CreateSubnetRequest(ServiceRequest):
    TagSpecifications: Optional[TagSpecificationList]
    AvailabilityZone: Optional[String]
    AvailabilityZoneId: Optional[String]
    CidrBlock: Optional[String]
    Ipv6CidrBlock: Optional[String]
    OutpostArn: Optional[String]
    VpcId: VpcId
    Ipv6Native: Optional[Boolean]
    Ipv4IpamPoolId: Optional[IpamPoolId]
    Ipv4NetmaskLength: Optional[NetmaskLength]
    Ipv6IpamPoolId: Optional[IpamPoolId]
    Ipv6NetmaskLength: Optional[NetmaskLength]
    DryRun: Optional[Boolean]


class CreateSubnetResult(TypedDict, total=False):
    Subnet: Optional[Subnet]


ResourceIdList = List[TaggableResourceId]


class CreateTagsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Resources: ResourceIdList
    Tags: TagList


class CreateTrafficMirrorFilterRequest(ServiceRequest):
    Description: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]


TrafficMirrorNetworkServiceList = List[TrafficMirrorNetworkService]


class TrafficMirrorPortRange(TypedDict, total=False):
    FromPort: Optional[Integer]
    ToPort: Optional[Integer]


class TrafficMirrorFilterRule(TypedDict, total=False):
    TrafficMirrorFilterRuleId: Optional[String]
    TrafficMirrorFilterId: Optional[String]
    TrafficDirection: Optional[TrafficDirection]
    RuleNumber: Optional[Integer]
    RuleAction: Optional[TrafficMirrorRuleAction]
    Protocol: Optional[Integer]
    DestinationPortRange: Optional[TrafficMirrorPortRange]
    SourcePortRange: Optional[TrafficMirrorPortRange]
    DestinationCidrBlock: Optional[String]
    SourceCidrBlock: Optional[String]
    Description: Optional[String]
    Tags: Optional[TagList]


TrafficMirrorFilterRuleList = List[TrafficMirrorFilterRule]


class TrafficMirrorFilter(TypedDict, total=False):
    TrafficMirrorFilterId: Optional[String]
    IngressFilterRules: Optional[TrafficMirrorFilterRuleList]
    EgressFilterRules: Optional[TrafficMirrorFilterRuleList]
    NetworkServices: Optional[TrafficMirrorNetworkServiceList]
    Description: Optional[String]
    Tags: Optional[TagList]


class CreateTrafficMirrorFilterResult(TypedDict, total=False):
    TrafficMirrorFilter: Optional[TrafficMirrorFilter]
    ClientToken: Optional[String]


class TrafficMirrorPortRangeRequest(TypedDict, total=False):
    FromPort: Optional[Integer]
    ToPort: Optional[Integer]


class CreateTrafficMirrorFilterRuleRequest(ServiceRequest):
    TrafficMirrorFilterId: TrafficMirrorFilterId
    TrafficDirection: TrafficDirection
    RuleNumber: Integer
    RuleAction: TrafficMirrorRuleAction
    DestinationPortRange: Optional[TrafficMirrorPortRangeRequest]
    SourcePortRange: Optional[TrafficMirrorPortRangeRequest]
    Protocol: Optional[Integer]
    DestinationCidrBlock: String
    SourceCidrBlock: String
    Description: Optional[String]
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]


class CreateTrafficMirrorFilterRuleResult(TypedDict, total=False):
    TrafficMirrorFilterRule: Optional[TrafficMirrorFilterRule]
    ClientToken: Optional[String]


class CreateTrafficMirrorSessionRequest(ServiceRequest):
    NetworkInterfaceId: NetworkInterfaceId
    TrafficMirrorTargetId: TrafficMirrorTargetId
    TrafficMirrorFilterId: TrafficMirrorFilterId
    PacketLength: Optional[Integer]
    SessionNumber: Integer
    VirtualNetworkId: Optional[Integer]
    Description: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]


class TrafficMirrorSession(TypedDict, total=False):
    TrafficMirrorSessionId: Optional[String]
    TrafficMirrorTargetId: Optional[String]
    TrafficMirrorFilterId: Optional[String]
    NetworkInterfaceId: Optional[String]
    OwnerId: Optional[String]
    PacketLength: Optional[Integer]
    SessionNumber: Optional[Integer]
    VirtualNetworkId: Optional[Integer]
    Description: Optional[String]
    Tags: Optional[TagList]


class CreateTrafficMirrorSessionResult(TypedDict, total=False):
    TrafficMirrorSession: Optional[TrafficMirrorSession]
    ClientToken: Optional[String]


class CreateTrafficMirrorTargetRequest(ServiceRequest):
    NetworkInterfaceId: Optional[NetworkInterfaceId]
    NetworkLoadBalancerArn: Optional[String]
    Description: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]
    GatewayLoadBalancerEndpointId: Optional[VpcEndpointId]


class TrafficMirrorTarget(TypedDict, total=False):
    TrafficMirrorTargetId: Optional[String]
    NetworkInterfaceId: Optional[String]
    NetworkLoadBalancerArn: Optional[String]
    Type: Optional[TrafficMirrorTargetType]
    Description: Optional[String]
    OwnerId: Optional[String]
    Tags: Optional[TagList]
    GatewayLoadBalancerEndpointId: Optional[String]


class CreateTrafficMirrorTargetResult(TypedDict, total=False):
    TrafficMirrorTarget: Optional[TrafficMirrorTarget]
    ClientToken: Optional[String]


InsideCidrBlocksStringList = List[String]


class TransitGatewayConnectRequestBgpOptions(TypedDict, total=False):
    PeerAsn: Optional[Long]


class CreateTransitGatewayConnectPeerRequest(ServiceRequest):
    TransitGatewayAttachmentId: TransitGatewayAttachmentId
    TransitGatewayAddress: Optional[String]
    PeerAddress: String
    BgpOptions: Optional[TransitGatewayConnectRequestBgpOptions]
    InsideCidrBlocks: InsideCidrBlocksStringList
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class TransitGatewayAttachmentBgpConfiguration(TypedDict, total=False):
    TransitGatewayAsn: Optional[Long]
    PeerAsn: Optional[Long]
    TransitGatewayAddress: Optional[String]
    PeerAddress: Optional[String]
    BgpStatus: Optional[BgpStatus]


TransitGatewayAttachmentBgpConfigurationList = List[TransitGatewayAttachmentBgpConfiguration]


class TransitGatewayConnectPeerConfiguration(TypedDict, total=False):
    TransitGatewayAddress: Optional[String]
    PeerAddress: Optional[String]
    InsideCidrBlocks: Optional[InsideCidrBlocksStringList]
    Protocol: Optional[ProtocolValue]
    BgpConfigurations: Optional[TransitGatewayAttachmentBgpConfigurationList]


class TransitGatewayConnectPeer(TypedDict, total=False):
    TransitGatewayAttachmentId: Optional[TransitGatewayAttachmentId]
    TransitGatewayConnectPeerId: Optional[TransitGatewayConnectPeerId]
    State: Optional[TransitGatewayConnectPeerState]
    CreationTime: Optional[DateTime]
    ConnectPeerConfiguration: Optional[TransitGatewayConnectPeerConfiguration]
    Tags: Optional[TagList]


class CreateTransitGatewayConnectPeerResult(TypedDict, total=False):
    TransitGatewayConnectPeer: Optional[TransitGatewayConnectPeer]


class CreateTransitGatewayConnectRequestOptions(TypedDict, total=False):
    Protocol: ProtocolValue


class CreateTransitGatewayConnectRequest(ServiceRequest):
    TransportTransitGatewayAttachmentId: TransitGatewayAttachmentId
    Options: CreateTransitGatewayConnectRequestOptions
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class TransitGatewayConnectOptions(TypedDict, total=False):
    Protocol: Optional[ProtocolValue]


class TransitGatewayConnect(TypedDict, total=False):
    TransitGatewayAttachmentId: Optional[TransitGatewayAttachmentId]
    TransportTransitGatewayAttachmentId: Optional[TransitGatewayAttachmentId]
    TransitGatewayId: Optional[TransitGatewayId]
    State: Optional[TransitGatewayAttachmentState]
    CreationTime: Optional[DateTime]
    Options: Optional[TransitGatewayConnectOptions]
    Tags: Optional[TagList]


class CreateTransitGatewayConnectResult(TypedDict, total=False):
    TransitGatewayConnect: Optional[TransitGatewayConnect]


class CreateTransitGatewayMulticastDomainRequestOptions(TypedDict, total=False):
    Igmpv2Support: Optional[Igmpv2SupportValue]
    StaticSourcesSupport: Optional[StaticSourcesSupportValue]
    AutoAcceptSharedAssociations: Optional[AutoAcceptSharedAssociationsValue]


class CreateTransitGatewayMulticastDomainRequest(ServiceRequest):
    TransitGatewayId: TransitGatewayId
    Options: Optional[CreateTransitGatewayMulticastDomainRequestOptions]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class TransitGatewayMulticastDomainOptions(TypedDict, total=False):
    Igmpv2Support: Optional[Igmpv2SupportValue]
    StaticSourcesSupport: Optional[StaticSourcesSupportValue]
    AutoAcceptSharedAssociations: Optional[AutoAcceptSharedAssociationsValue]


class TransitGatewayMulticastDomain(TypedDict, total=False):
    TransitGatewayMulticastDomainId: Optional[String]
    TransitGatewayId: Optional[String]
    TransitGatewayMulticastDomainArn: Optional[String]
    OwnerId: Optional[String]
    Options: Optional[TransitGatewayMulticastDomainOptions]
    State: Optional[TransitGatewayMulticastDomainState]
    CreationTime: Optional[DateTime]
    Tags: Optional[TagList]


class CreateTransitGatewayMulticastDomainResult(TypedDict, total=False):
    TransitGatewayMulticastDomain: Optional[TransitGatewayMulticastDomain]


class CreateTransitGatewayPeeringAttachmentRequestOptions(TypedDict, total=False):
    DynamicRouting: Optional[DynamicRoutingValue]


class CreateTransitGatewayPeeringAttachmentRequest(ServiceRequest):
    TransitGatewayId: TransitGatewayId
    PeerTransitGatewayId: TransitAssociationGatewayId
    PeerAccountId: String
    PeerRegion: String
    Options: Optional[CreateTransitGatewayPeeringAttachmentRequestOptions]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class CreateTransitGatewayPeeringAttachmentResult(TypedDict, total=False):
    TransitGatewayPeeringAttachment: Optional[TransitGatewayPeeringAttachment]


class CreateTransitGatewayPolicyTableRequest(ServiceRequest):
    TransitGatewayId: TransitGatewayId
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class TransitGatewayPolicyTable(TypedDict, total=False):
    TransitGatewayPolicyTableId: Optional[TransitGatewayPolicyTableId]
    TransitGatewayId: Optional[TransitGatewayId]
    State: Optional[TransitGatewayPolicyTableState]
    CreationTime: Optional[DateTime]
    Tags: Optional[TagList]


class CreateTransitGatewayPolicyTableResult(TypedDict, total=False):
    TransitGatewayPolicyTable: Optional[TransitGatewayPolicyTable]


class CreateTransitGatewayPrefixListReferenceRequest(ServiceRequest):
    TransitGatewayRouteTableId: TransitGatewayRouteTableId
    PrefixListId: PrefixListResourceId
    TransitGatewayAttachmentId: Optional[TransitGatewayAttachmentId]
    Blackhole: Optional[Boolean]
    DryRun: Optional[Boolean]


class TransitGatewayPrefixListAttachment(TypedDict, total=False):
    TransitGatewayAttachmentId: Optional[TransitGatewayAttachmentId]
    ResourceType: Optional[TransitGatewayAttachmentResourceType]
    ResourceId: Optional[String]


class TransitGatewayPrefixListReference(TypedDict, total=False):
    TransitGatewayRouteTableId: Optional[TransitGatewayRouteTableId]
    PrefixListId: Optional[PrefixListResourceId]
    PrefixListOwnerId: Optional[String]
    State: Optional[TransitGatewayPrefixListReferenceState]
    Blackhole: Optional[Boolean]
    TransitGatewayAttachment: Optional[TransitGatewayPrefixListAttachment]


class CreateTransitGatewayPrefixListReferenceResult(TypedDict, total=False):
    TransitGatewayPrefixListReference: Optional[TransitGatewayPrefixListReference]


TransitGatewayCidrBlockStringList = List[String]


class TransitGatewayRequestOptions(TypedDict, total=False):
    AmazonSideAsn: Optional[Long]
    AutoAcceptSharedAttachments: Optional[AutoAcceptSharedAttachmentsValue]
    DefaultRouteTableAssociation: Optional[DefaultRouteTableAssociationValue]
    DefaultRouteTablePropagation: Optional[DefaultRouteTablePropagationValue]
    VpnEcmpSupport: Optional[VpnEcmpSupportValue]
    DnsSupport: Optional[DnsSupportValue]
    SecurityGroupReferencingSupport: Optional[SecurityGroupReferencingSupportValue]
    MulticastSupport: Optional[MulticastSupportValue]
    TransitGatewayCidrBlocks: Optional[TransitGatewayCidrBlockStringList]


class CreateTransitGatewayRequest(ServiceRequest):
    Description: Optional[String]
    Options: Optional[TransitGatewayRequestOptions]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class TransitGatewayOptions(TypedDict, total=False):
    AmazonSideAsn: Optional[Long]
    TransitGatewayCidrBlocks: Optional[ValueStringList]
    AutoAcceptSharedAttachments: Optional[AutoAcceptSharedAttachmentsValue]
    DefaultRouteTableAssociation: Optional[DefaultRouteTableAssociationValue]
    AssociationDefaultRouteTableId: Optional[String]
    DefaultRouteTablePropagation: Optional[DefaultRouteTablePropagationValue]
    PropagationDefaultRouteTableId: Optional[String]
    VpnEcmpSupport: Optional[VpnEcmpSupportValue]
    DnsSupport: Optional[DnsSupportValue]
    SecurityGroupReferencingSupport: Optional[SecurityGroupReferencingSupportValue]
    MulticastSupport: Optional[MulticastSupportValue]


class TransitGateway(TypedDict, total=False):
    TransitGatewayId: Optional[String]
    TransitGatewayArn: Optional[String]
    State: Optional[TransitGatewayState]
    OwnerId: Optional[String]
    Description: Optional[String]
    CreationTime: Optional[DateTime]
    Options: Optional[TransitGatewayOptions]
    Tags: Optional[TagList]


class CreateTransitGatewayResult(TypedDict, total=False):
    TransitGateway: Optional[TransitGateway]


class CreateTransitGatewayRouteRequest(ServiceRequest):
    DestinationCidrBlock: String
    TransitGatewayRouteTableId: TransitGatewayRouteTableId
    TransitGatewayAttachmentId: Optional[TransitGatewayAttachmentId]
    Blackhole: Optional[Boolean]
    DryRun: Optional[Boolean]


class TransitGatewayRouteAttachment(TypedDict, total=False):
    ResourceId: Optional[String]
    TransitGatewayAttachmentId: Optional[String]
    ResourceType: Optional[TransitGatewayAttachmentResourceType]


TransitGatewayRouteAttachmentList = List[TransitGatewayRouteAttachment]


class TransitGatewayRoute(TypedDict, total=False):
    DestinationCidrBlock: Optional[String]
    PrefixListId: Optional[PrefixListResourceId]
    TransitGatewayRouteTableAnnouncementId: Optional[TransitGatewayRouteTableAnnouncementId]
    TransitGatewayAttachments: Optional[TransitGatewayRouteAttachmentList]
    Type: Optional[TransitGatewayRouteType]
    State: Optional[TransitGatewayRouteState]


class CreateTransitGatewayRouteResult(TypedDict, total=False):
    Route: Optional[TransitGatewayRoute]


class CreateTransitGatewayRouteTableAnnouncementRequest(ServiceRequest):
    TransitGatewayRouteTableId: TransitGatewayRouteTableId
    PeeringAttachmentId: TransitGatewayAttachmentId
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class TransitGatewayRouteTableAnnouncement(TypedDict, total=False):
    TransitGatewayRouteTableAnnouncementId: Optional[TransitGatewayRouteTableAnnouncementId]
    TransitGatewayId: Optional[TransitGatewayId]
    CoreNetworkId: Optional[String]
    PeerTransitGatewayId: Optional[TransitGatewayId]
    PeerCoreNetworkId: Optional[String]
    PeeringAttachmentId: Optional[TransitGatewayAttachmentId]
    AnnouncementDirection: Optional[TransitGatewayRouteTableAnnouncementDirection]
    TransitGatewayRouteTableId: Optional[TransitGatewayRouteTableId]
    State: Optional[TransitGatewayRouteTableAnnouncementState]
    CreationTime: Optional[DateTime]
    Tags: Optional[TagList]


class CreateTransitGatewayRouteTableAnnouncementResult(TypedDict, total=False):
    TransitGatewayRouteTableAnnouncement: Optional[TransitGatewayRouteTableAnnouncement]


class CreateTransitGatewayRouteTableRequest(ServiceRequest):
    TransitGatewayId: TransitGatewayId
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class TransitGatewayRouteTable(TypedDict, total=False):
    TransitGatewayRouteTableId: Optional[String]
    TransitGatewayId: Optional[String]
    State: Optional[TransitGatewayRouteTableState]
    DefaultAssociationRouteTable: Optional[Boolean]
    DefaultPropagationRouteTable: Optional[Boolean]
    CreationTime: Optional[DateTime]
    Tags: Optional[TagList]


class CreateTransitGatewayRouteTableResult(TypedDict, total=False):
    TransitGatewayRouteTable: Optional[TransitGatewayRouteTable]


class CreateTransitGatewayVpcAttachmentRequestOptions(TypedDict, total=False):
    DnsSupport: Optional[DnsSupportValue]
    SecurityGroupReferencingSupport: Optional[SecurityGroupReferencingSupportValue]
    Ipv6Support: Optional[Ipv6SupportValue]
    ApplianceModeSupport: Optional[ApplianceModeSupportValue]


class CreateTransitGatewayVpcAttachmentRequest(ServiceRequest):
    TransitGatewayId: TransitGatewayId
    VpcId: VpcId
    SubnetIds: TransitGatewaySubnetIdList
    Options: Optional[CreateTransitGatewayVpcAttachmentRequestOptions]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]


class CreateTransitGatewayVpcAttachmentResult(TypedDict, total=False):
    TransitGatewayVpcAttachment: Optional[TransitGatewayVpcAttachment]


class CreateVerifiedAccessEndpointEniOptions(TypedDict, total=False):
    NetworkInterfaceId: Optional[NetworkInterfaceId]
    Protocol: Optional[VerifiedAccessEndpointProtocol]
    Port: Optional[VerifiedAccessEndpointPortNumber]


CreateVerifiedAccessEndpointSubnetIdList = List[SubnetId]


class CreateVerifiedAccessEndpointLoadBalancerOptions(TypedDict, total=False):
    Protocol: Optional[VerifiedAccessEndpointProtocol]
    Port: Optional[VerifiedAccessEndpointPortNumber]
    LoadBalancerArn: Optional[LoadBalancerArn]
    SubnetIds: Optional[CreateVerifiedAccessEndpointSubnetIdList]


class VerifiedAccessSseSpecificationRequest(TypedDict, total=False):
    CustomerManagedKeyEnabled: Optional[Boolean]
    KmsKeyArn: Optional[KmsKeyArn]


SecurityGroupIdList = List[SecurityGroupId]


class CreateVerifiedAccessEndpointRequest(ServiceRequest):
    VerifiedAccessGroupId: VerifiedAccessGroupId
    EndpointType: VerifiedAccessEndpointType
    AttachmentType: VerifiedAccessEndpointAttachmentType
    DomainCertificateArn: CertificateArn
    ApplicationDomain: String
    EndpointDomainPrefix: String
    SecurityGroupIds: Optional[SecurityGroupIdList]
    LoadBalancerOptions: Optional[CreateVerifiedAccessEndpointLoadBalancerOptions]
    NetworkInterfaceOptions: Optional[CreateVerifiedAccessEndpointEniOptions]
    Description: Optional[String]
    PolicyDocument: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]
    SseSpecification: Optional[VerifiedAccessSseSpecificationRequest]


class VerifiedAccessEndpointStatus(TypedDict, total=False):
    Code: Optional[VerifiedAccessEndpointStatusCode]
    Message: Optional[String]


class VerifiedAccessEndpointEniOptions(TypedDict, total=False):
    NetworkInterfaceId: Optional[NetworkInterfaceId]
    Protocol: Optional[VerifiedAccessEndpointProtocol]
    Port: Optional[VerifiedAccessEndpointPortNumber]


VerifiedAccessEndpointSubnetIdList = List[SubnetId]


class VerifiedAccessEndpointLoadBalancerOptions(TypedDict, total=False):
    Protocol: Optional[VerifiedAccessEndpointProtocol]
    Port: Optional[VerifiedAccessEndpointPortNumber]
    LoadBalancerArn: Optional[String]
    SubnetIds: Optional[VerifiedAccessEndpointSubnetIdList]


class VerifiedAccessEndpoint(TypedDict, total=False):
    VerifiedAccessInstanceId: Optional[String]
    VerifiedAccessGroupId: Optional[String]
    VerifiedAccessEndpointId: Optional[String]
    ApplicationDomain: Optional[String]
    EndpointType: Optional[VerifiedAccessEndpointType]
    AttachmentType: Optional[VerifiedAccessEndpointAttachmentType]
    DomainCertificateArn: Optional[String]
    EndpointDomain: Optional[String]
    DeviceValidationDomain: Optional[String]
    SecurityGroupIds: Optional[SecurityGroupIdList]
    LoadBalancerOptions: Optional[VerifiedAccessEndpointLoadBalancerOptions]
    NetworkInterfaceOptions: Optional[VerifiedAccessEndpointEniOptions]
    Status: Optional[VerifiedAccessEndpointStatus]
    Description: Optional[String]
    CreationTime: Optional[String]
    LastUpdatedTime: Optional[String]
    DeletionTime: Optional[String]
    Tags: Optional[TagList]
    SseSpecification: Optional[VerifiedAccessSseSpecificationResponse]


class CreateVerifiedAccessEndpointResult(TypedDict, total=False):
    VerifiedAccessEndpoint: Optional[VerifiedAccessEndpoint]


class CreateVerifiedAccessGroupRequest(ServiceRequest):
    VerifiedAccessInstanceId: VerifiedAccessInstanceId
    Description: Optional[String]
    PolicyDocument: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]
    SseSpecification: Optional[VerifiedAccessSseSpecificationRequest]


class VerifiedAccessGroup(TypedDict, total=False):
    VerifiedAccessGroupId: Optional[String]
    VerifiedAccessInstanceId: Optional[String]
    Description: Optional[String]
    Owner: Optional[String]
    VerifiedAccessGroupArn: Optional[String]
    CreationTime: Optional[String]
    LastUpdatedTime: Optional[String]
    DeletionTime: Optional[String]
    Tags: Optional[TagList]
    SseSpecification: Optional[VerifiedAccessSseSpecificationResponse]


class CreateVerifiedAccessGroupResult(TypedDict, total=False):
    VerifiedAccessGroup: Optional[VerifiedAccessGroup]


class CreateVerifiedAccessInstanceRequest(ServiceRequest):
    Description: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]
    FIPSEnabled: Optional[Boolean]


class CreateVerifiedAccessInstanceResult(TypedDict, total=False):
    VerifiedAccessInstance: Optional[VerifiedAccessInstance]


class CreateVerifiedAccessTrustProviderDeviceOptions(TypedDict, total=False):
    TenantId: Optional[String]
    PublicSigningKeyUrl: Optional[String]


class CreateVerifiedAccessTrustProviderOidcOptions(TypedDict, total=False):
    Issuer: Optional[String]
    AuthorizationEndpoint: Optional[String]
    TokenEndpoint: Optional[String]
    UserInfoEndpoint: Optional[String]
    ClientId: Optional[String]
    ClientSecret: Optional[ClientSecretType]
    Scope: Optional[String]


class CreateVerifiedAccessTrustProviderRequest(ServiceRequest):
    TrustProviderType: TrustProviderType
    UserTrustProviderType: Optional[UserTrustProviderType]
    DeviceTrustProviderType: Optional[DeviceTrustProviderType]
    OidcOptions: Optional[CreateVerifiedAccessTrustProviderOidcOptions]
    DeviceOptions: Optional[CreateVerifiedAccessTrustProviderDeviceOptions]
    PolicyReferenceName: String
    Description: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]
    SseSpecification: Optional[VerifiedAccessSseSpecificationRequest]


class CreateVerifiedAccessTrustProviderResult(TypedDict, total=False):
    VerifiedAccessTrustProvider: Optional[VerifiedAccessTrustProvider]


class CreateVolumePermission(TypedDict, total=False):
    UserId: Optional[String]
    Group: Optional[PermissionGroup]


CreateVolumePermissionList = List[CreateVolumePermission]


class CreateVolumePermissionModifications(TypedDict, total=False):
    Add: Optional[CreateVolumePermissionList]
    Remove: Optional[CreateVolumePermissionList]


class CreateVolumeRequest(ServiceRequest):
    AvailabilityZone: AvailabilityZoneName
    Encrypted: Optional[Boolean]
    Iops: Optional[Integer]
    KmsKeyId: Optional[KmsKeyId]
    OutpostArn: Optional[String]
    Size: Optional[Integer]
    SnapshotId: Optional[SnapshotId]
    VolumeType: Optional[VolumeType]
    TagSpecifications: Optional[TagSpecificationList]
    MultiAttachEnabled: Optional[Boolean]
    Throughput: Optional[Integer]
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]


class CreateVpcEndpointConnectionNotificationRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ServiceId: Optional[VpcEndpointServiceId]
    VpcEndpointId: Optional[VpcEndpointId]
    ConnectionNotificationArn: String
    ConnectionEvents: ValueStringList
    ClientToken: Optional[String]


class CreateVpcEndpointConnectionNotificationResult(TypedDict, total=False):
    ConnectionNotification: Optional[ConnectionNotification]
    ClientToken: Optional[String]


class SubnetConfiguration(TypedDict, total=False):
    SubnetId: Optional[SubnetId]
    Ipv4: Optional[String]
    Ipv6: Optional[String]


SubnetConfigurationsList = List[SubnetConfiguration]


class DnsOptionsSpecification(TypedDict, total=False):
    DnsRecordIpType: Optional[DnsRecordIpType]
    PrivateDnsOnlyForInboundResolverEndpoint: Optional[Boolean]


VpcEndpointSecurityGroupIdList = List[SecurityGroupId]
VpcEndpointSubnetIdList = List[SubnetId]
VpcEndpointRouteTableIdList = List[RouteTableId]


class CreateVpcEndpointRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    VpcEndpointType: Optional[VpcEndpointType]
    VpcId: VpcId
    ServiceName: String
    PolicyDocument: Optional[String]
    RouteTableIds: Optional[VpcEndpointRouteTableIdList]
    SubnetIds: Optional[VpcEndpointSubnetIdList]
    SecurityGroupIds: Optional[VpcEndpointSecurityGroupIdList]
    IpAddressType: Optional[IpAddressType]
    DnsOptions: Optional[DnsOptionsSpecification]
    ClientToken: Optional[String]
    PrivateDnsEnabled: Optional[Boolean]
    TagSpecifications: Optional[TagSpecificationList]
    SubnetConfigurations: Optional[SubnetConfigurationsList]


class LastError(TypedDict, total=False):
    Message: Optional[String]
    Code: Optional[String]


class DnsEntry(TypedDict, total=False):
    DnsName: Optional[String]
    HostedZoneId: Optional[String]


DnsEntrySet = List[DnsEntry]


class DnsOptions(TypedDict, total=False):
    DnsRecordIpType: Optional[DnsRecordIpType]
    PrivateDnsOnlyForInboundResolverEndpoint: Optional[Boolean]


class SecurityGroupIdentifier(TypedDict, total=False):
    GroupId: Optional[String]
    GroupName: Optional[String]


GroupIdentifierSet = List[SecurityGroupIdentifier]


class VpcEndpoint(TypedDict, total=False):
    VpcEndpointId: Optional[String]
    VpcEndpointType: Optional[VpcEndpointType]
    VpcId: Optional[String]
    ServiceName: Optional[String]
    State: Optional[State]
    PolicyDocument: Optional[String]
    RouteTableIds: Optional[ValueStringList]
    SubnetIds: Optional[ValueStringList]
    Groups: Optional[GroupIdentifierSet]
    IpAddressType: Optional[IpAddressType]
    DnsOptions: Optional[DnsOptions]
    PrivateDnsEnabled: Optional[Boolean]
    RequesterManaged: Optional[Boolean]
    NetworkInterfaceIds: Optional[ValueStringList]
    DnsEntries: Optional[DnsEntrySet]
    CreationTimestamp: Optional[MillisecondDateTime]
    Tags: Optional[TagList]
    OwnerId: Optional[String]
    LastError: Optional[LastError]


class CreateVpcEndpointResult(TypedDict, total=False):
    VpcEndpoint: Optional[VpcEndpoint]
    ClientToken: Optional[String]


class CreateVpcEndpointServiceConfigurationRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    AcceptanceRequired: Optional[Boolean]
    PrivateDnsName: Optional[String]
    NetworkLoadBalancerArns: Optional[ValueStringList]
    GatewayLoadBalancerArns: Optional[ValueStringList]
    SupportedIpAddressTypes: Optional[ValueStringList]
    ClientToken: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]


class PrivateDnsNameConfiguration(TypedDict, total=False):
    State: Optional[DnsNameState]
    Type: Optional[String]
    Value: Optional[String]
    Name: Optional[String]


SupportedIpAddressTypes = List[ServiceConnectivityType]


class ServiceTypeDetail(TypedDict, total=False):
    ServiceType: Optional[ServiceType]


ServiceTypeDetailSet = List[ServiceTypeDetail]


class ServiceConfiguration(TypedDict, total=False):
    ServiceType: Optional[ServiceTypeDetailSet]
    ServiceId: Optional[String]
    ServiceName: Optional[String]
    ServiceState: Optional[ServiceState]
    AvailabilityZones: Optional[ValueStringList]
    AcceptanceRequired: Optional[Boolean]
    ManagesVpcEndpoints: Optional[Boolean]
    NetworkLoadBalancerArns: Optional[ValueStringList]
    GatewayLoadBalancerArns: Optional[ValueStringList]
    SupportedIpAddressTypes: Optional[SupportedIpAddressTypes]
    BaseEndpointDnsNames: Optional[ValueStringList]
    PrivateDnsName: Optional[String]
    PrivateDnsNameConfiguration: Optional[PrivateDnsNameConfiguration]
    PayerResponsibility: Optional[PayerResponsibility]
    Tags: Optional[TagList]


class CreateVpcEndpointServiceConfigurationResult(TypedDict, total=False):
    ServiceConfiguration: Optional[ServiceConfiguration]
    ClientToken: Optional[String]


class CreateVpcPeeringConnectionRequest(ServiceRequest):
    PeerRegion: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]
    VpcId: VpcId
    PeerVpcId: Optional[String]
    PeerOwnerId: Optional[String]


class CreateVpcPeeringConnectionResult(TypedDict, total=False):
    VpcPeeringConnection: Optional[VpcPeeringConnection]


class CreateVpcRequest(ServiceRequest):
    CidrBlock: Optional[String]
    Ipv6Pool: Optional[Ipv6PoolEc2Id]
    Ipv6CidrBlock: Optional[String]
    Ipv4IpamPoolId: Optional[IpamPoolId]
    Ipv4NetmaskLength: Optional[NetmaskLength]
    Ipv6IpamPoolId: Optional[IpamPoolId]
    Ipv6NetmaskLength: Optional[NetmaskLength]
    Ipv6CidrBlockNetworkBorderGroup: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]
    InstanceTenancy: Optional[Tenancy]
    AmazonProvidedIpv6CidrBlock: Optional[Boolean]


class CreateVpcResult(TypedDict, total=False):
    Vpc: Optional[Vpc]


class VpnTunnelLogOptionsSpecification(TypedDict, total=False):
    CloudWatchLogOptions: Optional[CloudWatchLogOptionsSpecification]


class IKEVersionsRequestListValue(TypedDict, total=False):
    Value: Optional[String]


IKEVersionsRequestList = List[IKEVersionsRequestListValue]


class Phase2DHGroupNumbersRequestListValue(TypedDict, total=False):
    Value: Optional[Integer]


Phase2DHGroupNumbersRequestList = List[Phase2DHGroupNumbersRequestListValue]


class Phase1DHGroupNumbersRequestListValue(TypedDict, total=False):
    Value: Optional[Integer]


Phase1DHGroupNumbersRequestList = List[Phase1DHGroupNumbersRequestListValue]


class Phase2IntegrityAlgorithmsRequestListValue(TypedDict, total=False):
    Value: Optional[String]


Phase2IntegrityAlgorithmsRequestList = List[Phase2IntegrityAlgorithmsRequestListValue]


class Phase1IntegrityAlgorithmsRequestListValue(TypedDict, total=False):
    Value: Optional[String]


Phase1IntegrityAlgorithmsRequestList = List[Phase1IntegrityAlgorithmsRequestListValue]


class Phase2EncryptionAlgorithmsRequestListValue(TypedDict, total=False):
    Value: Optional[String]


Phase2EncryptionAlgorithmsRequestList = List[Phase2EncryptionAlgorithmsRequestListValue]


class Phase1EncryptionAlgorithmsRequestListValue(TypedDict, total=False):
    Value: Optional[String]


Phase1EncryptionAlgorithmsRequestList = List[Phase1EncryptionAlgorithmsRequestListValue]


class VpnTunnelOptionsSpecification(TypedDict, total=False):
    TunnelInsideCidr: Optional[String]
    TunnelInsideIpv6Cidr: Optional[String]
    PreSharedKey: Optional[preSharedKey]
    Phase1LifetimeSeconds: Optional[Integer]
    Phase2LifetimeSeconds: Optional[Integer]
    RekeyMarginTimeSeconds: Optional[Integer]
    RekeyFuzzPercentage: Optional[Integer]
    ReplayWindowSize: Optional[Integer]
    DPDTimeoutSeconds: Optional[Integer]
    DPDTimeoutAction: Optional[String]
    Phase1EncryptionAlgorithms: Optional[Phase1EncryptionAlgorithmsRequestList]
    Phase2EncryptionAlgorithms: Optional[Phase2EncryptionAlgorithmsRequestList]
    Phase1IntegrityAlgorithms: Optional[Phase1IntegrityAlgorithmsRequestList]
    Phase2IntegrityAlgorithms: Optional[Phase2IntegrityAlgorithmsRequestList]
    Phase1DHGroupNumbers: Optional[Phase1DHGroupNumbersRequestList]
    Phase2DHGroupNumbers: Optional[Phase2DHGroupNumbersRequestList]
    IKEVersions: Optional[IKEVersionsRequestList]
    StartupAction: Optional[String]
    LogOptions: Optional[VpnTunnelLogOptionsSpecification]
    EnableTunnelLifecycleControl: Optional[Boolean]


VpnTunnelOptionsSpecificationsList = List[VpnTunnelOptionsSpecification]


class VpnConnectionOptionsSpecification(TypedDict, total=False):
    EnableAcceleration: Optional[Boolean]
    TunnelInsideIpVersion: Optional[TunnelInsideIpVersion]
    TunnelOptions: Optional[VpnTunnelOptionsSpecificationsList]
    LocalIpv4NetworkCidr: Optional[String]
    RemoteIpv4NetworkCidr: Optional[String]
    LocalIpv6NetworkCidr: Optional[String]
    RemoteIpv6NetworkCidr: Optional[String]
    OutsideIpAddressType: Optional[String]
    TransportTransitGatewayAttachmentId: Optional[TransitGatewayAttachmentId]
    StaticRoutesOnly: Optional[Boolean]


class CreateVpnConnectionRequest(ServiceRequest):
    CustomerGatewayId: CustomerGatewayId
    Type: String
    VpnGatewayId: Optional[VpnGatewayId]
    TransitGatewayId: Optional[TransitGatewayId]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]
    Options: Optional[VpnConnectionOptionsSpecification]


class VgwTelemetry(TypedDict, total=False):
    AcceptedRouteCount: Optional[Integer]
    LastStatusChange: Optional[DateTime]
    OutsideIpAddress: Optional[String]
    Status: Optional[TelemetryStatus]
    StatusMessage: Optional[String]
    CertificateArn: Optional[String]


VgwTelemetryList = List[VgwTelemetry]


class VpnStaticRoute(TypedDict, total=False):
    DestinationCidrBlock: Optional[String]
    Source: Optional[VpnStaticRouteSource]
    State: Optional[VpnState]


VpnStaticRouteList = List[VpnStaticRoute]


class VpnTunnelLogOptions(TypedDict, total=False):
    CloudWatchLogOptions: Optional[CloudWatchLogOptions]


class IKEVersionsListValue(TypedDict, total=False):
    Value: Optional[String]


IKEVersionsList = List[IKEVersionsListValue]


class Phase2DHGroupNumbersListValue(TypedDict, total=False):
    Value: Optional[Integer]


Phase2DHGroupNumbersList = List[Phase2DHGroupNumbersListValue]


class Phase1DHGroupNumbersListValue(TypedDict, total=False):
    Value: Optional[Integer]


Phase1DHGroupNumbersList = List[Phase1DHGroupNumbersListValue]


class Phase2IntegrityAlgorithmsListValue(TypedDict, total=False):
    Value: Optional[String]


Phase2IntegrityAlgorithmsList = List[Phase2IntegrityAlgorithmsListValue]


class Phase1IntegrityAlgorithmsListValue(TypedDict, total=False):
    Value: Optional[String]


Phase1IntegrityAlgorithmsList = List[Phase1IntegrityAlgorithmsListValue]


class Phase2EncryptionAlgorithmsListValue(TypedDict, total=False):
    Value: Optional[String]


Phase2EncryptionAlgorithmsList = List[Phase2EncryptionAlgorithmsListValue]


class Phase1EncryptionAlgorithmsListValue(TypedDict, total=False):
    Value: Optional[String]


Phase1EncryptionAlgorithmsList = List[Phase1EncryptionAlgorithmsListValue]


class TunnelOption(TypedDict, total=False):
    OutsideIpAddress: Optional[String]
    TunnelInsideCidr: Optional[String]
    TunnelInsideIpv6Cidr: Optional[String]
    PreSharedKey: Optional[preSharedKey]
    Phase1LifetimeSeconds: Optional[Integer]
    Phase2LifetimeSeconds: Optional[Integer]
    RekeyMarginTimeSeconds: Optional[Integer]
    RekeyFuzzPercentage: Optional[Integer]
    ReplayWindowSize: Optional[Integer]
    DpdTimeoutSeconds: Optional[Integer]
    DpdTimeoutAction: Optional[String]
    Phase1EncryptionAlgorithms: Optional[Phase1EncryptionAlgorithmsList]
    Phase2EncryptionAlgorithms: Optional[Phase2EncryptionAlgorithmsList]
    Phase1IntegrityAlgorithms: Optional[Phase1IntegrityAlgorithmsList]
    Phase2IntegrityAlgorithms: Optional[Phase2IntegrityAlgorithmsList]
    Phase1DHGroupNumbers: Optional[Phase1DHGroupNumbersList]
    Phase2DHGroupNumbers: Optional[Phase2DHGroupNumbersList]
    IkeVersions: Optional[IKEVersionsList]
    StartupAction: Optional[String]
    LogOptions: Optional[VpnTunnelLogOptions]
    EnableTunnelLifecycleControl: Optional[Boolean]


TunnelOptionsList = List[TunnelOption]


class VpnConnectionOptions(TypedDict, total=False):
    EnableAcceleration: Optional[Boolean]
    StaticRoutesOnly: Optional[Boolean]
    LocalIpv4NetworkCidr: Optional[String]
    RemoteIpv4NetworkCidr: Optional[String]
    LocalIpv6NetworkCidr: Optional[String]
    RemoteIpv6NetworkCidr: Optional[String]
    OutsideIpAddressType: Optional[String]
    TransportTransitGatewayAttachmentId: Optional[String]
    TunnelInsideIpVersion: Optional[TunnelInsideIpVersion]
    TunnelOptions: Optional[TunnelOptionsList]


class VpnConnection(TypedDict, total=False):
    Category: Optional[String]
    TransitGatewayId: Optional[String]
    CoreNetworkArn: Optional[String]
    CoreNetworkAttachmentArn: Optional[String]
    GatewayAssociationState: Optional[GatewayAssociationState]
    Options: Optional[VpnConnectionOptions]
    Routes: Optional[VpnStaticRouteList]
    Tags: Optional[TagList]
    VgwTelemetry: Optional[VgwTelemetryList]
    VpnConnectionId: Optional[String]
    State: Optional[VpnState]
    CustomerGatewayConfiguration: Optional[customerGatewayConfiguration]
    Type: Optional[GatewayType]
    CustomerGatewayId: Optional[String]
    VpnGatewayId: Optional[String]


class CreateVpnConnectionResult(TypedDict, total=False):
    VpnConnection: Optional[VpnConnection]


class CreateVpnConnectionRouteRequest(ServiceRequest):
    DestinationCidrBlock: String
    VpnConnectionId: VpnConnectionId


class CreateVpnGatewayRequest(ServiceRequest):
    AvailabilityZone: Optional[String]
    Type: GatewayType
    TagSpecifications: Optional[TagSpecificationList]
    AmazonSideAsn: Optional[Long]
    DryRun: Optional[Boolean]


VpcAttachmentList = List[VpcAttachment]


class VpnGateway(TypedDict, total=False):
    AmazonSideAsn: Optional[Long]
    Tags: Optional[TagList]
    VpnGatewayId: Optional[String]
    State: Optional[VpnState]
    Type: Optional[GatewayType]
    AvailabilityZone: Optional[String]
    VpcAttachments: Optional[VpcAttachmentList]


class CreateVpnGatewayResult(TypedDict, total=False):
    VpnGateway: Optional[VpnGateway]


CustomerGatewayIdStringList = List[CustomerGatewayId]
CustomerGatewayList = List[CustomerGateway]


class DataQuery(TypedDict, total=False):
    Id: Optional[String]
    Source: Optional[String]
    Destination: Optional[String]
    Metric: Optional[MetricType]
    Statistic: Optional[StatisticType]
    Period: Optional[PeriodType]


DataQueries = List[DataQuery]


class MetricPoint(TypedDict, total=False):
    StartDate: Optional[MillisecondDateTime]
    EndDate: Optional[MillisecondDateTime]
    Value: Optional[Float]
    Status: Optional[String]


MetricPoints = List[MetricPoint]


class DataResponse(TypedDict, total=False):
    Id: Optional[String]
    Source: Optional[String]
    Destination: Optional[String]
    Metric: Optional[MetricType]
    Statistic: Optional[StatisticType]
    Period: Optional[PeriodType]
    MetricPoints: Optional[MetricPoints]


DataResponses = List[DataResponse]


class DeleteCarrierGatewayRequest(ServiceRequest):
    CarrierGatewayId: CarrierGatewayId
    DryRun: Optional[Boolean]


class DeleteCarrierGatewayResult(TypedDict, total=False):
    CarrierGateway: Optional[CarrierGateway]


class DeleteClientVpnEndpointRequest(ServiceRequest):
    ClientVpnEndpointId: ClientVpnEndpointId
    DryRun: Optional[Boolean]


class DeleteClientVpnEndpointResult(TypedDict, total=False):
    Status: Optional[ClientVpnEndpointStatus]


class DeleteClientVpnRouteRequest(ServiceRequest):
    ClientVpnEndpointId: ClientVpnEndpointId
    TargetVpcSubnetId: Optional[SubnetId]
    DestinationCidrBlock: String
    DryRun: Optional[Boolean]


class DeleteClientVpnRouteResult(TypedDict, total=False):
    Status: Optional[ClientVpnRouteStatus]


class DeleteCoipCidrRequest(ServiceRequest):
    Cidr: String
    CoipPoolId: Ipv4PoolCoipId
    DryRun: Optional[Boolean]


class DeleteCoipCidrResult(TypedDict, total=False):
    CoipCidr: Optional[CoipCidr]


class DeleteCoipPoolRequest(ServiceRequest):
    CoipPoolId: Ipv4PoolCoipId
    DryRun: Optional[Boolean]


class DeleteCoipPoolResult(TypedDict, total=False):
    CoipPool: Optional[CoipPool]


class DeleteCustomerGatewayRequest(ServiceRequest):
    CustomerGatewayId: CustomerGatewayId
    DryRun: Optional[Boolean]


class DeleteDhcpOptionsRequest(ServiceRequest):
    DhcpOptionsId: DhcpOptionsId
    DryRun: Optional[Boolean]


class DeleteEgressOnlyInternetGatewayRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    EgressOnlyInternetGatewayId: EgressOnlyInternetGatewayId


class DeleteEgressOnlyInternetGatewayResult(TypedDict, total=False):
    ReturnCode: Optional[Boolean]


class DeleteFleetError(TypedDict, total=False):
    Code: Optional[DeleteFleetErrorCode]
    Message: Optional[String]


class DeleteFleetErrorItem(TypedDict, total=False):
    Error: Optional[DeleteFleetError]
    FleetId: Optional[FleetId]


DeleteFleetErrorSet = List[DeleteFleetErrorItem]


class DeleteFleetSuccessItem(TypedDict, total=False):
    CurrentFleetState: Optional[FleetStateCode]
    PreviousFleetState: Optional[FleetStateCode]
    FleetId: Optional[FleetId]


DeleteFleetSuccessSet = List[DeleteFleetSuccessItem]
FleetIdSet = List[FleetId]


class DeleteFleetsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    FleetIds: FleetIdSet
    TerminateInstances: Boolean


class DeleteFleetsResult(TypedDict, total=False):
    SuccessfulFleetDeletions: Optional[DeleteFleetSuccessSet]
    UnsuccessfulFleetDeletions: Optional[DeleteFleetErrorSet]


FlowLogIdList = List[VpcFlowLogId]


class DeleteFlowLogsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    FlowLogIds: FlowLogIdList


class DeleteFlowLogsResult(TypedDict, total=False):
    Unsuccessful: Optional[UnsuccessfulItemSet]


class DeleteFpgaImageRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    FpgaImageId: FpgaImageId


class DeleteFpgaImageResult(TypedDict, total=False):
    Return: Optional[Boolean]


class DeleteInstanceConnectEndpointRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceConnectEndpointId: InstanceConnectEndpointId


class DeleteInstanceConnectEndpointResult(TypedDict, total=False):
    InstanceConnectEndpoint: Optional[Ec2InstanceConnectEndpoint]


class DeleteInstanceEventWindowRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ForceDelete: Optional[Boolean]
    InstanceEventWindowId: InstanceEventWindowId


class InstanceEventWindowStateChange(TypedDict, total=False):
    InstanceEventWindowId: Optional[InstanceEventWindowId]
    State: Optional[InstanceEventWindowState]


class DeleteInstanceEventWindowResult(TypedDict, total=False):
    InstanceEventWindowState: Optional[InstanceEventWindowStateChange]


class DeleteInternetGatewayRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InternetGatewayId: InternetGatewayId


class DeleteIpamExternalResourceVerificationTokenRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamExternalResourceVerificationTokenId: IpamExternalResourceVerificationTokenId


class DeleteIpamExternalResourceVerificationTokenResult(TypedDict, total=False):
    IpamExternalResourceVerificationToken: Optional[IpamExternalResourceVerificationToken]


class DeleteIpamPoolRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamPoolId: IpamPoolId
    Cascade: Optional[Boolean]


class DeleteIpamPoolResult(TypedDict, total=False):
    IpamPool: Optional[IpamPool]


class DeleteIpamRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamId: IpamId
    Cascade: Optional[Boolean]


class DeleteIpamResourceDiscoveryRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamResourceDiscoveryId: IpamResourceDiscoveryId


class DeleteIpamResourceDiscoveryResult(TypedDict, total=False):
    IpamResourceDiscovery: Optional[IpamResourceDiscovery]


class DeleteIpamResult(TypedDict, total=False):
    Ipam: Optional[Ipam]


class DeleteIpamScopeRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamScopeId: IpamScopeId


class DeleteIpamScopeResult(TypedDict, total=False):
    IpamScope: Optional[IpamScope]


class DeleteKeyPairRequest(ServiceRequest):
    KeyName: Optional[KeyPairNameWithResolver]
    KeyPairId: Optional[KeyPairId]
    DryRun: Optional[Boolean]


class DeleteKeyPairResult(TypedDict, total=False):
    Return: Optional[Boolean]
    KeyPairId: Optional[String]


class DeleteLaunchTemplateRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    LaunchTemplateId: Optional[LaunchTemplateId]
    LaunchTemplateName: Optional[LaunchTemplateName]


class DeleteLaunchTemplateResult(TypedDict, total=False):
    LaunchTemplate: Optional[LaunchTemplate]


VersionStringList = List[String]


class DeleteLaunchTemplateVersionsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    LaunchTemplateId: Optional[LaunchTemplateId]
    LaunchTemplateName: Optional[LaunchTemplateName]
    Versions: VersionStringList


class ResponseError(TypedDict, total=False):
    Code: Optional[LaunchTemplateErrorCode]
    Message: Optional[String]


class DeleteLaunchTemplateVersionsResponseErrorItem(TypedDict, total=False):
    LaunchTemplateId: Optional[String]
    LaunchTemplateName: Optional[String]
    VersionNumber: Optional[Long]
    ResponseError: Optional[ResponseError]


DeleteLaunchTemplateVersionsResponseErrorSet = List[DeleteLaunchTemplateVersionsResponseErrorItem]


class DeleteLaunchTemplateVersionsResponseSuccessItem(TypedDict, total=False):
    LaunchTemplateId: Optional[String]
    LaunchTemplateName: Optional[String]
    VersionNumber: Optional[Long]


DeleteLaunchTemplateVersionsResponseSuccessSet = List[
    DeleteLaunchTemplateVersionsResponseSuccessItem
]


class DeleteLaunchTemplateVersionsResult(TypedDict, total=False):
    SuccessfullyDeletedLaunchTemplateVersions: Optional[
        DeleteLaunchTemplateVersionsResponseSuccessSet
    ]
    UnsuccessfullyDeletedLaunchTemplateVersions: Optional[
        DeleteLaunchTemplateVersionsResponseErrorSet
    ]


class DeleteLocalGatewayRouteRequest(ServiceRequest):
    DestinationCidrBlock: Optional[String]
    LocalGatewayRouteTableId: LocalGatewayRoutetableId
    DryRun: Optional[Boolean]
    DestinationPrefixListId: Optional[PrefixListResourceId]


class DeleteLocalGatewayRouteResult(TypedDict, total=False):
    Route: Optional[LocalGatewayRoute]


class DeleteLocalGatewayRouteTableRequest(ServiceRequest):
    LocalGatewayRouteTableId: LocalGatewayRoutetableId
    DryRun: Optional[Boolean]


class DeleteLocalGatewayRouteTableResult(TypedDict, total=False):
    LocalGatewayRouteTable: Optional[LocalGatewayRouteTable]


class DeleteLocalGatewayRouteTableVirtualInterfaceGroupAssociationRequest(ServiceRequest):
    LocalGatewayRouteTableVirtualInterfaceGroupAssociationId: (
        LocalGatewayRouteTableVirtualInterfaceGroupAssociationId
    )
    DryRun: Optional[Boolean]


class DeleteLocalGatewayRouteTableVirtualInterfaceGroupAssociationResult(TypedDict, total=False):
    LocalGatewayRouteTableVirtualInterfaceGroupAssociation: Optional[
        LocalGatewayRouteTableVirtualInterfaceGroupAssociation
    ]


class DeleteLocalGatewayRouteTableVpcAssociationRequest(ServiceRequest):
    LocalGatewayRouteTableVpcAssociationId: LocalGatewayRouteTableVpcAssociationId
    DryRun: Optional[Boolean]


class DeleteLocalGatewayRouteTableVpcAssociationResult(TypedDict, total=False):
    LocalGatewayRouteTableVpcAssociation: Optional[LocalGatewayRouteTableVpcAssociation]


class DeleteManagedPrefixListRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    PrefixListId: PrefixListResourceId


class DeleteManagedPrefixListResult(TypedDict, total=False):
    PrefixList: Optional[ManagedPrefixList]


class DeleteNatGatewayRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    NatGatewayId: NatGatewayId


class DeleteNatGatewayResult(TypedDict, total=False):
    NatGatewayId: Optional[String]


class DeleteNetworkAclEntryRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    NetworkAclId: NetworkAclId
    RuleNumber: Integer
    Egress: Boolean


class DeleteNetworkAclRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    NetworkAclId: NetworkAclId


class DeleteNetworkInsightsAccessScopeAnalysisRequest(ServiceRequest):
    NetworkInsightsAccessScopeAnalysisId: NetworkInsightsAccessScopeAnalysisId
    DryRun: Optional[Boolean]


class DeleteNetworkInsightsAccessScopeAnalysisResult(TypedDict, total=False):
    NetworkInsightsAccessScopeAnalysisId: Optional[NetworkInsightsAccessScopeAnalysisId]


class DeleteNetworkInsightsAccessScopeRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    NetworkInsightsAccessScopeId: NetworkInsightsAccessScopeId


class DeleteNetworkInsightsAccessScopeResult(TypedDict, total=False):
    NetworkInsightsAccessScopeId: Optional[NetworkInsightsAccessScopeId]


class DeleteNetworkInsightsAnalysisRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    NetworkInsightsAnalysisId: NetworkInsightsAnalysisId


class DeleteNetworkInsightsAnalysisResult(TypedDict, total=False):
    NetworkInsightsAnalysisId: Optional[NetworkInsightsAnalysisId]


class DeleteNetworkInsightsPathRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    NetworkInsightsPathId: NetworkInsightsPathId


class DeleteNetworkInsightsPathResult(TypedDict, total=False):
    NetworkInsightsPathId: Optional[NetworkInsightsPathId]


class DeleteNetworkInterfacePermissionRequest(ServiceRequest):
    NetworkInterfacePermissionId: NetworkInterfacePermissionId
    Force: Optional[Boolean]
    DryRun: Optional[Boolean]


class DeleteNetworkInterfacePermissionResult(TypedDict, total=False):
    Return: Optional[Boolean]


class DeleteNetworkInterfaceRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    NetworkInterfaceId: NetworkInterfaceId


class DeletePlacementGroupRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    GroupName: PlacementGroupName


class DeletePublicIpv4PoolRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    PoolId: Ipv4PoolEc2Id
    NetworkBorderGroup: Optional[String]


class DeletePublicIpv4PoolResult(TypedDict, total=False):
    ReturnValue: Optional[Boolean]


class DeleteQueuedReservedInstancesError(TypedDict, total=False):
    Code: Optional[DeleteQueuedReservedInstancesErrorCode]
    Message: Optional[String]


DeleteQueuedReservedInstancesIdList = List[ReservationId]


class DeleteQueuedReservedInstancesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ReservedInstancesIds: DeleteQueuedReservedInstancesIdList


class FailedQueuedPurchaseDeletion(TypedDict, total=False):
    Error: Optional[DeleteQueuedReservedInstancesError]
    ReservedInstancesId: Optional[String]


FailedQueuedPurchaseDeletionSet = List[FailedQueuedPurchaseDeletion]


class SuccessfulQueuedPurchaseDeletion(TypedDict, total=False):
    ReservedInstancesId: Optional[String]


SuccessfulQueuedPurchaseDeletionSet = List[SuccessfulQueuedPurchaseDeletion]


class DeleteQueuedReservedInstancesResult(TypedDict, total=False):
    SuccessfulQueuedPurchaseDeletions: Optional[SuccessfulQueuedPurchaseDeletionSet]
    FailedQueuedPurchaseDeletions: Optional[FailedQueuedPurchaseDeletionSet]


class DeleteRouteRequest(ServiceRequest):
    DestinationPrefixListId: Optional[PrefixListResourceId]
    DryRun: Optional[Boolean]
    RouteTableId: RouteTableId
    DestinationCidrBlock: Optional[String]
    DestinationIpv6CidrBlock: Optional[String]


class DeleteRouteTableRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    RouteTableId: RouteTableId


class DeleteSecurityGroupRequest(ServiceRequest):
    GroupId: Optional[SecurityGroupId]
    GroupName: Optional[SecurityGroupName]
    DryRun: Optional[Boolean]


class DeleteSnapshotRequest(ServiceRequest):
    SnapshotId: SnapshotId
    DryRun: Optional[Boolean]


class DeleteSpotDatafeedSubscriptionRequest(ServiceRequest):
    DryRun: Optional[Boolean]


class DeleteSubnetCidrReservationRequest(ServiceRequest):
    SubnetCidrReservationId: SubnetCidrReservationId
    DryRun: Optional[Boolean]


class DeleteSubnetCidrReservationResult(TypedDict, total=False):
    DeletedSubnetCidrReservation: Optional[SubnetCidrReservation]


class DeleteSubnetRequest(ServiceRequest):
    SubnetId: SubnetId
    DryRun: Optional[Boolean]


class DeleteTagsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Resources: ResourceIdList
    Tags: Optional[TagList]


class DeleteTrafficMirrorFilterRequest(ServiceRequest):
    TrafficMirrorFilterId: TrafficMirrorFilterId
    DryRun: Optional[Boolean]


class DeleteTrafficMirrorFilterResult(TypedDict, total=False):
    TrafficMirrorFilterId: Optional[String]


class DeleteTrafficMirrorFilterRuleRequest(ServiceRequest):
    TrafficMirrorFilterRuleId: TrafficMirrorFilterRuleIdWithResolver
    DryRun: Optional[Boolean]


class DeleteTrafficMirrorFilterRuleResult(TypedDict, total=False):
    TrafficMirrorFilterRuleId: Optional[String]


class DeleteTrafficMirrorSessionRequest(ServiceRequest):
    TrafficMirrorSessionId: TrafficMirrorSessionId
    DryRun: Optional[Boolean]


class DeleteTrafficMirrorSessionResult(TypedDict, total=False):
    TrafficMirrorSessionId: Optional[String]


class DeleteTrafficMirrorTargetRequest(ServiceRequest):
    TrafficMirrorTargetId: TrafficMirrorTargetId
    DryRun: Optional[Boolean]


class DeleteTrafficMirrorTargetResult(TypedDict, total=False):
    TrafficMirrorTargetId: Optional[String]


class DeleteTransitGatewayConnectPeerRequest(ServiceRequest):
    TransitGatewayConnectPeerId: TransitGatewayConnectPeerId
    DryRun: Optional[Boolean]


class DeleteTransitGatewayConnectPeerResult(TypedDict, total=False):
    TransitGatewayConnectPeer: Optional[TransitGatewayConnectPeer]


class DeleteTransitGatewayConnectRequest(ServiceRequest):
    TransitGatewayAttachmentId: TransitGatewayAttachmentId
    DryRun: Optional[Boolean]


class DeleteTransitGatewayConnectResult(TypedDict, total=False):
    TransitGatewayConnect: Optional[TransitGatewayConnect]


class DeleteTransitGatewayMulticastDomainRequest(ServiceRequest):
    TransitGatewayMulticastDomainId: TransitGatewayMulticastDomainId
    DryRun: Optional[Boolean]


class DeleteTransitGatewayMulticastDomainResult(TypedDict, total=False):
    TransitGatewayMulticastDomain: Optional[TransitGatewayMulticastDomain]


class DeleteTransitGatewayPeeringAttachmentRequest(ServiceRequest):
    TransitGatewayAttachmentId: TransitGatewayAttachmentId
    DryRun: Optional[Boolean]


class DeleteTransitGatewayPeeringAttachmentResult(TypedDict, total=False):
    TransitGatewayPeeringAttachment: Optional[TransitGatewayPeeringAttachment]


class DeleteTransitGatewayPolicyTableRequest(ServiceRequest):
    TransitGatewayPolicyTableId: TransitGatewayPolicyTableId
    DryRun: Optional[Boolean]


class DeleteTransitGatewayPolicyTableResult(TypedDict, total=False):
    TransitGatewayPolicyTable: Optional[TransitGatewayPolicyTable]


class DeleteTransitGatewayPrefixListReferenceRequest(ServiceRequest):
    TransitGatewayRouteTableId: TransitGatewayRouteTableId
    PrefixListId: PrefixListResourceId
    DryRun: Optional[Boolean]


class DeleteTransitGatewayPrefixListReferenceResult(TypedDict, total=False):
    TransitGatewayPrefixListReference: Optional[TransitGatewayPrefixListReference]


class DeleteTransitGatewayRequest(ServiceRequest):
    TransitGatewayId: TransitGatewayId
    DryRun: Optional[Boolean]


class DeleteTransitGatewayResult(TypedDict, total=False):
    TransitGateway: Optional[TransitGateway]


class DeleteTransitGatewayRouteRequest(ServiceRequest):
    TransitGatewayRouteTableId: TransitGatewayRouteTableId
    DestinationCidrBlock: String
    DryRun: Optional[Boolean]


class DeleteTransitGatewayRouteResult(TypedDict, total=False):
    Route: Optional[TransitGatewayRoute]


class DeleteTransitGatewayRouteTableAnnouncementRequest(ServiceRequest):
    TransitGatewayRouteTableAnnouncementId: TransitGatewayRouteTableAnnouncementId
    DryRun: Optional[Boolean]


class DeleteTransitGatewayRouteTableAnnouncementResult(TypedDict, total=False):
    TransitGatewayRouteTableAnnouncement: Optional[TransitGatewayRouteTableAnnouncement]


class DeleteTransitGatewayRouteTableRequest(ServiceRequest):
    TransitGatewayRouteTableId: TransitGatewayRouteTableId
    DryRun: Optional[Boolean]


class DeleteTransitGatewayRouteTableResult(TypedDict, total=False):
    TransitGatewayRouteTable: Optional[TransitGatewayRouteTable]


class DeleteTransitGatewayVpcAttachmentRequest(ServiceRequest):
    TransitGatewayAttachmentId: TransitGatewayAttachmentId
    DryRun: Optional[Boolean]


class DeleteTransitGatewayVpcAttachmentResult(TypedDict, total=False):
    TransitGatewayVpcAttachment: Optional[TransitGatewayVpcAttachment]


class DeleteVerifiedAccessEndpointRequest(ServiceRequest):
    VerifiedAccessEndpointId: VerifiedAccessEndpointId
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]


class DeleteVerifiedAccessEndpointResult(TypedDict, total=False):
    VerifiedAccessEndpoint: Optional[VerifiedAccessEndpoint]


class DeleteVerifiedAccessGroupRequest(ServiceRequest):
    VerifiedAccessGroupId: VerifiedAccessGroupId
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]


class DeleteVerifiedAccessGroupResult(TypedDict, total=False):
    VerifiedAccessGroup: Optional[VerifiedAccessGroup]


class DeleteVerifiedAccessInstanceRequest(ServiceRequest):
    VerifiedAccessInstanceId: VerifiedAccessInstanceId
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]


class DeleteVerifiedAccessInstanceResult(TypedDict, total=False):
    VerifiedAccessInstance: Optional[VerifiedAccessInstance]


class DeleteVerifiedAccessTrustProviderRequest(ServiceRequest):
    VerifiedAccessTrustProviderId: VerifiedAccessTrustProviderId
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]


class DeleteVerifiedAccessTrustProviderResult(TypedDict, total=False):
    VerifiedAccessTrustProvider: Optional[VerifiedAccessTrustProvider]


class DeleteVolumeRequest(ServiceRequest):
    VolumeId: VolumeId
    DryRun: Optional[Boolean]


class DeleteVpcEndpointConnectionNotificationsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ConnectionNotificationIds: ConnectionNotificationIdsList


class DeleteVpcEndpointConnectionNotificationsResult(TypedDict, total=False):
    Unsuccessful: Optional[UnsuccessfulItemSet]


VpcEndpointServiceIdList = List[VpcEndpointServiceId]


class DeleteVpcEndpointServiceConfigurationsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ServiceIds: VpcEndpointServiceIdList


class DeleteVpcEndpointServiceConfigurationsResult(TypedDict, total=False):
    Unsuccessful: Optional[UnsuccessfulItemSet]


class DeleteVpcEndpointsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    VpcEndpointIds: VpcEndpointIdList


class DeleteVpcEndpointsResult(TypedDict, total=False):
    Unsuccessful: Optional[UnsuccessfulItemSet]


class DeleteVpcPeeringConnectionRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    VpcPeeringConnectionId: VpcPeeringConnectionId


class DeleteVpcPeeringConnectionResult(TypedDict, total=False):
    Return: Optional[Boolean]


class DeleteVpcRequest(ServiceRequest):
    VpcId: VpcId
    DryRun: Optional[Boolean]


class DeleteVpnConnectionRequest(ServiceRequest):
    VpnConnectionId: VpnConnectionId
    DryRun: Optional[Boolean]


class DeleteVpnConnectionRouteRequest(ServiceRequest):
    DestinationCidrBlock: String
    VpnConnectionId: VpnConnectionId


class DeleteVpnGatewayRequest(ServiceRequest):
    VpnGatewayId: VpnGatewayId
    DryRun: Optional[Boolean]


class DeprovisionByoipCidrRequest(ServiceRequest):
    Cidr: String
    DryRun: Optional[Boolean]


class DeprovisionByoipCidrResult(TypedDict, total=False):
    ByoipCidr: Optional[ByoipCidr]


class DeprovisionIpamByoasnRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamId: IpamId
    Asn: String


class DeprovisionIpamByoasnResult(TypedDict, total=False):
    Byoasn: Optional[Byoasn]


class DeprovisionIpamPoolCidrRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamPoolId: IpamPoolId
    Cidr: Optional[String]


class IpamPoolCidrFailureReason(TypedDict, total=False):
    Code: Optional[IpamPoolCidrFailureCode]
    Message: Optional[String]


class IpamPoolCidr(TypedDict, total=False):
    Cidr: Optional[String]
    State: Optional[IpamPoolCidrState]
    FailureReason: Optional[IpamPoolCidrFailureReason]
    IpamPoolCidrId: Optional[IpamPoolCidrId]
    NetmaskLength: Optional[Integer]


class DeprovisionIpamPoolCidrResult(TypedDict, total=False):
    IpamPoolCidr: Optional[IpamPoolCidr]


class DeprovisionPublicIpv4PoolCidrRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    PoolId: Ipv4PoolEc2Id
    Cidr: String


DeprovisionedAddressSet = List[String]


class DeprovisionPublicIpv4PoolCidrResult(TypedDict, total=False):
    PoolId: Optional[Ipv4PoolEc2Id]
    DeprovisionedAddresses: Optional[DeprovisionedAddressSet]


class DeregisterImageRequest(ServiceRequest):
    ImageId: ImageId
    DryRun: Optional[Boolean]


InstanceTagKeySet = List[String]


class DeregisterInstanceTagAttributeRequest(TypedDict, total=False):
    IncludeAllTagsOfInstance: Optional[Boolean]
    InstanceTagKeys: Optional[InstanceTagKeySet]


class DeregisterInstanceEventNotificationAttributesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceTagAttribute: DeregisterInstanceTagAttributeRequest


class InstanceTagNotificationAttribute(TypedDict, total=False):
    InstanceTagKeys: Optional[InstanceTagKeySet]
    IncludeAllTagsOfInstance: Optional[Boolean]


class DeregisterInstanceEventNotificationAttributesResult(TypedDict, total=False):
    InstanceTagAttribute: Optional[InstanceTagNotificationAttribute]


TransitGatewayNetworkInterfaceIdList = List[NetworkInterfaceId]


class DeregisterTransitGatewayMulticastGroupMembersRequest(ServiceRequest):
    TransitGatewayMulticastDomainId: Optional[TransitGatewayMulticastDomainId]
    GroupIpAddress: Optional[String]
    NetworkInterfaceIds: Optional[TransitGatewayNetworkInterfaceIdList]
    DryRun: Optional[Boolean]


class TransitGatewayMulticastDeregisteredGroupMembers(TypedDict, total=False):
    TransitGatewayMulticastDomainId: Optional[String]
    DeregisteredNetworkInterfaceIds: Optional[ValueStringList]
    GroupIpAddress: Optional[String]


class DeregisterTransitGatewayMulticastGroupMembersResult(TypedDict, total=False):
    DeregisteredMulticastGroupMembers: Optional[TransitGatewayMulticastDeregisteredGroupMembers]


class DeregisterTransitGatewayMulticastGroupSourcesRequest(ServiceRequest):
    TransitGatewayMulticastDomainId: Optional[TransitGatewayMulticastDomainId]
    GroupIpAddress: Optional[String]
    NetworkInterfaceIds: Optional[TransitGatewayNetworkInterfaceIdList]
    DryRun: Optional[Boolean]


class TransitGatewayMulticastDeregisteredGroupSources(TypedDict, total=False):
    TransitGatewayMulticastDomainId: Optional[String]
    DeregisteredNetworkInterfaceIds: Optional[ValueStringList]
    GroupIpAddress: Optional[String]


class DeregisterTransitGatewayMulticastGroupSourcesResult(TypedDict, total=False):
    DeregisteredMulticastGroupSources: Optional[TransitGatewayMulticastDeregisteredGroupSources]


class DescribeAccountAttributesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    AttributeNames: Optional[AccountAttributeNameStringList]


class DescribeAccountAttributesResult(TypedDict, total=False):
    AccountAttributes: Optional[AccountAttributeList]


class DescribeAddressTransfersRequest(ServiceRequest):
    AllocationIds: Optional[AllocationIdList]
    NextToken: Optional[String]
    MaxResults: Optional[DescribeAddressTransfersMaxResults]
    DryRun: Optional[Boolean]


class DescribeAddressTransfersResult(TypedDict, total=False):
    AddressTransfers: Optional[AddressTransferList]
    NextToken: Optional[String]


class DescribeAddressesAttributeRequest(ServiceRequest):
    AllocationIds: Optional[AllocationIds]
    Attribute: Optional[AddressAttributeName]
    NextToken: Optional[NextToken]
    MaxResults: Optional[AddressMaxResults]
    DryRun: Optional[Boolean]


class DescribeAddressesAttributeResult(TypedDict, total=False):
    Addresses: Optional[AddressSet]
    NextToken: Optional[NextToken]


class Filter(TypedDict, total=False):
    Name: Optional[String]
    Values: Optional[ValueStringList]


FilterList = List[Filter]
PublicIpStringList = List[String]


class DescribeAddressesRequest(ServiceRequest):
    PublicIps: Optional[PublicIpStringList]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    AllocationIds: Optional[AllocationIdList]


class DescribeAddressesResult(TypedDict, total=False):
    Addresses: Optional[AddressList]


class DescribeAggregateIdFormatRequest(ServiceRequest):
    DryRun: Optional[Boolean]


class IdFormat(TypedDict, total=False):
    Deadline: Optional[DateTime]
    Resource: Optional[String]
    UseLongIds: Optional[Boolean]


IdFormatList = List[IdFormat]


class DescribeAggregateIdFormatResult(TypedDict, total=False):
    UseLongIdsAggregated: Optional[Boolean]
    Statuses: Optional[IdFormatList]


ZoneIdStringList = List[String]
ZoneNameStringList = List[String]


class DescribeAvailabilityZonesRequest(ServiceRequest):
    ZoneNames: Optional[ZoneNameStringList]
    ZoneIds: Optional[ZoneIdStringList]
    AllAvailabilityZones: Optional[Boolean]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]


class DescribeAvailabilityZonesResult(TypedDict, total=False):
    AvailabilityZones: Optional[AvailabilityZoneList]


class DescribeAwsNetworkPerformanceMetricSubscriptionsRequest(ServiceRequest):
    MaxResults: Optional[MaxResultsParam]
    NextToken: Optional[String]
    Filters: Optional[FilterList]
    DryRun: Optional[Boolean]


class Subscription(TypedDict, total=False):
    Source: Optional[String]
    Destination: Optional[String]
    Metric: Optional[MetricType]
    Statistic: Optional[StatisticType]
    Period: Optional[PeriodType]


SubscriptionList = List[Subscription]


class DescribeAwsNetworkPerformanceMetricSubscriptionsResult(TypedDict, total=False):
    NextToken: Optional[String]
    Subscriptions: Optional[SubscriptionList]


class DescribeBundleTasksRequest(ServiceRequest):
    BundleIds: Optional[BundleIdStringList]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]


class DescribeBundleTasksResult(TypedDict, total=False):
    BundleTasks: Optional[BundleTaskList]


class DescribeByoipCidrsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    MaxResults: DescribeByoipCidrsMaxResults
    NextToken: Optional[NextToken]


class DescribeByoipCidrsResult(TypedDict, total=False):
    ByoipCidrs: Optional[ByoipCidrSet]
    NextToken: Optional[String]


class DescribeCapacityBlockOfferingsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceType: Optional[String]
    InstanceCount: Optional[Integer]
    StartDateRange: Optional[MillisecondDateTime]
    EndDateRange: Optional[MillisecondDateTime]
    CapacityDurationHours: Integer
    NextToken: Optional[String]
    MaxResults: Optional[DescribeCapacityBlockOfferingsMaxResults]


class DescribeCapacityBlockOfferingsResult(TypedDict, total=False):
    CapacityBlockOfferings: Optional[CapacityBlockOfferingSet]
    NextToken: Optional[String]


class DescribeCapacityReservationBillingRequestsRequest(ServiceRequest):
    CapacityReservationIds: Optional[CapacityReservationIdSet]
    Role: CallerRole
    NextToken: Optional[String]
    MaxResults: Optional[DescribeCapacityReservationBillingRequestsRequestMaxResults]
    Filters: Optional[FilterList]
    DryRun: Optional[Boolean]


class DescribeCapacityReservationBillingRequestsResult(TypedDict, total=False):
    NextToken: Optional[String]
    CapacityReservationBillingRequests: Optional[CapacityReservationBillingRequestSet]


class DescribeCapacityReservationFleetsRequest(ServiceRequest):
    CapacityReservationFleetIds: Optional[CapacityReservationFleetIdSet]
    NextToken: Optional[String]
    MaxResults: Optional[DescribeCapacityReservationFleetsMaxResults]
    Filters: Optional[FilterList]
    DryRun: Optional[Boolean]


class DescribeCapacityReservationFleetsResult(TypedDict, total=False):
    CapacityReservationFleets: Optional[CapacityReservationFleetSet]
    NextToken: Optional[String]


class DescribeCapacityReservationsRequest(ServiceRequest):
    CapacityReservationIds: Optional[CapacityReservationIdSet]
    NextToken: Optional[String]
    MaxResults: Optional[DescribeCapacityReservationsMaxResults]
    Filters: Optional[FilterList]
    DryRun: Optional[Boolean]


class DescribeCapacityReservationsResult(TypedDict, total=False):
    NextToken: Optional[String]
    CapacityReservations: Optional[CapacityReservationSet]


class DescribeCarrierGatewaysRequest(ServiceRequest):
    CarrierGatewayIds: Optional[CarrierGatewayIdSet]
    Filters: Optional[FilterList]
    MaxResults: Optional[CarrierGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


class DescribeCarrierGatewaysResult(TypedDict, total=False):
    CarrierGateways: Optional[CarrierGatewaySet]
    NextToken: Optional[String]


InstanceIdStringList = List[InstanceId]


class DescribeClassicLinkInstancesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceIds: Optional[InstanceIdStringList]
    Filters: Optional[FilterList]
    NextToken: Optional[String]
    MaxResults: Optional[DescribeClassicLinkInstancesMaxResults]


class DescribeClassicLinkInstancesResult(TypedDict, total=False):
    Instances: Optional[ClassicLinkInstanceList]
    NextToken: Optional[String]


class DescribeClientVpnAuthorizationRulesRequest(ServiceRequest):
    ClientVpnEndpointId: ClientVpnEndpointId
    DryRun: Optional[Boolean]
    NextToken: Optional[NextToken]
    Filters: Optional[FilterList]
    MaxResults: Optional[DescribeClientVpnAuthorizationRulesMaxResults]


class DescribeClientVpnAuthorizationRulesResult(TypedDict, total=False):
    AuthorizationRules: Optional[AuthorizationRuleSet]
    NextToken: Optional[NextToken]


class DescribeClientVpnConnectionsRequest(ServiceRequest):
    ClientVpnEndpointId: ClientVpnEndpointId
    Filters: Optional[FilterList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[DescribeClientVpnConnectionsMaxResults]
    DryRun: Optional[Boolean]


class DescribeClientVpnConnectionsResult(TypedDict, total=False):
    Connections: Optional[ClientVpnConnectionSet]
    NextToken: Optional[NextToken]


class DescribeClientVpnEndpointsRequest(ServiceRequest):
    ClientVpnEndpointIds: Optional[ClientVpnEndpointIdList]
    MaxResults: Optional[DescribeClientVpnEndpointMaxResults]
    NextToken: Optional[NextToken]
    Filters: Optional[FilterList]
    DryRun: Optional[Boolean]


EndpointSet = List[ClientVpnEndpoint]


class DescribeClientVpnEndpointsResult(TypedDict, total=False):
    ClientVpnEndpoints: Optional[EndpointSet]
    NextToken: Optional[NextToken]


class DescribeClientVpnRoutesRequest(ServiceRequest):
    ClientVpnEndpointId: ClientVpnEndpointId
    Filters: Optional[FilterList]
    MaxResults: Optional[DescribeClientVpnRoutesMaxResults]
    NextToken: Optional[NextToken]
    DryRun: Optional[Boolean]


class DescribeClientVpnRoutesResult(TypedDict, total=False):
    Routes: Optional[ClientVpnRouteSet]
    NextToken: Optional[NextToken]


class DescribeClientVpnTargetNetworksRequest(ServiceRequest):
    ClientVpnEndpointId: ClientVpnEndpointId
    AssociationIds: Optional[ValueStringList]
    MaxResults: Optional[DescribeClientVpnTargetNetworksMaxResults]
    NextToken: Optional[NextToken]
    Filters: Optional[FilterList]
    DryRun: Optional[Boolean]


class TargetNetwork(TypedDict, total=False):
    AssociationId: Optional[String]
    VpcId: Optional[String]
    TargetNetworkId: Optional[String]
    ClientVpnEndpointId: Optional[String]
    Status: Optional[AssociationStatus]
    SecurityGroups: Optional[ValueStringList]


TargetNetworkSet = List[TargetNetwork]


class DescribeClientVpnTargetNetworksResult(TypedDict, total=False):
    ClientVpnTargetNetworks: Optional[TargetNetworkSet]
    NextToken: Optional[NextToken]


class DescribeCoipPoolsRequest(ServiceRequest):
    PoolIds: Optional[CoipPoolIdSet]
    Filters: Optional[FilterList]
    MaxResults: Optional[CoipPoolMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


class DescribeCoipPoolsResult(TypedDict, total=False):
    CoipPools: Optional[CoipPoolSet]
    NextToken: Optional[String]


DescribeConversionTaskList = List[ConversionTask]


class DescribeConversionTasksRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ConversionTaskIds: Optional[ConversionIdStringList]


class DescribeConversionTasksResult(TypedDict, total=False):
    ConversionTasks: Optional[DescribeConversionTaskList]


class DescribeCustomerGatewaysRequest(ServiceRequest):
    CustomerGatewayIds: Optional[CustomerGatewayIdStringList]
    Filters: Optional[FilterList]
    DryRun: Optional[Boolean]


class DescribeCustomerGatewaysResult(TypedDict, total=False):
    CustomerGateways: Optional[CustomerGatewayList]


DhcpOptionsIdStringList = List[DhcpOptionsId]


class DescribeDhcpOptionsRequest(ServiceRequest):
    DhcpOptionsIds: Optional[DhcpOptionsIdStringList]
    NextToken: Optional[String]
    MaxResults: Optional[DescribeDhcpOptionsMaxResults]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]


DhcpOptionsList = List[DhcpOptions]


class DescribeDhcpOptionsResult(TypedDict, total=False):
    NextToken: Optional[String]
    DhcpOptions: Optional[DhcpOptionsList]


EgressOnlyInternetGatewayIdList = List[EgressOnlyInternetGatewayId]


class DescribeEgressOnlyInternetGatewaysRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    EgressOnlyInternetGatewayIds: Optional[EgressOnlyInternetGatewayIdList]
    MaxResults: Optional[DescribeEgressOnlyInternetGatewaysMaxResults]
    NextToken: Optional[String]
    Filters: Optional[FilterList]


EgressOnlyInternetGatewayList = List[EgressOnlyInternetGateway]


class DescribeEgressOnlyInternetGatewaysResult(TypedDict, total=False):
    EgressOnlyInternetGateways: Optional[EgressOnlyInternetGatewayList]
    NextToken: Optional[String]


ElasticGpuIdSet = List[ElasticGpuId]


class DescribeElasticGpusRequest(ServiceRequest):
    ElasticGpuIds: Optional[ElasticGpuIdSet]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    MaxResults: Optional[DescribeElasticGpusMaxResults]
    NextToken: Optional[String]


class ElasticGpuHealth(TypedDict, total=False):
    Status: Optional[ElasticGpuStatus]


class ElasticGpus(TypedDict, total=False):
    ElasticGpuId: Optional[String]
    AvailabilityZone: Optional[String]
    ElasticGpuType: Optional[String]
    ElasticGpuHealth: Optional[ElasticGpuHealth]
    ElasticGpuState: Optional[ElasticGpuState]
    InstanceId: Optional[String]
    Tags: Optional[TagList]


ElasticGpuSet = List[ElasticGpus]


class DescribeElasticGpusResult(TypedDict, total=False):
    ElasticGpuSet: Optional[ElasticGpuSet]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]


ExportImageTaskIdList = List[ExportImageTaskId]


class DescribeExportImageTasksRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    ExportImageTaskIds: Optional[ExportImageTaskIdList]
    MaxResults: Optional[DescribeExportImageTasksMaxResults]
    NextToken: Optional[NextToken]


class ExportTaskS3Location(TypedDict, total=False):
    S3Bucket: Optional[String]
    S3Prefix: Optional[String]


class ExportImageTask(TypedDict, total=False):
    Description: Optional[String]
    ExportImageTaskId: Optional[String]
    ImageId: Optional[String]
    Progress: Optional[String]
    S3ExportLocation: Optional[ExportTaskS3Location]
    Status: Optional[String]
    StatusMessage: Optional[String]
    Tags: Optional[TagList]


ExportImageTaskList = List[ExportImageTask]


class DescribeExportImageTasksResult(TypedDict, total=False):
    ExportImageTasks: Optional[ExportImageTaskList]
    NextToken: Optional[NextToken]


ExportTaskIdStringList = List[ExportTaskId]


class DescribeExportTasksRequest(ServiceRequest):
    Filters: Optional[FilterList]
    ExportTaskIds: Optional[ExportTaskIdStringList]


ExportTaskList = List[ExportTask]


class DescribeExportTasksResult(TypedDict, total=False):
    ExportTasks: Optional[ExportTaskList]


FastLaunchImageIdList = List[ImageId]


class DescribeFastLaunchImagesRequest(ServiceRequest):
    ImageIds: Optional[FastLaunchImageIdList]
    Filters: Optional[FilterList]
    MaxResults: Optional[DescribeFastLaunchImagesRequestMaxResults]
    NextToken: Optional[NextToken]
    DryRun: Optional[Boolean]


class FastLaunchLaunchTemplateSpecificationResponse(TypedDict, total=False):
    LaunchTemplateId: Optional[LaunchTemplateId]
    LaunchTemplateName: Optional[String]
    Version: Optional[String]


class FastLaunchSnapshotConfigurationResponse(TypedDict, total=False):
    TargetResourceCount: Optional[Integer]


class DescribeFastLaunchImagesSuccessItem(TypedDict, total=False):
    ImageId: Optional[ImageId]
    ResourceType: Optional[FastLaunchResourceType]
    SnapshotConfiguration: Optional[FastLaunchSnapshotConfigurationResponse]
    LaunchTemplate: Optional[FastLaunchLaunchTemplateSpecificationResponse]
    MaxParallelLaunches: Optional[Integer]
    OwnerId: Optional[String]
    State: Optional[FastLaunchStateCode]
    StateTransitionReason: Optional[String]
    StateTransitionTime: Optional[MillisecondDateTime]


DescribeFastLaunchImagesSuccessSet = List[DescribeFastLaunchImagesSuccessItem]


class DescribeFastLaunchImagesResult(TypedDict, total=False):
    FastLaunchImages: Optional[DescribeFastLaunchImagesSuccessSet]
    NextToken: Optional[NextToken]


class DescribeFastSnapshotRestoreSuccessItem(TypedDict, total=False):
    SnapshotId: Optional[String]
    AvailabilityZone: Optional[String]
    State: Optional[FastSnapshotRestoreStateCode]
    StateTransitionReason: Optional[String]
    OwnerId: Optional[String]
    OwnerAlias: Optional[String]
    EnablingTime: Optional[MillisecondDateTime]
    OptimizingTime: Optional[MillisecondDateTime]
    EnabledTime: Optional[MillisecondDateTime]
    DisablingTime: Optional[MillisecondDateTime]
    DisabledTime: Optional[MillisecondDateTime]


DescribeFastSnapshotRestoreSuccessSet = List[DescribeFastSnapshotRestoreSuccessItem]


class DescribeFastSnapshotRestoresRequest(ServiceRequest):
    Filters: Optional[FilterList]
    MaxResults: Optional[DescribeFastSnapshotRestoresMaxResults]
    NextToken: Optional[NextToken]
    DryRun: Optional[Boolean]


class DescribeFastSnapshotRestoresResult(TypedDict, total=False):
    FastSnapshotRestores: Optional[DescribeFastSnapshotRestoreSuccessSet]
    NextToken: Optional[NextToken]


class DescribeFleetError(TypedDict, total=False):
    LaunchTemplateAndOverrides: Optional[LaunchTemplateAndOverridesResponse]
    Lifecycle: Optional[InstanceLifecycle]
    ErrorCode: Optional[String]
    ErrorMessage: Optional[String]


class DescribeFleetHistoryRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    EventType: Optional[FleetEventType]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]
    FleetId: FleetId
    StartTime: DateTime


class EventInformation(TypedDict, total=False):
    EventDescription: Optional[String]
    EventSubType: Optional[String]
    InstanceId: Optional[String]


class HistoryRecordEntry(TypedDict, total=False):
    EventInformation: Optional[EventInformation]
    EventType: Optional[FleetEventType]
    Timestamp: Optional[DateTime]


HistoryRecordSet = List[HistoryRecordEntry]


class DescribeFleetHistoryResult(TypedDict, total=False):
    HistoryRecords: Optional[HistoryRecordSet]
    LastEvaluatedTime: Optional[DateTime]
    NextToken: Optional[String]
    FleetId: Optional[FleetId]
    StartTime: Optional[DateTime]


class DescribeFleetInstancesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]
    FleetId: FleetId
    Filters: Optional[FilterList]


class DescribeFleetInstancesResult(TypedDict, total=False):
    ActiveInstances: Optional[ActiveInstanceSet]
    NextToken: Optional[String]
    FleetId: Optional[FleetId]


DescribeFleetsErrorSet = List[DescribeFleetError]


class DescribeFleetsInstances(TypedDict, total=False):
    LaunchTemplateAndOverrides: Optional[LaunchTemplateAndOverridesResponse]
    Lifecycle: Optional[InstanceLifecycle]
    InstanceIds: Optional[InstanceIdsSet]
    InstanceType: Optional[InstanceType]
    Platform: Optional[PlatformValues]


DescribeFleetsInstancesSet = List[DescribeFleetsInstances]


class DescribeFleetsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]
    FleetIds: Optional[FleetIdSet]
    Filters: Optional[FilterList]


class OnDemandOptions(TypedDict, total=False):
    AllocationStrategy: Optional[FleetOnDemandAllocationStrategy]
    CapacityReservationOptions: Optional[CapacityReservationOptions]
    SingleInstanceType: Optional[Boolean]
    SingleAvailabilityZone: Optional[Boolean]
    MinTargetCapacity: Optional[Integer]
    MaxTotalPrice: Optional[String]


class FleetSpotCapacityRebalance(TypedDict, total=False):
    ReplacementStrategy: Optional[FleetReplacementStrategy]
    TerminationDelay: Optional[Integer]


class FleetSpotMaintenanceStrategies(TypedDict, total=False):
    CapacityRebalance: Optional[FleetSpotCapacityRebalance]


class SpotOptions(TypedDict, total=False):
    AllocationStrategy: Optional[SpotAllocationStrategy]
    MaintenanceStrategies: Optional[FleetSpotMaintenanceStrategies]
    InstanceInterruptionBehavior: Optional[SpotInstanceInterruptionBehavior]
    InstancePoolsToUseCount: Optional[Integer]
    SingleInstanceType: Optional[Boolean]
    SingleAvailabilityZone: Optional[Boolean]
    MinTargetCapacity: Optional[Integer]
    MaxTotalPrice: Optional[String]


class TargetCapacitySpecification(TypedDict, total=False):
    TotalTargetCapacity: Optional[Integer]
    OnDemandTargetCapacity: Optional[Integer]
    SpotTargetCapacity: Optional[Integer]
    DefaultTargetCapacityType: Optional[DefaultTargetCapacityType]
    TargetCapacityUnitType: Optional[TargetCapacityUnitType]


FleetLaunchTemplateOverridesList = List[FleetLaunchTemplateOverrides]


class FleetLaunchTemplateConfig(TypedDict, total=False):
    LaunchTemplateSpecification: Optional[FleetLaunchTemplateSpecification]
    Overrides: Optional[FleetLaunchTemplateOverridesList]


FleetLaunchTemplateConfigList = List[FleetLaunchTemplateConfig]


class FleetData(TypedDict, total=False):
    ActivityStatus: Optional[FleetActivityStatus]
    CreateTime: Optional[DateTime]
    FleetId: Optional[FleetId]
    FleetState: Optional[FleetStateCode]
    ClientToken: Optional[String]
    ExcessCapacityTerminationPolicy: Optional[FleetExcessCapacityTerminationPolicy]
    FulfilledCapacity: Optional[Double]
    FulfilledOnDemandCapacity: Optional[Double]
    LaunchTemplateConfigs: Optional[FleetLaunchTemplateConfigList]
    TargetCapacitySpecification: Optional[TargetCapacitySpecification]
    TerminateInstancesWithExpiration: Optional[Boolean]
    Type: Optional[FleetType]
    ValidFrom: Optional[DateTime]
    ValidUntil: Optional[DateTime]
    ReplaceUnhealthyInstances: Optional[Boolean]
    SpotOptions: Optional[SpotOptions]
    OnDemandOptions: Optional[OnDemandOptions]
    Tags: Optional[TagList]
    Errors: Optional[DescribeFleetsErrorSet]
    Instances: Optional[DescribeFleetsInstancesSet]
    Context: Optional[String]


FleetSet = List[FleetData]


class DescribeFleetsResult(TypedDict, total=False):
    NextToken: Optional[String]
    Fleets: Optional[FleetSet]


class DescribeFlowLogsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Filter: Optional[FilterList]
    FlowLogIds: Optional[FlowLogIdList]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]


class DestinationOptionsResponse(TypedDict, total=False):
    FileFormat: Optional[DestinationFileFormat]
    HiveCompatiblePartitions: Optional[Boolean]
    PerHourPartition: Optional[Boolean]


class FlowLog(TypedDict, total=False):
    CreationTime: Optional[MillisecondDateTime]
    DeliverLogsErrorMessage: Optional[String]
    DeliverLogsPermissionArn: Optional[String]
    DeliverCrossAccountRole: Optional[String]
    DeliverLogsStatus: Optional[String]
    FlowLogId: Optional[String]
    FlowLogStatus: Optional[String]
    LogGroupName: Optional[String]
    ResourceId: Optional[String]
    TrafficType: Optional[TrafficType]
    LogDestinationType: Optional[LogDestinationType]
    LogDestination: Optional[String]
    LogFormat: Optional[String]
    Tags: Optional[TagList]
    MaxAggregationInterval: Optional[Integer]
    DestinationOptions: Optional[DestinationOptionsResponse]


FlowLogSet = List[FlowLog]


class DescribeFlowLogsResult(TypedDict, total=False):
    FlowLogs: Optional[FlowLogSet]
    NextToken: Optional[String]


class DescribeFpgaImageAttributeRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    FpgaImageId: FpgaImageId
    Attribute: FpgaImageAttributeName


class ProductCode(TypedDict, total=False):
    ProductCodeId: Optional[String]
    ProductCodeType: Optional[ProductCodeValues]


ProductCodeList = List[ProductCode]


class LoadPermission(TypedDict, total=False):
    UserId: Optional[String]
    Group: Optional[PermissionGroup]


LoadPermissionList = List[LoadPermission]


class FpgaImageAttribute(TypedDict, total=False):
    FpgaImageId: Optional[String]
    Name: Optional[String]
    Description: Optional[String]
    LoadPermissions: Optional[LoadPermissionList]
    ProductCodes: Optional[ProductCodeList]


class DescribeFpgaImageAttributeResult(TypedDict, total=False):
    FpgaImageAttribute: Optional[FpgaImageAttribute]


OwnerStringList = List[String]
FpgaImageIdList = List[FpgaImageId]


class DescribeFpgaImagesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    FpgaImageIds: Optional[FpgaImageIdList]
    Owners: Optional[OwnerStringList]
    Filters: Optional[FilterList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[DescribeFpgaImagesMaxResults]


InstanceTypesList = List[String]


class FpgaImageState(TypedDict, total=False):
    Code: Optional[FpgaImageStateCode]
    Message: Optional[String]


class PciId(TypedDict, total=False):
    DeviceId: Optional[String]
    VendorId: Optional[String]
    SubsystemId: Optional[String]
    SubsystemVendorId: Optional[String]


class FpgaImage(TypedDict, total=False):
    FpgaImageId: Optional[String]
    FpgaImageGlobalId: Optional[String]
    Name: Optional[String]
    Description: Optional[String]
    ShellVersion: Optional[String]
    PciId: Optional[PciId]
    State: Optional[FpgaImageState]
    CreateTime: Optional[DateTime]
    UpdateTime: Optional[DateTime]
    OwnerId: Optional[String]
    OwnerAlias: Optional[String]
    ProductCodes: Optional[ProductCodeList]
    Tags: Optional[TagList]
    Public: Optional[Boolean]
    DataRetentionSupport: Optional[Boolean]
    InstanceTypes: Optional[InstanceTypesList]


FpgaImageList = List[FpgaImage]


class DescribeFpgaImagesResult(TypedDict, total=False):
    FpgaImages: Optional[FpgaImageList]
    NextToken: Optional[NextToken]


class DescribeHostReservationOfferingsRequest(ServiceRequest):
    Filter: Optional[FilterList]
    MaxDuration: Optional[Integer]
    MaxResults: Optional[DescribeHostReservationsMaxResults]
    MinDuration: Optional[Integer]
    NextToken: Optional[String]
    OfferingId: Optional[OfferingId]


class HostOffering(TypedDict, total=False):
    CurrencyCode: Optional[CurrencyCodeValues]
    Duration: Optional[Integer]
    HourlyPrice: Optional[String]
    InstanceFamily: Optional[String]
    OfferingId: Optional[OfferingId]
    PaymentOption: Optional[PaymentOption]
    UpfrontPrice: Optional[String]


HostOfferingSet = List[HostOffering]


class DescribeHostReservationOfferingsResult(TypedDict, total=False):
    NextToken: Optional[String]
    OfferingSet: Optional[HostOfferingSet]


HostReservationIdSet = List[HostReservationId]


class DescribeHostReservationsRequest(ServiceRequest):
    Filter: Optional[FilterList]
    HostReservationIdSet: Optional[HostReservationIdSet]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]


ResponseHostIdSet = List[String]


class HostReservation(TypedDict, total=False):
    Count: Optional[Integer]
    CurrencyCode: Optional[CurrencyCodeValues]
    Duration: Optional[Integer]
    End: Optional[DateTime]
    HostIdSet: Optional[ResponseHostIdSet]
    HostReservationId: Optional[HostReservationId]
    HourlyPrice: Optional[String]
    InstanceFamily: Optional[String]
    OfferingId: Optional[OfferingId]
    PaymentOption: Optional[PaymentOption]
    Start: Optional[DateTime]
    State: Optional[ReservationState]
    UpfrontPrice: Optional[String]
    Tags: Optional[TagList]


HostReservationSet = List[HostReservation]


class DescribeHostReservationsResult(TypedDict, total=False):
    HostReservationSet: Optional[HostReservationSet]
    NextToken: Optional[String]


RequestHostIdList = List[DedicatedHostId]


class DescribeHostsRequest(ServiceRequest):
    HostIds: Optional[RequestHostIdList]
    NextToken: Optional[String]
    MaxResults: Optional[Integer]
    Filter: Optional[FilterList]


class HostInstance(TypedDict, total=False):
    InstanceId: Optional[String]
    InstanceType: Optional[String]
    OwnerId: Optional[String]


HostInstanceList = List[HostInstance]


class HostProperties(TypedDict, total=False):
    Cores: Optional[Integer]
    InstanceType: Optional[String]
    InstanceFamily: Optional[String]
    Sockets: Optional[Integer]
    TotalVCpus: Optional[Integer]


class Host(TypedDict, total=False):
    AutoPlacement: Optional[AutoPlacement]
    AvailabilityZone: Optional[String]
    AvailableCapacity: Optional[AvailableCapacity]
    ClientToken: Optional[String]
    HostId: Optional[String]
    HostProperties: Optional[HostProperties]
    HostReservationId: Optional[String]
    Instances: Optional[HostInstanceList]
    State: Optional[AllocationState]
    AllocationTime: Optional[DateTime]
    ReleaseTime: Optional[DateTime]
    Tags: Optional[TagList]
    HostRecovery: Optional[HostRecovery]
    AllowsMultipleInstanceTypes: Optional[AllowsMultipleInstanceTypes]
    OwnerId: Optional[String]
    AvailabilityZoneId: Optional[String]
    MemberOfServiceLinkedResourceGroup: Optional[Boolean]
    OutpostArn: Optional[String]
    HostMaintenance: Optional[HostMaintenance]
    AssetId: Optional[AssetId]


HostList = List[Host]


class DescribeHostsResult(TypedDict, total=False):
    Hosts: Optional[HostList]
    NextToken: Optional[String]


class DescribeIamInstanceProfileAssociationsRequest(ServiceRequest):
    AssociationIds: Optional[AssociationIdList]
    Filters: Optional[FilterList]
    MaxResults: Optional[DescribeIamInstanceProfileAssociationsMaxResults]
    NextToken: Optional[NextToken]


IamInstanceProfileAssociationSet = List[IamInstanceProfileAssociation]


class DescribeIamInstanceProfileAssociationsResult(TypedDict, total=False):
    IamInstanceProfileAssociations: Optional[IamInstanceProfileAssociationSet]
    NextToken: Optional[NextToken]


class DescribeIdFormatRequest(ServiceRequest):
    Resource: Optional[String]


class DescribeIdFormatResult(TypedDict, total=False):
    Statuses: Optional[IdFormatList]


class DescribeIdentityIdFormatRequest(ServiceRequest):
    Resource: Optional[String]
    PrincipalArn: String


class DescribeIdentityIdFormatResult(TypedDict, total=False):
    Statuses: Optional[IdFormatList]


class DescribeImageAttributeRequest(ServiceRequest):
    Attribute: ImageAttributeName
    ImageId: ImageId
    DryRun: Optional[Boolean]


ImageIdStringList = List[ImageId]
ExecutableByStringList = List[String]


class DescribeImagesRequest(ServiceRequest):
    ExecutableUsers: Optional[ExecutableByStringList]
    ImageIds: Optional[ImageIdStringList]
    Owners: Optional[OwnerStringList]
    IncludeDeprecated: Optional[Boolean]
    IncludeDisabled: Optional[Boolean]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]


class Image(TypedDict, total=False):
    PlatformDetails: Optional[String]
    UsageOperation: Optional[String]
    BlockDeviceMappings: Optional[BlockDeviceMappingList]
    Description: Optional[String]
    EnaSupport: Optional[Boolean]
    Hypervisor: Optional[HypervisorType]
    ImageOwnerAlias: Optional[String]
    Name: Optional[String]
    RootDeviceName: Optional[String]
    RootDeviceType: Optional[DeviceType]
    SriovNetSupport: Optional[String]
    StateReason: Optional[StateReason]
    Tags: Optional[TagList]
    VirtualizationType: Optional[VirtualizationType]
    BootMode: Optional[BootModeValues]
    TpmSupport: Optional[TpmSupportValues]
    DeprecationTime: Optional[String]
    ImdsSupport: Optional[ImdsSupportValues]
    SourceInstanceId: Optional[String]
    DeregistrationProtection: Optional[String]
    LastLaunchedTime: Optional[String]
    SourceImageId: Optional[String]
    SourceImageRegion: Optional[String]
    ImageId: Optional[String]
    ImageLocation: Optional[String]
    State: Optional[ImageState]
    OwnerId: Optional[String]
    CreationDate: Optional[String]
    Public: Optional[Boolean]
    ProductCodes: Optional[ProductCodeList]
    Architecture: Optional[ArchitectureValues]
    ImageType: Optional[ImageTypeValues]
    KernelId: Optional[String]
    RamdiskId: Optional[String]
    Platform: Optional[PlatformValues]


ImageList = List[Image]


class DescribeImagesResult(TypedDict, total=False):
    NextToken: Optional[String]
    Images: Optional[ImageList]


ImportTaskIdList = List[ImportImageTaskId]


class DescribeImportImageTasksRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    ImportTaskIds: Optional[ImportTaskIdList]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]


class ImportImageLicenseConfigurationResponse(TypedDict, total=False):
    LicenseConfigurationArn: Optional[String]


ImportImageLicenseSpecificationListResponse = List[ImportImageLicenseConfigurationResponse]


class UserBucketDetails(TypedDict, total=False):
    S3Bucket: Optional[String]
    S3Key: Optional[String]


class SnapshotDetail(TypedDict, total=False):
    Description: Optional[String]
    DeviceName: Optional[String]
    DiskImageSize: Optional[Double]
    Format: Optional[String]
    Progress: Optional[String]
    SnapshotId: Optional[String]
    Status: Optional[String]
    StatusMessage: Optional[String]
    Url: Optional[SensitiveUrl]
    UserBucket: Optional[UserBucketDetails]


SnapshotDetailList = List[SnapshotDetail]


class ImportImageTask(TypedDict, total=False):
    Architecture: Optional[String]
    Description: Optional[String]
    Encrypted: Optional[Boolean]
    Hypervisor: Optional[String]
    ImageId: Optional[String]
    ImportTaskId: Optional[String]
    KmsKeyId: Optional[String]
    LicenseType: Optional[String]
    Platform: Optional[String]
    Progress: Optional[String]
    SnapshotDetails: Optional[SnapshotDetailList]
    Status: Optional[String]
    StatusMessage: Optional[String]
    Tags: Optional[TagList]
    LicenseSpecifications: Optional[ImportImageLicenseSpecificationListResponse]
    UsageOperation: Optional[String]
    BootMode: Optional[BootModeValues]


ImportImageTaskList = List[ImportImageTask]


class DescribeImportImageTasksResult(TypedDict, total=False):
    ImportImageTasks: Optional[ImportImageTaskList]
    NextToken: Optional[String]


ImportSnapshotTaskIdList = List[ImportSnapshotTaskId]


class DescribeImportSnapshotTasksRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    ImportTaskIds: Optional[ImportSnapshotTaskIdList]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]


class SnapshotTaskDetail(TypedDict, total=False):
    Description: Optional[String]
    DiskImageSize: Optional[Double]
    Encrypted: Optional[Boolean]
    Format: Optional[String]
    KmsKeyId: Optional[String]
    Progress: Optional[String]
    SnapshotId: Optional[String]
    Status: Optional[String]
    StatusMessage: Optional[String]
    Url: Optional[SensitiveUrl]
    UserBucket: Optional[UserBucketDetails]


class ImportSnapshotTask(TypedDict, total=False):
    Description: Optional[String]
    ImportTaskId: Optional[String]
    SnapshotTaskDetail: Optional[SnapshotTaskDetail]
    Tags: Optional[TagList]


ImportSnapshotTaskList = List[ImportSnapshotTask]


class DescribeImportSnapshotTasksResult(TypedDict, total=False):
    ImportSnapshotTasks: Optional[ImportSnapshotTaskList]
    NextToken: Optional[String]


class DescribeInstanceAttributeRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceId: InstanceId
    Attribute: InstanceAttributeName


class DescribeInstanceConnectEndpointsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    MaxResults: Optional[InstanceConnectEndpointMaxResults]
    NextToken: Optional[NextToken]
    Filters: Optional[FilterList]
    InstanceConnectEndpointIds: Optional[ValueStringList]


InstanceConnectEndpointSet = List[Ec2InstanceConnectEndpoint]


class DescribeInstanceConnectEndpointsResult(TypedDict, total=False):
    InstanceConnectEndpoints: Optional[InstanceConnectEndpointSet]
    NextToken: Optional[NextToken]


class DescribeInstanceCreditSpecificationsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    InstanceIds: Optional[InstanceIdStringList]
    MaxResults: Optional[DescribeInstanceCreditSpecificationsMaxResults]
    NextToken: Optional[String]


class InstanceCreditSpecification(TypedDict, total=False):
    InstanceId: Optional[String]
    CpuCredits: Optional[String]


InstanceCreditSpecificationList = List[InstanceCreditSpecification]


class DescribeInstanceCreditSpecificationsResult(TypedDict, total=False):
    InstanceCreditSpecifications: Optional[InstanceCreditSpecificationList]
    NextToken: Optional[String]


class DescribeInstanceEventNotificationAttributesRequest(ServiceRequest):
    DryRun: Optional[Boolean]


class DescribeInstanceEventNotificationAttributesResult(TypedDict, total=False):
    InstanceTagAttribute: Optional[InstanceTagNotificationAttribute]


InstanceEventWindowIdSet = List[InstanceEventWindowId]


class DescribeInstanceEventWindowsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceEventWindowIds: Optional[InstanceEventWindowIdSet]
    Filters: Optional[FilterList]
    MaxResults: Optional[ResultRange]
    NextToken: Optional[String]


InstanceEventWindowSet = List[InstanceEventWindow]


class DescribeInstanceEventWindowsResult(TypedDict, total=False):
    InstanceEventWindows: Optional[InstanceEventWindowSet]
    NextToken: Optional[String]


class DescribeInstanceImageMetadataRequest(ServiceRequest):
    Filters: Optional[FilterList]
    InstanceIds: Optional[InstanceIdStringList]
    MaxResults: Optional[DescribeInstanceImageMetadataMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


class ImageMetadata(TypedDict, total=False):
    ImageId: Optional[ImageId]
    Name: Optional[String]
    OwnerId: Optional[String]
    State: Optional[ImageState]
    ImageOwnerAlias: Optional[String]
    CreationDate: Optional[String]
    DeprecationTime: Optional[String]
    IsPublic: Optional[Boolean]


class InstanceState(TypedDict, total=False):
    Code: Optional[Integer]
    Name: Optional[InstanceStateName]


class InstanceImageMetadata(TypedDict, total=False):
    InstanceId: Optional[InstanceId]
    InstanceType: Optional[InstanceType]
    LaunchTime: Optional[MillisecondDateTime]
    AvailabilityZone: Optional[String]
    ZoneId: Optional[String]
    State: Optional[InstanceState]
    OwnerId: Optional[String]
    Tags: Optional[TagList]
    ImageMetadata: Optional[ImageMetadata]


InstanceImageMetadataList = List[InstanceImageMetadata]


class DescribeInstanceImageMetadataResult(TypedDict, total=False):
    InstanceImageMetadata: Optional[InstanceImageMetadataList]
    NextToken: Optional[String]


class DescribeInstanceStatusRequest(ServiceRequest):
    InstanceIds: Optional[InstanceIdStringList]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    IncludeAllInstances: Optional[Boolean]


class EbsStatusDetails(TypedDict, total=False):
    ImpairedSince: Optional[MillisecondDateTime]
    Name: Optional[StatusName]
    Status: Optional[StatusType]


EbsStatusDetailsList = List[EbsStatusDetails]


class EbsStatusSummary(TypedDict, total=False):
    Details: Optional[EbsStatusDetailsList]
    Status: Optional[SummaryStatus]


class InstanceStatusDetails(TypedDict, total=False):
    ImpairedSince: Optional[DateTime]
    Name: Optional[StatusName]
    Status: Optional[StatusType]


InstanceStatusDetailsList = List[InstanceStatusDetails]


class InstanceStatusSummary(TypedDict, total=False):
    Details: Optional[InstanceStatusDetailsList]
    Status: Optional[SummaryStatus]


class InstanceStatusEvent(TypedDict, total=False):
    InstanceEventId: Optional[InstanceEventId]
    Code: Optional[EventCode]
    Description: Optional[String]
    NotAfter: Optional[DateTime]
    NotBefore: Optional[DateTime]
    NotBeforeDeadline: Optional[DateTime]


InstanceStatusEventList = List[InstanceStatusEvent]


class InstanceStatus(TypedDict, total=False):
    AvailabilityZone: Optional[String]
    OutpostArn: Optional[String]
    Events: Optional[InstanceStatusEventList]
    InstanceId: Optional[String]
    InstanceState: Optional[InstanceState]
    InstanceStatus: Optional[InstanceStatusSummary]
    SystemStatus: Optional[InstanceStatusSummary]
    AttachedEbsStatus: Optional[EbsStatusSummary]


InstanceStatusList = List[InstanceStatus]


class DescribeInstanceStatusResult(TypedDict, total=False):
    InstanceStatuses: Optional[InstanceStatusList]
    NextToken: Optional[String]


DescribeInstanceTopologyGroupNameSet = List[PlacementGroupName]
DescribeInstanceTopologyInstanceIdSet = List[InstanceId]


class DescribeInstanceTopologyRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    NextToken: Optional[String]
    MaxResults: Optional[DescribeInstanceTopologyMaxResults]
    InstanceIds: Optional[DescribeInstanceTopologyInstanceIdSet]
    GroupNames: Optional[DescribeInstanceTopologyGroupNameSet]
    Filters: Optional[FilterList]


NetworkNodesList = List[String]


class InstanceTopology(TypedDict, total=False):
    InstanceId: Optional[String]
    InstanceType: Optional[String]
    GroupName: Optional[String]
    NetworkNodes: Optional[NetworkNodesList]
    AvailabilityZone: Optional[String]
    ZoneId: Optional[String]


InstanceSet = List[InstanceTopology]


class DescribeInstanceTopologyResult(TypedDict, total=False):
    Instances: Optional[InstanceSet]
    NextToken: Optional[String]


class DescribeInstanceTypeOfferingsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    LocationType: Optional[LocationType]
    Filters: Optional[FilterList]
    MaxResults: Optional[DITOMaxResults]
    NextToken: Optional[NextToken]


class InstanceTypeOffering(TypedDict, total=False):
    InstanceType: Optional[InstanceType]
    LocationType: Optional[LocationType]
    Location: Optional[Location]


InstanceTypeOfferingsList = List[InstanceTypeOffering]


class DescribeInstanceTypeOfferingsResult(TypedDict, total=False):
    InstanceTypeOfferings: Optional[InstanceTypeOfferingsList]
    NextToken: Optional[NextToken]


RequestInstanceTypeList = List[InstanceType]


class DescribeInstanceTypesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceTypes: Optional[RequestInstanceTypeList]
    Filters: Optional[FilterList]
    MaxResults: Optional[DITMaxResults]
    NextToken: Optional[NextToken]


class NeuronDeviceMemoryInfo(TypedDict, total=False):
    SizeInMiB: Optional[NeuronDeviceMemorySize]


class NeuronDeviceCoreInfo(TypedDict, total=False):
    Count: Optional[NeuronDeviceCoreCount]
    Version: Optional[NeuronDeviceCoreVersion]


class NeuronDeviceInfo(TypedDict, total=False):
    Count: Optional[NeuronDeviceCount]
    Name: Optional[NeuronDeviceName]
    CoreInfo: Optional[NeuronDeviceCoreInfo]
    MemoryInfo: Optional[NeuronDeviceMemoryInfo]


NeuronDeviceInfoList = List[NeuronDeviceInfo]


class NeuronInfo(TypedDict, total=False):
    NeuronDevices: Optional[NeuronDeviceInfoList]
    TotalNeuronDeviceMemoryInMiB: Optional[TotalNeuronMemory]


class MediaDeviceMemoryInfo(TypedDict, total=False):
    SizeInMiB: Optional[MediaDeviceMemorySize]


class MediaDeviceInfo(TypedDict, total=False):
    Count: Optional[MediaDeviceCount]
    Name: Optional[MediaDeviceName]
    Manufacturer: Optional[MediaDeviceManufacturerName]
    MemoryInfo: Optional[MediaDeviceMemoryInfo]


MediaDeviceInfoList = List[MediaDeviceInfo]


class MediaAcceleratorInfo(TypedDict, total=False):
    Accelerators: Optional[MediaDeviceInfoList]
    TotalMediaMemoryInMiB: Optional[TotalMediaMemory]


NitroTpmSupportedVersionsList = List[NitroTpmSupportedVersionType]


class NitroTpmInfo(TypedDict, total=False):
    SupportedVersions: Optional[NitroTpmSupportedVersionsList]


class InferenceDeviceMemoryInfo(TypedDict, total=False):
    SizeInMiB: Optional[InferenceDeviceMemorySize]


class InferenceDeviceInfo(TypedDict, total=False):
    Count: Optional[InferenceDeviceCount]
    Name: Optional[InferenceDeviceName]
    Manufacturer: Optional[InferenceDeviceManufacturerName]
    MemoryInfo: Optional[InferenceDeviceMemoryInfo]


InferenceDeviceInfoList = List[InferenceDeviceInfo]


class InferenceAcceleratorInfo(TypedDict, total=False):
    Accelerators: Optional[InferenceDeviceInfoList]
    TotalInferenceMemoryInMiB: Optional[totalInferenceMemory]


PlacementGroupStrategyList = List[PlacementGroupStrategy]


class PlacementGroupInfo(TypedDict, total=False):
    SupportedStrategies: Optional[PlacementGroupStrategyList]


class FpgaDeviceMemoryInfo(TypedDict, total=False):
    SizeInMiB: Optional[FpgaDeviceMemorySize]


class FpgaDeviceInfo(TypedDict, total=False):
    Name: Optional[FpgaDeviceName]
    Manufacturer: Optional[FpgaDeviceManufacturerName]
    Count: Optional[FpgaDeviceCount]
    MemoryInfo: Optional[FpgaDeviceMemoryInfo]


FpgaDeviceInfoList = List[FpgaDeviceInfo]


class FpgaInfo(TypedDict, total=False):
    Fpgas: Optional[FpgaDeviceInfoList]
    TotalFpgaMemoryInMiB: Optional[totalFpgaMemory]


class GpuDeviceMemoryInfo(TypedDict, total=False):
    SizeInMiB: Optional[GpuDeviceMemorySize]


class GpuDeviceInfo(TypedDict, total=False):
    Name: Optional[GpuDeviceName]
    Manufacturer: Optional[GpuDeviceManufacturerName]
    Count: Optional[GpuDeviceCount]
    MemoryInfo: Optional[GpuDeviceMemoryInfo]


GpuDeviceInfoList = List[GpuDeviceInfo]


class GpuInfo(TypedDict, total=False):
    Gpus: Optional[GpuDeviceInfoList]
    TotalGpuMemoryInMiB: Optional[totalGpuMemory]


class EfaInfo(TypedDict, total=False):
    MaximumEfaInterfaces: Optional[MaximumEfaInterfaces]


class NetworkCardInfo(TypedDict, total=False):
    NetworkCardIndex: Optional[NetworkCardIndex]
    NetworkPerformance: Optional[NetworkPerformance]
    MaximumNetworkInterfaces: Optional[MaxNetworkInterfaces]
    BaselineBandwidthInGbps: Optional[BaselineBandwidthInGbps]
    PeakBandwidthInGbps: Optional[PeakBandwidthInGbps]


NetworkCardInfoList = List[NetworkCardInfo]


class NetworkInfo(TypedDict, total=False):
    NetworkPerformance: Optional[NetworkPerformance]
    MaximumNetworkInterfaces: Optional[MaxNetworkInterfaces]
    MaximumNetworkCards: Optional[MaximumNetworkCards]
    DefaultNetworkCardIndex: Optional[DefaultNetworkCardIndex]
    NetworkCards: Optional[NetworkCardInfoList]
    Ipv4AddressesPerInterface: Optional[MaxIpv4AddrPerInterface]
    Ipv6AddressesPerInterface: Optional[MaxIpv6AddrPerInterface]
    Ipv6Supported: Optional[Ipv6Flag]
    EnaSupport: Optional[EnaSupport]
    EfaSupported: Optional[EfaSupportedFlag]
    EfaInfo: Optional[EfaInfo]
    EncryptionInTransitSupported: Optional[EncryptionInTransitSupported]
    EnaSrdSupported: Optional[EnaSrdSupported]


class EbsOptimizedInfo(TypedDict, total=False):
    BaselineBandwidthInMbps: Optional[BaselineBandwidthInMbps]
    BaselineThroughputInMBps: Optional[BaselineThroughputInMBps]
    BaselineIops: Optional[BaselineIops]
    MaximumBandwidthInMbps: Optional[MaximumBandwidthInMbps]
    MaximumThroughputInMBps: Optional[MaximumThroughputInMBps]
    MaximumIops: Optional[MaximumIops]


class EbsInfo(TypedDict, total=False):
    EbsOptimizedSupport: Optional[EbsOptimizedSupport]
    EncryptionSupport: Optional[EbsEncryptionSupport]
    EbsOptimizedInfo: Optional[EbsOptimizedInfo]
    NvmeSupport: Optional[EbsNvmeSupport]


DiskSize = int


class DiskInfo(TypedDict, total=False):
    SizeInGB: Optional[DiskSize]
    Count: Optional[DiskCount]
    Type: Optional[DiskType]


DiskInfoList = List[DiskInfo]


class InstanceStorageInfo(TypedDict, total=False):
    TotalSizeInGB: Optional[DiskSize]
    Disks: Optional[DiskInfoList]
    NvmeSupport: Optional[EphemeralNvmeSupport]
    EncryptionSupport: Optional[InstanceStorageEncryptionSupport]


MemorySize = int


class MemoryInfo(TypedDict, total=False):
    SizeInMiB: Optional[MemorySize]


ThreadsPerCoreList = List[ThreadsPerCore]


class VCpuInfo(TypedDict, total=False):
    DefaultVCpus: Optional[VCpuCount]
    DefaultCores: Optional[CoreCount]
    DefaultThreadsPerCore: Optional[ThreadsPerCore]
    ValidCores: Optional[CoreCountList]
    ValidThreadsPerCore: Optional[ThreadsPerCoreList]


SupportedAdditionalProcessorFeatureList = List[SupportedAdditionalProcessorFeature]


class ProcessorInfo(TypedDict, total=False):
    SupportedArchitectures: Optional[ArchitectureTypeList]
    SustainedClockSpeedInGhz: Optional[ProcessorSustainedClockSpeed]
    SupportedFeatures: Optional[SupportedAdditionalProcessorFeatureList]
    Manufacturer: Optional[CpuManufacturerName]


VirtualizationTypeList = List[VirtualizationType]
RootDeviceTypeList = List[RootDeviceType]
UsageClassTypeList = List[UsageClassType]


class InstanceTypeInfo(TypedDict, total=False):
    InstanceType: Optional[InstanceType]
    CurrentGeneration: Optional[CurrentGenerationFlag]
    FreeTierEligible: Optional[FreeTierEligibleFlag]
    SupportedUsageClasses: Optional[UsageClassTypeList]
    SupportedRootDeviceTypes: Optional[RootDeviceTypeList]
    SupportedVirtualizationTypes: Optional[VirtualizationTypeList]
    BareMetal: Optional[BareMetalFlag]
    Hypervisor: Optional[InstanceTypeHypervisor]
    ProcessorInfo: Optional[ProcessorInfo]
    VCpuInfo: Optional[VCpuInfo]
    MemoryInfo: Optional[MemoryInfo]
    InstanceStorageSupported: Optional[InstanceStorageFlag]
    InstanceStorageInfo: Optional[InstanceStorageInfo]
    EbsInfo: Optional[EbsInfo]
    NetworkInfo: Optional[NetworkInfo]
    GpuInfo: Optional[GpuInfo]
    FpgaInfo: Optional[FpgaInfo]
    PlacementGroupInfo: Optional[PlacementGroupInfo]
    InferenceAcceleratorInfo: Optional[InferenceAcceleratorInfo]
    HibernationSupported: Optional[HibernationFlag]
    BurstablePerformanceSupported: Optional[BurstablePerformanceFlag]
    DedicatedHostsSupported: Optional[DedicatedHostFlag]
    AutoRecoverySupported: Optional[AutoRecoveryFlag]
    SupportedBootModes: Optional[BootModeTypeList]
    NitroEnclavesSupport: Optional[NitroEnclavesSupport]
    NitroTpmSupport: Optional[NitroTpmSupport]
    NitroTpmInfo: Optional[NitroTpmInfo]
    MediaAcceleratorInfo: Optional[MediaAcceleratorInfo]
    NeuronInfo: Optional[NeuronInfo]
    PhcSupport: Optional[PhcSupport]


InstanceTypeInfoList = List[InstanceTypeInfo]


class DescribeInstanceTypesResult(TypedDict, total=False):
    InstanceTypes: Optional[InstanceTypeInfoList]
    NextToken: Optional[NextToken]


class DescribeInstancesRequest(ServiceRequest):
    InstanceIds: Optional[InstanceIdStringList]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    NextToken: Optional[String]
    MaxResults: Optional[Integer]


class Monitoring(TypedDict, total=False):
    State: Optional[MonitoringState]


class InstanceMaintenanceOptions(TypedDict, total=False):
    AutoRecovery: Optional[InstanceAutoRecoveryState]


class PrivateDnsNameOptionsResponse(TypedDict, total=False):
    HostnameType: Optional[HostnameType]
    EnableResourceNameDnsARecord: Optional[Boolean]
    EnableResourceNameDnsAAAARecord: Optional[Boolean]


class EnclaveOptions(TypedDict, total=False):
    Enabled: Optional[Boolean]


class InstanceMetadataOptionsResponse(TypedDict, total=False):
    State: Optional[InstanceMetadataOptionsState]
    HttpTokens: Optional[HttpTokensState]
    HttpPutResponseHopLimit: Optional[Integer]
    HttpEndpoint: Optional[InstanceMetadataEndpointState]
    HttpProtocolIpv6: Optional[InstanceMetadataProtocolState]
    InstanceMetadataTags: Optional[InstanceMetadataTagsState]


class LicenseConfiguration(TypedDict, total=False):
    LicenseConfigurationArn: Optional[String]


LicenseList = List[LicenseConfiguration]


class HibernationOptions(TypedDict, total=False):
    Configured: Optional[Boolean]


class InstanceIpv6Prefix(TypedDict, total=False):
    Ipv6Prefix: Optional[String]


InstanceIpv6PrefixList = List[InstanceIpv6Prefix]


class InstanceIpv4Prefix(TypedDict, total=False):
    Ipv4Prefix: Optional[String]


InstanceIpv4PrefixList = List[InstanceIpv4Prefix]


class InstanceNetworkInterfaceAssociation(TypedDict, total=False):
    CarrierIp: Optional[String]
    CustomerOwnedIp: Optional[String]
    IpOwnerId: Optional[String]
    PublicDnsName: Optional[String]
    PublicIp: Optional[String]


class InstancePrivateIpAddress(TypedDict, total=False):
    Association: Optional[InstanceNetworkInterfaceAssociation]
    Primary: Optional[Boolean]
    PrivateDnsName: Optional[String]
    PrivateIpAddress: Optional[String]


InstancePrivateIpAddressList = List[InstancePrivateIpAddress]


class InstanceAttachmentEnaSrdUdpSpecification(TypedDict, total=False):
    EnaSrdUdpEnabled: Optional[Boolean]


class InstanceAttachmentEnaSrdSpecification(TypedDict, total=False):
    EnaSrdEnabled: Optional[Boolean]
    EnaSrdUdpSpecification: Optional[InstanceAttachmentEnaSrdUdpSpecification]


class InstanceNetworkInterfaceAttachment(TypedDict, total=False):
    AttachTime: Optional[DateTime]
    AttachmentId: Optional[String]
    DeleteOnTermination: Optional[Boolean]
    DeviceIndex: Optional[Integer]
    Status: Optional[AttachmentStatus]
    NetworkCardIndex: Optional[Integer]
    EnaSrdSpecification: Optional[InstanceAttachmentEnaSrdSpecification]


class InstanceNetworkInterface(TypedDict, total=False):
    Association: Optional[InstanceNetworkInterfaceAssociation]
    Attachment: Optional[InstanceNetworkInterfaceAttachment]
    Description: Optional[String]
    Groups: Optional[GroupIdentifierList]
    Ipv6Addresses: Optional[InstanceIpv6AddressList]
    MacAddress: Optional[String]
    NetworkInterfaceId: Optional[String]
    OwnerId: Optional[String]
    PrivateDnsName: Optional[String]
    PrivateIpAddress: Optional[String]
    PrivateIpAddresses: Optional[InstancePrivateIpAddressList]
    SourceDestCheck: Optional[Boolean]
    Status: Optional[NetworkInterfaceStatus]
    SubnetId: Optional[String]
    VpcId: Optional[String]
    InterfaceType: Optional[String]
    Ipv4Prefixes: Optional[InstanceIpv4PrefixList]
    Ipv6Prefixes: Optional[InstanceIpv6PrefixList]
    ConnectionTrackingConfiguration: Optional[ConnectionTrackingSpecificationResponse]


InstanceNetworkInterfaceList = List[InstanceNetworkInterface]


class ElasticInferenceAcceleratorAssociation(TypedDict, total=False):
    ElasticInferenceAcceleratorArn: Optional[String]
    ElasticInferenceAcceleratorAssociationId: Optional[String]
    ElasticInferenceAcceleratorAssociationState: Optional[String]
    ElasticInferenceAcceleratorAssociationTime: Optional[DateTime]


ElasticInferenceAcceleratorAssociationList = List[ElasticInferenceAcceleratorAssociation]


class ElasticGpuAssociation(TypedDict, total=False):
    ElasticGpuId: Optional[ElasticGpuId]
    ElasticGpuAssociationId: Optional[String]
    ElasticGpuAssociationState: Optional[String]
    ElasticGpuAssociationTime: Optional[String]


ElasticGpuAssociationList = List[ElasticGpuAssociation]


class EbsInstanceBlockDevice(TypedDict, total=False):
    AttachTime: Optional[DateTime]
    DeleteOnTermination: Optional[Boolean]
    Status: Optional[AttachmentStatus]
    VolumeId: Optional[String]
    AssociatedResource: Optional[String]
    VolumeOwnerId: Optional[String]


class InstanceBlockDeviceMapping(TypedDict, total=False):
    DeviceName: Optional[String]
    Ebs: Optional[EbsInstanceBlockDevice]


InstanceBlockDeviceMappingList = List[InstanceBlockDeviceMapping]


class Instance(TypedDict, total=False):
    Architecture: Optional[ArchitectureValues]
    BlockDeviceMappings: Optional[InstanceBlockDeviceMappingList]
    ClientToken: Optional[String]
    EbsOptimized: Optional[Boolean]
    EnaSupport: Optional[Boolean]
    Hypervisor: Optional[HypervisorType]
    IamInstanceProfile: Optional[IamInstanceProfile]
    InstanceLifecycle: Optional[InstanceLifecycleType]
    ElasticGpuAssociations: Optional[ElasticGpuAssociationList]
    ElasticInferenceAcceleratorAssociations: Optional[ElasticInferenceAcceleratorAssociationList]
    NetworkInterfaces: Optional[InstanceNetworkInterfaceList]
    OutpostArn: Optional[String]
    RootDeviceName: Optional[String]
    RootDeviceType: Optional[DeviceType]
    SecurityGroups: Optional[GroupIdentifierList]
    SourceDestCheck: Optional[Boolean]
    SpotInstanceRequestId: Optional[String]
    SriovNetSupport: Optional[String]
    StateReason: Optional[StateReason]
    Tags: Optional[TagList]
    VirtualizationType: Optional[VirtualizationType]
    CpuOptions: Optional[CpuOptions]
    CapacityReservationId: Optional[String]
    CapacityReservationSpecification: Optional[CapacityReservationSpecificationResponse]
    HibernationOptions: Optional[HibernationOptions]
    Licenses: Optional[LicenseList]
    MetadataOptions: Optional[InstanceMetadataOptionsResponse]
    EnclaveOptions: Optional[EnclaveOptions]
    BootMode: Optional[BootModeValues]
    PlatformDetails: Optional[String]
    UsageOperation: Optional[String]
    UsageOperationUpdateTime: Optional[MillisecondDateTime]
    PrivateDnsNameOptions: Optional[PrivateDnsNameOptionsResponse]
    Ipv6Address: Optional[String]
    TpmSupport: Optional[String]
    MaintenanceOptions: Optional[InstanceMaintenanceOptions]
    CurrentInstanceBootMode: Optional[InstanceBootModeValues]
    InstanceId: Optional[String]
    ImageId: Optional[String]
    State: Optional[InstanceState]
    PrivateDnsName: Optional[String]
    PublicDnsName: Optional[String]
    StateTransitionReason: Optional[String]
    KeyName: Optional[String]
    AmiLaunchIndex: Optional[Integer]
    ProductCodes: Optional[ProductCodeList]
    InstanceType: Optional[InstanceType]
    LaunchTime: Optional[DateTime]
    Placement: Optional[Placement]
    KernelId: Optional[String]
    RamdiskId: Optional[String]
    Platform: Optional[PlatformValues]
    Monitoring: Optional[Monitoring]
    SubnetId: Optional[String]
    VpcId: Optional[String]
    PrivateIpAddress: Optional[String]
    PublicIpAddress: Optional[String]


InstanceList = List[Instance]


class Reservation(TypedDict, total=False):
    ReservationId: Optional[String]
    OwnerId: Optional[String]
    RequesterId: Optional[String]
    Groups: Optional[GroupIdentifierList]
    Instances: Optional[InstanceList]


ReservationList = List[Reservation]


class DescribeInstancesResult(TypedDict, total=False):
    NextToken: Optional[String]
    Reservations: Optional[ReservationList]


InternetGatewayIdList = List[InternetGatewayId]


class DescribeInternetGatewaysRequest(ServiceRequest):
    NextToken: Optional[String]
    MaxResults: Optional[DescribeInternetGatewaysMaxResults]
    DryRun: Optional[Boolean]
    InternetGatewayIds: Optional[InternetGatewayIdList]
    Filters: Optional[FilterList]


InternetGatewayList = List[InternetGateway]


class DescribeInternetGatewaysResult(TypedDict, total=False):
    InternetGateways: Optional[InternetGatewayList]
    NextToken: Optional[String]


class DescribeIpamByoasnRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    MaxResults: Optional[DescribeIpamByoasnMaxResults]
    NextToken: Optional[NextToken]


class DescribeIpamByoasnResult(TypedDict, total=False):
    Byoasns: Optional[ByoasnSet]
    NextToken: Optional[String]


class DescribeIpamExternalResourceVerificationTokensRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[IpamMaxResults]
    IpamExternalResourceVerificationTokenIds: Optional[ValueStringList]


IpamExternalResourceVerificationTokenSet = List[IpamExternalResourceVerificationToken]


class DescribeIpamExternalResourceVerificationTokensResult(TypedDict, total=False):
    NextToken: Optional[NextToken]
    IpamExternalResourceVerificationTokens: Optional[IpamExternalResourceVerificationTokenSet]


class DescribeIpamPoolsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    MaxResults: Optional[IpamMaxResults]
    NextToken: Optional[NextToken]
    IpamPoolIds: Optional[ValueStringList]


IpamPoolSet = List[IpamPool]


class DescribeIpamPoolsResult(TypedDict, total=False):
    NextToken: Optional[NextToken]
    IpamPools: Optional[IpamPoolSet]


class DescribeIpamResourceDiscoveriesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamResourceDiscoveryIds: Optional[ValueStringList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[IpamMaxResults]
    Filters: Optional[FilterList]


IpamResourceDiscoverySet = List[IpamResourceDiscovery]


class DescribeIpamResourceDiscoveriesResult(TypedDict, total=False):
    IpamResourceDiscoveries: Optional[IpamResourceDiscoverySet]
    NextToken: Optional[NextToken]


class DescribeIpamResourceDiscoveryAssociationsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamResourceDiscoveryAssociationIds: Optional[ValueStringList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[IpamMaxResults]
    Filters: Optional[FilterList]


IpamResourceDiscoveryAssociationSet = List[IpamResourceDiscoveryAssociation]


class DescribeIpamResourceDiscoveryAssociationsResult(TypedDict, total=False):
    IpamResourceDiscoveryAssociations: Optional[IpamResourceDiscoveryAssociationSet]
    NextToken: Optional[NextToken]


class DescribeIpamScopesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    MaxResults: Optional[IpamMaxResults]
    NextToken: Optional[NextToken]
    IpamScopeIds: Optional[ValueStringList]


IpamScopeSet = List[IpamScope]


class DescribeIpamScopesResult(TypedDict, total=False):
    NextToken: Optional[NextToken]
    IpamScopes: Optional[IpamScopeSet]


class DescribeIpamsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    MaxResults: Optional[IpamMaxResults]
    NextToken: Optional[NextToken]
    IpamIds: Optional[ValueStringList]


IpamSet = List[Ipam]


class DescribeIpamsResult(TypedDict, total=False):
    NextToken: Optional[NextToken]
    Ipams: Optional[IpamSet]


Ipv6PoolIdList = List[Ipv6PoolEc2Id]


class DescribeIpv6PoolsRequest(ServiceRequest):
    PoolIds: Optional[Ipv6PoolIdList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[Ipv6PoolMaxResults]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]


class PoolCidrBlock(TypedDict, total=False):
    Cidr: Optional[String]


PoolCidrBlocksSet = List[PoolCidrBlock]


class Ipv6Pool(TypedDict, total=False):
    PoolId: Optional[String]
    Description: Optional[String]
    PoolCidrBlocks: Optional[PoolCidrBlocksSet]
    Tags: Optional[TagList]


Ipv6PoolSet = List[Ipv6Pool]


class DescribeIpv6PoolsResult(TypedDict, total=False):
    Ipv6Pools: Optional[Ipv6PoolSet]
    NextToken: Optional[NextToken]


KeyPairIdStringList = List[KeyPairId]
KeyNameStringList = List[KeyPairName]


class DescribeKeyPairsRequest(ServiceRequest):
    KeyNames: Optional[KeyNameStringList]
    KeyPairIds: Optional[KeyPairIdStringList]
    IncludePublicKey: Optional[Boolean]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]


class KeyPairInfo(TypedDict, total=False):
    KeyPairId: Optional[String]
    KeyType: Optional[KeyType]
    Tags: Optional[TagList]
    PublicKey: Optional[String]
    CreateTime: Optional[MillisecondDateTime]
    KeyName: Optional[String]
    KeyFingerprint: Optional[String]


KeyPairList = List[KeyPairInfo]


class DescribeKeyPairsResult(TypedDict, total=False):
    KeyPairs: Optional[KeyPairList]


class DescribeLaunchTemplateVersionsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    LaunchTemplateId: Optional[LaunchTemplateId]
    LaunchTemplateName: Optional[LaunchTemplateName]
    Versions: Optional[VersionStringList]
    MinVersion: Optional[String]
    MaxVersion: Optional[String]
    NextToken: Optional[String]
    MaxResults: Optional[Integer]
    Filters: Optional[FilterList]
    ResolveAlias: Optional[Boolean]


LaunchTemplateVersionSet = List[LaunchTemplateVersion]


class DescribeLaunchTemplateVersionsResult(TypedDict, total=False):
    LaunchTemplateVersions: Optional[LaunchTemplateVersionSet]
    NextToken: Optional[String]


LaunchTemplateNameStringList = List[LaunchTemplateName]
LaunchTemplateIdStringList = List[LaunchTemplateId]


class DescribeLaunchTemplatesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    LaunchTemplateIds: Optional[LaunchTemplateIdStringList]
    LaunchTemplateNames: Optional[LaunchTemplateNameStringList]
    Filters: Optional[FilterList]
    NextToken: Optional[String]
    MaxResults: Optional[DescribeLaunchTemplatesMaxResults]


LaunchTemplateSet = List[LaunchTemplate]


class DescribeLaunchTemplatesResult(TypedDict, total=False):
    LaunchTemplates: Optional[LaunchTemplateSet]
    NextToken: Optional[String]


LocalGatewayRouteTableVirtualInterfaceGroupAssociationIdSet = List[
    LocalGatewayRouteTableVirtualInterfaceGroupAssociationId
]


class DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociationsRequest(ServiceRequest):
    LocalGatewayRouteTableVirtualInterfaceGroupAssociationIds: Optional[
        LocalGatewayRouteTableVirtualInterfaceGroupAssociationIdSet
    ]
    Filters: Optional[FilterList]
    MaxResults: Optional[LocalGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


LocalGatewayRouteTableVirtualInterfaceGroupAssociationSet = List[
    LocalGatewayRouteTableVirtualInterfaceGroupAssociation
]


class DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociationsResult(TypedDict, total=False):
    LocalGatewayRouteTableVirtualInterfaceGroupAssociations: Optional[
        LocalGatewayRouteTableVirtualInterfaceGroupAssociationSet
    ]
    NextToken: Optional[String]


LocalGatewayRouteTableVpcAssociationIdSet = List[LocalGatewayRouteTableVpcAssociationId]


class DescribeLocalGatewayRouteTableVpcAssociationsRequest(ServiceRequest):
    LocalGatewayRouteTableVpcAssociationIds: Optional[LocalGatewayRouteTableVpcAssociationIdSet]
    Filters: Optional[FilterList]
    MaxResults: Optional[LocalGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


LocalGatewayRouteTableVpcAssociationSet = List[LocalGatewayRouteTableVpcAssociation]


class DescribeLocalGatewayRouteTableVpcAssociationsResult(TypedDict, total=False):
    LocalGatewayRouteTableVpcAssociations: Optional[LocalGatewayRouteTableVpcAssociationSet]
    NextToken: Optional[String]


LocalGatewayRouteTableIdSet = List[LocalGatewayRoutetableId]


class DescribeLocalGatewayRouteTablesRequest(ServiceRequest):
    LocalGatewayRouteTableIds: Optional[LocalGatewayRouteTableIdSet]
    Filters: Optional[FilterList]
    MaxResults: Optional[LocalGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


LocalGatewayRouteTableSet = List[LocalGatewayRouteTable]


class DescribeLocalGatewayRouteTablesResult(TypedDict, total=False):
    LocalGatewayRouteTables: Optional[LocalGatewayRouteTableSet]
    NextToken: Optional[String]


LocalGatewayVirtualInterfaceGroupIdSet = List[LocalGatewayVirtualInterfaceGroupId]


class DescribeLocalGatewayVirtualInterfaceGroupsRequest(ServiceRequest):
    LocalGatewayVirtualInterfaceGroupIds: Optional[LocalGatewayVirtualInterfaceGroupIdSet]
    Filters: Optional[FilterList]
    MaxResults: Optional[LocalGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


LocalGatewayVirtualInterfaceIdSet = List[LocalGatewayVirtualInterfaceId]


class LocalGatewayVirtualInterfaceGroup(TypedDict, total=False):
    LocalGatewayVirtualInterfaceGroupId: Optional[LocalGatewayVirtualInterfaceGroupId]
    LocalGatewayVirtualInterfaceIds: Optional[LocalGatewayVirtualInterfaceIdSet]
    LocalGatewayId: Optional[String]
    OwnerId: Optional[String]
    Tags: Optional[TagList]


LocalGatewayVirtualInterfaceGroupSet = List[LocalGatewayVirtualInterfaceGroup]


class DescribeLocalGatewayVirtualInterfaceGroupsResult(TypedDict, total=False):
    LocalGatewayVirtualInterfaceGroups: Optional[LocalGatewayVirtualInterfaceGroupSet]
    NextToken: Optional[String]


class DescribeLocalGatewayVirtualInterfacesRequest(ServiceRequest):
    LocalGatewayVirtualInterfaceIds: Optional[LocalGatewayVirtualInterfaceIdSet]
    Filters: Optional[FilterList]
    MaxResults: Optional[LocalGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


class LocalGatewayVirtualInterface(TypedDict, total=False):
    LocalGatewayVirtualInterfaceId: Optional[LocalGatewayVirtualInterfaceId]
    LocalGatewayId: Optional[String]
    Vlan: Optional[Integer]
    LocalAddress: Optional[String]
    PeerAddress: Optional[String]
    LocalBgpAsn: Optional[Integer]
    PeerBgpAsn: Optional[Integer]
    OwnerId: Optional[String]
    Tags: Optional[TagList]


LocalGatewayVirtualInterfaceSet = List[LocalGatewayVirtualInterface]


class DescribeLocalGatewayVirtualInterfacesResult(TypedDict, total=False):
    LocalGatewayVirtualInterfaces: Optional[LocalGatewayVirtualInterfaceSet]
    NextToken: Optional[String]


LocalGatewayIdSet = List[LocalGatewayId]


class DescribeLocalGatewaysRequest(ServiceRequest):
    LocalGatewayIds: Optional[LocalGatewayIdSet]
    Filters: Optional[FilterList]
    MaxResults: Optional[LocalGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


class LocalGateway(TypedDict, total=False):
    LocalGatewayId: Optional[LocalGatewayId]
    OutpostArn: Optional[String]
    OwnerId: Optional[String]
    State: Optional[String]
    Tags: Optional[TagList]


LocalGatewaySet = List[LocalGateway]


class DescribeLocalGatewaysResult(TypedDict, total=False):
    LocalGateways: Optional[LocalGatewaySet]
    NextToken: Optional[String]


SnapshotIdStringList = List[SnapshotId]


class DescribeLockedSnapshotsRequest(ServiceRequest):
    Filters: Optional[FilterList]
    MaxResults: Optional[DescribeLockedSnapshotsMaxResults]
    NextToken: Optional[String]
    SnapshotIds: Optional[SnapshotIdStringList]
    DryRun: Optional[Boolean]


class LockedSnapshotsInfo(TypedDict, total=False):
    OwnerId: Optional[String]
    SnapshotId: Optional[String]
    LockState: Optional[LockState]
    LockDuration: Optional[RetentionPeriodResponseDays]
    CoolOffPeriod: Optional[CoolOffPeriodResponseHours]
    CoolOffPeriodExpiresOn: Optional[MillisecondDateTime]
    LockCreatedOn: Optional[MillisecondDateTime]
    LockDurationStartTime: Optional[MillisecondDateTime]
    LockExpiresOn: Optional[MillisecondDateTime]


LockedSnapshotsInfoList = List[LockedSnapshotsInfo]


class DescribeLockedSnapshotsResult(TypedDict, total=False):
    Snapshots: Optional[LockedSnapshotsInfoList]
    NextToken: Optional[String]


class DescribeMacHostsRequest(ServiceRequest):
    Filters: Optional[FilterList]
    HostIds: Optional[RequestHostIdList]
    MaxResults: Optional[DescribeMacHostsRequestMaxResults]
    NextToken: Optional[String]


MacOSVersionStringList = List[String]


class MacHost(TypedDict, total=False):
    HostId: Optional[DedicatedHostId]
    MacOSLatestSupportedVersions: Optional[MacOSVersionStringList]


MacHostList = List[MacHost]


class DescribeMacHostsResult(TypedDict, total=False):
    MacHosts: Optional[MacHostList]
    NextToken: Optional[String]


class DescribeManagedPrefixListsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    MaxResults: Optional[PrefixListMaxResults]
    NextToken: Optional[NextToken]
    PrefixListIds: Optional[ValueStringList]


ManagedPrefixListSet = List[ManagedPrefixList]


class DescribeManagedPrefixListsResult(TypedDict, total=False):
    NextToken: Optional[NextToken]
    PrefixLists: Optional[ManagedPrefixListSet]


class DescribeMovingAddressesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    PublicIps: Optional[ValueStringList]
    NextToken: Optional[String]
    Filters: Optional[FilterList]
    MaxResults: Optional[DescribeMovingAddressesMaxResults]


class MovingAddressStatus(TypedDict, total=False):
    MoveStatus: Optional[MoveStatus]
    PublicIp: Optional[String]


MovingAddressStatusSet = List[MovingAddressStatus]


class DescribeMovingAddressesResult(TypedDict, total=False):
    MovingAddressStatuses: Optional[MovingAddressStatusSet]
    NextToken: Optional[String]


NatGatewayIdStringList = List[NatGatewayId]


class DescribeNatGatewaysRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Filter: Optional[FilterList]
    MaxResults: Optional[DescribeNatGatewaysMaxResults]
    NatGatewayIds: Optional[NatGatewayIdStringList]
    NextToken: Optional[String]


NatGatewayList = List[NatGateway]


class DescribeNatGatewaysResult(TypedDict, total=False):
    NatGateways: Optional[NatGatewayList]
    NextToken: Optional[String]


NetworkAclIdStringList = List[NetworkAclId]


class DescribeNetworkAclsRequest(ServiceRequest):
    NextToken: Optional[String]
    MaxResults: Optional[DescribeNetworkAclsMaxResults]
    DryRun: Optional[Boolean]
    NetworkAclIds: Optional[NetworkAclIdStringList]
    Filters: Optional[FilterList]


NetworkAclList = List[NetworkAcl]


class DescribeNetworkAclsResult(TypedDict, total=False):
    NetworkAcls: Optional[NetworkAclList]
    NextToken: Optional[String]


NetworkInsightsAccessScopeAnalysisIdList = List[NetworkInsightsAccessScopeAnalysisId]


class DescribeNetworkInsightsAccessScopeAnalysesRequest(ServiceRequest):
    NetworkInsightsAccessScopeAnalysisIds: Optional[NetworkInsightsAccessScopeAnalysisIdList]
    NetworkInsightsAccessScopeId: Optional[NetworkInsightsAccessScopeId]
    AnalysisStartTimeBegin: Optional[MillisecondDateTime]
    AnalysisStartTimeEnd: Optional[MillisecondDateTime]
    Filters: Optional[FilterList]
    MaxResults: Optional[NetworkInsightsMaxResults]
    DryRun: Optional[Boolean]
    NextToken: Optional[NextToken]


class NetworkInsightsAccessScopeAnalysis(TypedDict, total=False):
    NetworkInsightsAccessScopeAnalysisId: Optional[NetworkInsightsAccessScopeAnalysisId]
    NetworkInsightsAccessScopeAnalysisArn: Optional[ResourceArn]
    NetworkInsightsAccessScopeId: Optional[NetworkInsightsAccessScopeId]
    Status: Optional[AnalysisStatus]
    StatusMessage: Optional[String]
    WarningMessage: Optional[String]
    StartDate: Optional[MillisecondDateTime]
    EndDate: Optional[MillisecondDateTime]
    FindingsFound: Optional[FindingsFound]
    AnalyzedEniCount: Optional[Integer]
    Tags: Optional[TagList]


NetworkInsightsAccessScopeAnalysisList = List[NetworkInsightsAccessScopeAnalysis]


class DescribeNetworkInsightsAccessScopeAnalysesResult(TypedDict, total=False):
    NetworkInsightsAccessScopeAnalyses: Optional[NetworkInsightsAccessScopeAnalysisList]
    NextToken: Optional[String]


NetworkInsightsAccessScopeIdList = List[NetworkInsightsAccessScopeId]


class DescribeNetworkInsightsAccessScopesRequest(ServiceRequest):
    NetworkInsightsAccessScopeIds: Optional[NetworkInsightsAccessScopeIdList]
    Filters: Optional[FilterList]
    MaxResults: Optional[NetworkInsightsMaxResults]
    DryRun: Optional[Boolean]
    NextToken: Optional[NextToken]


NetworkInsightsAccessScopeList = List[NetworkInsightsAccessScope]


class DescribeNetworkInsightsAccessScopesResult(TypedDict, total=False):
    NetworkInsightsAccessScopes: Optional[NetworkInsightsAccessScopeList]
    NextToken: Optional[String]


NetworkInsightsAnalysisIdList = List[NetworkInsightsAnalysisId]


class DescribeNetworkInsightsAnalysesRequest(ServiceRequest):
    NetworkInsightsAnalysisIds: Optional[NetworkInsightsAnalysisIdList]
    NetworkInsightsPathId: Optional[NetworkInsightsPathId]
    AnalysisStartTime: Optional[MillisecondDateTime]
    AnalysisEndTime: Optional[MillisecondDateTime]
    Filters: Optional[FilterList]
    MaxResults: Optional[NetworkInsightsMaxResults]
    DryRun: Optional[Boolean]
    NextToken: Optional[NextToken]


class NetworkInsightsAnalysis(TypedDict, total=False):
    NetworkInsightsAnalysisId: Optional[NetworkInsightsAnalysisId]
    NetworkInsightsAnalysisArn: Optional[ResourceArn]
    NetworkInsightsPathId: Optional[NetworkInsightsPathId]
    AdditionalAccounts: Optional[ValueStringList]
    FilterInArns: Optional[ArnList]
    StartDate: Optional[MillisecondDateTime]
    Status: Optional[AnalysisStatus]
    StatusMessage: Optional[String]
    WarningMessage: Optional[String]
    NetworkPathFound: Optional[Boolean]
    ForwardPathComponents: Optional[PathComponentList]
    ReturnPathComponents: Optional[PathComponentList]
    Explanations: Optional[ExplanationList]
    AlternatePathHints: Optional[AlternatePathHintList]
    SuggestedAccounts: Optional[ValueStringList]
    Tags: Optional[TagList]


NetworkInsightsAnalysisList = List[NetworkInsightsAnalysis]


class DescribeNetworkInsightsAnalysesResult(TypedDict, total=False):
    NetworkInsightsAnalyses: Optional[NetworkInsightsAnalysisList]
    NextToken: Optional[String]


NetworkInsightsPathIdList = List[NetworkInsightsPathId]


class DescribeNetworkInsightsPathsRequest(ServiceRequest):
    NetworkInsightsPathIds: Optional[NetworkInsightsPathIdList]
    Filters: Optional[FilterList]
    MaxResults: Optional[NetworkInsightsMaxResults]
    DryRun: Optional[Boolean]
    NextToken: Optional[NextToken]


NetworkInsightsPathList = List[NetworkInsightsPath]


class DescribeNetworkInsightsPathsResult(TypedDict, total=False):
    NetworkInsightsPaths: Optional[NetworkInsightsPathList]
    NextToken: Optional[String]


class DescribeNetworkInterfaceAttributeRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    NetworkInterfaceId: NetworkInterfaceId
    Attribute: Optional[NetworkInterfaceAttribute]


class DescribeNetworkInterfaceAttributeResult(TypedDict, total=False):
    Attachment: Optional[NetworkInterfaceAttachment]
    Description: Optional[AttributeValue]
    Groups: Optional[GroupIdentifierList]
    NetworkInterfaceId: Optional[String]
    SourceDestCheck: Optional[AttributeBooleanValue]
    AssociatePublicIpAddress: Optional[Boolean]


NetworkInterfacePermissionIdList = List[NetworkInterfacePermissionId]


class DescribeNetworkInterfacePermissionsRequest(ServiceRequest):
    NetworkInterfacePermissionIds: Optional[NetworkInterfacePermissionIdList]
    Filters: Optional[FilterList]
    NextToken: Optional[String]
    MaxResults: Optional[DescribeNetworkInterfacePermissionsMaxResults]


NetworkInterfacePermissionList = List[NetworkInterfacePermission]


class DescribeNetworkInterfacePermissionsResult(TypedDict, total=False):
    NetworkInterfacePermissions: Optional[NetworkInterfacePermissionList]
    NextToken: Optional[String]


NetworkInterfaceIdList = List[NetworkInterfaceId]


class DescribeNetworkInterfacesRequest(ServiceRequest):
    NextToken: Optional[String]
    MaxResults: Optional[DescribeNetworkInterfacesMaxResults]
    DryRun: Optional[Boolean]
    NetworkInterfaceIds: Optional[NetworkInterfaceIdList]
    Filters: Optional[FilterList]


NetworkInterfaceList = List[NetworkInterface]


class DescribeNetworkInterfacesResult(TypedDict, total=False):
    NetworkInterfaces: Optional[NetworkInterfaceList]
    NextToken: Optional[String]


PlacementGroupStringList = List[PlacementGroupName]
PlacementGroupIdStringList = List[PlacementGroupId]


class DescribePlacementGroupsRequest(ServiceRequest):
    GroupIds: Optional[PlacementGroupIdStringList]
    DryRun: Optional[Boolean]
    GroupNames: Optional[PlacementGroupStringList]
    Filters: Optional[FilterList]


PlacementGroupList = List[PlacementGroup]


class DescribePlacementGroupsResult(TypedDict, total=False):
    PlacementGroups: Optional[PlacementGroupList]


PrefixListResourceIdStringList = List[PrefixListResourceId]


class DescribePrefixListsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]
    PrefixListIds: Optional[PrefixListResourceIdStringList]


class PrefixList(TypedDict, total=False):
    Cidrs: Optional[ValueStringList]
    PrefixListId: Optional[String]
    PrefixListName: Optional[String]


PrefixListSet = List[PrefixList]


class DescribePrefixListsResult(TypedDict, total=False):
    NextToken: Optional[String]
    PrefixLists: Optional[PrefixListSet]


ResourceList = List[String]


class DescribePrincipalIdFormatRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Resources: Optional[ResourceList]
    MaxResults: Optional[DescribePrincipalIdFormatMaxResults]
    NextToken: Optional[String]


class PrincipalIdFormat(TypedDict, total=False):
    Arn: Optional[String]
    Statuses: Optional[IdFormatList]


PrincipalIdFormatList = List[PrincipalIdFormat]


class DescribePrincipalIdFormatResult(TypedDict, total=False):
    Principals: Optional[PrincipalIdFormatList]
    NextToken: Optional[String]


PublicIpv4PoolIdStringList = List[Ipv4PoolEc2Id]


class DescribePublicIpv4PoolsRequest(ServiceRequest):
    PoolIds: Optional[PublicIpv4PoolIdStringList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[PoolMaxResults]
    Filters: Optional[FilterList]


class PublicIpv4PoolRange(TypedDict, total=False):
    FirstAddress: Optional[String]
    LastAddress: Optional[String]
    AddressCount: Optional[Integer]
    AvailableAddressCount: Optional[Integer]


PublicIpv4PoolRangeSet = List[PublicIpv4PoolRange]


class PublicIpv4Pool(TypedDict, total=False):
    PoolId: Optional[String]
    Description: Optional[String]
    PoolAddressRanges: Optional[PublicIpv4PoolRangeSet]
    TotalAddressCount: Optional[Integer]
    TotalAvailableAddressCount: Optional[Integer]
    NetworkBorderGroup: Optional[String]
    Tags: Optional[TagList]


PublicIpv4PoolSet = List[PublicIpv4Pool]


class DescribePublicIpv4PoolsResult(TypedDict, total=False):
    PublicIpv4Pools: Optional[PublicIpv4PoolSet]
    NextToken: Optional[String]


RegionNameStringList = List[String]


class DescribeRegionsRequest(ServiceRequest):
    RegionNames: Optional[RegionNameStringList]
    AllRegions: Optional[Boolean]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]


class Region(TypedDict, total=False):
    OptInStatus: Optional[String]
    RegionName: Optional[String]
    Endpoint: Optional[String]


RegionList = List[Region]


class DescribeRegionsResult(TypedDict, total=False):
    Regions: Optional[RegionList]


ReplaceRootVolumeTaskIds = List[ReplaceRootVolumeTaskId]


class DescribeReplaceRootVolumeTasksRequest(ServiceRequest):
    ReplaceRootVolumeTaskIds: Optional[ReplaceRootVolumeTaskIds]
    Filters: Optional[FilterList]
    MaxResults: Optional[DescribeReplaceRootVolumeTasksMaxResults]
    NextToken: Optional[NextToken]
    DryRun: Optional[Boolean]


ReplaceRootVolumeTasks = List[ReplaceRootVolumeTask]


class DescribeReplaceRootVolumeTasksResult(TypedDict, total=False):
    ReplaceRootVolumeTasks: Optional[ReplaceRootVolumeTasks]
    NextToken: Optional[String]


class DescribeReservedInstancesListingsRequest(ServiceRequest):
    ReservedInstancesId: Optional[ReservationId]
    ReservedInstancesListingId: Optional[ReservedInstancesListingId]
    Filters: Optional[FilterList]


class DescribeReservedInstancesListingsResult(TypedDict, total=False):
    ReservedInstancesListings: Optional[ReservedInstancesListingList]


ReservedInstancesModificationIdStringList = List[ReservedInstancesModificationId]


class DescribeReservedInstancesModificationsRequest(ServiceRequest):
    ReservedInstancesModificationIds: Optional[ReservedInstancesModificationIdStringList]
    NextToken: Optional[String]
    Filters: Optional[FilterList]


class ReservedInstancesId(TypedDict, total=False):
    ReservedInstancesId: Optional[String]


ReservedIntancesIds = List[ReservedInstancesId]


class ReservedInstancesConfiguration(TypedDict, total=False):
    AvailabilityZone: Optional[String]
    InstanceCount: Optional[Integer]
    InstanceType: Optional[InstanceType]
    Platform: Optional[String]
    Scope: Optional[scope]


class ReservedInstancesModificationResult(TypedDict, total=False):
    ReservedInstancesId: Optional[String]
    TargetConfiguration: Optional[ReservedInstancesConfiguration]


ReservedInstancesModificationResultList = List[ReservedInstancesModificationResult]


class ReservedInstancesModification(TypedDict, total=False):
    ClientToken: Optional[String]
    CreateDate: Optional[DateTime]
    EffectiveDate: Optional[DateTime]
    ModificationResults: Optional[ReservedInstancesModificationResultList]
    ReservedInstancesIds: Optional[ReservedIntancesIds]
    ReservedInstancesModificationId: Optional[String]
    Status: Optional[String]
    StatusMessage: Optional[String]
    UpdateDate: Optional[DateTime]


ReservedInstancesModificationList = List[ReservedInstancesModification]


class DescribeReservedInstancesModificationsResult(TypedDict, total=False):
    NextToken: Optional[String]
    ReservedInstancesModifications: Optional[ReservedInstancesModificationList]


ReservedInstancesOfferingIdStringList = List[ReservedInstancesOfferingId]


class DescribeReservedInstancesOfferingsRequest(ServiceRequest):
    AvailabilityZone: Optional[String]
    IncludeMarketplace: Optional[Boolean]
    InstanceType: Optional[InstanceType]
    MaxDuration: Optional[Long]
    MaxInstanceCount: Optional[Integer]
    MinDuration: Optional[Long]
    OfferingClass: Optional[OfferingClassType]
    ProductDescription: Optional[RIProductDescription]
    ReservedInstancesOfferingIds: Optional[ReservedInstancesOfferingIdStringList]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    InstanceTenancy: Optional[Tenancy]
    OfferingType: Optional[OfferingTypeValues]
    NextToken: Optional[String]
    MaxResults: Optional[Integer]


class RecurringCharge(TypedDict, total=False):
    Amount: Optional[Double]
    Frequency: Optional[RecurringChargeFrequency]


RecurringChargesList = List[RecurringCharge]


class PricingDetail(TypedDict, total=False):
    Count: Optional[Integer]
    Price: Optional[Double]


PricingDetailsList = List[PricingDetail]


class ReservedInstancesOffering(TypedDict, total=False):
    CurrencyCode: Optional[CurrencyCodeValues]
    InstanceTenancy: Optional[Tenancy]
    Marketplace: Optional[Boolean]
    OfferingClass: Optional[OfferingClassType]
    OfferingType: Optional[OfferingTypeValues]
    PricingDetails: Optional[PricingDetailsList]
    RecurringCharges: Optional[RecurringChargesList]
    Scope: Optional[scope]
    ReservedInstancesOfferingId: Optional[String]
    InstanceType: Optional[InstanceType]
    AvailabilityZone: Optional[String]
    Duration: Optional[Long]
    UsagePrice: Optional[Float]
    FixedPrice: Optional[Float]
    ProductDescription: Optional[RIProductDescription]


ReservedInstancesOfferingList = List[ReservedInstancesOffering]


class DescribeReservedInstancesOfferingsResult(TypedDict, total=False):
    NextToken: Optional[String]
    ReservedInstancesOfferings: Optional[ReservedInstancesOfferingList]


ReservedInstancesIdStringList = List[ReservationId]


class DescribeReservedInstancesRequest(ServiceRequest):
    OfferingClass: Optional[OfferingClassType]
    ReservedInstancesIds: Optional[ReservedInstancesIdStringList]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    OfferingType: Optional[OfferingTypeValues]


class ReservedInstances(TypedDict, total=False):
    CurrencyCode: Optional[CurrencyCodeValues]
    InstanceTenancy: Optional[Tenancy]
    OfferingClass: Optional[OfferingClassType]
    OfferingType: Optional[OfferingTypeValues]
    RecurringCharges: Optional[RecurringChargesList]
    Scope: Optional[scope]
    Tags: Optional[TagList]
    ReservedInstancesId: Optional[String]
    InstanceType: Optional[InstanceType]
    AvailabilityZone: Optional[String]
    Start: Optional[DateTime]
    End: Optional[DateTime]
    Duration: Optional[Long]
    UsagePrice: Optional[Float]
    FixedPrice: Optional[Float]
    InstanceCount: Optional[Integer]
    ProductDescription: Optional[RIProductDescription]
    State: Optional[ReservedInstanceState]


ReservedInstancesList = List[ReservedInstances]


class DescribeReservedInstancesResult(TypedDict, total=False):
    ReservedInstances: Optional[ReservedInstancesList]


RouteTableIdStringList = List[RouteTableId]


class DescribeRouteTablesRequest(ServiceRequest):
    NextToken: Optional[String]
    MaxResults: Optional[DescribeRouteTablesMaxResults]
    DryRun: Optional[Boolean]
    RouteTableIds: Optional[RouteTableIdStringList]
    Filters: Optional[FilterList]


RouteTableList = List[RouteTable]


class DescribeRouteTablesResult(TypedDict, total=False):
    RouteTables: Optional[RouteTableList]
    NextToken: Optional[String]


OccurrenceDayRequestSet = List[Integer]


class ScheduledInstanceRecurrenceRequest(TypedDict, total=False):
    Frequency: Optional[String]
    Interval: Optional[Integer]
    OccurrenceDays: Optional[OccurrenceDayRequestSet]
    OccurrenceRelativeToEnd: Optional[Boolean]
    OccurrenceUnit: Optional[String]


class SlotDateTimeRangeRequest(TypedDict, total=False):
    EarliestTime: DateTime
    LatestTime: DateTime


class DescribeScheduledInstanceAvailabilityRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    FirstSlotStartTimeRange: SlotDateTimeRangeRequest
    MaxResults: Optional[DescribeScheduledInstanceAvailabilityMaxResults]
    MaxSlotDurationInHours: Optional[Integer]
    MinSlotDurationInHours: Optional[Integer]
    NextToken: Optional[String]
    Recurrence: ScheduledInstanceRecurrenceRequest


OccurrenceDaySet = List[Integer]


class ScheduledInstanceRecurrence(TypedDict, total=False):
    Frequency: Optional[String]
    Interval: Optional[Integer]
    OccurrenceDaySet: Optional[OccurrenceDaySet]
    OccurrenceRelativeToEnd: Optional[Boolean]
    OccurrenceUnit: Optional[String]


class ScheduledInstanceAvailability(TypedDict, total=False):
    AvailabilityZone: Optional[String]
    AvailableInstanceCount: Optional[Integer]
    FirstSlotStartTime: Optional[DateTime]
    HourlyPrice: Optional[String]
    InstanceType: Optional[String]
    MaxTermDurationInDays: Optional[Integer]
    MinTermDurationInDays: Optional[Integer]
    NetworkPlatform: Optional[String]
    Platform: Optional[String]
    PurchaseToken: Optional[String]
    Recurrence: Optional[ScheduledInstanceRecurrence]
    SlotDurationInHours: Optional[Integer]
    TotalScheduledInstanceHours: Optional[Integer]


ScheduledInstanceAvailabilitySet = List[ScheduledInstanceAvailability]


class DescribeScheduledInstanceAvailabilityResult(TypedDict, total=False):
    NextToken: Optional[String]
    ScheduledInstanceAvailabilitySet: Optional[ScheduledInstanceAvailabilitySet]


class SlotStartTimeRangeRequest(TypedDict, total=False):
    EarliestTime: Optional[DateTime]
    LatestTime: Optional[DateTime]


ScheduledInstanceIdRequestSet = List[ScheduledInstanceId]


class DescribeScheduledInstancesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]
    ScheduledInstanceIds: Optional[ScheduledInstanceIdRequestSet]
    SlotStartTimeRange: Optional[SlotStartTimeRangeRequest]


class ScheduledInstance(TypedDict, total=False):
    AvailabilityZone: Optional[String]
    CreateDate: Optional[DateTime]
    HourlyPrice: Optional[String]
    InstanceCount: Optional[Integer]
    InstanceType: Optional[String]
    NetworkPlatform: Optional[String]
    NextSlotStartTime: Optional[DateTime]
    Platform: Optional[String]
    PreviousSlotEndTime: Optional[DateTime]
    Recurrence: Optional[ScheduledInstanceRecurrence]
    ScheduledInstanceId: Optional[String]
    SlotDurationInHours: Optional[Integer]
    TermEndDate: Optional[DateTime]
    TermStartDate: Optional[DateTime]
    TotalScheduledInstanceHours: Optional[Integer]


ScheduledInstanceSet = List[ScheduledInstance]


class DescribeScheduledInstancesResult(TypedDict, total=False):
    NextToken: Optional[String]
    ScheduledInstanceSet: Optional[ScheduledInstanceSet]


GroupIds = List[SecurityGroupId]


class DescribeSecurityGroupReferencesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    GroupId: GroupIds


class SecurityGroupReference(TypedDict, total=False):
    GroupId: Optional[String]
    ReferencingVpcId: Optional[String]
    VpcPeeringConnectionId: Optional[String]
    TransitGatewayId: Optional[String]


SecurityGroupReferences = List[SecurityGroupReference]


class DescribeSecurityGroupReferencesResult(TypedDict, total=False):
    SecurityGroupReferenceSet: Optional[SecurityGroupReferences]


SecurityGroupRuleIdList = List[String]


class DescribeSecurityGroupRulesRequest(ServiceRequest):
    Filters: Optional[FilterList]
    SecurityGroupRuleIds: Optional[SecurityGroupRuleIdList]
    DryRun: Optional[Boolean]
    NextToken: Optional[String]
    MaxResults: Optional[DescribeSecurityGroupRulesMaxResults]


class DescribeSecurityGroupRulesResult(TypedDict, total=False):
    SecurityGroupRules: Optional[SecurityGroupRuleList]
    NextToken: Optional[String]


class DescribeSecurityGroupVpcAssociationsRequest(ServiceRequest):
    Filters: Optional[FilterList]
    NextToken: Optional[String]
    MaxResults: Optional[DescribeSecurityGroupVpcAssociationsMaxResults]
    DryRun: Optional[Boolean]


class SecurityGroupVpcAssociation(TypedDict, total=False):
    GroupId: Optional[SecurityGroupId]
    VpcId: Optional[VpcId]
    VpcOwnerId: Optional[String]
    State: Optional[SecurityGroupVpcAssociationState]
    StateReason: Optional[String]


SecurityGroupVpcAssociationList = List[SecurityGroupVpcAssociation]


class DescribeSecurityGroupVpcAssociationsResult(TypedDict, total=False):
    SecurityGroupVpcAssociations: Optional[SecurityGroupVpcAssociationList]
    NextToken: Optional[String]


GroupNameStringList = List[SecurityGroupName]


class DescribeSecurityGroupsRequest(ServiceRequest):
    GroupIds: Optional[GroupIdStringList]
    GroupNames: Optional[GroupNameStringList]
    NextToken: Optional[String]
    MaxResults: Optional[DescribeSecurityGroupsMaxResults]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]


class SecurityGroup(TypedDict, total=False):
    GroupId: Optional[String]
    IpPermissionsEgress: Optional[IpPermissionList]
    Tags: Optional[TagList]
    VpcId: Optional[String]
    SecurityGroupArn: Optional[String]
    OwnerId: Optional[String]
    GroupName: Optional[String]
    Description: Optional[String]
    IpPermissions: Optional[IpPermissionList]


SecurityGroupList = List[SecurityGroup]


class DescribeSecurityGroupsResult(TypedDict, total=False):
    NextToken: Optional[String]
    SecurityGroups: Optional[SecurityGroupList]


class DescribeSnapshotAttributeRequest(ServiceRequest):
    Attribute: SnapshotAttributeName
    SnapshotId: SnapshotId
    DryRun: Optional[Boolean]


class DescribeSnapshotAttributeResult(TypedDict, total=False):
    ProductCodes: Optional[ProductCodeList]
    SnapshotId: Optional[String]
    CreateVolumePermissions: Optional[CreateVolumePermissionList]


class DescribeSnapshotTierStatusRequest(ServiceRequest):
    Filters: Optional[FilterList]
    DryRun: Optional[Boolean]
    NextToken: Optional[String]
    MaxResults: Optional[DescribeSnapshotTierStatusMaxResults]


class SnapshotTierStatus(TypedDict, total=False):
    SnapshotId: Optional[SnapshotId]
    VolumeId: Optional[VolumeId]
    Status: Optional[SnapshotState]
    OwnerId: Optional[String]
    Tags: Optional[TagList]
    StorageTier: Optional[StorageTier]
    LastTieringStartTime: Optional[MillisecondDateTime]
    LastTieringProgress: Optional[Integer]
    LastTieringOperationStatus: Optional[TieringOperationStatus]
    LastTieringOperationStatusDetail: Optional[String]
    ArchivalCompleteTime: Optional[MillisecondDateTime]
    RestoreExpiryTime: Optional[MillisecondDateTime]


snapshotTierStatusSet = List[SnapshotTierStatus]


class DescribeSnapshotTierStatusResult(TypedDict, total=False):
    SnapshotTierStatuses: Optional[snapshotTierStatusSet]
    NextToken: Optional[String]


RestorableByStringList = List[String]


class DescribeSnapshotsRequest(ServiceRequest):
    MaxResults: Optional[Integer]
    NextToken: Optional[String]
    OwnerIds: Optional[OwnerStringList]
    RestorableByUserIds: Optional[RestorableByStringList]
    SnapshotIds: Optional[SnapshotIdStringList]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]


class Snapshot(TypedDict, total=False):
    OwnerAlias: Optional[String]
    OutpostArn: Optional[String]
    Tags: Optional[TagList]
    StorageTier: Optional[StorageTier]
    RestoreExpiryTime: Optional[MillisecondDateTime]
    SseType: Optional[SSEType]
    SnapshotId: Optional[String]
    VolumeId: Optional[String]
    State: Optional[SnapshotState]
    StateMessage: Optional[String]
    StartTime: Optional[DateTime]
    Progress: Optional[String]
    OwnerId: Optional[String]
    Description: Optional[String]
    VolumeSize: Optional[Integer]
    Encrypted: Optional[Boolean]
    KmsKeyId: Optional[String]
    DataEncryptionKeyId: Optional[String]


SnapshotList = List[Snapshot]


class DescribeSnapshotsResult(TypedDict, total=False):
    NextToken: Optional[String]
    Snapshots: Optional[SnapshotList]


class DescribeSpotDatafeedSubscriptionRequest(ServiceRequest):
    DryRun: Optional[Boolean]


class DescribeSpotDatafeedSubscriptionResult(TypedDict, total=False):
    SpotDatafeedSubscription: Optional[SpotDatafeedSubscription]


class DescribeSpotFleetInstancesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    SpotFleetRequestId: SpotFleetRequestId
    NextToken: Optional[String]
    MaxResults: Optional[DescribeSpotFleetInstancesMaxResults]


class DescribeSpotFleetInstancesResponse(TypedDict, total=False):
    ActiveInstances: Optional[ActiveInstanceSet]
    NextToken: Optional[String]
    SpotFleetRequestId: Optional[String]


class DescribeSpotFleetRequestHistoryRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    SpotFleetRequestId: SpotFleetRequestId
    EventType: Optional[EventType]
    StartTime: DateTime
    NextToken: Optional[String]
    MaxResults: Optional[DescribeSpotFleetRequestHistoryMaxResults]


class HistoryRecord(TypedDict, total=False):
    EventInformation: Optional[EventInformation]
    EventType: Optional[EventType]
    Timestamp: Optional[DateTime]


HistoryRecords = List[HistoryRecord]


class DescribeSpotFleetRequestHistoryResponse(TypedDict, total=False):
    HistoryRecords: Optional[HistoryRecords]
    LastEvaluatedTime: Optional[DateTime]
    NextToken: Optional[String]
    SpotFleetRequestId: Optional[String]
    StartTime: Optional[DateTime]


class DescribeSpotFleetRequestsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    SpotFleetRequestIds: Optional[SpotFleetRequestIdList]
    NextToken: Optional[String]
    MaxResults: Optional[Integer]


class TargetGroup(TypedDict, total=False):
    Arn: Optional[String]


TargetGroups = List[TargetGroup]


class TargetGroupsConfig(TypedDict, total=False):
    TargetGroups: Optional[TargetGroups]


class LoadBalancersConfig(TypedDict, total=False):
    ClassicLoadBalancersConfig: Optional[ClassicLoadBalancersConfig]
    TargetGroupsConfig: Optional[TargetGroupsConfig]


class LaunchTemplateOverrides(TypedDict, total=False):
    InstanceType: Optional[InstanceType]
    SpotPrice: Optional[String]
    SubnetId: Optional[SubnetId]
    AvailabilityZone: Optional[String]
    WeightedCapacity: Optional[Double]
    Priority: Optional[Double]
    InstanceRequirements: Optional[InstanceRequirements]


LaunchTemplateOverridesList = List[LaunchTemplateOverrides]


class LaunchTemplateConfig(TypedDict, total=False):
    LaunchTemplateSpecification: Optional[FleetLaunchTemplateSpecification]
    Overrides: Optional[LaunchTemplateOverridesList]


LaunchTemplateConfigList = List[LaunchTemplateConfig]


class SpotFleetTagSpecification(TypedDict, total=False):
    ResourceType: Optional[ResourceType]
    Tags: Optional[TagList]


SpotFleetTagSpecificationList = List[SpotFleetTagSpecification]


class SpotPlacement(TypedDict, total=False):
    AvailabilityZone: Optional[String]
    GroupName: Optional[PlacementGroupName]
    Tenancy: Optional[Tenancy]


class InstanceNetworkInterfaceSpecification(TypedDict, total=False):
    AssociatePublicIpAddress: Optional[Boolean]
    DeleteOnTermination: Optional[Boolean]
    Description: Optional[String]
    DeviceIndex: Optional[Integer]
    Groups: Optional[SecurityGroupIdStringList]
    Ipv6AddressCount: Optional[Integer]
    Ipv6Addresses: Optional[InstanceIpv6AddressList]
    NetworkInterfaceId: Optional[NetworkInterfaceId]
    PrivateIpAddress: Optional[String]
    PrivateIpAddresses: Optional[PrivateIpAddressSpecificationList]
    SecondaryPrivateIpAddressCount: Optional[Integer]
    SubnetId: Optional[String]
    AssociateCarrierIpAddress: Optional[Boolean]
    InterfaceType: Optional[String]
    NetworkCardIndex: Optional[Integer]
    Ipv4Prefixes: Optional[Ipv4PrefixList]
    Ipv4PrefixCount: Optional[Integer]
    Ipv6Prefixes: Optional[Ipv6PrefixList]
    Ipv6PrefixCount: Optional[Integer]
    PrimaryIpv6: Optional[Boolean]
    EnaSrdSpecification: Optional[EnaSrdSpecificationRequest]
    ConnectionTrackingSpecification: Optional[ConnectionTrackingSpecificationRequest]


InstanceNetworkInterfaceSpecificationList = List[InstanceNetworkInterfaceSpecification]


class SpotFleetMonitoring(TypedDict, total=False):
    Enabled: Optional[Boolean]


class SpotFleetLaunchSpecification(TypedDict, total=False):
    AddressingType: Optional[String]
    BlockDeviceMappings: Optional[BlockDeviceMappingList]
    EbsOptimized: Optional[Boolean]
    IamInstanceProfile: Optional[IamInstanceProfileSpecification]
    ImageId: Optional[ImageId]
    InstanceType: Optional[InstanceType]
    KernelId: Optional[String]
    KeyName: Optional[KeyPairName]
    Monitoring: Optional[SpotFleetMonitoring]
    NetworkInterfaces: Optional[InstanceNetworkInterfaceSpecificationList]
    Placement: Optional[SpotPlacement]
    RamdiskId: Optional[String]
    SpotPrice: Optional[String]
    SubnetId: Optional[SubnetId]
    UserData: Optional[SensitiveUserData]
    WeightedCapacity: Optional[Double]
    TagSpecifications: Optional[SpotFleetTagSpecificationList]
    InstanceRequirements: Optional[InstanceRequirements]
    SecurityGroups: Optional[GroupIdentifierList]


LaunchSpecsList = List[SpotFleetLaunchSpecification]


class SpotCapacityRebalance(TypedDict, total=False):
    ReplacementStrategy: Optional[ReplacementStrategy]
    TerminationDelay: Optional[Integer]


class SpotMaintenanceStrategies(TypedDict, total=False):
    CapacityRebalance: Optional[SpotCapacityRebalance]


class SpotFleetRequestConfigData(TypedDict, total=False):
    AllocationStrategy: Optional[AllocationStrategy]
    OnDemandAllocationStrategy: Optional[OnDemandAllocationStrategy]
    SpotMaintenanceStrategies: Optional[SpotMaintenanceStrategies]
    ClientToken: Optional[String]
    ExcessCapacityTerminationPolicy: Optional[ExcessCapacityTerminationPolicy]
    FulfilledCapacity: Optional[Double]
    OnDemandFulfilledCapacity: Optional[Double]
    IamFleetRole: String
    LaunchSpecifications: Optional[LaunchSpecsList]
    LaunchTemplateConfigs: Optional[LaunchTemplateConfigList]
    SpotPrice: Optional[String]
    TargetCapacity: Integer
    OnDemandTargetCapacity: Optional[Integer]
    OnDemandMaxTotalPrice: Optional[String]
    SpotMaxTotalPrice: Optional[String]
    TerminateInstancesWithExpiration: Optional[Boolean]
    Type: Optional[FleetType]
    ValidFrom: Optional[DateTime]
    ValidUntil: Optional[DateTime]
    ReplaceUnhealthyInstances: Optional[Boolean]
    InstanceInterruptionBehavior: Optional[InstanceInterruptionBehavior]
    LoadBalancersConfig: Optional[LoadBalancersConfig]
    InstancePoolsToUseCount: Optional[Integer]
    Context: Optional[String]
    TargetCapacityUnitType: Optional[TargetCapacityUnitType]
    TagSpecifications: Optional[TagSpecificationList]


class SpotFleetRequestConfig(TypedDict, total=False):
    ActivityStatus: Optional[ActivityStatus]
    CreateTime: Optional[MillisecondDateTime]
    SpotFleetRequestConfig: Optional[SpotFleetRequestConfigData]
    SpotFleetRequestId: Optional[String]
    SpotFleetRequestState: Optional[BatchState]
    Tags: Optional[TagList]


SpotFleetRequestConfigSet = List[SpotFleetRequestConfig]


class DescribeSpotFleetRequestsResponse(TypedDict, total=False):
    NextToken: Optional[String]
    SpotFleetRequestConfigs: Optional[SpotFleetRequestConfigSet]


class DescribeSpotInstanceRequestsRequest(ServiceRequest):
    NextToken: Optional[String]
    MaxResults: Optional[Integer]
    DryRun: Optional[Boolean]
    SpotInstanceRequestIds: Optional[SpotInstanceRequestIdList]
    Filters: Optional[FilterList]


class SpotInstanceStatus(TypedDict, total=False):
    Code: Optional[String]
    Message: Optional[String]
    UpdateTime: Optional[DateTime]


class RunInstancesMonitoringEnabled(TypedDict, total=False):
    Enabled: Boolean


class LaunchSpecification(TypedDict, total=False):
    UserData: Optional[SensitiveUserData]
    AddressingType: Optional[String]
    BlockDeviceMappings: Optional[BlockDeviceMappingList]
    EbsOptimized: Optional[Boolean]
    IamInstanceProfile: Optional[IamInstanceProfileSpecification]
    ImageId: Optional[String]
    InstanceType: Optional[InstanceType]
    KernelId: Optional[String]
    KeyName: Optional[String]
    NetworkInterfaces: Optional[InstanceNetworkInterfaceSpecificationList]
    Placement: Optional[SpotPlacement]
    RamdiskId: Optional[String]
    SubnetId: Optional[String]
    SecurityGroups: Optional[GroupIdentifierList]
    Monitoring: Optional[RunInstancesMonitoringEnabled]


class SpotInstanceRequest(TypedDict, total=False):
    ActualBlockHourlyPrice: Optional[String]
    AvailabilityZoneGroup: Optional[String]
    BlockDurationMinutes: Optional[Integer]
    CreateTime: Optional[DateTime]
    Fault: Optional[SpotInstanceStateFault]
    InstanceId: Optional[InstanceId]
    LaunchGroup: Optional[String]
    LaunchSpecification: Optional[LaunchSpecification]
    LaunchedAvailabilityZone: Optional[String]
    ProductDescription: Optional[RIProductDescription]
    SpotInstanceRequestId: Optional[String]
    SpotPrice: Optional[String]
    State: Optional[SpotInstanceState]
    Status: Optional[SpotInstanceStatus]
    Tags: Optional[TagList]
    Type: Optional[SpotInstanceType]
    ValidFrom: Optional[DateTime]
    ValidUntil: Optional[DateTime]
    InstanceInterruptionBehavior: Optional[InstanceInterruptionBehavior]


SpotInstanceRequestList = List[SpotInstanceRequest]


class DescribeSpotInstanceRequestsResult(TypedDict, total=False):
    SpotInstanceRequests: Optional[SpotInstanceRequestList]
    NextToken: Optional[String]


ProductDescriptionList = List[String]
InstanceTypeList = List[InstanceType]


class DescribeSpotPriceHistoryRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    StartTime: Optional[DateTime]
    EndTime: Optional[DateTime]
    InstanceTypes: Optional[InstanceTypeList]
    ProductDescriptions: Optional[ProductDescriptionList]
    Filters: Optional[FilterList]
    AvailabilityZone: Optional[String]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]


class SpotPrice(TypedDict, total=False):
    AvailabilityZone: Optional[String]
    InstanceType: Optional[InstanceType]
    ProductDescription: Optional[RIProductDescription]
    SpotPrice: Optional[String]
    Timestamp: Optional[DateTime]


SpotPriceHistoryList = List[SpotPrice]


class DescribeSpotPriceHistoryResult(TypedDict, total=False):
    NextToken: Optional[String]
    SpotPriceHistory: Optional[SpotPriceHistoryList]


class DescribeStaleSecurityGroupsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    MaxResults: Optional[DescribeStaleSecurityGroupsMaxResults]
    NextToken: Optional[DescribeStaleSecurityGroupsNextToken]
    VpcId: VpcId


UserIdGroupPairSet = List[UserIdGroupPair]
PrefixListIdSet = List[String]
IpRanges = List[String]


class StaleIpPermission(TypedDict, total=False):
    FromPort: Optional[Integer]
    IpProtocol: Optional[String]
    IpRanges: Optional[IpRanges]
    PrefixListIds: Optional[PrefixListIdSet]
    ToPort: Optional[Integer]
    UserIdGroupPairs: Optional[UserIdGroupPairSet]


StaleIpPermissionSet = List[StaleIpPermission]


class StaleSecurityGroup(TypedDict, total=False):
    Description: Optional[String]
    GroupId: Optional[String]
    GroupName: Optional[String]
    StaleIpPermissions: Optional[StaleIpPermissionSet]
    StaleIpPermissionsEgress: Optional[StaleIpPermissionSet]
    VpcId: Optional[String]


StaleSecurityGroupSet = List[StaleSecurityGroup]


class DescribeStaleSecurityGroupsResult(TypedDict, total=False):
    NextToken: Optional[String]
    StaleSecurityGroupSet: Optional[StaleSecurityGroupSet]


ImageIdList = List[ImageId]


class DescribeStoreImageTasksRequest(ServiceRequest):
    ImageIds: Optional[ImageIdList]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    NextToken: Optional[String]
    MaxResults: Optional[DescribeStoreImageTasksRequestMaxResults]


class StoreImageTaskResult(TypedDict, total=False):
    AmiId: Optional[String]
    TaskStartTime: Optional[MillisecondDateTime]
    Bucket: Optional[String]
    S3objectKey: Optional[String]
    ProgressPercentage: Optional[Integer]
    StoreTaskState: Optional[String]
    StoreTaskFailureReason: Optional[String]


StoreImageTaskResultSet = List[StoreImageTaskResult]


class DescribeStoreImageTasksResult(TypedDict, total=False):
    StoreImageTaskResults: Optional[StoreImageTaskResultSet]
    NextToken: Optional[String]


SubnetIdStringList = List[SubnetId]


class DescribeSubnetsRequest(ServiceRequest):
    Filters: Optional[FilterList]
    SubnetIds: Optional[SubnetIdStringList]
    NextToken: Optional[String]
    MaxResults: Optional[DescribeSubnetsMaxResults]
    DryRun: Optional[Boolean]


SubnetList = List[Subnet]


class DescribeSubnetsResult(TypedDict, total=False):
    NextToken: Optional[String]
    Subnets: Optional[SubnetList]


class DescribeTagsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]


class TagDescription(TypedDict, total=False):
    Key: Optional[String]
    ResourceId: Optional[String]
    ResourceType: Optional[ResourceType]
    Value: Optional[String]


TagDescriptionList = List[TagDescription]


class DescribeTagsResult(TypedDict, total=False):
    NextToken: Optional[String]
    Tags: Optional[TagDescriptionList]


TrafficMirrorFilterRuleIdList = List[TrafficMirrorFilterRuleIdWithResolver]


class DescribeTrafficMirrorFilterRulesRequest(ServiceRequest):
    TrafficMirrorFilterRuleIds: Optional[TrafficMirrorFilterRuleIdList]
    TrafficMirrorFilterId: Optional[TrafficMirrorFilterId]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    MaxResults: Optional[TrafficMirroringMaxResults]
    NextToken: Optional[NextToken]


TrafficMirrorFilterRuleSet = List[TrafficMirrorFilterRule]


class DescribeTrafficMirrorFilterRulesResult(TypedDict, total=False):
    TrafficMirrorFilterRules: Optional[TrafficMirrorFilterRuleSet]
    NextToken: Optional[String]


TrafficMirrorFilterIdList = List[TrafficMirrorFilterId]


class DescribeTrafficMirrorFiltersRequest(ServiceRequest):
    TrafficMirrorFilterIds: Optional[TrafficMirrorFilterIdList]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    MaxResults: Optional[TrafficMirroringMaxResults]
    NextToken: Optional[NextToken]


TrafficMirrorFilterSet = List[TrafficMirrorFilter]


class DescribeTrafficMirrorFiltersResult(TypedDict, total=False):
    TrafficMirrorFilters: Optional[TrafficMirrorFilterSet]
    NextToken: Optional[String]


TrafficMirrorSessionIdList = List[TrafficMirrorSessionId]


class DescribeTrafficMirrorSessionsRequest(ServiceRequest):
    TrafficMirrorSessionIds: Optional[TrafficMirrorSessionIdList]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    MaxResults: Optional[TrafficMirroringMaxResults]
    NextToken: Optional[NextToken]


TrafficMirrorSessionSet = List[TrafficMirrorSession]


class DescribeTrafficMirrorSessionsResult(TypedDict, total=False):
    TrafficMirrorSessions: Optional[TrafficMirrorSessionSet]
    NextToken: Optional[String]


TrafficMirrorTargetIdList = List[TrafficMirrorTargetId]


class DescribeTrafficMirrorTargetsRequest(ServiceRequest):
    TrafficMirrorTargetIds: Optional[TrafficMirrorTargetIdList]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    MaxResults: Optional[TrafficMirroringMaxResults]
    NextToken: Optional[NextToken]


TrafficMirrorTargetSet = List[TrafficMirrorTarget]


class DescribeTrafficMirrorTargetsResult(TypedDict, total=False):
    TrafficMirrorTargets: Optional[TrafficMirrorTargetSet]
    NextToken: Optional[String]


TransitGatewayAttachmentIdStringList = List[TransitGatewayAttachmentId]


class DescribeTransitGatewayAttachmentsRequest(ServiceRequest):
    TransitGatewayAttachmentIds: Optional[TransitGatewayAttachmentIdStringList]
    Filters: Optional[FilterList]
    MaxResults: Optional[TransitGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


class TransitGatewayAttachmentAssociation(TypedDict, total=False):
    TransitGatewayRouteTableId: Optional[String]
    State: Optional[TransitGatewayAssociationState]


class TransitGatewayAttachment(TypedDict, total=False):
    TransitGatewayAttachmentId: Optional[String]
    TransitGatewayId: Optional[String]
    TransitGatewayOwnerId: Optional[String]
    ResourceOwnerId: Optional[String]
    ResourceType: Optional[TransitGatewayAttachmentResourceType]
    ResourceId: Optional[String]
    State: Optional[TransitGatewayAttachmentState]
    Association: Optional[TransitGatewayAttachmentAssociation]
    CreationTime: Optional[DateTime]
    Tags: Optional[TagList]


TransitGatewayAttachmentList = List[TransitGatewayAttachment]


class DescribeTransitGatewayAttachmentsResult(TypedDict, total=False):
    TransitGatewayAttachments: Optional[TransitGatewayAttachmentList]
    NextToken: Optional[String]


TransitGatewayConnectPeerIdStringList = List[TransitGatewayConnectPeerId]


class DescribeTransitGatewayConnectPeersRequest(ServiceRequest):
    TransitGatewayConnectPeerIds: Optional[TransitGatewayConnectPeerIdStringList]
    Filters: Optional[FilterList]
    MaxResults: Optional[TransitGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


TransitGatewayConnectPeerList = List[TransitGatewayConnectPeer]


class DescribeTransitGatewayConnectPeersResult(TypedDict, total=False):
    TransitGatewayConnectPeers: Optional[TransitGatewayConnectPeerList]
    NextToken: Optional[String]


class DescribeTransitGatewayConnectsRequest(ServiceRequest):
    TransitGatewayAttachmentIds: Optional[TransitGatewayAttachmentIdStringList]
    Filters: Optional[FilterList]
    MaxResults: Optional[TransitGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


TransitGatewayConnectList = List[TransitGatewayConnect]


class DescribeTransitGatewayConnectsResult(TypedDict, total=False):
    TransitGatewayConnects: Optional[TransitGatewayConnectList]
    NextToken: Optional[String]


TransitGatewayMulticastDomainIdStringList = List[TransitGatewayMulticastDomainId]


class DescribeTransitGatewayMulticastDomainsRequest(ServiceRequest):
    TransitGatewayMulticastDomainIds: Optional[TransitGatewayMulticastDomainIdStringList]
    Filters: Optional[FilterList]
    MaxResults: Optional[TransitGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


TransitGatewayMulticastDomainList = List[TransitGatewayMulticastDomain]


class DescribeTransitGatewayMulticastDomainsResult(TypedDict, total=False):
    TransitGatewayMulticastDomains: Optional[TransitGatewayMulticastDomainList]
    NextToken: Optional[String]


class DescribeTransitGatewayPeeringAttachmentsRequest(ServiceRequest):
    TransitGatewayAttachmentIds: Optional[TransitGatewayAttachmentIdStringList]
    Filters: Optional[FilterList]
    MaxResults: Optional[TransitGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


TransitGatewayPeeringAttachmentList = List[TransitGatewayPeeringAttachment]


class DescribeTransitGatewayPeeringAttachmentsResult(TypedDict, total=False):
    TransitGatewayPeeringAttachments: Optional[TransitGatewayPeeringAttachmentList]
    NextToken: Optional[String]


TransitGatewayPolicyTableIdStringList = List[TransitGatewayPolicyTableId]


class DescribeTransitGatewayPolicyTablesRequest(ServiceRequest):
    TransitGatewayPolicyTableIds: Optional[TransitGatewayPolicyTableIdStringList]
    Filters: Optional[FilterList]
    MaxResults: Optional[TransitGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


TransitGatewayPolicyTableList = List[TransitGatewayPolicyTable]


class DescribeTransitGatewayPolicyTablesResult(TypedDict, total=False):
    TransitGatewayPolicyTables: Optional[TransitGatewayPolicyTableList]
    NextToken: Optional[String]


TransitGatewayRouteTableAnnouncementIdStringList = List[TransitGatewayRouteTableAnnouncementId]


class DescribeTransitGatewayRouteTableAnnouncementsRequest(ServiceRequest):
    TransitGatewayRouteTableAnnouncementIds: Optional[
        TransitGatewayRouteTableAnnouncementIdStringList
    ]
    Filters: Optional[FilterList]
    MaxResults: Optional[TransitGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


TransitGatewayRouteTableAnnouncementList = List[TransitGatewayRouteTableAnnouncement]


class DescribeTransitGatewayRouteTableAnnouncementsResult(TypedDict, total=False):
    TransitGatewayRouteTableAnnouncements: Optional[TransitGatewayRouteTableAnnouncementList]
    NextToken: Optional[String]


TransitGatewayRouteTableIdStringList = List[TransitGatewayRouteTableId]


class DescribeTransitGatewayRouteTablesRequest(ServiceRequest):
    TransitGatewayRouteTableIds: Optional[TransitGatewayRouteTableIdStringList]
    Filters: Optional[FilterList]
    MaxResults: Optional[TransitGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


TransitGatewayRouteTableList = List[TransitGatewayRouteTable]


class DescribeTransitGatewayRouteTablesResult(TypedDict, total=False):
    TransitGatewayRouteTables: Optional[TransitGatewayRouteTableList]
    NextToken: Optional[String]


class DescribeTransitGatewayVpcAttachmentsRequest(ServiceRequest):
    TransitGatewayAttachmentIds: Optional[TransitGatewayAttachmentIdStringList]
    Filters: Optional[FilterList]
    MaxResults: Optional[TransitGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


TransitGatewayVpcAttachmentList = List[TransitGatewayVpcAttachment]


class DescribeTransitGatewayVpcAttachmentsResult(TypedDict, total=False):
    TransitGatewayVpcAttachments: Optional[TransitGatewayVpcAttachmentList]
    NextToken: Optional[String]


TransitGatewayIdStringList = List[TransitGatewayId]


class DescribeTransitGatewaysRequest(ServiceRequest):
    TransitGatewayIds: Optional[TransitGatewayIdStringList]
    Filters: Optional[FilterList]
    MaxResults: Optional[TransitGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


TransitGatewayList = List[TransitGateway]


class DescribeTransitGatewaysResult(TypedDict, total=False):
    TransitGateways: Optional[TransitGatewayList]
    NextToken: Optional[String]


TrunkInterfaceAssociationIdList = List[TrunkInterfaceAssociationId]


class DescribeTrunkInterfaceAssociationsRequest(ServiceRequest):
    AssociationIds: Optional[TrunkInterfaceAssociationIdList]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    NextToken: Optional[String]
    MaxResults: Optional[DescribeTrunkInterfaceAssociationsMaxResults]


TrunkInterfaceAssociationList = List[TrunkInterfaceAssociation]


class DescribeTrunkInterfaceAssociationsResult(TypedDict, total=False):
    InterfaceAssociations: Optional[TrunkInterfaceAssociationList]
    NextToken: Optional[String]


VerifiedAccessEndpointIdList = List[VerifiedAccessEndpointId]


class DescribeVerifiedAccessEndpointsRequest(ServiceRequest):
    VerifiedAccessEndpointIds: Optional[VerifiedAccessEndpointIdList]
    VerifiedAccessInstanceId: Optional[VerifiedAccessInstanceId]
    VerifiedAccessGroupId: Optional[VerifiedAccessGroupId]
    MaxResults: Optional[DescribeVerifiedAccessEndpointsMaxResults]
    NextToken: Optional[NextToken]
    Filters: Optional[FilterList]
    DryRun: Optional[Boolean]


VerifiedAccessEndpointList = List[VerifiedAccessEndpoint]


class DescribeVerifiedAccessEndpointsResult(TypedDict, total=False):
    VerifiedAccessEndpoints: Optional[VerifiedAccessEndpointList]
    NextToken: Optional[NextToken]


VerifiedAccessGroupIdList = List[VerifiedAccessGroupId]


class DescribeVerifiedAccessGroupsRequest(ServiceRequest):
    VerifiedAccessGroupIds: Optional[VerifiedAccessGroupIdList]
    VerifiedAccessInstanceId: Optional[VerifiedAccessInstanceId]
    MaxResults: Optional[DescribeVerifiedAccessGroupMaxResults]
    NextToken: Optional[NextToken]
    Filters: Optional[FilterList]
    DryRun: Optional[Boolean]


VerifiedAccessGroupList = List[VerifiedAccessGroup]


class DescribeVerifiedAccessGroupsResult(TypedDict, total=False):
    VerifiedAccessGroups: Optional[VerifiedAccessGroupList]
    NextToken: Optional[NextToken]


VerifiedAccessInstanceIdList = List[VerifiedAccessInstanceId]


class DescribeVerifiedAccessInstanceLoggingConfigurationsRequest(ServiceRequest):
    VerifiedAccessInstanceIds: Optional[VerifiedAccessInstanceIdList]
    MaxResults: Optional[DescribeVerifiedAccessInstanceLoggingConfigurationsMaxResults]
    NextToken: Optional[NextToken]
    Filters: Optional[FilterList]
    DryRun: Optional[Boolean]


class VerifiedAccessLogDeliveryStatus(TypedDict, total=False):
    Code: Optional[VerifiedAccessLogDeliveryStatusCode]
    Message: Optional[String]


class VerifiedAccessLogKinesisDataFirehoseDestination(TypedDict, total=False):
    Enabled: Optional[Boolean]
    DeliveryStatus: Optional[VerifiedAccessLogDeliveryStatus]
    DeliveryStream: Optional[String]


class VerifiedAccessLogCloudWatchLogsDestination(TypedDict, total=False):
    Enabled: Optional[Boolean]
    DeliveryStatus: Optional[VerifiedAccessLogDeliveryStatus]
    LogGroup: Optional[String]


class VerifiedAccessLogS3Destination(TypedDict, total=False):
    Enabled: Optional[Boolean]
    DeliveryStatus: Optional[VerifiedAccessLogDeliveryStatus]
    BucketName: Optional[String]
    Prefix: Optional[String]
    BucketOwner: Optional[String]


class VerifiedAccessLogs(TypedDict, total=False):
    S3: Optional[VerifiedAccessLogS3Destination]
    CloudWatchLogs: Optional[VerifiedAccessLogCloudWatchLogsDestination]
    KinesisDataFirehose: Optional[VerifiedAccessLogKinesisDataFirehoseDestination]
    LogVersion: Optional[String]
    IncludeTrustContext: Optional[Boolean]


class VerifiedAccessInstanceLoggingConfiguration(TypedDict, total=False):
    VerifiedAccessInstanceId: Optional[String]
    AccessLogs: Optional[VerifiedAccessLogs]


VerifiedAccessInstanceLoggingConfigurationList = List[VerifiedAccessInstanceLoggingConfiguration]


class DescribeVerifiedAccessInstanceLoggingConfigurationsResult(TypedDict, total=False):
    LoggingConfigurations: Optional[VerifiedAccessInstanceLoggingConfigurationList]
    NextToken: Optional[NextToken]


class DescribeVerifiedAccessInstancesRequest(ServiceRequest):
    VerifiedAccessInstanceIds: Optional[VerifiedAccessInstanceIdList]
    MaxResults: Optional[DescribeVerifiedAccessInstancesMaxResults]
    NextToken: Optional[NextToken]
    Filters: Optional[FilterList]
    DryRun: Optional[Boolean]


VerifiedAccessInstanceList = List[VerifiedAccessInstance]


class DescribeVerifiedAccessInstancesResult(TypedDict, total=False):
    VerifiedAccessInstances: Optional[VerifiedAccessInstanceList]
    NextToken: Optional[NextToken]


VerifiedAccessTrustProviderIdList = List[VerifiedAccessTrustProviderId]


class DescribeVerifiedAccessTrustProvidersRequest(ServiceRequest):
    VerifiedAccessTrustProviderIds: Optional[VerifiedAccessTrustProviderIdList]
    MaxResults: Optional[DescribeVerifiedAccessTrustProvidersMaxResults]
    NextToken: Optional[NextToken]
    Filters: Optional[FilterList]
    DryRun: Optional[Boolean]


VerifiedAccessTrustProviderList = List[VerifiedAccessTrustProvider]


class DescribeVerifiedAccessTrustProvidersResult(TypedDict, total=False):
    VerifiedAccessTrustProviders: Optional[VerifiedAccessTrustProviderList]
    NextToken: Optional[NextToken]


class DescribeVolumeAttributeRequest(ServiceRequest):
    Attribute: VolumeAttributeName
    VolumeId: VolumeId
    DryRun: Optional[Boolean]


class DescribeVolumeAttributeResult(TypedDict, total=False):
    AutoEnableIO: Optional[AttributeBooleanValue]
    ProductCodes: Optional[ProductCodeList]
    VolumeId: Optional[String]


class DescribeVolumeStatusRequest(ServiceRequest):
    MaxResults: Optional[Integer]
    NextToken: Optional[String]
    VolumeIds: Optional[VolumeIdStringList]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]


class VolumeStatusAttachmentStatus(TypedDict, total=False):
    IoPerformance: Optional[String]
    InstanceId: Optional[String]


VolumeStatusAttachmentStatusList = List[VolumeStatusAttachmentStatus]


class VolumeStatusDetails(TypedDict, total=False):
    Name: Optional[VolumeStatusName]
    Status: Optional[String]


VolumeStatusDetailsList = List[VolumeStatusDetails]


class VolumeStatusInfo(TypedDict, total=False):
    Details: Optional[VolumeStatusDetailsList]
    Status: Optional[VolumeStatusInfoStatus]


class VolumeStatusEvent(TypedDict, total=False):
    Description: Optional[String]
    EventId: Optional[String]
    EventType: Optional[String]
    NotAfter: Optional[MillisecondDateTime]
    NotBefore: Optional[MillisecondDateTime]
    InstanceId: Optional[String]


VolumeStatusEventsList = List[VolumeStatusEvent]


class VolumeStatusAction(TypedDict, total=False):
    Code: Optional[String]
    Description: Optional[String]
    EventId: Optional[String]
    EventType: Optional[String]


VolumeStatusActionsList = List[VolumeStatusAction]


class VolumeStatusItem(TypedDict, total=False):
    Actions: Optional[VolumeStatusActionsList]
    AvailabilityZone: Optional[String]
    OutpostArn: Optional[String]
    Events: Optional[VolumeStatusEventsList]
    VolumeId: Optional[String]
    VolumeStatus: Optional[VolumeStatusInfo]
    AttachmentStatuses: Optional[VolumeStatusAttachmentStatusList]


VolumeStatusList = List[VolumeStatusItem]


class DescribeVolumeStatusResult(TypedDict, total=False):
    NextToken: Optional[String]
    VolumeStatuses: Optional[VolumeStatusList]


class DescribeVolumesModificationsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    VolumeIds: Optional[VolumeIdStringList]
    Filters: Optional[FilterList]
    NextToken: Optional[String]
    MaxResults: Optional[Integer]


class VolumeModification(TypedDict, total=False):
    VolumeId: Optional[String]
    ModificationState: Optional[VolumeModificationState]
    StatusMessage: Optional[String]
    TargetSize: Optional[Integer]
    TargetIops: Optional[Integer]
    TargetVolumeType: Optional[VolumeType]
    TargetThroughput: Optional[Integer]
    TargetMultiAttachEnabled: Optional[Boolean]
    OriginalSize: Optional[Integer]
    OriginalIops: Optional[Integer]
    OriginalVolumeType: Optional[VolumeType]
    OriginalThroughput: Optional[Integer]
    OriginalMultiAttachEnabled: Optional[Boolean]
    Progress: Optional[Long]
    StartTime: Optional[DateTime]
    EndTime: Optional[DateTime]


VolumeModificationList = List[VolumeModification]


class DescribeVolumesModificationsResult(TypedDict, total=False):
    NextToken: Optional[String]
    VolumesModifications: Optional[VolumeModificationList]


class DescribeVolumesRequest(ServiceRequest):
    VolumeIds: Optional[VolumeIdStringList]
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    NextToken: Optional[String]
    MaxResults: Optional[Integer]


class VolumeAttachment(TypedDict, total=False):
    DeleteOnTermination: Optional[Boolean]
    AssociatedResource: Optional[String]
    InstanceOwningService: Optional[String]
    VolumeId: Optional[String]
    InstanceId: Optional[String]
    Device: Optional[String]
    State: Optional[VolumeAttachmentState]
    AttachTime: Optional[DateTime]


VolumeAttachmentList = List[VolumeAttachment]


class Volume(TypedDict, total=False):
    OutpostArn: Optional[String]
    Iops: Optional[Integer]
    Tags: Optional[TagList]
    VolumeType: Optional[VolumeType]
    FastRestored: Optional[Boolean]
    MultiAttachEnabled: Optional[Boolean]
    Throughput: Optional[Integer]
    SseType: Optional[SSEType]
    VolumeId: Optional[String]
    Size: Optional[Integer]
    SnapshotId: Optional[String]
    AvailabilityZone: Optional[String]
    State: Optional[VolumeState]
    CreateTime: Optional[DateTime]
    Attachments: Optional[VolumeAttachmentList]
    Encrypted: Optional[Boolean]
    KmsKeyId: Optional[String]


VolumeList = List[Volume]


class DescribeVolumesResult(TypedDict, total=False):
    NextToken: Optional[String]
    Volumes: Optional[VolumeList]


class DescribeVpcAttributeRequest(ServiceRequest):
    Attribute: VpcAttributeName
    VpcId: VpcId
    DryRun: Optional[Boolean]


class DescribeVpcAttributeResult(TypedDict, total=False):
    EnableDnsHostnames: Optional[AttributeBooleanValue]
    EnableDnsSupport: Optional[AttributeBooleanValue]
    EnableNetworkAddressUsageMetrics: Optional[AttributeBooleanValue]
    VpcId: Optional[String]


VpcClassicLinkIdList = List[VpcId]


class DescribeVpcClassicLinkDnsSupportRequest(ServiceRequest):
    VpcIds: Optional[VpcClassicLinkIdList]
    MaxResults: Optional[DescribeVpcClassicLinkDnsSupportMaxResults]
    NextToken: Optional[DescribeVpcClassicLinkDnsSupportNextToken]


class DescribeVpcClassicLinkDnsSupportResult(TypedDict, total=False):
    NextToken: Optional[DescribeVpcClassicLinkDnsSupportNextToken]
    Vpcs: Optional[ClassicLinkDnsSupportList]


class DescribeVpcClassicLinkRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    VpcIds: Optional[VpcClassicLinkIdList]
    Filters: Optional[FilterList]


class VpcClassicLink(TypedDict, total=False):
    ClassicLinkEnabled: Optional[Boolean]
    Tags: Optional[TagList]
    VpcId: Optional[String]


VpcClassicLinkList = List[VpcClassicLink]


class DescribeVpcClassicLinkResult(TypedDict, total=False):
    Vpcs: Optional[VpcClassicLinkList]


class DescribeVpcEndpointConnectionNotificationsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ConnectionNotificationId: Optional[ConnectionNotificationId]
    Filters: Optional[FilterList]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]


class DescribeVpcEndpointConnectionNotificationsResult(TypedDict, total=False):
    ConnectionNotificationSet: Optional[ConnectionNotificationSet]
    NextToken: Optional[String]


class DescribeVpcEndpointConnectionsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]


class VpcEndpointConnection(TypedDict, total=False):
    ServiceId: Optional[String]
    VpcEndpointId: Optional[String]
    VpcEndpointOwner: Optional[String]
    VpcEndpointState: Optional[State]
    CreationTimestamp: Optional[MillisecondDateTime]
    DnsEntries: Optional[DnsEntrySet]
    NetworkLoadBalancerArns: Optional[ValueStringList]
    GatewayLoadBalancerArns: Optional[ValueStringList]
    IpAddressType: Optional[IpAddressType]
    VpcEndpointConnectionId: Optional[String]
    Tags: Optional[TagList]


VpcEndpointConnectionSet = List[VpcEndpointConnection]


class DescribeVpcEndpointConnectionsResult(TypedDict, total=False):
    VpcEndpointConnections: Optional[VpcEndpointConnectionSet]
    NextToken: Optional[String]


class DescribeVpcEndpointServiceConfigurationsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ServiceIds: Optional[VpcEndpointServiceIdList]
    Filters: Optional[FilterList]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]


ServiceConfigurationSet = List[ServiceConfiguration]


class DescribeVpcEndpointServiceConfigurationsResult(TypedDict, total=False):
    ServiceConfigurations: Optional[ServiceConfigurationSet]
    NextToken: Optional[String]


class DescribeVpcEndpointServicePermissionsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ServiceId: VpcEndpointServiceId
    Filters: Optional[FilterList]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]


class DescribeVpcEndpointServicePermissionsResult(TypedDict, total=False):
    AllowedPrincipals: Optional[AllowedPrincipalSet]
    NextToken: Optional[String]


class DescribeVpcEndpointServicesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ServiceNames: Optional[ValueStringList]
    Filters: Optional[FilterList]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]


class PrivateDnsDetails(TypedDict, total=False):
    PrivateDnsName: Optional[String]


PrivateDnsDetailsSet = List[PrivateDnsDetails]


class ServiceDetail(TypedDict, total=False):
    ServiceName: Optional[String]
    ServiceId: Optional[String]
    ServiceType: Optional[ServiceTypeDetailSet]
    AvailabilityZones: Optional[ValueStringList]
    Owner: Optional[String]
    BaseEndpointDnsNames: Optional[ValueStringList]
    PrivateDnsName: Optional[String]
    PrivateDnsNames: Optional[PrivateDnsDetailsSet]
    VpcEndpointPolicySupported: Optional[Boolean]
    AcceptanceRequired: Optional[Boolean]
    ManagesVpcEndpoints: Optional[Boolean]
    PayerResponsibility: Optional[PayerResponsibility]
    Tags: Optional[TagList]
    PrivateDnsNameVerificationState: Optional[DnsNameState]
    SupportedIpAddressTypes: Optional[SupportedIpAddressTypes]


ServiceDetailSet = List[ServiceDetail]


class DescribeVpcEndpointServicesResult(TypedDict, total=False):
    ServiceNames: Optional[ValueStringList]
    ServiceDetails: Optional[ServiceDetailSet]
    NextToken: Optional[String]


class DescribeVpcEndpointsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    VpcEndpointIds: Optional[VpcEndpointIdList]
    Filters: Optional[FilterList]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]


VpcEndpointSet = List[VpcEndpoint]


class DescribeVpcEndpointsResult(TypedDict, total=False):
    VpcEndpoints: Optional[VpcEndpointSet]
    NextToken: Optional[String]


VpcPeeringConnectionIdList = List[VpcPeeringConnectionId]


class DescribeVpcPeeringConnectionsRequest(ServiceRequest):
    NextToken: Optional[String]
    MaxResults: Optional[DescribeVpcPeeringConnectionsMaxResults]
    DryRun: Optional[Boolean]
    VpcPeeringConnectionIds: Optional[VpcPeeringConnectionIdList]
    Filters: Optional[FilterList]


VpcPeeringConnectionList = List[VpcPeeringConnection]


class DescribeVpcPeeringConnectionsResult(TypedDict, total=False):
    VpcPeeringConnections: Optional[VpcPeeringConnectionList]
    NextToken: Optional[String]


VpcIdStringList = List[VpcId]


class DescribeVpcsRequest(ServiceRequest):
    Filters: Optional[FilterList]
    VpcIds: Optional[VpcIdStringList]
    NextToken: Optional[String]
    MaxResults: Optional[DescribeVpcsMaxResults]
    DryRun: Optional[Boolean]


VpcList = List[Vpc]


class DescribeVpcsResult(TypedDict, total=False):
    NextToken: Optional[String]
    Vpcs: Optional[VpcList]


VpnConnectionIdStringList = List[VpnConnectionId]


class DescribeVpnConnectionsRequest(ServiceRequest):
    Filters: Optional[FilterList]
    VpnConnectionIds: Optional[VpnConnectionIdStringList]
    DryRun: Optional[Boolean]


VpnConnectionList = List[VpnConnection]


class DescribeVpnConnectionsResult(TypedDict, total=False):
    VpnConnections: Optional[VpnConnectionList]


VpnGatewayIdStringList = List[VpnGatewayId]


class DescribeVpnGatewaysRequest(ServiceRequest):
    Filters: Optional[FilterList]
    VpnGatewayIds: Optional[VpnGatewayIdStringList]
    DryRun: Optional[Boolean]


VpnGatewayList = List[VpnGateway]


class DescribeVpnGatewaysResult(TypedDict, total=False):
    VpnGateways: Optional[VpnGatewayList]


class DetachClassicLinkVpcRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceId: InstanceId
    VpcId: VpcId


class DetachClassicLinkVpcResult(TypedDict, total=False):
    Return: Optional[Boolean]


class DetachInternetGatewayRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InternetGatewayId: InternetGatewayId
    VpcId: VpcId


class DetachNetworkInterfaceRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    AttachmentId: NetworkInterfaceAttachmentId
    Force: Optional[Boolean]


class DetachVerifiedAccessTrustProviderRequest(ServiceRequest):
    VerifiedAccessInstanceId: VerifiedAccessInstanceId
    VerifiedAccessTrustProviderId: VerifiedAccessTrustProviderId
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]


class DetachVerifiedAccessTrustProviderResult(TypedDict, total=False):
    VerifiedAccessTrustProvider: Optional[VerifiedAccessTrustProvider]
    VerifiedAccessInstance: Optional[VerifiedAccessInstance]


class DetachVolumeRequest(ServiceRequest):
    Device: Optional[String]
    Force: Optional[Boolean]
    InstanceId: Optional[InstanceIdForResolver]
    VolumeId: VolumeIdWithResolver
    DryRun: Optional[Boolean]


class DetachVpnGatewayRequest(ServiceRequest):
    VpcId: VpcId
    VpnGatewayId: VpnGatewayId
    DryRun: Optional[Boolean]


class DisableAddressTransferRequest(ServiceRequest):
    AllocationId: AllocationId
    DryRun: Optional[Boolean]


class DisableAddressTransferResult(TypedDict, total=False):
    AddressTransfer: Optional[AddressTransfer]


class DisableAwsNetworkPerformanceMetricSubscriptionRequest(ServiceRequest):
    Source: Optional[String]
    Destination: Optional[String]
    Metric: Optional[MetricType]
    Statistic: Optional[StatisticType]
    DryRun: Optional[Boolean]


class DisableAwsNetworkPerformanceMetricSubscriptionResult(TypedDict, total=False):
    Output: Optional[Boolean]


class DisableEbsEncryptionByDefaultRequest(ServiceRequest):
    DryRun: Optional[Boolean]


class DisableEbsEncryptionByDefaultResult(TypedDict, total=False):
    EbsEncryptionByDefault: Optional[Boolean]


class DisableFastLaunchRequest(ServiceRequest):
    ImageId: ImageId
    Force: Optional[Boolean]
    DryRun: Optional[Boolean]


class DisableFastLaunchResult(TypedDict, total=False):
    ImageId: Optional[ImageId]
    ResourceType: Optional[FastLaunchResourceType]
    SnapshotConfiguration: Optional[FastLaunchSnapshotConfigurationResponse]
    LaunchTemplate: Optional[FastLaunchLaunchTemplateSpecificationResponse]
    MaxParallelLaunches: Optional[Integer]
    OwnerId: Optional[String]
    State: Optional[FastLaunchStateCode]
    StateTransitionReason: Optional[String]
    StateTransitionTime: Optional[MillisecondDateTime]


class DisableFastSnapshotRestoreStateError(TypedDict, total=False):
    Code: Optional[String]
    Message: Optional[String]


class DisableFastSnapshotRestoreStateErrorItem(TypedDict, total=False):
    AvailabilityZone: Optional[String]
    Error: Optional[DisableFastSnapshotRestoreStateError]


DisableFastSnapshotRestoreStateErrorSet = List[DisableFastSnapshotRestoreStateErrorItem]


class DisableFastSnapshotRestoreErrorItem(TypedDict, total=False):
    SnapshotId: Optional[String]
    FastSnapshotRestoreStateErrors: Optional[DisableFastSnapshotRestoreStateErrorSet]


DisableFastSnapshotRestoreErrorSet = List[DisableFastSnapshotRestoreErrorItem]


class DisableFastSnapshotRestoreSuccessItem(TypedDict, total=False):
    SnapshotId: Optional[String]
    AvailabilityZone: Optional[String]
    State: Optional[FastSnapshotRestoreStateCode]
    StateTransitionReason: Optional[String]
    OwnerId: Optional[String]
    OwnerAlias: Optional[String]
    EnablingTime: Optional[MillisecondDateTime]
    OptimizingTime: Optional[MillisecondDateTime]
    EnabledTime: Optional[MillisecondDateTime]
    DisablingTime: Optional[MillisecondDateTime]
    DisabledTime: Optional[MillisecondDateTime]


DisableFastSnapshotRestoreSuccessSet = List[DisableFastSnapshotRestoreSuccessItem]


class DisableFastSnapshotRestoresRequest(ServiceRequest):
    AvailabilityZones: AvailabilityZoneStringList
    SourceSnapshotIds: SnapshotIdStringList
    DryRun: Optional[Boolean]


class DisableFastSnapshotRestoresResult(TypedDict, total=False):
    Successful: Optional[DisableFastSnapshotRestoreSuccessSet]
    Unsuccessful: Optional[DisableFastSnapshotRestoreErrorSet]


class DisableImageBlockPublicAccessRequest(ServiceRequest):
    DryRun: Optional[Boolean]


class DisableImageBlockPublicAccessResult(TypedDict, total=False):
    ImageBlockPublicAccessState: Optional[ImageBlockPublicAccessDisabledState]


class DisableImageDeprecationRequest(ServiceRequest):
    ImageId: ImageId
    DryRun: Optional[Boolean]


class DisableImageDeprecationResult(TypedDict, total=False):
    Return: Optional[Boolean]


class DisableImageDeregistrationProtectionRequest(ServiceRequest):
    ImageId: ImageId
    DryRun: Optional[Boolean]


class DisableImageDeregistrationProtectionResult(TypedDict, total=False):
    Return: Optional[String]


class DisableImageRequest(ServiceRequest):
    ImageId: ImageId
    DryRun: Optional[Boolean]


class DisableImageResult(TypedDict, total=False):
    Return: Optional[Boolean]


class DisableIpamOrganizationAdminAccountRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    DelegatedAdminAccountId: String


class DisableIpamOrganizationAdminAccountResult(TypedDict, total=False):
    Success: Optional[Boolean]


class DisableSerialConsoleAccessRequest(ServiceRequest):
    DryRun: Optional[Boolean]


class DisableSerialConsoleAccessResult(TypedDict, total=False):
    SerialConsoleAccessEnabled: Optional[Boolean]


class DisableSnapshotBlockPublicAccessRequest(ServiceRequest):
    DryRun: Optional[Boolean]


class DisableSnapshotBlockPublicAccessResult(TypedDict, total=False):
    State: Optional[SnapshotBlockPublicAccessState]


class DisableTransitGatewayRouteTablePropagationRequest(ServiceRequest):
    TransitGatewayRouteTableId: TransitGatewayRouteTableId
    TransitGatewayAttachmentId: Optional[TransitGatewayAttachmentId]
    DryRun: Optional[Boolean]
    TransitGatewayRouteTableAnnouncementId: Optional[TransitGatewayRouteTableAnnouncementId]


class TransitGatewayPropagation(TypedDict, total=False):
    TransitGatewayAttachmentId: Optional[TransitGatewayAttachmentId]
    ResourceId: Optional[String]
    ResourceType: Optional[TransitGatewayAttachmentResourceType]
    TransitGatewayRouteTableId: Optional[String]
    State: Optional[TransitGatewayPropagationState]
    TransitGatewayRouteTableAnnouncementId: Optional[TransitGatewayRouteTableAnnouncementId]


class DisableTransitGatewayRouteTablePropagationResult(TypedDict, total=False):
    Propagation: Optional[TransitGatewayPropagation]


class DisableVgwRoutePropagationRequest(ServiceRequest):
    GatewayId: VpnGatewayId
    RouteTableId: RouteTableId
    DryRun: Optional[Boolean]


class DisableVpcClassicLinkDnsSupportRequest(ServiceRequest):
    VpcId: Optional[VpcId]


class DisableVpcClassicLinkDnsSupportResult(TypedDict, total=False):
    Return: Optional[Boolean]


class DisableVpcClassicLinkRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    VpcId: VpcId


class DisableVpcClassicLinkResult(TypedDict, total=False):
    Return: Optional[Boolean]


class DisassociateAddressRequest(ServiceRequest):
    AssociationId: Optional[ElasticIpAssociationId]
    PublicIp: Optional[EipAllocationPublicIp]
    DryRun: Optional[Boolean]


class DisassociateCapacityReservationBillingOwnerRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    CapacityReservationId: CapacityReservationId
    UnusedReservationBillingOwnerId: AccountID


class DisassociateCapacityReservationBillingOwnerResult(TypedDict, total=False):
    Return: Optional[Boolean]


class DisassociateClientVpnTargetNetworkRequest(ServiceRequest):
    ClientVpnEndpointId: ClientVpnEndpointId
    AssociationId: String
    DryRun: Optional[Boolean]


class DisassociateClientVpnTargetNetworkResult(TypedDict, total=False):
    AssociationId: Optional[String]
    Status: Optional[AssociationStatus]


class DisassociateEnclaveCertificateIamRoleRequest(ServiceRequest):
    CertificateArn: CertificateId
    RoleArn: RoleId
    DryRun: Optional[Boolean]


class DisassociateEnclaveCertificateIamRoleResult(TypedDict, total=False):
    Return: Optional[Boolean]


class DisassociateIamInstanceProfileRequest(ServiceRequest):
    AssociationId: IamInstanceProfileAssociationId


class DisassociateIamInstanceProfileResult(TypedDict, total=False):
    IamInstanceProfileAssociation: Optional[IamInstanceProfileAssociation]


class InstanceEventWindowDisassociationRequest(TypedDict, total=False):
    InstanceIds: Optional[InstanceIdList]
    InstanceTags: Optional[TagList]
    DedicatedHostIds: Optional[DedicatedHostIdList]


class DisassociateInstanceEventWindowRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceEventWindowId: InstanceEventWindowId
    AssociationTarget: InstanceEventWindowDisassociationRequest


class DisassociateInstanceEventWindowResult(TypedDict, total=False):
    InstanceEventWindow: Optional[InstanceEventWindow]


class DisassociateIpamByoasnRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Asn: String
    Cidr: String


class DisassociateIpamByoasnResult(TypedDict, total=False):
    AsnAssociation: Optional[AsnAssociation]


class DisassociateIpamResourceDiscoveryRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamResourceDiscoveryAssociationId: IpamResourceDiscoveryAssociationId


class DisassociateIpamResourceDiscoveryResult(TypedDict, total=False):
    IpamResourceDiscoveryAssociation: Optional[IpamResourceDiscoveryAssociation]


EipAssociationIdList = List[ElasticIpAssociationId]


class DisassociateNatGatewayAddressRequest(ServiceRequest):
    NatGatewayId: NatGatewayId
    AssociationIds: EipAssociationIdList
    MaxDrainDurationSeconds: Optional[DrainSeconds]
    DryRun: Optional[Boolean]


class DisassociateNatGatewayAddressResult(TypedDict, total=False):
    NatGatewayId: Optional[NatGatewayId]
    NatGatewayAddresses: Optional[NatGatewayAddressList]


class DisassociateRouteTableRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    AssociationId: RouteTableAssociationId


class DisassociateSecurityGroupVpcRequest(ServiceRequest):
    GroupId: DisassociateSecurityGroupVpcSecurityGroupId
    VpcId: String
    DryRun: Optional[Boolean]


class DisassociateSecurityGroupVpcResult(TypedDict, total=False):
    State: Optional[SecurityGroupVpcAssociationState]


class DisassociateSubnetCidrBlockRequest(ServiceRequest):
    AssociationId: SubnetCidrAssociationId


class DisassociateSubnetCidrBlockResult(TypedDict, total=False):
    Ipv6CidrBlockAssociation: Optional[SubnetIpv6CidrBlockAssociation]
    SubnetId: Optional[String]


class DisassociateTransitGatewayMulticastDomainRequest(ServiceRequest):
    TransitGatewayMulticastDomainId: TransitGatewayMulticastDomainId
    TransitGatewayAttachmentId: TransitGatewayAttachmentId
    SubnetIds: TransitGatewaySubnetIdList
    DryRun: Optional[Boolean]


class DisassociateTransitGatewayMulticastDomainResult(TypedDict, total=False):
    Associations: Optional[TransitGatewayMulticastDomainAssociations]


class DisassociateTransitGatewayPolicyTableRequest(ServiceRequest):
    TransitGatewayPolicyTableId: TransitGatewayPolicyTableId
    TransitGatewayAttachmentId: TransitGatewayAttachmentId
    DryRun: Optional[Boolean]


class DisassociateTransitGatewayPolicyTableResult(TypedDict, total=False):
    Association: Optional[TransitGatewayPolicyTableAssociation]


class DisassociateTransitGatewayRouteTableRequest(ServiceRequest):
    TransitGatewayRouteTableId: TransitGatewayRouteTableId
    TransitGatewayAttachmentId: TransitGatewayAttachmentId
    DryRun: Optional[Boolean]


class DisassociateTransitGatewayRouteTableResult(TypedDict, total=False):
    Association: Optional[TransitGatewayAssociation]


class DisassociateTrunkInterfaceRequest(ServiceRequest):
    AssociationId: TrunkInterfaceAssociationId
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]


class DisassociateTrunkInterfaceResult(TypedDict, total=False):
    Return: Optional[Boolean]
    ClientToken: Optional[String]


class DisassociateVpcCidrBlockRequest(ServiceRequest):
    AssociationId: VpcCidrAssociationId


class DisassociateVpcCidrBlockResult(TypedDict, total=False):
    Ipv6CidrBlockAssociation: Optional[VpcIpv6CidrBlockAssociation]
    CidrBlockAssociation: Optional[VpcCidrBlockAssociation]
    VpcId: Optional[String]


class VolumeDetail(TypedDict, total=False):
    Size: Long


class DiskImageDetail(TypedDict, total=False):
    Format: DiskImageFormat
    Bytes: Long
    ImportManifestUrl: ImportManifestUrl


class DiskImage(TypedDict, total=False):
    Description: Optional[String]
    Image: Optional[DiskImageDetail]
    Volume: Optional[VolumeDetail]


DiskImageList = List[DiskImage]


class DnsServersOptionsModifyStructure(TypedDict, total=False):
    CustomDnsServers: Optional[ValueStringList]
    Enabled: Optional[Boolean]


class EbsInstanceBlockDeviceSpecification(TypedDict, total=False):
    VolumeId: Optional[VolumeId]
    DeleteOnTermination: Optional[Boolean]


ElasticGpuSpecifications = List[ElasticGpuSpecification]


class ElasticInferenceAccelerator(TypedDict, total=False):
    Type: String
    Count: Optional[ElasticInferenceAcceleratorCount]


ElasticInferenceAccelerators = List[ElasticInferenceAccelerator]


class EnableAddressTransferRequest(ServiceRequest):
    AllocationId: AllocationId
    TransferAccountId: String
    DryRun: Optional[Boolean]


class EnableAddressTransferResult(TypedDict, total=False):
    AddressTransfer: Optional[AddressTransfer]


class EnableAwsNetworkPerformanceMetricSubscriptionRequest(ServiceRequest):
    Source: Optional[String]
    Destination: Optional[String]
    Metric: Optional[MetricType]
    Statistic: Optional[StatisticType]
    DryRun: Optional[Boolean]


class EnableAwsNetworkPerformanceMetricSubscriptionResult(TypedDict, total=False):
    Output: Optional[Boolean]


class EnableEbsEncryptionByDefaultRequest(ServiceRequest):
    DryRun: Optional[Boolean]


class EnableEbsEncryptionByDefaultResult(TypedDict, total=False):
    EbsEncryptionByDefault: Optional[Boolean]


class FastLaunchLaunchTemplateSpecificationRequest(TypedDict, total=False):
    LaunchTemplateId: Optional[LaunchTemplateId]
    LaunchTemplateName: Optional[String]
    Version: String


class FastLaunchSnapshotConfigurationRequest(TypedDict, total=False):
    TargetResourceCount: Optional[Integer]


class EnableFastLaunchRequest(ServiceRequest):
    ImageId: ImageId
    ResourceType: Optional[String]
    SnapshotConfiguration: Optional[FastLaunchSnapshotConfigurationRequest]
    LaunchTemplate: Optional[FastLaunchLaunchTemplateSpecificationRequest]
    MaxParallelLaunches: Optional[Integer]
    DryRun: Optional[Boolean]


class EnableFastLaunchResult(TypedDict, total=False):
    ImageId: Optional[ImageId]
    ResourceType: Optional[FastLaunchResourceType]
    SnapshotConfiguration: Optional[FastLaunchSnapshotConfigurationResponse]
    LaunchTemplate: Optional[FastLaunchLaunchTemplateSpecificationResponse]
    MaxParallelLaunches: Optional[Integer]
    OwnerId: Optional[String]
    State: Optional[FastLaunchStateCode]
    StateTransitionReason: Optional[String]
    StateTransitionTime: Optional[MillisecondDateTime]


class EnableFastSnapshotRestoreStateError(TypedDict, total=False):
    Code: Optional[String]
    Message: Optional[String]


class EnableFastSnapshotRestoreStateErrorItem(TypedDict, total=False):
    AvailabilityZone: Optional[String]
    Error: Optional[EnableFastSnapshotRestoreStateError]


EnableFastSnapshotRestoreStateErrorSet = List[EnableFastSnapshotRestoreStateErrorItem]


class EnableFastSnapshotRestoreErrorItem(TypedDict, total=False):
    SnapshotId: Optional[String]
    FastSnapshotRestoreStateErrors: Optional[EnableFastSnapshotRestoreStateErrorSet]


EnableFastSnapshotRestoreErrorSet = List[EnableFastSnapshotRestoreErrorItem]


class EnableFastSnapshotRestoreSuccessItem(TypedDict, total=False):
    SnapshotId: Optional[String]
    AvailabilityZone: Optional[String]
    State: Optional[FastSnapshotRestoreStateCode]
    StateTransitionReason: Optional[String]
    OwnerId: Optional[String]
    OwnerAlias: Optional[String]
    EnablingTime: Optional[MillisecondDateTime]
    OptimizingTime: Optional[MillisecondDateTime]
    EnabledTime: Optional[MillisecondDateTime]
    DisablingTime: Optional[MillisecondDateTime]
    DisabledTime: Optional[MillisecondDateTime]


EnableFastSnapshotRestoreSuccessSet = List[EnableFastSnapshotRestoreSuccessItem]


class EnableFastSnapshotRestoresRequest(ServiceRequest):
    AvailabilityZones: AvailabilityZoneStringList
    SourceSnapshotIds: SnapshotIdStringList
    DryRun: Optional[Boolean]


class EnableFastSnapshotRestoresResult(TypedDict, total=False):
    Successful: Optional[EnableFastSnapshotRestoreSuccessSet]
    Unsuccessful: Optional[EnableFastSnapshotRestoreErrorSet]


class EnableImageBlockPublicAccessRequest(ServiceRequest):
    ImageBlockPublicAccessState: ImageBlockPublicAccessEnabledState
    DryRun: Optional[Boolean]


class EnableImageBlockPublicAccessResult(TypedDict, total=False):
    ImageBlockPublicAccessState: Optional[ImageBlockPublicAccessEnabledState]


class EnableImageDeprecationRequest(ServiceRequest):
    ImageId: ImageId
    DeprecateAt: MillisecondDateTime
    DryRun: Optional[Boolean]


class EnableImageDeprecationResult(TypedDict, total=False):
    Return: Optional[Boolean]


class EnableImageDeregistrationProtectionRequest(ServiceRequest):
    ImageId: ImageId
    WithCooldown: Optional[Boolean]
    DryRun: Optional[Boolean]


class EnableImageDeregistrationProtectionResult(TypedDict, total=False):
    Return: Optional[String]


class EnableImageRequest(ServiceRequest):
    ImageId: ImageId
    DryRun: Optional[Boolean]


class EnableImageResult(TypedDict, total=False):
    Return: Optional[Boolean]


class EnableIpamOrganizationAdminAccountRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    DelegatedAdminAccountId: String


class EnableIpamOrganizationAdminAccountResult(TypedDict, total=False):
    Success: Optional[Boolean]


class EnableReachabilityAnalyzerOrganizationSharingRequest(ServiceRequest):
    DryRun: Optional[Boolean]


class EnableReachabilityAnalyzerOrganizationSharingResult(TypedDict, total=False):
    ReturnValue: Optional[Boolean]


class EnableSerialConsoleAccessRequest(ServiceRequest):
    DryRun: Optional[Boolean]


class EnableSerialConsoleAccessResult(TypedDict, total=False):
    SerialConsoleAccessEnabled: Optional[Boolean]


class EnableSnapshotBlockPublicAccessRequest(ServiceRequest):
    State: SnapshotBlockPublicAccessState
    DryRun: Optional[Boolean]


class EnableSnapshotBlockPublicAccessResult(TypedDict, total=False):
    State: Optional[SnapshotBlockPublicAccessState]


class EnableTransitGatewayRouteTablePropagationRequest(ServiceRequest):
    TransitGatewayRouteTableId: TransitGatewayRouteTableId
    TransitGatewayAttachmentId: Optional[TransitGatewayAttachmentId]
    DryRun: Optional[Boolean]
    TransitGatewayRouteTableAnnouncementId: Optional[TransitGatewayRouteTableAnnouncementId]


class EnableTransitGatewayRouteTablePropagationResult(TypedDict, total=False):
    Propagation: Optional[TransitGatewayPropagation]


class EnableVgwRoutePropagationRequest(ServiceRequest):
    GatewayId: VpnGatewayId
    RouteTableId: RouteTableId
    DryRun: Optional[Boolean]


class EnableVolumeIORequest(ServiceRequest):
    DryRun: Optional[Boolean]
    VolumeId: VolumeId


class EnableVpcClassicLinkDnsSupportRequest(ServiceRequest):
    VpcId: Optional[VpcId]


class EnableVpcClassicLinkDnsSupportResult(TypedDict, total=False):
    Return: Optional[Boolean]


class EnableVpcClassicLinkRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    VpcId: VpcId


class EnableVpcClassicLinkResult(TypedDict, total=False):
    Return: Optional[Boolean]


class EnclaveOptionsRequest(TypedDict, total=False):
    Enabled: Optional[Boolean]


class ExportClientVpnClientCertificateRevocationListRequest(ServiceRequest):
    ClientVpnEndpointId: ClientVpnEndpointId
    DryRun: Optional[Boolean]


class ExportClientVpnClientCertificateRevocationListResult(TypedDict, total=False):
    CertificateRevocationList: Optional[String]
    Status: Optional[ClientCertificateRevocationListStatus]


class ExportClientVpnClientConfigurationRequest(ServiceRequest):
    ClientVpnEndpointId: ClientVpnEndpointId
    DryRun: Optional[Boolean]


class ExportClientVpnClientConfigurationResult(TypedDict, total=False):
    ClientConfiguration: Optional[String]


class ExportTaskS3LocationRequest(TypedDict, total=False):
    S3Bucket: String
    S3Prefix: Optional[String]


class ExportImageRequest(ServiceRequest):
    ClientToken: Optional[String]
    Description: Optional[String]
    DiskImageFormat: DiskImageFormat
    DryRun: Optional[Boolean]
    ImageId: ImageId
    S3ExportLocation: ExportTaskS3LocationRequest
    RoleName: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]


class ExportImageResult(TypedDict, total=False):
    Description: Optional[String]
    DiskImageFormat: Optional[DiskImageFormat]
    ExportImageTaskId: Optional[String]
    ImageId: Optional[String]
    RoleName: Optional[String]
    Progress: Optional[String]
    S3ExportLocation: Optional[ExportTaskS3Location]
    Status: Optional[String]
    StatusMessage: Optional[String]
    Tags: Optional[TagList]


class ExportTransitGatewayRoutesRequest(ServiceRequest):
    TransitGatewayRouteTableId: TransitGatewayRouteTableId
    Filters: Optional[FilterList]
    S3Bucket: String
    DryRun: Optional[Boolean]


class ExportTransitGatewayRoutesResult(TypedDict, total=False):
    S3Location: Optional[String]


class GetAssociatedEnclaveCertificateIamRolesRequest(ServiceRequest):
    CertificateArn: CertificateId
    DryRun: Optional[Boolean]


class GetAssociatedEnclaveCertificateIamRolesResult(TypedDict, total=False):
    AssociatedRoles: Optional[AssociatedRolesList]


class GetAssociatedIpv6PoolCidrsRequest(ServiceRequest):
    PoolId: Ipv6PoolEc2Id
    NextToken: Optional[NextToken]
    MaxResults: Optional[Ipv6PoolMaxResults]
    DryRun: Optional[Boolean]


class Ipv6CidrAssociation(TypedDict, total=False):
    Ipv6Cidr: Optional[String]
    AssociatedResource: Optional[String]


Ipv6CidrAssociationSet = List[Ipv6CidrAssociation]


class GetAssociatedIpv6PoolCidrsResult(TypedDict, total=False):
    Ipv6CidrAssociations: Optional[Ipv6CidrAssociationSet]
    NextToken: Optional[String]


class GetAwsNetworkPerformanceDataRequest(ServiceRequest):
    DataQueries: Optional[DataQueries]
    StartTime: Optional[MillisecondDateTime]
    EndTime: Optional[MillisecondDateTime]
    MaxResults: Optional[Integer]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


class GetAwsNetworkPerformanceDataResult(TypedDict, total=False):
    DataResponses: Optional[DataResponses]
    NextToken: Optional[String]


class GetCapacityReservationUsageRequest(ServiceRequest):
    CapacityReservationId: CapacityReservationId
    NextToken: Optional[String]
    MaxResults: Optional[GetCapacityReservationUsageRequestMaxResults]
    DryRun: Optional[Boolean]


class InstanceUsage(TypedDict, total=False):
    AccountId: Optional[String]
    UsedInstanceCount: Optional[Integer]


InstanceUsageSet = List[InstanceUsage]


class GetCapacityReservationUsageResult(TypedDict, total=False):
    NextToken: Optional[String]
    CapacityReservationId: Optional[String]
    InstanceType: Optional[String]
    TotalInstanceCount: Optional[Integer]
    AvailableInstanceCount: Optional[Integer]
    State: Optional[CapacityReservationState]
    InstanceUsages: Optional[InstanceUsageSet]


class GetCoipPoolUsageRequest(ServiceRequest):
    PoolId: Ipv4PoolCoipId
    Filters: Optional[FilterList]
    MaxResults: Optional[CoipPoolMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


class GetCoipPoolUsageResult(TypedDict, total=False):
    CoipPoolId: Optional[String]
    CoipAddressUsages: Optional[CoipAddressUsageSet]
    LocalGatewayRouteTableId: Optional[String]
    NextToken: Optional[String]


class GetConsoleOutputRequest(ServiceRequest):
    InstanceId: InstanceId
    Latest: Optional[Boolean]
    DryRun: Optional[Boolean]


class GetConsoleOutputResult(TypedDict, total=False):
    InstanceId: Optional[String]
    Timestamp: Optional[DateTime]
    Output: Optional[String]


class GetConsoleScreenshotRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceId: InstanceId
    WakeUp: Optional[Boolean]


class GetConsoleScreenshotResult(TypedDict, total=False):
    ImageData: Optional[String]
    InstanceId: Optional[String]


class GetDefaultCreditSpecificationRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceFamily: UnlimitedSupportedInstanceFamily


class InstanceFamilyCreditSpecification(TypedDict, total=False):
    InstanceFamily: Optional[UnlimitedSupportedInstanceFamily]
    CpuCredits: Optional[String]


class GetDefaultCreditSpecificationResult(TypedDict, total=False):
    InstanceFamilyCreditSpecification: Optional[InstanceFamilyCreditSpecification]


class GetEbsDefaultKmsKeyIdRequest(ServiceRequest):
    DryRun: Optional[Boolean]


class GetEbsDefaultKmsKeyIdResult(TypedDict, total=False):
    KmsKeyId: Optional[String]


class GetEbsEncryptionByDefaultRequest(ServiceRequest):
    DryRun: Optional[Boolean]


class GetEbsEncryptionByDefaultResult(TypedDict, total=False):
    EbsEncryptionByDefault: Optional[Boolean]
    SseType: Optional[SSEType]


class IntegrateServices(TypedDict, total=False):
    AthenaIntegrations: Optional[AthenaIntegrationsSet]


class GetFlowLogsIntegrationTemplateRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    FlowLogId: VpcFlowLogId
    ConfigDeliveryS3DestinationArn: String
    IntegrateServices: IntegrateServices


class GetFlowLogsIntegrationTemplateResult(TypedDict, total=False):
    Result: Optional[String]


class GetGroupsForCapacityReservationRequest(ServiceRequest):
    CapacityReservationId: CapacityReservationId
    NextToken: Optional[String]
    MaxResults: Optional[GetGroupsForCapacityReservationRequestMaxResults]
    DryRun: Optional[Boolean]


class GetGroupsForCapacityReservationResult(TypedDict, total=False):
    NextToken: Optional[String]
    CapacityReservationGroups: Optional[CapacityReservationGroupSet]


RequestHostIdSet = List[DedicatedHostId]


class GetHostReservationPurchasePreviewRequest(ServiceRequest):
    HostIdSet: RequestHostIdSet
    OfferingId: OfferingId


class Purchase(TypedDict, total=False):
    CurrencyCode: Optional[CurrencyCodeValues]
    Duration: Optional[Integer]
    HostIdSet: Optional[ResponseHostIdSet]
    HostReservationId: Optional[HostReservationId]
    HourlyPrice: Optional[String]
    InstanceFamily: Optional[String]
    PaymentOption: Optional[PaymentOption]
    UpfrontPrice: Optional[String]


PurchaseSet = List[Purchase]


class GetHostReservationPurchasePreviewResult(TypedDict, total=False):
    CurrencyCode: Optional[CurrencyCodeValues]
    Purchase: Optional[PurchaseSet]
    TotalHourlyPrice: Optional[String]
    TotalUpfrontPrice: Optional[String]


class GetImageBlockPublicAccessStateRequest(ServiceRequest):
    DryRun: Optional[Boolean]


class GetImageBlockPublicAccessStateResult(TypedDict, total=False):
    ImageBlockPublicAccessState: Optional[String]


class GetInstanceMetadataDefaultsRequest(ServiceRequest):
    DryRun: Optional[Boolean]


class InstanceMetadataDefaultsResponse(TypedDict, total=False):
    HttpTokens: Optional[HttpTokensState]
    HttpPutResponseHopLimit: Optional[BoxedInteger]
    HttpEndpoint: Optional[InstanceMetadataEndpointState]
    InstanceMetadataTags: Optional[InstanceMetadataTagsState]


class GetInstanceMetadataDefaultsResult(TypedDict, total=False):
    AccountLevel: Optional[InstanceMetadataDefaultsResponse]


class GetInstanceTpmEkPubRequest(ServiceRequest):
    InstanceId: InstanceId
    KeyType: EkPubKeyType
    KeyFormat: EkPubKeyFormat
    DryRun: Optional[Boolean]


class GetInstanceTpmEkPubResult(TypedDict, total=False):
    InstanceId: Optional[InstanceId]
    KeyType: Optional[EkPubKeyType]
    KeyFormat: Optional[EkPubKeyFormat]
    KeyValue: Optional[EkPubKeyValue]


VirtualizationTypeSet = List[VirtualizationType]


class GetInstanceTypesFromInstanceRequirementsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ArchitectureTypes: ArchitectureTypeSet
    VirtualizationTypes: VirtualizationTypeSet
    InstanceRequirements: InstanceRequirementsRequest
    MaxResults: Optional[Integer]
    NextToken: Optional[String]


class InstanceTypeInfoFromInstanceRequirements(TypedDict, total=False):
    InstanceType: Optional[String]


InstanceTypeInfoFromInstanceRequirementsSet = List[InstanceTypeInfoFromInstanceRequirements]


class GetInstanceTypesFromInstanceRequirementsResult(TypedDict, total=False):
    InstanceTypes: Optional[InstanceTypeInfoFromInstanceRequirementsSet]
    NextToken: Optional[String]


class GetInstanceUefiDataRequest(ServiceRequest):
    InstanceId: InstanceId
    DryRun: Optional[Boolean]


class GetInstanceUefiDataResult(TypedDict, total=False):
    InstanceId: Optional[InstanceId]
    UefiData: Optional[String]


class GetIpamAddressHistoryRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Cidr: String
    IpamScopeId: IpamScopeId
    VpcId: Optional[String]
    StartTime: Optional[MillisecondDateTime]
    EndTime: Optional[MillisecondDateTime]
    MaxResults: Optional[IpamAddressHistoryMaxResults]
    NextToken: Optional[NextToken]


class IpamAddressHistoryRecord(TypedDict, total=False):
    ResourceOwnerId: Optional[String]
    ResourceRegion: Optional[String]
    ResourceType: Optional[IpamAddressHistoryResourceType]
    ResourceId: Optional[String]
    ResourceCidr: Optional[String]
    ResourceName: Optional[String]
    ResourceComplianceStatus: Optional[IpamComplianceStatus]
    ResourceOverlapStatus: Optional[IpamOverlapStatus]
    VpcId: Optional[String]
    SampledStartTime: Optional[MillisecondDateTime]
    SampledEndTime: Optional[MillisecondDateTime]


IpamAddressHistoryRecordSet = List[IpamAddressHistoryRecord]


class GetIpamAddressHistoryResult(TypedDict, total=False):
    HistoryRecords: Optional[IpamAddressHistoryRecordSet]
    NextToken: Optional[NextToken]


class GetIpamDiscoveredAccountsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamResourceDiscoveryId: IpamResourceDiscoveryId
    DiscoveryRegion: String
    Filters: Optional[FilterList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[IpamMaxResults]


class IpamDiscoveryFailureReason(TypedDict, total=False):
    Code: Optional[IpamDiscoveryFailureCode]
    Message: Optional[String]


class IpamDiscoveredAccount(TypedDict, total=False):
    AccountId: Optional[String]
    DiscoveryRegion: Optional[String]
    FailureReason: Optional[IpamDiscoveryFailureReason]
    LastAttemptedDiscoveryTime: Optional[MillisecondDateTime]
    LastSuccessfulDiscoveryTime: Optional[MillisecondDateTime]


IpamDiscoveredAccountSet = List[IpamDiscoveredAccount]


class GetIpamDiscoveredAccountsResult(TypedDict, total=False):
    IpamDiscoveredAccounts: Optional[IpamDiscoveredAccountSet]
    NextToken: Optional[NextToken]


class GetIpamDiscoveredPublicAddressesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamResourceDiscoveryId: IpamResourceDiscoveryId
    AddressRegion: String
    Filters: Optional[FilterList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[IpamMaxResults]


class IpamPublicAddressSecurityGroup(TypedDict, total=False):
    GroupName: Optional[String]
    GroupId: Optional[String]


IpamPublicAddressSecurityGroupList = List[IpamPublicAddressSecurityGroup]


class IpamPublicAddressTag(TypedDict, total=False):
    Key: Optional[String]
    Value: Optional[String]


IpamPublicAddressTagList = List[IpamPublicAddressTag]


class IpamPublicAddressTags(TypedDict, total=False):
    EipTags: Optional[IpamPublicAddressTagList]


class IpamDiscoveredPublicAddress(TypedDict, total=False):
    IpamResourceDiscoveryId: Optional[IpamResourceDiscoveryId]
    AddressRegion: Optional[String]
    Address: Optional[String]
    AddressOwnerId: Optional[String]
    AddressAllocationId: Optional[String]
    AssociationStatus: Optional[IpamPublicAddressAssociationStatus]
    AddressType: Optional[IpamPublicAddressType]
    Service: Optional[IpamPublicAddressAwsService]
    ServiceResource: Optional[String]
    VpcId: Optional[String]
    SubnetId: Optional[String]
    PublicIpv4PoolId: Optional[String]
    NetworkInterfaceId: Optional[String]
    NetworkInterfaceDescription: Optional[String]
    InstanceId: Optional[String]
    Tags: Optional[IpamPublicAddressTags]
    NetworkBorderGroup: Optional[String]
    SecurityGroups: Optional[IpamPublicAddressSecurityGroupList]
    SampleTime: Optional[MillisecondDateTime]


IpamDiscoveredPublicAddressSet = List[IpamDiscoveredPublicAddress]


class GetIpamDiscoveredPublicAddressesResult(TypedDict, total=False):
    IpamDiscoveredPublicAddresses: Optional[IpamDiscoveredPublicAddressSet]
    OldestSampleTime: Optional[MillisecondDateTime]
    NextToken: Optional[NextToken]


class GetIpamDiscoveredResourceCidrsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamResourceDiscoveryId: IpamResourceDiscoveryId
    ResourceRegion: String
    Filters: Optional[FilterList]
    NextToken: Optional[NextToken]
    MaxResults: Optional[IpamMaxResults]


class IpamDiscoveredResourceCidr(TypedDict, total=False):
    IpamResourceDiscoveryId: Optional[IpamResourceDiscoveryId]
    ResourceRegion: Optional[String]
    ResourceId: Optional[String]
    ResourceOwnerId: Optional[String]
    ResourceCidr: Optional[String]
    IpSource: Optional[IpamResourceCidrIpSource]
    ResourceType: Optional[IpamResourceType]
    ResourceTags: Optional[IpamResourceTagList]
    IpUsage: Optional[BoxedDouble]
    VpcId: Optional[String]
    SubnetId: Optional[String]
    NetworkInterfaceAttachmentStatus: Optional[IpamNetworkInterfaceAttachmentStatus]
    SampleTime: Optional[MillisecondDateTime]
    AvailabilityZoneId: Optional[String]


IpamDiscoveredResourceCidrSet = List[IpamDiscoveredResourceCidr]


class GetIpamDiscoveredResourceCidrsResult(TypedDict, total=False):
    IpamDiscoveredResourceCidrs: Optional[IpamDiscoveredResourceCidrSet]
    NextToken: Optional[NextToken]


class GetIpamPoolAllocationsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamPoolId: IpamPoolId
    IpamPoolAllocationId: Optional[IpamPoolAllocationId]
    Filters: Optional[FilterList]
    MaxResults: Optional[GetIpamPoolAllocationsMaxResults]
    NextToken: Optional[NextToken]


IpamPoolAllocationSet = List[IpamPoolAllocation]


class GetIpamPoolAllocationsResult(TypedDict, total=False):
    IpamPoolAllocations: Optional[IpamPoolAllocationSet]
    NextToken: Optional[NextToken]


class GetIpamPoolCidrsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamPoolId: IpamPoolId
    Filters: Optional[FilterList]
    MaxResults: Optional[IpamMaxResults]
    NextToken: Optional[NextToken]


IpamPoolCidrSet = List[IpamPoolCidr]


class GetIpamPoolCidrsResult(TypedDict, total=False):
    IpamPoolCidrs: Optional[IpamPoolCidrSet]
    NextToken: Optional[NextToken]


class GetIpamResourceCidrsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Filters: Optional[FilterList]
    MaxResults: Optional[IpamMaxResults]
    NextToken: Optional[NextToken]
    IpamScopeId: IpamScopeId
    IpamPoolId: Optional[IpamPoolId]
    ResourceId: Optional[String]
    ResourceType: Optional[IpamResourceType]
    ResourceTag: Optional[RequestIpamResourceTag]
    ResourceOwner: Optional[String]


class IpamResourceCidr(TypedDict, total=False):
    IpamId: Optional[IpamId]
    IpamScopeId: Optional[IpamScopeId]
    IpamPoolId: Optional[IpamPoolId]
    ResourceRegion: Optional[String]
    ResourceOwnerId: Optional[String]
    ResourceId: Optional[String]
    ResourceName: Optional[String]
    ResourceCidr: Optional[String]
    ResourceType: Optional[IpamResourceType]
    ResourceTags: Optional[IpamResourceTagList]
    IpUsage: Optional[BoxedDouble]
    ComplianceStatus: Optional[IpamComplianceStatus]
    ManagementState: Optional[IpamManagementState]
    OverlapStatus: Optional[IpamOverlapStatus]
    VpcId: Optional[String]
    AvailabilityZoneId: Optional[String]


IpamResourceCidrSet = List[IpamResourceCidr]


class GetIpamResourceCidrsResult(TypedDict, total=False):
    NextToken: Optional[NextToken]
    IpamResourceCidrs: Optional[IpamResourceCidrSet]


class GetLaunchTemplateDataRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceId: InstanceId


class GetLaunchTemplateDataResult(TypedDict, total=False):
    LaunchTemplateData: Optional[ResponseLaunchTemplateData]


class GetManagedPrefixListAssociationsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    PrefixListId: PrefixListResourceId
    MaxResults: Optional[GetManagedPrefixListAssociationsMaxResults]
    NextToken: Optional[NextToken]


class PrefixListAssociation(TypedDict, total=False):
    ResourceId: Optional[String]
    ResourceOwner: Optional[String]


PrefixListAssociationSet = List[PrefixListAssociation]


class GetManagedPrefixListAssociationsResult(TypedDict, total=False):
    PrefixListAssociations: Optional[PrefixListAssociationSet]
    NextToken: Optional[String]


class GetManagedPrefixListEntriesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    PrefixListId: PrefixListResourceId
    TargetVersion: Optional[Long]
    MaxResults: Optional[PrefixListMaxResults]
    NextToken: Optional[NextToken]


class PrefixListEntry(TypedDict, total=False):
    Cidr: Optional[String]
    Description: Optional[String]


PrefixListEntrySet = List[PrefixListEntry]


class GetManagedPrefixListEntriesResult(TypedDict, total=False):
    Entries: Optional[PrefixListEntrySet]
    NextToken: Optional[NextToken]


class GetNetworkInsightsAccessScopeAnalysisFindingsRequest(ServiceRequest):
    NetworkInsightsAccessScopeAnalysisId: NetworkInsightsAccessScopeAnalysisId
    MaxResults: Optional[GetNetworkInsightsAccessScopeAnalysisFindingsMaxResults]
    NextToken: Optional[NextToken]
    DryRun: Optional[Boolean]


class GetNetworkInsightsAccessScopeAnalysisFindingsResult(TypedDict, total=False):
    NetworkInsightsAccessScopeAnalysisId: Optional[NetworkInsightsAccessScopeAnalysisId]
    AnalysisStatus: Optional[AnalysisStatus]
    AnalysisFindings: Optional[AccessScopeAnalysisFindingList]
    NextToken: Optional[String]


class GetNetworkInsightsAccessScopeContentRequest(ServiceRequest):
    NetworkInsightsAccessScopeId: NetworkInsightsAccessScopeId
    DryRun: Optional[Boolean]


class GetNetworkInsightsAccessScopeContentResult(TypedDict, total=False):
    NetworkInsightsAccessScopeContent: Optional[NetworkInsightsAccessScopeContent]


class GetPasswordDataRequest(ServiceRequest):
    InstanceId: InstanceId
    DryRun: Optional[Boolean]


class GetPasswordDataResult(TypedDict, total=False):
    InstanceId: Optional[String]
    Timestamp: Optional[DateTime]
    PasswordData: Optional[PasswordData]


class GetReservedInstancesExchangeQuoteRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ReservedInstanceIds: ReservedInstanceIdSet
    TargetConfigurations: Optional[TargetConfigurationRequestSet]


class TargetConfiguration(TypedDict, total=False):
    InstanceCount: Optional[Integer]
    OfferingId: Optional[String]


class ReservationValue(TypedDict, total=False):
    HourlyPrice: Optional[String]
    RemainingTotalValue: Optional[String]
    RemainingUpfrontValue: Optional[String]


class TargetReservationValue(TypedDict, total=False):
    ReservationValue: Optional[ReservationValue]
    TargetConfiguration: Optional[TargetConfiguration]


TargetReservationValueSet = List[TargetReservationValue]


class ReservedInstanceReservationValue(TypedDict, total=False):
    ReservationValue: Optional[ReservationValue]
    ReservedInstanceId: Optional[String]


ReservedInstanceReservationValueSet = List[ReservedInstanceReservationValue]


class GetReservedInstancesExchangeQuoteResult(TypedDict, total=False):
    CurrencyCode: Optional[String]
    IsValidExchange: Optional[Boolean]
    OutputReservedInstancesWillExpireAt: Optional[DateTime]
    PaymentDue: Optional[String]
    ReservedInstanceValueRollup: Optional[ReservationValue]
    ReservedInstanceValueSet: Optional[ReservedInstanceReservationValueSet]
    TargetConfigurationValueRollup: Optional[ReservationValue]
    TargetConfigurationValueSet: Optional[TargetReservationValueSet]
    ValidationFailureReason: Optional[String]


class GetSecurityGroupsForVpcRequest(ServiceRequest):
    VpcId: VpcId
    NextToken: Optional[String]
    MaxResults: Optional[GetSecurityGroupsForVpcRequestMaxResults]
    Filters: Optional[FilterList]
    DryRun: Optional[Boolean]


class SecurityGroupForVpc(TypedDict, total=False):
    Description: Optional[String]
    GroupName: Optional[String]
    OwnerId: Optional[String]
    GroupId: Optional[String]
    Tags: Optional[TagList]
    PrimaryVpcId: Optional[String]


SecurityGroupForVpcList = List[SecurityGroupForVpc]


class GetSecurityGroupsForVpcResult(TypedDict, total=False):
    NextToken: Optional[String]
    SecurityGroupForVpcs: Optional[SecurityGroupForVpcList]


class GetSerialConsoleAccessStatusRequest(ServiceRequest):
    DryRun: Optional[Boolean]


class GetSerialConsoleAccessStatusResult(TypedDict, total=False):
    SerialConsoleAccessEnabled: Optional[Boolean]


class GetSnapshotBlockPublicAccessStateRequest(ServiceRequest):
    DryRun: Optional[Boolean]


class GetSnapshotBlockPublicAccessStateResult(TypedDict, total=False):
    State: Optional[SnapshotBlockPublicAccessState]


class InstanceRequirementsWithMetadataRequest(TypedDict, total=False):
    ArchitectureTypes: Optional[ArchitectureTypeSet]
    VirtualizationTypes: Optional[VirtualizationTypeSet]
    InstanceRequirements: Optional[InstanceRequirementsRequest]


RegionNames = List[String]
InstanceTypes = List[String]


class GetSpotPlacementScoresRequest(ServiceRequest):
    InstanceTypes: Optional[InstanceTypes]
    TargetCapacity: SpotPlacementScoresTargetCapacity
    TargetCapacityUnitType: Optional[TargetCapacityUnitType]
    SingleAvailabilityZone: Optional[Boolean]
    RegionNames: Optional[RegionNames]
    InstanceRequirementsWithMetadata: Optional[InstanceRequirementsWithMetadataRequest]
    DryRun: Optional[Boolean]
    MaxResults: Optional[SpotPlacementScoresMaxResults]
    NextToken: Optional[String]


class SpotPlacementScore(TypedDict, total=False):
    Region: Optional[String]
    AvailabilityZoneId: Optional[String]
    Score: Optional[Integer]


SpotPlacementScores = List[SpotPlacementScore]


class GetSpotPlacementScoresResult(TypedDict, total=False):
    SpotPlacementScores: Optional[SpotPlacementScores]
    NextToken: Optional[String]


class GetSubnetCidrReservationsRequest(ServiceRequest):
    Filters: Optional[FilterList]
    SubnetId: SubnetId
    DryRun: Optional[Boolean]
    NextToken: Optional[String]
    MaxResults: Optional[GetSubnetCidrReservationsMaxResults]


SubnetCidrReservationList = List[SubnetCidrReservation]


class GetSubnetCidrReservationsResult(TypedDict, total=False):
    SubnetIpv4CidrReservations: Optional[SubnetCidrReservationList]
    SubnetIpv6CidrReservations: Optional[SubnetCidrReservationList]
    NextToken: Optional[String]


class GetTransitGatewayAttachmentPropagationsRequest(ServiceRequest):
    TransitGatewayAttachmentId: TransitGatewayAttachmentId
    Filters: Optional[FilterList]
    MaxResults: Optional[TransitGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


class TransitGatewayAttachmentPropagation(TypedDict, total=False):
    TransitGatewayRouteTableId: Optional[String]
    State: Optional[TransitGatewayPropagationState]


TransitGatewayAttachmentPropagationList = List[TransitGatewayAttachmentPropagation]


class GetTransitGatewayAttachmentPropagationsResult(TypedDict, total=False):
    TransitGatewayAttachmentPropagations: Optional[TransitGatewayAttachmentPropagationList]
    NextToken: Optional[String]


class GetTransitGatewayMulticastDomainAssociationsRequest(ServiceRequest):
    TransitGatewayMulticastDomainId: TransitGatewayMulticastDomainId
    Filters: Optional[FilterList]
    MaxResults: Optional[TransitGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


class TransitGatewayMulticastDomainAssociation(TypedDict, total=False):
    TransitGatewayAttachmentId: Optional[String]
    ResourceId: Optional[String]
    ResourceType: Optional[TransitGatewayAttachmentResourceType]
    ResourceOwnerId: Optional[String]
    Subnet: Optional[SubnetAssociation]


TransitGatewayMulticastDomainAssociationList = List[TransitGatewayMulticastDomainAssociation]


class GetTransitGatewayMulticastDomainAssociationsResult(TypedDict, total=False):
    MulticastDomainAssociations: Optional[TransitGatewayMulticastDomainAssociationList]
    NextToken: Optional[String]


class GetTransitGatewayPolicyTableAssociationsRequest(ServiceRequest):
    TransitGatewayPolicyTableId: TransitGatewayPolicyTableId
    Filters: Optional[FilterList]
    MaxResults: Optional[TransitGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


TransitGatewayPolicyTableAssociationList = List[TransitGatewayPolicyTableAssociation]


class GetTransitGatewayPolicyTableAssociationsResult(TypedDict, total=False):
    Associations: Optional[TransitGatewayPolicyTableAssociationList]
    NextToken: Optional[String]


class GetTransitGatewayPolicyTableEntriesRequest(ServiceRequest):
    TransitGatewayPolicyTableId: TransitGatewayPolicyTableId
    Filters: Optional[FilterList]
    MaxResults: Optional[TransitGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


class TransitGatewayPolicyRuleMetaData(TypedDict, total=False):
    MetaDataKey: Optional[String]
    MetaDataValue: Optional[String]


class TransitGatewayPolicyRule(TypedDict, total=False):
    SourceCidrBlock: Optional[String]
    SourcePortRange: Optional[String]
    DestinationCidrBlock: Optional[String]
    DestinationPortRange: Optional[String]
    Protocol: Optional[String]
    MetaData: Optional[TransitGatewayPolicyRuleMetaData]


class TransitGatewayPolicyTableEntry(TypedDict, total=False):
    PolicyRuleNumber: Optional[String]
    PolicyRule: Optional[TransitGatewayPolicyRule]
    TargetRouteTableId: Optional[TransitGatewayRouteTableId]


TransitGatewayPolicyTableEntryList = List[TransitGatewayPolicyTableEntry]


class GetTransitGatewayPolicyTableEntriesResult(TypedDict, total=False):
    TransitGatewayPolicyTableEntries: Optional[TransitGatewayPolicyTableEntryList]


class GetTransitGatewayPrefixListReferencesRequest(ServiceRequest):
    TransitGatewayRouteTableId: TransitGatewayRouteTableId
    Filters: Optional[FilterList]
    MaxResults: Optional[TransitGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


TransitGatewayPrefixListReferenceSet = List[TransitGatewayPrefixListReference]


class GetTransitGatewayPrefixListReferencesResult(TypedDict, total=False):
    TransitGatewayPrefixListReferences: Optional[TransitGatewayPrefixListReferenceSet]
    NextToken: Optional[String]


class GetTransitGatewayRouteTableAssociationsRequest(ServiceRequest):
    TransitGatewayRouteTableId: TransitGatewayRouteTableId
    Filters: Optional[FilterList]
    MaxResults: Optional[TransitGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


class TransitGatewayRouteTableAssociation(TypedDict, total=False):
    TransitGatewayAttachmentId: Optional[String]
    ResourceId: Optional[String]
    ResourceType: Optional[TransitGatewayAttachmentResourceType]
    State: Optional[TransitGatewayAssociationState]


TransitGatewayRouteTableAssociationList = List[TransitGatewayRouteTableAssociation]


class GetTransitGatewayRouteTableAssociationsResult(TypedDict, total=False):
    Associations: Optional[TransitGatewayRouteTableAssociationList]
    NextToken: Optional[String]


class GetTransitGatewayRouteTablePropagationsRequest(ServiceRequest):
    TransitGatewayRouteTableId: TransitGatewayRouteTableId
    Filters: Optional[FilterList]
    MaxResults: Optional[TransitGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


class TransitGatewayRouteTablePropagation(TypedDict, total=False):
    TransitGatewayAttachmentId: Optional[String]
    ResourceId: Optional[String]
    ResourceType: Optional[TransitGatewayAttachmentResourceType]
    State: Optional[TransitGatewayPropagationState]
    TransitGatewayRouteTableAnnouncementId: Optional[TransitGatewayRouteTableAnnouncementId]


TransitGatewayRouteTablePropagationList = List[TransitGatewayRouteTablePropagation]


class GetTransitGatewayRouteTablePropagationsResult(TypedDict, total=False):
    TransitGatewayRouteTablePropagations: Optional[TransitGatewayRouteTablePropagationList]
    NextToken: Optional[String]


class GetVerifiedAccessEndpointPolicyRequest(ServiceRequest):
    VerifiedAccessEndpointId: VerifiedAccessEndpointId
    DryRun: Optional[Boolean]


class GetVerifiedAccessEndpointPolicyResult(TypedDict, total=False):
    PolicyEnabled: Optional[Boolean]
    PolicyDocument: Optional[String]


class GetVerifiedAccessGroupPolicyRequest(ServiceRequest):
    VerifiedAccessGroupId: VerifiedAccessGroupId
    DryRun: Optional[Boolean]


class GetVerifiedAccessGroupPolicyResult(TypedDict, total=False):
    PolicyEnabled: Optional[Boolean]
    PolicyDocument: Optional[String]


class GetVpnConnectionDeviceSampleConfigurationRequest(ServiceRequest):
    VpnConnectionId: VpnConnectionId
    VpnConnectionDeviceTypeId: VpnConnectionDeviceTypeId
    InternetKeyExchangeVersion: Optional[String]
    DryRun: Optional[Boolean]


class GetVpnConnectionDeviceSampleConfigurationResult(TypedDict, total=False):
    VpnConnectionDeviceSampleConfiguration: Optional[VpnConnectionDeviceSampleConfiguration]


class GetVpnConnectionDeviceTypesRequest(ServiceRequest):
    MaxResults: Optional[GVCDMaxResults]
    NextToken: Optional[NextToken]
    DryRun: Optional[Boolean]


class VpnConnectionDeviceType(TypedDict, total=False):
    VpnConnectionDeviceTypeId: Optional[String]
    Vendor: Optional[String]
    Platform: Optional[String]
    Software: Optional[String]


VpnConnectionDeviceTypeList = List[VpnConnectionDeviceType]


class GetVpnConnectionDeviceTypesResult(TypedDict, total=False):
    VpnConnectionDeviceTypes: Optional[VpnConnectionDeviceTypeList]
    NextToken: Optional[NextToken]


class GetVpnTunnelReplacementStatusRequest(ServiceRequest):
    VpnConnectionId: VpnConnectionId
    VpnTunnelOutsideIpAddress: String
    DryRun: Optional[Boolean]


class MaintenanceDetails(TypedDict, total=False):
    PendingMaintenance: Optional[String]
    MaintenanceAutoAppliedAfter: Optional[MillisecondDateTime]
    LastMaintenanceApplied: Optional[MillisecondDateTime]


class GetVpnTunnelReplacementStatusResult(TypedDict, total=False):
    VpnConnectionId: Optional[VpnConnectionId]
    TransitGatewayId: Optional[TransitGatewayId]
    CustomerGatewayId: Optional[CustomerGatewayId]
    VpnGatewayId: Optional[VpnGatewayId]
    VpnTunnelOutsideIpAddress: Optional[String]
    MaintenanceDetails: Optional[MaintenanceDetails]


class HibernationOptionsRequest(TypedDict, total=False):
    Configured: Optional[Boolean]


class LaunchPermission(TypedDict, total=False):
    OrganizationArn: Optional[String]
    OrganizationalUnitArn: Optional[String]
    UserId: Optional[String]
    Group: Optional[PermissionGroup]


LaunchPermissionList = List[LaunchPermission]


class ImageAttribute(TypedDict, total=False):
    Description: Optional[AttributeValue]
    KernelId: Optional[AttributeValue]
    RamdiskId: Optional[AttributeValue]
    SriovNetSupport: Optional[AttributeValue]
    BootMode: Optional[AttributeValue]
    TpmSupport: Optional[AttributeValue]
    UefiData: Optional[AttributeValue]
    LastLaunchedTime: Optional[AttributeValue]
    ImdsSupport: Optional[AttributeValue]
    DeregistrationProtection: Optional[AttributeValue]
    ImageId: Optional[String]
    LaunchPermissions: Optional[LaunchPermissionList]
    ProductCodes: Optional[ProductCodeList]
    BlockDeviceMappings: Optional[BlockDeviceMappingList]


class UserBucket(TypedDict, total=False):
    S3Bucket: Optional[String]
    S3Key: Optional[String]


class ImageDiskContainer(TypedDict, total=False):
    Description: Optional[String]
    DeviceName: Optional[String]
    Format: Optional[String]
    SnapshotId: Optional[SnapshotId]
    Url: Optional[SensitiveUrl]
    UserBucket: Optional[UserBucket]


ImageDiskContainerList = List[ImageDiskContainer]


class ImageRecycleBinInfo(TypedDict, total=False):
    ImageId: Optional[String]
    Name: Optional[String]
    Description: Optional[String]
    RecycleBinEnterTime: Optional[MillisecondDateTime]
    RecycleBinExitTime: Optional[MillisecondDateTime]


ImageRecycleBinInfoList = List[ImageRecycleBinInfo]


class ImportClientVpnClientCertificateRevocationListRequest(ServiceRequest):
    ClientVpnEndpointId: ClientVpnEndpointId
    CertificateRevocationList: String
    DryRun: Optional[Boolean]


class ImportClientVpnClientCertificateRevocationListResult(TypedDict, total=False):
    Return: Optional[Boolean]


class ImportImageLicenseConfigurationRequest(TypedDict, total=False):
    LicenseConfigurationArn: Optional[String]


ImportImageLicenseSpecificationListRequest = List[ImportImageLicenseConfigurationRequest]


class ImportImageRequest(ServiceRequest):
    Architecture: Optional[String]
    ClientData: Optional[ClientData]
    ClientToken: Optional[String]
    Description: Optional[String]
    DiskContainers: Optional[ImageDiskContainerList]
    DryRun: Optional[Boolean]
    Encrypted: Optional[Boolean]
    Hypervisor: Optional[String]
    KmsKeyId: Optional[KmsKeyId]
    LicenseType: Optional[String]
    Platform: Optional[String]
    RoleName: Optional[String]
    LicenseSpecifications: Optional[ImportImageLicenseSpecificationListRequest]
    TagSpecifications: Optional[TagSpecificationList]
    UsageOperation: Optional[String]
    BootMode: Optional[BootModeValues]


class ImportImageResult(TypedDict, total=False):
    Architecture: Optional[String]
    Description: Optional[String]
    Encrypted: Optional[Boolean]
    Hypervisor: Optional[String]
    ImageId: Optional[String]
    ImportTaskId: Optional[ImportImageTaskId]
    KmsKeyId: Optional[KmsKeyId]
    LicenseType: Optional[String]
    Platform: Optional[String]
    Progress: Optional[String]
    SnapshotDetails: Optional[SnapshotDetailList]
    Status: Optional[String]
    StatusMessage: Optional[String]
    LicenseSpecifications: Optional[ImportImageLicenseSpecificationListResponse]
    Tags: Optional[TagList]
    UsageOperation: Optional[String]


class UserData(TypedDict, total=False):
    Data: Optional[String]


class ImportInstanceLaunchSpecification(TypedDict, total=False):
    Architecture: Optional[ArchitectureValues]
    GroupNames: Optional[SecurityGroupStringList]
    GroupIds: Optional[SecurityGroupIdStringList]
    AdditionalInfo: Optional[String]
    UserData: Optional[UserData]
    InstanceType: Optional[InstanceType]
    Placement: Optional[Placement]
    Monitoring: Optional[Boolean]
    SubnetId: Optional[SubnetId]
    InstanceInitiatedShutdownBehavior: Optional[ShutdownBehavior]
    PrivateIpAddress: Optional[String]


class ImportInstanceRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Description: Optional[String]
    LaunchSpecification: Optional[ImportInstanceLaunchSpecification]
    DiskImages: Optional[DiskImageList]
    Platform: PlatformValues


class ImportInstanceResult(TypedDict, total=False):
    ConversionTask: Optional[ConversionTask]


class ImportKeyPairRequest(ServiceRequest):
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]
    KeyName: String
    PublicKeyMaterial: Blob


class ImportKeyPairResult(TypedDict, total=False):
    KeyFingerprint: Optional[String]
    KeyName: Optional[String]
    KeyPairId: Optional[String]
    Tags: Optional[TagList]


class SnapshotDiskContainer(TypedDict, total=False):
    Description: Optional[String]
    Format: Optional[String]
    Url: Optional[SensitiveUrl]
    UserBucket: Optional[UserBucket]


class ImportSnapshotRequest(ServiceRequest):
    ClientData: Optional[ClientData]
    ClientToken: Optional[String]
    Description: Optional[String]
    DiskContainer: Optional[SnapshotDiskContainer]
    DryRun: Optional[Boolean]
    Encrypted: Optional[Boolean]
    KmsKeyId: Optional[KmsKeyId]
    RoleName: Optional[String]
    TagSpecifications: Optional[TagSpecificationList]


class ImportSnapshotResult(TypedDict, total=False):
    Description: Optional[String]
    ImportTaskId: Optional[String]
    SnapshotTaskDetail: Optional[SnapshotTaskDetail]
    Tags: Optional[TagList]


class ImportVolumeRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    AvailabilityZone: String
    Image: DiskImageDetail
    Description: Optional[String]
    Volume: VolumeDetail


class ImportVolumeResult(TypedDict, total=False):
    ConversionTask: Optional[ConversionTask]


class InstanceAttribute(TypedDict, total=False):
    BlockDeviceMappings: Optional[InstanceBlockDeviceMappingList]
    DisableApiTermination: Optional[AttributeBooleanValue]
    EnaSupport: Optional[AttributeBooleanValue]
    EnclaveOptions: Optional[EnclaveOptions]
    EbsOptimized: Optional[AttributeBooleanValue]
    InstanceId: Optional[String]
    InstanceInitiatedShutdownBehavior: Optional[AttributeValue]
    InstanceType: Optional[AttributeValue]
    KernelId: Optional[AttributeValue]
    ProductCodes: Optional[ProductCodeList]
    RamdiskId: Optional[AttributeValue]
    RootDeviceName: Optional[AttributeValue]
    SourceDestCheck: Optional[AttributeBooleanValue]
    SriovNetSupport: Optional[AttributeValue]
    UserData: Optional[AttributeValue]
    DisableApiStop: Optional[AttributeBooleanValue]
    Groups: Optional[GroupIdentifierList]


class InstanceBlockDeviceMappingSpecification(TypedDict, total=False):
    DeviceName: Optional[String]
    Ebs: Optional[EbsInstanceBlockDeviceSpecification]
    VirtualName: Optional[String]
    NoDevice: Optional[String]


InstanceBlockDeviceMappingSpecificationList = List[InstanceBlockDeviceMappingSpecification]


class InstanceCreditSpecificationRequest(TypedDict, total=False):
    InstanceId: InstanceId
    CpuCredits: Optional[String]


InstanceCreditSpecificationListRequest = List[InstanceCreditSpecificationRequest]
InstanceIdSet = List[InstanceId]


class InstanceMaintenanceOptionsRequest(TypedDict, total=False):
    AutoRecovery: Optional[InstanceAutoRecoveryState]


class SpotMarketOptions(TypedDict, total=False):
    MaxPrice: Optional[String]
    SpotInstanceType: Optional[SpotInstanceType]
    BlockDurationMinutes: Optional[Integer]
    ValidUntil: Optional[DateTime]
    InstanceInterruptionBehavior: Optional[InstanceInterruptionBehavior]


class InstanceMarketOptionsRequest(TypedDict, total=False):
    MarketType: Optional[MarketType]
    SpotOptions: Optional[SpotMarketOptions]


class InstanceMetadataOptionsRequest(TypedDict, total=False):
    HttpTokens: Optional[HttpTokensState]
    HttpPutResponseHopLimit: Optional[Integer]
    HttpEndpoint: Optional[InstanceMetadataEndpointState]
    HttpProtocolIpv6: Optional[InstanceMetadataProtocolState]
    InstanceMetadataTags: Optional[InstanceMetadataTagsState]


class InstanceMonitoring(TypedDict, total=False):
    InstanceId: Optional[String]
    Monitoring: Optional[Monitoring]


InstanceMonitoringList = List[InstanceMonitoring]


class InstanceStateChange(TypedDict, total=False):
    InstanceId: Optional[String]
    CurrentState: Optional[InstanceState]
    PreviousState: Optional[InstanceState]


InstanceStateChangeList = List[InstanceStateChange]


class IpamCidrAuthorizationContext(TypedDict, total=False):
    Message: Optional[String]
    Signature: Optional[String]


class KeyPair(TypedDict, total=False):
    KeyPairId: Optional[String]
    Tags: Optional[TagList]
    KeyName: Optional[String]
    KeyFingerprint: Optional[String]
    KeyMaterial: Optional[SensitiveUserData]


class LaunchPermissionModifications(TypedDict, total=False):
    Add: Optional[LaunchPermissionList]
    Remove: Optional[LaunchPermissionList]


class LaunchTemplateSpecification(TypedDict, total=False):
    LaunchTemplateId: Optional[LaunchTemplateId]
    LaunchTemplateName: Optional[String]
    Version: Optional[String]


class LicenseConfigurationRequest(TypedDict, total=False):
    LicenseConfigurationArn: Optional[String]


LicenseSpecificationListRequest = List[LicenseConfigurationRequest]


class ListImagesInRecycleBinRequest(ServiceRequest):
    ImageIds: Optional[ImageIdStringList]
    NextToken: Optional[String]
    MaxResults: Optional[ListImagesInRecycleBinMaxResults]
    DryRun: Optional[Boolean]


class ListImagesInRecycleBinResult(TypedDict, total=False):
    Images: Optional[ImageRecycleBinInfoList]
    NextToken: Optional[String]


class ListSnapshotsInRecycleBinRequest(ServiceRequest):
    MaxResults: Optional[ListSnapshotsInRecycleBinMaxResults]
    NextToken: Optional[String]
    SnapshotIds: Optional[SnapshotIdStringList]
    DryRun: Optional[Boolean]


class SnapshotRecycleBinInfo(TypedDict, total=False):
    SnapshotId: Optional[String]
    RecycleBinEnterTime: Optional[MillisecondDateTime]
    RecycleBinExitTime: Optional[MillisecondDateTime]
    Description: Optional[String]
    VolumeId: Optional[String]


SnapshotRecycleBinInfoList = List[SnapshotRecycleBinInfo]


class ListSnapshotsInRecycleBinResult(TypedDict, total=False):
    Snapshots: Optional[SnapshotRecycleBinInfoList]
    NextToken: Optional[String]


class LoadPermissionRequest(TypedDict, total=False):
    Group: Optional[PermissionGroup]
    UserId: Optional[String]


LoadPermissionListRequest = List[LoadPermissionRequest]


class LoadPermissionModifications(TypedDict, total=False):
    Add: Optional[LoadPermissionListRequest]
    Remove: Optional[LoadPermissionListRequest]


LocalGatewayRouteList = List[LocalGatewayRoute]


class LockSnapshotRequest(ServiceRequest):
    SnapshotId: SnapshotId
    DryRun: Optional[Boolean]
    LockMode: LockMode
    CoolOffPeriod: Optional[CoolOffPeriodRequestHours]
    LockDuration: Optional[RetentionPeriodRequestDays]
    ExpirationDate: Optional[MillisecondDateTime]


class LockSnapshotResult(TypedDict, total=False):
    SnapshotId: Optional[String]
    LockState: Optional[LockState]
    LockDuration: Optional[RetentionPeriodResponseDays]
    CoolOffPeriod: Optional[CoolOffPeriodResponseHours]
    CoolOffPeriodExpiresOn: Optional[MillisecondDateTime]
    LockCreatedOn: Optional[MillisecondDateTime]
    LockExpiresOn: Optional[MillisecondDateTime]
    LockDurationStartTime: Optional[MillisecondDateTime]


class ModifyAddressAttributeRequest(ServiceRequest):
    AllocationId: AllocationId
    DomainName: Optional[String]
    DryRun: Optional[Boolean]


class ModifyAddressAttributeResult(TypedDict, total=False):
    Address: Optional[AddressAttribute]


class ModifyAvailabilityZoneGroupRequest(ServiceRequest):
    GroupName: String
    OptInStatus: ModifyAvailabilityZoneOptInStatus
    DryRun: Optional[Boolean]


class ModifyAvailabilityZoneGroupResult(TypedDict, total=False):
    Return: Optional[Boolean]


class ModifyCapacityReservationFleetRequest(ServiceRequest):
    CapacityReservationFleetId: CapacityReservationFleetId
    TotalTargetCapacity: Optional[Integer]
    EndDate: Optional[MillisecondDateTime]
    DryRun: Optional[Boolean]
    RemoveEndDate: Optional[Boolean]


class ModifyCapacityReservationFleetResult(TypedDict, total=False):
    Return: Optional[Boolean]


class ModifyCapacityReservationRequest(ServiceRequest):
    CapacityReservationId: CapacityReservationId
    InstanceCount: Optional[Integer]
    EndDate: Optional[DateTime]
    EndDateType: Optional[EndDateType]
    Accept: Optional[Boolean]
    DryRun: Optional[Boolean]
    AdditionalInfo: Optional[String]
    InstanceMatchCriteria: Optional[InstanceMatchCriteria]


class ModifyCapacityReservationResult(TypedDict, total=False):
    Return: Optional[Boolean]


class ModifyClientVpnEndpointRequest(ServiceRequest):
    ClientVpnEndpointId: ClientVpnEndpointId
    ServerCertificateArn: Optional[String]
    ConnectionLogOptions: Optional[ConnectionLogOptions]
    DnsServers: Optional[DnsServersOptionsModifyStructure]
    VpnPort: Optional[Integer]
    Description: Optional[String]
    SplitTunnel: Optional[Boolean]
    DryRun: Optional[Boolean]
    SecurityGroupIds: Optional[ClientVpnSecurityGroupIdSet]
    VpcId: Optional[VpcId]
    SelfServicePortal: Optional[SelfServicePortal]
    ClientConnectOptions: Optional[ClientConnectOptions]
    SessionTimeoutHours: Optional[Integer]
    ClientLoginBannerOptions: Optional[ClientLoginBannerOptions]


class ModifyClientVpnEndpointResult(TypedDict, total=False):
    Return: Optional[Boolean]


class ModifyDefaultCreditSpecificationRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceFamily: UnlimitedSupportedInstanceFamily
    CpuCredits: String


class ModifyDefaultCreditSpecificationResult(TypedDict, total=False):
    InstanceFamilyCreditSpecification: Optional[InstanceFamilyCreditSpecification]


class ModifyEbsDefaultKmsKeyIdRequest(ServiceRequest):
    KmsKeyId: KmsKeyId
    DryRun: Optional[Boolean]


class ModifyEbsDefaultKmsKeyIdResult(TypedDict, total=False):
    KmsKeyId: Optional[String]


class ModifyFleetRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ExcessCapacityTerminationPolicy: Optional[FleetExcessCapacityTerminationPolicy]
    LaunchTemplateConfigs: Optional[FleetLaunchTemplateConfigListRequest]
    FleetId: FleetId
    TargetCapacitySpecification: Optional[TargetCapacitySpecificationRequest]
    Context: Optional[String]


class ModifyFleetResult(TypedDict, total=False):
    Return: Optional[Boolean]


ProductCodeStringList = List[String]
UserGroupStringList = List[String]
UserIdStringList = List[String]


class ModifyFpgaImageAttributeRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    FpgaImageId: FpgaImageId
    Attribute: Optional[FpgaImageAttributeName]
    OperationType: Optional[OperationType]
    UserIds: Optional[UserIdStringList]
    UserGroups: Optional[UserGroupStringList]
    ProductCodes: Optional[ProductCodeStringList]
    LoadPermission: Optional[LoadPermissionModifications]
    Description: Optional[String]
    Name: Optional[String]


class ModifyFpgaImageAttributeResult(TypedDict, total=False):
    FpgaImageAttribute: Optional[FpgaImageAttribute]


class ModifyHostsRequest(ServiceRequest):
    HostRecovery: Optional[HostRecovery]
    InstanceType: Optional[String]
    InstanceFamily: Optional[String]
    HostMaintenance: Optional[HostMaintenance]
    HostIds: RequestHostIdList
    AutoPlacement: Optional[AutoPlacement]


UnsuccessfulItemList = List[UnsuccessfulItem]


class ModifyHostsResult(TypedDict, total=False):
    Successful: Optional[ResponseHostIdList]
    Unsuccessful: Optional[UnsuccessfulItemList]


class ModifyIdFormatRequest(ServiceRequest):
    Resource: String
    UseLongIds: Boolean


class ModifyIdentityIdFormatRequest(ServiceRequest):
    Resource: String
    UseLongIds: Boolean
    PrincipalArn: String


OrganizationalUnitArnStringList = List[String]
OrganizationArnStringList = List[String]


class ModifyImageAttributeRequest(ServiceRequest):
    Attribute: Optional[String]
    Description: Optional[AttributeValue]
    ImageId: ImageId
    LaunchPermission: Optional[LaunchPermissionModifications]
    OperationType: Optional[OperationType]
    ProductCodes: Optional[ProductCodeStringList]
    UserGroups: Optional[UserGroupStringList]
    UserIds: Optional[UserIdStringList]
    Value: Optional[String]
    OrganizationArns: Optional[OrganizationArnStringList]
    OrganizationalUnitArns: Optional[OrganizationalUnitArnStringList]
    ImdsSupport: Optional[AttributeValue]
    DryRun: Optional[Boolean]


class ModifyInstanceAttributeRequest(ServiceRequest):
    SourceDestCheck: Optional[AttributeBooleanValue]
    DisableApiStop: Optional[AttributeBooleanValue]
    DryRun: Optional[Boolean]
    InstanceId: InstanceId
    Attribute: Optional[InstanceAttributeName]
    Value: Optional[String]
    BlockDeviceMappings: Optional[InstanceBlockDeviceMappingSpecificationList]
    DisableApiTermination: Optional[AttributeBooleanValue]
    InstanceType: Optional[AttributeValue]
    Kernel: Optional[AttributeValue]
    Ramdisk: Optional[AttributeValue]
    UserData: Optional[BlobAttributeValue]
    InstanceInitiatedShutdownBehavior: Optional[AttributeValue]
    Groups: Optional[GroupIdStringList]
    EbsOptimized: Optional[AttributeBooleanValue]
    SriovNetSupport: Optional[AttributeValue]
    EnaSupport: Optional[AttributeBooleanValue]


class ModifyInstanceCapacityReservationAttributesRequest(ServiceRequest):
    InstanceId: InstanceId
    CapacityReservationSpecification: CapacityReservationSpecification
    DryRun: Optional[Boolean]


class ModifyInstanceCapacityReservationAttributesResult(TypedDict, total=False):
    Return: Optional[Boolean]


class ModifyInstanceCpuOptionsRequest(ServiceRequest):
    InstanceId: InstanceId
    CoreCount: Integer
    ThreadsPerCore: Integer
    DryRun: Optional[Boolean]


class ModifyInstanceCpuOptionsResult(TypedDict, total=False):
    InstanceId: Optional[InstanceId]
    CoreCount: Optional[Integer]
    ThreadsPerCore: Optional[Integer]


class ModifyInstanceCreditSpecificationRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]
    InstanceCreditSpecifications: InstanceCreditSpecificationListRequest


class UnsuccessfulInstanceCreditSpecificationItemError(TypedDict, total=False):
    Code: Optional[UnsuccessfulInstanceCreditSpecificationErrorCode]
    Message: Optional[String]


class UnsuccessfulInstanceCreditSpecificationItem(TypedDict, total=False):
    InstanceId: Optional[String]
    Error: Optional[UnsuccessfulInstanceCreditSpecificationItemError]


UnsuccessfulInstanceCreditSpecificationSet = List[UnsuccessfulInstanceCreditSpecificationItem]


class SuccessfulInstanceCreditSpecificationItem(TypedDict, total=False):
    InstanceId: Optional[String]


SuccessfulInstanceCreditSpecificationSet = List[SuccessfulInstanceCreditSpecificationItem]


class ModifyInstanceCreditSpecificationResult(TypedDict, total=False):
    SuccessfulInstanceCreditSpecifications: Optional[SuccessfulInstanceCreditSpecificationSet]
    UnsuccessfulInstanceCreditSpecifications: Optional[UnsuccessfulInstanceCreditSpecificationSet]


class ModifyInstanceEventStartTimeRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceId: InstanceId
    InstanceEventId: String
    NotBefore: DateTime


class ModifyInstanceEventStartTimeResult(TypedDict, total=False):
    Event: Optional[InstanceStatusEvent]


class ModifyInstanceEventWindowRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Name: Optional[String]
    InstanceEventWindowId: InstanceEventWindowId
    TimeRanges: Optional[InstanceEventWindowTimeRangeRequestSet]
    CronExpression: Optional[InstanceEventWindowCronExpression]


class ModifyInstanceEventWindowResult(TypedDict, total=False):
    InstanceEventWindow: Optional[InstanceEventWindow]


class ModifyInstanceMaintenanceOptionsRequest(ServiceRequest):
    InstanceId: InstanceId
    AutoRecovery: Optional[InstanceAutoRecoveryState]
    DryRun: Optional[Boolean]


class ModifyInstanceMaintenanceOptionsResult(TypedDict, total=False):
    InstanceId: Optional[String]
    AutoRecovery: Optional[InstanceAutoRecoveryState]


class ModifyInstanceMetadataDefaultsRequest(ServiceRequest):
    HttpTokens: Optional[MetadataDefaultHttpTokensState]
    HttpPutResponseHopLimit: Optional[BoxedInteger]
    HttpEndpoint: Optional[DefaultInstanceMetadataEndpointState]
    InstanceMetadataTags: Optional[DefaultInstanceMetadataTagsState]
    DryRun: Optional[Boolean]


class ModifyInstanceMetadataDefaultsResult(TypedDict, total=False):
    Return: Optional[Boolean]


class ModifyInstanceMetadataOptionsRequest(ServiceRequest):
    InstanceId: InstanceId
    HttpTokens: Optional[HttpTokensState]
    HttpPutResponseHopLimit: Optional[Integer]
    HttpEndpoint: Optional[InstanceMetadataEndpointState]
    DryRun: Optional[Boolean]
    HttpProtocolIpv6: Optional[InstanceMetadataProtocolState]
    InstanceMetadataTags: Optional[InstanceMetadataTagsState]


class ModifyInstanceMetadataOptionsResult(TypedDict, total=False):
    InstanceId: Optional[String]
    InstanceMetadataOptions: Optional[InstanceMetadataOptionsResponse]


class ModifyInstancePlacementRequest(ServiceRequest):
    GroupName: Optional[PlacementGroupName]
    PartitionNumber: Optional[Integer]
    HostResourceGroupArn: Optional[String]
    GroupId: Optional[PlacementGroupId]
    InstanceId: InstanceId
    Tenancy: Optional[HostTenancy]
    Affinity: Optional[Affinity]
    HostId: Optional[DedicatedHostId]


class ModifyInstancePlacementResult(TypedDict, total=False):
    Return: Optional[Boolean]


class ModifyIpamPoolRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamPoolId: IpamPoolId
    Description: Optional[String]
    AutoImport: Optional[Boolean]
    AllocationMinNetmaskLength: Optional[IpamNetmaskLength]
    AllocationMaxNetmaskLength: Optional[IpamNetmaskLength]
    AllocationDefaultNetmaskLength: Optional[IpamNetmaskLength]
    ClearAllocationDefaultNetmaskLength: Optional[Boolean]
    AddAllocationResourceTags: Optional[RequestIpamResourceTagList]
    RemoveAllocationResourceTags: Optional[RequestIpamResourceTagList]


class ModifyIpamPoolResult(TypedDict, total=False):
    IpamPool: Optional[IpamPool]


class RemoveIpamOperatingRegion(TypedDict, total=False):
    RegionName: Optional[String]


RemoveIpamOperatingRegionSet = List[RemoveIpamOperatingRegion]


class ModifyIpamRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamId: IpamId
    Description: Optional[String]
    AddOperatingRegions: Optional[AddIpamOperatingRegionSet]
    RemoveOperatingRegions: Optional[RemoveIpamOperatingRegionSet]
    Tier: Optional[IpamTier]
    EnablePrivateGua: Optional[Boolean]


class ModifyIpamResourceCidrRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ResourceId: String
    ResourceCidr: String
    ResourceRegion: String
    CurrentIpamScopeId: IpamScopeId
    DestinationIpamScopeId: Optional[IpamScopeId]
    Monitored: Boolean


class ModifyIpamResourceCidrResult(TypedDict, total=False):
    IpamResourceCidr: Optional[IpamResourceCidr]


class ModifyIpamResourceDiscoveryRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamResourceDiscoveryId: IpamResourceDiscoveryId
    Description: Optional[String]
    AddOperatingRegions: Optional[AddIpamOperatingRegionSet]
    RemoveOperatingRegions: Optional[RemoveIpamOperatingRegionSet]


class ModifyIpamResourceDiscoveryResult(TypedDict, total=False):
    IpamResourceDiscovery: Optional[IpamResourceDiscovery]


class ModifyIpamResult(TypedDict, total=False):
    Ipam: Optional[Ipam]


class ModifyIpamScopeRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamScopeId: IpamScopeId
    Description: Optional[String]


class ModifyIpamScopeResult(TypedDict, total=False):
    IpamScope: Optional[IpamScope]


class ModifyLaunchTemplateRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]
    LaunchTemplateId: Optional[LaunchTemplateId]
    LaunchTemplateName: Optional[LaunchTemplateName]
    DefaultVersion: Optional[String]


class ModifyLaunchTemplateResult(TypedDict, total=False):
    LaunchTemplate: Optional[LaunchTemplate]


class ModifyLocalGatewayRouteRequest(ServiceRequest):
    DestinationCidrBlock: Optional[String]
    LocalGatewayRouteTableId: LocalGatewayRoutetableId
    LocalGatewayVirtualInterfaceGroupId: Optional[LocalGatewayVirtualInterfaceGroupId]
    NetworkInterfaceId: Optional[NetworkInterfaceId]
    DryRun: Optional[Boolean]
    DestinationPrefixListId: Optional[PrefixListResourceId]


class ModifyLocalGatewayRouteResult(TypedDict, total=False):
    Route: Optional[LocalGatewayRoute]


class RemovePrefixListEntry(TypedDict, total=False):
    Cidr: String


RemovePrefixListEntries = List[RemovePrefixListEntry]


class ModifyManagedPrefixListRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    PrefixListId: PrefixListResourceId
    CurrentVersion: Optional[Long]
    PrefixListName: Optional[String]
    AddEntries: Optional[AddPrefixListEntries]
    RemoveEntries: Optional[RemovePrefixListEntries]
    MaxEntries: Optional[Integer]


class ModifyManagedPrefixListResult(TypedDict, total=False):
    PrefixList: Optional[ManagedPrefixList]


class NetworkInterfaceAttachmentChanges(TypedDict, total=False):
    AttachmentId: Optional[NetworkInterfaceAttachmentId]
    DeleteOnTermination: Optional[Boolean]


class ModifyNetworkInterfaceAttributeRequest(ServiceRequest):
    EnaSrdSpecification: Optional[EnaSrdSpecification]
    EnablePrimaryIpv6: Optional[Boolean]
    ConnectionTrackingSpecification: Optional[ConnectionTrackingSpecificationRequest]
    AssociatePublicIpAddress: Optional[Boolean]
    DryRun: Optional[Boolean]
    NetworkInterfaceId: NetworkInterfaceId
    Description: Optional[AttributeValue]
    SourceDestCheck: Optional[AttributeBooleanValue]
    Groups: Optional[SecurityGroupIdStringList]
    Attachment: Optional[NetworkInterfaceAttachmentChanges]


class ModifyPrivateDnsNameOptionsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceId: InstanceId
    PrivateDnsHostnameType: Optional[HostnameType]
    EnableResourceNameDnsARecord: Optional[Boolean]
    EnableResourceNameDnsAAAARecord: Optional[Boolean]


class ModifyPrivateDnsNameOptionsResult(TypedDict, total=False):
    Return: Optional[Boolean]


ReservedInstancesConfigurationList = List[ReservedInstancesConfiguration]


class ModifyReservedInstancesRequest(ServiceRequest):
    ReservedInstancesIds: ReservedInstancesIdStringList
    ClientToken: Optional[String]
    TargetConfigurations: ReservedInstancesConfigurationList


class ModifyReservedInstancesResult(TypedDict, total=False):
    ReservedInstancesModificationId: Optional[String]


class SecurityGroupRuleRequest(TypedDict, total=False):
    IpProtocol: Optional[String]
    FromPort: Optional[Integer]
    ToPort: Optional[Integer]
    CidrIpv4: Optional[String]
    CidrIpv6: Optional[String]
    PrefixListId: Optional[PrefixListResourceId]
    ReferencedGroupId: Optional[SecurityGroupId]
    Description: Optional[String]


class SecurityGroupRuleUpdate(TypedDict, total=False):
    SecurityGroupRuleId: SecurityGroupRuleId
    SecurityGroupRule: Optional[SecurityGroupRuleRequest]


SecurityGroupRuleUpdateList = List[SecurityGroupRuleUpdate]


class ModifySecurityGroupRulesRequest(ServiceRequest):
    GroupId: SecurityGroupId
    SecurityGroupRules: SecurityGroupRuleUpdateList
    DryRun: Optional[Boolean]


class ModifySecurityGroupRulesResult(TypedDict, total=False):
    Return: Optional[Boolean]


class ModifySnapshotAttributeRequest(ServiceRequest):
    Attribute: Optional[SnapshotAttributeName]
    CreateVolumePermission: Optional[CreateVolumePermissionModifications]
    GroupNames: Optional[GroupNameStringList]
    OperationType: Optional[OperationType]
    SnapshotId: SnapshotId
    UserIds: Optional[UserIdStringList]
    DryRun: Optional[Boolean]


class ModifySnapshotTierRequest(ServiceRequest):
    SnapshotId: SnapshotId
    StorageTier: Optional[TargetStorageTier]
    DryRun: Optional[Boolean]


class ModifySnapshotTierResult(TypedDict, total=False):
    SnapshotId: Optional[String]
    TieringStartTime: Optional[MillisecondDateTime]


class ModifySpotFleetRequestRequest(ServiceRequest):
    LaunchTemplateConfigs: Optional[LaunchTemplateConfigList]
    OnDemandTargetCapacity: Optional[Integer]
    Context: Optional[String]
    SpotFleetRequestId: SpotFleetRequestId
    TargetCapacity: Optional[Integer]
    ExcessCapacityTerminationPolicy: Optional[ExcessCapacityTerminationPolicy]


class ModifySpotFleetRequestResponse(TypedDict, total=False):
    Return: Optional[Boolean]


class ModifySubnetAttributeRequest(ServiceRequest):
    AssignIpv6AddressOnCreation: Optional[AttributeBooleanValue]
    MapPublicIpOnLaunch: Optional[AttributeBooleanValue]
    SubnetId: SubnetId
    MapCustomerOwnedIpOnLaunch: Optional[AttributeBooleanValue]
    CustomerOwnedIpv4Pool: Optional[CoipPoolId]
    EnableDns64: Optional[AttributeBooleanValue]
    PrivateDnsHostnameTypeOnLaunch: Optional[HostnameType]
    EnableResourceNameDnsARecordOnLaunch: Optional[AttributeBooleanValue]
    EnableResourceNameDnsAAAARecordOnLaunch: Optional[AttributeBooleanValue]
    EnableLniAtDeviceIndex: Optional[Integer]
    DisableLniAtDeviceIndex: Optional[AttributeBooleanValue]


class ModifyTrafficMirrorFilterNetworkServicesRequest(ServiceRequest):
    TrafficMirrorFilterId: TrafficMirrorFilterId
    AddNetworkServices: Optional[TrafficMirrorNetworkServiceList]
    RemoveNetworkServices: Optional[TrafficMirrorNetworkServiceList]
    DryRun: Optional[Boolean]


class ModifyTrafficMirrorFilterNetworkServicesResult(TypedDict, total=False):
    TrafficMirrorFilter: Optional[TrafficMirrorFilter]


TrafficMirrorFilterRuleFieldList = List[TrafficMirrorFilterRuleField]


class ModifyTrafficMirrorFilterRuleRequest(ServiceRequest):
    TrafficMirrorFilterRuleId: TrafficMirrorFilterRuleIdWithResolver
    TrafficDirection: Optional[TrafficDirection]
    RuleNumber: Optional[Integer]
    RuleAction: Optional[TrafficMirrorRuleAction]
    DestinationPortRange: Optional[TrafficMirrorPortRangeRequest]
    SourcePortRange: Optional[TrafficMirrorPortRangeRequest]
    Protocol: Optional[Integer]
    DestinationCidrBlock: Optional[String]
    SourceCidrBlock: Optional[String]
    Description: Optional[String]
    RemoveFields: Optional[TrafficMirrorFilterRuleFieldList]
    DryRun: Optional[Boolean]


class ModifyTrafficMirrorFilterRuleResult(TypedDict, total=False):
    TrafficMirrorFilterRule: Optional[TrafficMirrorFilterRule]


TrafficMirrorSessionFieldList = List[TrafficMirrorSessionField]


class ModifyTrafficMirrorSessionRequest(ServiceRequest):
    TrafficMirrorSessionId: TrafficMirrorSessionId
    TrafficMirrorTargetId: Optional[TrafficMirrorTargetId]
    TrafficMirrorFilterId: Optional[TrafficMirrorFilterId]
    PacketLength: Optional[Integer]
    SessionNumber: Optional[Integer]
    VirtualNetworkId: Optional[Integer]
    Description: Optional[String]
    RemoveFields: Optional[TrafficMirrorSessionFieldList]
    DryRun: Optional[Boolean]


class ModifyTrafficMirrorSessionResult(TypedDict, total=False):
    TrafficMirrorSession: Optional[TrafficMirrorSession]


class ModifyTransitGatewayOptions(TypedDict, total=False):
    AddTransitGatewayCidrBlocks: Optional[TransitGatewayCidrBlockStringList]
    RemoveTransitGatewayCidrBlocks: Optional[TransitGatewayCidrBlockStringList]
    VpnEcmpSupport: Optional[VpnEcmpSupportValue]
    DnsSupport: Optional[DnsSupportValue]
    SecurityGroupReferencingSupport: Optional[SecurityGroupReferencingSupportValue]
    AutoAcceptSharedAttachments: Optional[AutoAcceptSharedAttachmentsValue]
    DefaultRouteTableAssociation: Optional[DefaultRouteTableAssociationValue]
    AssociationDefaultRouteTableId: Optional[TransitGatewayRouteTableId]
    DefaultRouteTablePropagation: Optional[DefaultRouteTablePropagationValue]
    PropagationDefaultRouteTableId: Optional[TransitGatewayRouteTableId]
    AmazonSideAsn: Optional[Long]


class ModifyTransitGatewayPrefixListReferenceRequest(ServiceRequest):
    TransitGatewayRouteTableId: TransitGatewayRouteTableId
    PrefixListId: PrefixListResourceId
    TransitGatewayAttachmentId: Optional[TransitGatewayAttachmentId]
    Blackhole: Optional[Boolean]
    DryRun: Optional[Boolean]


class ModifyTransitGatewayPrefixListReferenceResult(TypedDict, total=False):
    TransitGatewayPrefixListReference: Optional[TransitGatewayPrefixListReference]


class ModifyTransitGatewayRequest(ServiceRequest):
    TransitGatewayId: TransitGatewayId
    Description: Optional[String]
    Options: Optional[ModifyTransitGatewayOptions]
    DryRun: Optional[Boolean]


class ModifyTransitGatewayResult(TypedDict, total=False):
    TransitGateway: Optional[TransitGateway]


class ModifyTransitGatewayVpcAttachmentRequestOptions(TypedDict, total=False):
    DnsSupport: Optional[DnsSupportValue]
    SecurityGroupReferencingSupport: Optional[SecurityGroupReferencingSupportValue]
    Ipv6Support: Optional[Ipv6SupportValue]
    ApplianceModeSupport: Optional[ApplianceModeSupportValue]


class ModifyTransitGatewayVpcAttachmentRequest(ServiceRequest):
    TransitGatewayAttachmentId: TransitGatewayAttachmentId
    AddSubnetIds: Optional[TransitGatewaySubnetIdList]
    RemoveSubnetIds: Optional[TransitGatewaySubnetIdList]
    Options: Optional[ModifyTransitGatewayVpcAttachmentRequestOptions]
    DryRun: Optional[Boolean]


class ModifyTransitGatewayVpcAttachmentResult(TypedDict, total=False):
    TransitGatewayVpcAttachment: Optional[TransitGatewayVpcAttachment]


class ModifyVerifiedAccessEndpointEniOptions(TypedDict, total=False):
    Protocol: Optional[VerifiedAccessEndpointProtocol]
    Port: Optional[VerifiedAccessEndpointPortNumber]


ModifyVerifiedAccessEndpointSubnetIdList = List[SubnetId]


class ModifyVerifiedAccessEndpointLoadBalancerOptions(TypedDict, total=False):
    SubnetIds: Optional[ModifyVerifiedAccessEndpointSubnetIdList]
    Protocol: Optional[VerifiedAccessEndpointProtocol]
    Port: Optional[VerifiedAccessEndpointPortNumber]


class ModifyVerifiedAccessEndpointPolicyRequest(ServiceRequest):
    VerifiedAccessEndpointId: VerifiedAccessEndpointId
    PolicyEnabled: Optional[Boolean]
    PolicyDocument: Optional[String]
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]
    SseSpecification: Optional[VerifiedAccessSseSpecificationRequest]


class ModifyVerifiedAccessEndpointPolicyResult(TypedDict, total=False):
    PolicyEnabled: Optional[Boolean]
    PolicyDocument: Optional[String]
    SseSpecification: Optional[VerifiedAccessSseSpecificationResponse]


class ModifyVerifiedAccessEndpointRequest(ServiceRequest):
    VerifiedAccessEndpointId: VerifiedAccessEndpointId
    VerifiedAccessGroupId: Optional[VerifiedAccessGroupId]
    LoadBalancerOptions: Optional[ModifyVerifiedAccessEndpointLoadBalancerOptions]
    NetworkInterfaceOptions: Optional[ModifyVerifiedAccessEndpointEniOptions]
    Description: Optional[String]
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]


class ModifyVerifiedAccessEndpointResult(TypedDict, total=False):
    VerifiedAccessEndpoint: Optional[VerifiedAccessEndpoint]


class ModifyVerifiedAccessGroupPolicyRequest(ServiceRequest):
    VerifiedAccessGroupId: VerifiedAccessGroupId
    PolicyEnabled: Optional[Boolean]
    PolicyDocument: Optional[String]
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]
    SseSpecification: Optional[VerifiedAccessSseSpecificationRequest]


class ModifyVerifiedAccessGroupPolicyResult(TypedDict, total=False):
    PolicyEnabled: Optional[Boolean]
    PolicyDocument: Optional[String]
    SseSpecification: Optional[VerifiedAccessSseSpecificationResponse]


class ModifyVerifiedAccessGroupRequest(ServiceRequest):
    VerifiedAccessGroupId: VerifiedAccessGroupId
    VerifiedAccessInstanceId: Optional[VerifiedAccessInstanceId]
    Description: Optional[String]
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]


class ModifyVerifiedAccessGroupResult(TypedDict, total=False):
    VerifiedAccessGroup: Optional[VerifiedAccessGroup]


class VerifiedAccessLogKinesisDataFirehoseDestinationOptions(TypedDict, total=False):
    Enabled: Boolean
    DeliveryStream: Optional[String]


class VerifiedAccessLogCloudWatchLogsDestinationOptions(TypedDict, total=False):
    Enabled: Boolean
    LogGroup: Optional[String]


class VerifiedAccessLogS3DestinationOptions(TypedDict, total=False):
    Enabled: Boolean
    BucketName: Optional[String]
    Prefix: Optional[String]
    BucketOwner: Optional[String]


class VerifiedAccessLogOptions(TypedDict, total=False):
    S3: Optional[VerifiedAccessLogS3DestinationOptions]
    CloudWatchLogs: Optional[VerifiedAccessLogCloudWatchLogsDestinationOptions]
    KinesisDataFirehose: Optional[VerifiedAccessLogKinesisDataFirehoseDestinationOptions]
    LogVersion: Optional[String]
    IncludeTrustContext: Optional[Boolean]


class ModifyVerifiedAccessInstanceLoggingConfigurationRequest(ServiceRequest):
    VerifiedAccessInstanceId: VerifiedAccessInstanceId
    AccessLogs: VerifiedAccessLogOptions
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]


class ModifyVerifiedAccessInstanceLoggingConfigurationResult(TypedDict, total=False):
    LoggingConfiguration: Optional[VerifiedAccessInstanceLoggingConfiguration]


class ModifyVerifiedAccessInstanceRequest(ServiceRequest):
    VerifiedAccessInstanceId: VerifiedAccessInstanceId
    Description: Optional[String]
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]


class ModifyVerifiedAccessInstanceResult(TypedDict, total=False):
    VerifiedAccessInstance: Optional[VerifiedAccessInstance]


class ModifyVerifiedAccessTrustProviderDeviceOptions(TypedDict, total=False):
    PublicSigningKeyUrl: Optional[String]


class ModifyVerifiedAccessTrustProviderOidcOptions(TypedDict, total=False):
    Issuer: Optional[String]
    AuthorizationEndpoint: Optional[String]
    TokenEndpoint: Optional[String]
    UserInfoEndpoint: Optional[String]
    ClientId: Optional[String]
    ClientSecret: Optional[ClientSecretType]
    Scope: Optional[String]


class ModifyVerifiedAccessTrustProviderRequest(ServiceRequest):
    VerifiedAccessTrustProviderId: VerifiedAccessTrustProviderId
    OidcOptions: Optional[ModifyVerifiedAccessTrustProviderOidcOptions]
    DeviceOptions: Optional[ModifyVerifiedAccessTrustProviderDeviceOptions]
    Description: Optional[String]
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]
    SseSpecification: Optional[VerifiedAccessSseSpecificationRequest]


class ModifyVerifiedAccessTrustProviderResult(TypedDict, total=False):
    VerifiedAccessTrustProvider: Optional[VerifiedAccessTrustProvider]


class ModifyVolumeAttributeRequest(ServiceRequest):
    AutoEnableIO: Optional[AttributeBooleanValue]
    VolumeId: VolumeId
    DryRun: Optional[Boolean]


class ModifyVolumeRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    VolumeId: VolumeId
    Size: Optional[Integer]
    VolumeType: Optional[VolumeType]
    Iops: Optional[Integer]
    Throughput: Optional[Integer]
    MultiAttachEnabled: Optional[Boolean]


class ModifyVolumeResult(TypedDict, total=False):
    VolumeModification: Optional[VolumeModification]


class ModifyVpcAttributeRequest(ServiceRequest):
    EnableDnsHostnames: Optional[AttributeBooleanValue]
    EnableDnsSupport: Optional[AttributeBooleanValue]
    VpcId: VpcId
    EnableNetworkAddressUsageMetrics: Optional[AttributeBooleanValue]


class ModifyVpcEndpointConnectionNotificationRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ConnectionNotificationId: ConnectionNotificationId
    ConnectionNotificationArn: Optional[String]
    ConnectionEvents: Optional[ValueStringList]


class ModifyVpcEndpointConnectionNotificationResult(TypedDict, total=False):
    ReturnValue: Optional[Boolean]


class ModifyVpcEndpointRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    VpcEndpointId: VpcEndpointId
    ResetPolicy: Optional[Boolean]
    PolicyDocument: Optional[String]
    AddRouteTableIds: Optional[VpcEndpointRouteTableIdList]
    RemoveRouteTableIds: Optional[VpcEndpointRouteTableIdList]
    AddSubnetIds: Optional[VpcEndpointSubnetIdList]
    RemoveSubnetIds: Optional[VpcEndpointSubnetIdList]
    AddSecurityGroupIds: Optional[VpcEndpointSecurityGroupIdList]
    RemoveSecurityGroupIds: Optional[VpcEndpointSecurityGroupIdList]
    IpAddressType: Optional[IpAddressType]
    DnsOptions: Optional[DnsOptionsSpecification]
    PrivateDnsEnabled: Optional[Boolean]
    SubnetConfigurations: Optional[SubnetConfigurationsList]


class ModifyVpcEndpointResult(TypedDict, total=False):
    Return: Optional[Boolean]


class ModifyVpcEndpointServiceConfigurationRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ServiceId: VpcEndpointServiceId
    PrivateDnsName: Optional[String]
    RemovePrivateDnsName: Optional[Boolean]
    AcceptanceRequired: Optional[Boolean]
    AddNetworkLoadBalancerArns: Optional[ValueStringList]
    RemoveNetworkLoadBalancerArns: Optional[ValueStringList]
    AddGatewayLoadBalancerArns: Optional[ValueStringList]
    RemoveGatewayLoadBalancerArns: Optional[ValueStringList]
    AddSupportedIpAddressTypes: Optional[ValueStringList]
    RemoveSupportedIpAddressTypes: Optional[ValueStringList]


class ModifyVpcEndpointServiceConfigurationResult(TypedDict, total=False):
    Return: Optional[Boolean]


class ModifyVpcEndpointServicePayerResponsibilityRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ServiceId: VpcEndpointServiceId
    PayerResponsibility: PayerResponsibility


class ModifyVpcEndpointServicePayerResponsibilityResult(TypedDict, total=False):
    ReturnValue: Optional[Boolean]


class ModifyVpcEndpointServicePermissionsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ServiceId: VpcEndpointServiceId
    AddAllowedPrincipals: Optional[ValueStringList]
    RemoveAllowedPrincipals: Optional[ValueStringList]


class ModifyVpcEndpointServicePermissionsResult(TypedDict, total=False):
    AddedPrincipals: Optional[AddedPrincipalSet]
    ReturnValue: Optional[Boolean]


class PeeringConnectionOptionsRequest(TypedDict, total=False):
    AllowDnsResolutionFromRemoteVpc: Optional[Boolean]
    AllowEgressFromLocalClassicLinkToRemoteVpc: Optional[Boolean]
    AllowEgressFromLocalVpcToRemoteClassicLink: Optional[Boolean]


class ModifyVpcPeeringConnectionOptionsRequest(ServiceRequest):
    AccepterPeeringConnectionOptions: Optional[PeeringConnectionOptionsRequest]
    DryRun: Optional[Boolean]
    RequesterPeeringConnectionOptions: Optional[PeeringConnectionOptionsRequest]
    VpcPeeringConnectionId: VpcPeeringConnectionId


class PeeringConnectionOptions(TypedDict, total=False):
    AllowDnsResolutionFromRemoteVpc: Optional[Boolean]
    AllowEgressFromLocalClassicLinkToRemoteVpc: Optional[Boolean]
    AllowEgressFromLocalVpcToRemoteClassicLink: Optional[Boolean]


class ModifyVpcPeeringConnectionOptionsResult(TypedDict, total=False):
    AccepterPeeringConnectionOptions: Optional[PeeringConnectionOptions]
    RequesterPeeringConnectionOptions: Optional[PeeringConnectionOptions]


class ModifyVpcTenancyRequest(ServiceRequest):
    VpcId: VpcId
    InstanceTenancy: VpcTenancy
    DryRun: Optional[Boolean]


class ModifyVpcTenancyResult(TypedDict, total=False):
    ReturnValue: Optional[Boolean]


class ModifyVpnConnectionOptionsRequest(ServiceRequest):
    VpnConnectionId: VpnConnectionId
    LocalIpv4NetworkCidr: Optional[String]
    RemoteIpv4NetworkCidr: Optional[String]
    LocalIpv6NetworkCidr: Optional[String]
    RemoteIpv6NetworkCidr: Optional[String]
    DryRun: Optional[Boolean]


class ModifyVpnConnectionOptionsResult(TypedDict, total=False):
    VpnConnection: Optional[VpnConnection]


class ModifyVpnConnectionRequest(ServiceRequest):
    VpnConnectionId: VpnConnectionId
    TransitGatewayId: Optional[TransitGatewayId]
    CustomerGatewayId: Optional[CustomerGatewayId]
    VpnGatewayId: Optional[VpnGatewayId]
    DryRun: Optional[Boolean]


class ModifyVpnConnectionResult(TypedDict, total=False):
    VpnConnection: Optional[VpnConnection]


class ModifyVpnTunnelCertificateRequest(ServiceRequest):
    VpnConnectionId: VpnConnectionId
    VpnTunnelOutsideIpAddress: String
    DryRun: Optional[Boolean]


class ModifyVpnTunnelCertificateResult(TypedDict, total=False):
    VpnConnection: Optional[VpnConnection]


class ModifyVpnTunnelOptionsSpecification(TypedDict, total=False):
    TunnelInsideCidr: Optional[String]
    TunnelInsideIpv6Cidr: Optional[String]
    PreSharedKey: Optional[preSharedKey]
    Phase1LifetimeSeconds: Optional[Integer]
    Phase2LifetimeSeconds: Optional[Integer]
    RekeyMarginTimeSeconds: Optional[Integer]
    RekeyFuzzPercentage: Optional[Integer]
    ReplayWindowSize: Optional[Integer]
    DPDTimeoutSeconds: Optional[Integer]
    DPDTimeoutAction: Optional[String]
    Phase1EncryptionAlgorithms: Optional[Phase1EncryptionAlgorithmsRequestList]
    Phase2EncryptionAlgorithms: Optional[Phase2EncryptionAlgorithmsRequestList]
    Phase1IntegrityAlgorithms: Optional[Phase1IntegrityAlgorithmsRequestList]
    Phase2IntegrityAlgorithms: Optional[Phase2IntegrityAlgorithmsRequestList]
    Phase1DHGroupNumbers: Optional[Phase1DHGroupNumbersRequestList]
    Phase2DHGroupNumbers: Optional[Phase2DHGroupNumbersRequestList]
    IKEVersions: Optional[IKEVersionsRequestList]
    StartupAction: Optional[String]
    LogOptions: Optional[VpnTunnelLogOptionsSpecification]
    EnableTunnelLifecycleControl: Optional[Boolean]


class ModifyVpnTunnelOptionsRequest(ServiceRequest):
    VpnConnectionId: VpnConnectionId
    VpnTunnelOutsideIpAddress: String
    TunnelOptions: ModifyVpnTunnelOptionsSpecification
    DryRun: Optional[Boolean]
    SkipTunnelReplacement: Optional[Boolean]


class ModifyVpnTunnelOptionsResult(TypedDict, total=False):
    VpnConnection: Optional[VpnConnection]


class MonitorInstancesRequest(ServiceRequest):
    InstanceIds: InstanceIdStringList
    DryRun: Optional[Boolean]


class MonitorInstancesResult(TypedDict, total=False):
    InstanceMonitorings: Optional[InstanceMonitoringList]


class MoveAddressToVpcRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    PublicIp: String


class MoveAddressToVpcResult(TypedDict, total=False):
    AllocationId: Optional[String]
    Status: Optional[Status]


class MoveByoipCidrToIpamRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Cidr: String
    IpamPoolId: IpamPoolId
    IpamPoolOwner: String


class MoveByoipCidrToIpamResult(TypedDict, total=False):
    ByoipCidr: Optional[ByoipCidr]


class MoveCapacityReservationInstancesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ClientToken: Optional[String]
    SourceCapacityReservationId: CapacityReservationId
    DestinationCapacityReservationId: CapacityReservationId
    InstanceCount: Integer


class MoveCapacityReservationInstancesResult(TypedDict, total=False):
    SourceCapacityReservation: Optional[CapacityReservation]
    DestinationCapacityReservation: Optional[CapacityReservation]
    InstanceCount: Optional[Integer]


class PrivateDnsNameOptionsRequest(TypedDict, total=False):
    HostnameType: Optional[HostnameType]
    EnableResourceNameDnsARecord: Optional[Boolean]
    EnableResourceNameDnsAAAARecord: Optional[Boolean]


class ScheduledInstancesPrivateIpAddressConfig(TypedDict, total=False):
    Primary: Optional[Boolean]
    PrivateIpAddress: Optional[String]


PrivateIpAddressConfigSet = List[ScheduledInstancesPrivateIpAddressConfig]


class ProvisionByoipCidrRequest(ServiceRequest):
    Cidr: String
    CidrAuthorizationContext: Optional[CidrAuthorizationContext]
    PubliclyAdvertisable: Optional[Boolean]
    Description: Optional[String]
    DryRun: Optional[Boolean]
    PoolTagSpecifications: Optional[TagSpecificationList]
    MultiRegion: Optional[Boolean]
    NetworkBorderGroup: Optional[String]


class ProvisionByoipCidrResult(TypedDict, total=False):
    ByoipCidr: Optional[ByoipCidr]


class ProvisionIpamByoasnRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamId: IpamId
    Asn: String
    AsnAuthorizationContext: AsnAuthorizationContext


class ProvisionIpamByoasnResult(TypedDict, total=False):
    Byoasn: Optional[Byoasn]


class ProvisionIpamPoolCidrRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamPoolId: IpamPoolId
    Cidr: Optional[String]
    CidrAuthorizationContext: Optional[IpamCidrAuthorizationContext]
    NetmaskLength: Optional[Integer]
    ClientToken: Optional[String]
    VerificationMethod: Optional[VerificationMethod]
    IpamExternalResourceVerificationTokenId: Optional[IpamExternalResourceVerificationTokenId]


class ProvisionIpamPoolCidrResult(TypedDict, total=False):
    IpamPoolCidr: Optional[IpamPoolCidr]


class ProvisionPublicIpv4PoolCidrRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamPoolId: IpamPoolId
    PoolId: Ipv4PoolEc2Id
    NetmaskLength: Integer
    NetworkBorderGroup: Optional[String]


class ProvisionPublicIpv4PoolCidrResult(TypedDict, total=False):
    PoolId: Optional[Ipv4PoolEc2Id]
    PoolAddressRange: Optional[PublicIpv4PoolRange]


class PurchaseCapacityBlockRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    TagSpecifications: Optional[TagSpecificationList]
    CapacityBlockOfferingId: OfferingId
    InstancePlatform: CapacityReservationInstancePlatform


class PurchaseCapacityBlockResult(TypedDict, total=False):
    CapacityReservation: Optional[CapacityReservation]


class PurchaseHostReservationRequest(ServiceRequest):
    ClientToken: Optional[String]
    CurrencyCode: Optional[CurrencyCodeValues]
    HostIdSet: RequestHostIdSet
    LimitPrice: Optional[String]
    OfferingId: OfferingId
    TagSpecifications: Optional[TagSpecificationList]


class PurchaseHostReservationResult(TypedDict, total=False):
    ClientToken: Optional[String]
    CurrencyCode: Optional[CurrencyCodeValues]
    Purchase: Optional[PurchaseSet]
    TotalHourlyPrice: Optional[String]
    TotalUpfrontPrice: Optional[String]


class PurchaseRequest(TypedDict, total=False):
    InstanceCount: Integer
    PurchaseToken: String


PurchaseRequestSet = List[PurchaseRequest]


class ReservedInstanceLimitPrice(TypedDict, total=False):
    Amount: Optional[Double]
    CurrencyCode: Optional[CurrencyCodeValues]


class PurchaseReservedInstancesOfferingRequest(ServiceRequest):
    InstanceCount: Integer
    ReservedInstancesOfferingId: ReservedInstancesOfferingId
    PurchaseTime: Optional[DateTime]
    DryRun: Optional[Boolean]
    LimitPrice: Optional[ReservedInstanceLimitPrice]


class PurchaseReservedInstancesOfferingResult(TypedDict, total=False):
    ReservedInstancesId: Optional[String]


class PurchaseScheduledInstancesRequest(ServiceRequest):
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]
    PurchaseRequests: PurchaseRequestSet


PurchasedScheduledInstanceSet = List[ScheduledInstance]


class PurchaseScheduledInstancesResult(TypedDict, total=False):
    ScheduledInstanceSet: Optional[PurchasedScheduledInstanceSet]


ReasonCodesList = List[ReportInstanceReasonCodes]


class RebootInstancesRequest(ServiceRequest):
    InstanceIds: InstanceIdStringList
    DryRun: Optional[Boolean]


class RegisterImageRequest(ServiceRequest):
    ImageLocation: Optional[String]
    BillingProducts: Optional[BillingProductList]
    BootMode: Optional[BootModeValues]
    TpmSupport: Optional[TpmSupportValues]
    UefiData: Optional[StringType]
    ImdsSupport: Optional[ImdsSupportValues]
    TagSpecifications: Optional[TagSpecificationList]
    DryRun: Optional[Boolean]
    Name: String
    Description: Optional[String]
    Architecture: Optional[ArchitectureValues]
    KernelId: Optional[KernelId]
    RamdiskId: Optional[RamdiskId]
    RootDeviceName: Optional[String]
    BlockDeviceMappings: Optional[BlockDeviceMappingRequestList]
    VirtualizationType: Optional[String]
    SriovNetSupport: Optional[String]
    EnaSupport: Optional[Boolean]


class RegisterImageResult(TypedDict, total=False):
    ImageId: Optional[String]


class RegisterInstanceTagAttributeRequest(TypedDict, total=False):
    IncludeAllTagsOfInstance: Optional[Boolean]
    InstanceTagKeys: Optional[InstanceTagKeySet]


class RegisterInstanceEventNotificationAttributesRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceTagAttribute: RegisterInstanceTagAttributeRequest


class RegisterInstanceEventNotificationAttributesResult(TypedDict, total=False):
    InstanceTagAttribute: Optional[InstanceTagNotificationAttribute]


class RegisterTransitGatewayMulticastGroupMembersRequest(ServiceRequest):
    TransitGatewayMulticastDomainId: TransitGatewayMulticastDomainId
    GroupIpAddress: Optional[String]
    NetworkInterfaceIds: TransitGatewayNetworkInterfaceIdList
    DryRun: Optional[Boolean]


class TransitGatewayMulticastRegisteredGroupMembers(TypedDict, total=False):
    TransitGatewayMulticastDomainId: Optional[String]
    RegisteredNetworkInterfaceIds: Optional[ValueStringList]
    GroupIpAddress: Optional[String]


class RegisterTransitGatewayMulticastGroupMembersResult(TypedDict, total=False):
    RegisteredMulticastGroupMembers: Optional[TransitGatewayMulticastRegisteredGroupMembers]


class RegisterTransitGatewayMulticastGroupSourcesRequest(ServiceRequest):
    TransitGatewayMulticastDomainId: TransitGatewayMulticastDomainId
    GroupIpAddress: Optional[String]
    NetworkInterfaceIds: TransitGatewayNetworkInterfaceIdList
    DryRun: Optional[Boolean]


class TransitGatewayMulticastRegisteredGroupSources(TypedDict, total=False):
    TransitGatewayMulticastDomainId: Optional[String]
    RegisteredNetworkInterfaceIds: Optional[ValueStringList]
    GroupIpAddress: Optional[String]


class RegisterTransitGatewayMulticastGroupSourcesResult(TypedDict, total=False):
    RegisteredMulticastGroupSources: Optional[TransitGatewayMulticastRegisteredGroupSources]


class RejectCapacityReservationBillingOwnershipRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    CapacityReservationId: CapacityReservationId


class RejectCapacityReservationBillingOwnershipResult(TypedDict, total=False):
    Return: Optional[Boolean]


class RejectTransitGatewayMulticastDomainAssociationsRequest(ServiceRequest):
    TransitGatewayMulticastDomainId: Optional[TransitGatewayMulticastDomainId]
    TransitGatewayAttachmentId: Optional[TransitGatewayAttachmentId]
    SubnetIds: Optional[ValueStringList]
    DryRun: Optional[Boolean]


class RejectTransitGatewayMulticastDomainAssociationsResult(TypedDict, total=False):
    Associations: Optional[TransitGatewayMulticastDomainAssociations]


class RejectTransitGatewayPeeringAttachmentRequest(ServiceRequest):
    TransitGatewayAttachmentId: TransitGatewayAttachmentId
    DryRun: Optional[Boolean]


class RejectTransitGatewayPeeringAttachmentResult(TypedDict, total=False):
    TransitGatewayPeeringAttachment: Optional[TransitGatewayPeeringAttachment]


class RejectTransitGatewayVpcAttachmentRequest(ServiceRequest):
    TransitGatewayAttachmentId: TransitGatewayAttachmentId
    DryRun: Optional[Boolean]


class RejectTransitGatewayVpcAttachmentResult(TypedDict, total=False):
    TransitGatewayVpcAttachment: Optional[TransitGatewayVpcAttachment]


class RejectVpcEndpointConnectionsRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ServiceId: VpcEndpointServiceId
    VpcEndpointIds: VpcEndpointIdList


class RejectVpcEndpointConnectionsResult(TypedDict, total=False):
    Unsuccessful: Optional[UnsuccessfulItemSet]


class RejectVpcPeeringConnectionRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    VpcPeeringConnectionId: VpcPeeringConnectionId


class RejectVpcPeeringConnectionResult(TypedDict, total=False):
    Return: Optional[Boolean]


class ReleaseAddressRequest(ServiceRequest):
    AllocationId: Optional[AllocationId]
    PublicIp: Optional[String]
    NetworkBorderGroup: Optional[String]
    DryRun: Optional[Boolean]


class ReleaseHostsRequest(ServiceRequest):
    HostIds: RequestHostIdList


class ReleaseHostsResult(TypedDict, total=False):
    Successful: Optional[ResponseHostIdList]
    Unsuccessful: Optional[UnsuccessfulItemList]


class ReleaseIpamPoolAllocationRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    IpamPoolId: IpamPoolId
    Cidr: String
    IpamPoolAllocationId: IpamPoolAllocationId


class ReleaseIpamPoolAllocationResult(TypedDict, total=False):
    Success: Optional[Boolean]


class ReplaceIamInstanceProfileAssociationRequest(ServiceRequest):
    IamInstanceProfile: IamInstanceProfileSpecification
    AssociationId: IamInstanceProfileAssociationId


class ReplaceIamInstanceProfileAssociationResult(TypedDict, total=False):
    IamInstanceProfileAssociation: Optional[IamInstanceProfileAssociation]


class ReplaceNetworkAclAssociationRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    AssociationId: NetworkAclAssociationId
    NetworkAclId: NetworkAclId


class ReplaceNetworkAclAssociationResult(TypedDict, total=False):
    NewAssociationId: Optional[String]


class ReplaceNetworkAclEntryRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    NetworkAclId: NetworkAclId
    RuleNumber: Integer
    Protocol: String
    RuleAction: RuleAction
    Egress: Boolean
    CidrBlock: Optional[String]
    Ipv6CidrBlock: Optional[String]
    IcmpTypeCode: Optional[IcmpTypeCode]
    PortRange: Optional[PortRange]


class ReplaceRouteRequest(ServiceRequest):
    DestinationPrefixListId: Optional[PrefixListResourceId]
    VpcEndpointId: Optional[VpcEndpointId]
    LocalTarget: Optional[Boolean]
    TransitGatewayId: Optional[TransitGatewayId]
    LocalGatewayId: Optional[LocalGatewayId]
    CarrierGatewayId: Optional[CarrierGatewayId]
    CoreNetworkArn: Optional[CoreNetworkArn]
    DryRun: Optional[Boolean]
    RouteTableId: RouteTableId
    DestinationCidrBlock: Optional[String]
    GatewayId: Optional[RouteGatewayId]
    DestinationIpv6CidrBlock: Optional[String]
    EgressOnlyInternetGatewayId: Optional[EgressOnlyInternetGatewayId]
    InstanceId: Optional[InstanceId]
    NetworkInterfaceId: Optional[NetworkInterfaceId]
    VpcPeeringConnectionId: Optional[VpcPeeringConnectionId]
    NatGatewayId: Optional[NatGatewayId]


class ReplaceRouteTableAssociationRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    AssociationId: RouteTableAssociationId
    RouteTableId: RouteTableId


class ReplaceRouteTableAssociationResult(TypedDict, total=False):
    NewAssociationId: Optional[String]
    AssociationState: Optional[RouteTableAssociationState]


class ReplaceTransitGatewayRouteRequest(ServiceRequest):
    DestinationCidrBlock: String
    TransitGatewayRouteTableId: TransitGatewayRouteTableId
    TransitGatewayAttachmentId: Optional[TransitGatewayAttachmentId]
    Blackhole: Optional[Boolean]
    DryRun: Optional[Boolean]


class ReplaceTransitGatewayRouteResult(TypedDict, total=False):
    Route: Optional[TransitGatewayRoute]


class ReplaceVpnTunnelRequest(ServiceRequest):
    VpnConnectionId: VpnConnectionId
    VpnTunnelOutsideIpAddress: String
    ApplyPendingMaintenance: Optional[Boolean]
    DryRun: Optional[Boolean]


class ReplaceVpnTunnelResult(TypedDict, total=False):
    Return: Optional[Boolean]


class ReportInstanceStatusRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    Instances: InstanceIdStringList
    Status: ReportStatusType
    StartTime: Optional[DateTime]
    EndTime: Optional[DateTime]
    ReasonCodes: ReasonCodesList
    Description: Optional[ReportInstanceStatusRequestDescription]


class RequestSpotFleetRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    SpotFleetRequestConfig: SpotFleetRequestConfigData


class RequestSpotFleetResponse(TypedDict, total=False):
    SpotFleetRequestId: Optional[String]


RequestSpotLaunchSpecificationSecurityGroupList = List[String]
RequestSpotLaunchSpecificationSecurityGroupIdList = List[SecurityGroupId]


class RequestSpotLaunchSpecification(TypedDict, total=False):
    SecurityGroupIds: Optional[RequestSpotLaunchSpecificationSecurityGroupIdList]
    SecurityGroups: Optional[RequestSpotLaunchSpecificationSecurityGroupList]
    AddressingType: Optional[String]
    BlockDeviceMappings: Optional[BlockDeviceMappingList]
    EbsOptimized: Optional[Boolean]
    IamInstanceProfile: Optional[IamInstanceProfileSpecification]
    ImageId: Optional[ImageId]
    InstanceType: Optional[InstanceType]
    KernelId: Optional[KernelId]
    KeyName: Optional[KeyPairNameWithResolver]
    Monitoring: Optional[RunInstancesMonitoringEnabled]
    NetworkInterfaces: Optional[InstanceNetworkInterfaceSpecificationList]
    Placement: Optional[SpotPlacement]
    RamdiskId: Optional[RamdiskId]
    SubnetId: Optional[SubnetId]
    UserData: Optional[SensitiveUserData]


class RequestSpotInstancesRequest(ServiceRequest):
    LaunchSpecification: Optional[RequestSpotLaunchSpecification]
    TagSpecifications: Optional[TagSpecificationList]
    InstanceInterruptionBehavior: Optional[InstanceInterruptionBehavior]
    DryRun: Optional[Boolean]
    SpotPrice: Optional[String]
    ClientToken: Optional[String]
    InstanceCount: Optional[Integer]
    Type: Optional[SpotInstanceType]
    ValidFrom: Optional[DateTime]
    ValidUntil: Optional[DateTime]
    LaunchGroup: Optional[String]
    AvailabilityZoneGroup: Optional[String]
    BlockDurationMinutes: Optional[Integer]


class RequestSpotInstancesResult(TypedDict, total=False):
    SpotInstanceRequests: Optional[SpotInstanceRequestList]


class ResetAddressAttributeRequest(ServiceRequest):
    AllocationId: AllocationId
    Attribute: AddressAttributeName
    DryRun: Optional[Boolean]


class ResetAddressAttributeResult(TypedDict, total=False):
    Address: Optional[AddressAttribute]


class ResetEbsDefaultKmsKeyIdRequest(ServiceRequest):
    DryRun: Optional[Boolean]


class ResetEbsDefaultKmsKeyIdResult(TypedDict, total=False):
    KmsKeyId: Optional[String]


class ResetFpgaImageAttributeRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    FpgaImageId: FpgaImageId
    Attribute: Optional[ResetFpgaImageAttributeName]


class ResetFpgaImageAttributeResult(TypedDict, total=False):
    Return: Optional[Boolean]


class ResetImageAttributeRequest(ServiceRequest):
    Attribute: ResetImageAttributeName
    ImageId: ImageId
    DryRun: Optional[Boolean]


class ResetInstanceAttributeRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    InstanceId: InstanceId
    Attribute: InstanceAttributeName


class ResetNetworkInterfaceAttributeRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    NetworkInterfaceId: NetworkInterfaceId
    SourceDestCheck: Optional[String]


class ResetSnapshotAttributeRequest(ServiceRequest):
    Attribute: SnapshotAttributeName
    SnapshotId: SnapshotId
    DryRun: Optional[Boolean]


class RestoreAddressToClassicRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    PublicIp: String


class RestoreAddressToClassicResult(TypedDict, total=False):
    PublicIp: Optional[String]
    Status: Optional[Status]


class RestoreImageFromRecycleBinRequest(ServiceRequest):
    ImageId: ImageId
    DryRun: Optional[Boolean]


class RestoreImageFromRecycleBinResult(TypedDict, total=False):
    Return: Optional[Boolean]


class RestoreManagedPrefixListVersionRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    PrefixListId: PrefixListResourceId
    PreviousVersion: Long
    CurrentVersion: Long


class RestoreManagedPrefixListVersionResult(TypedDict, total=False):
    PrefixList: Optional[ManagedPrefixList]


class RestoreSnapshotFromRecycleBinRequest(ServiceRequest):
    SnapshotId: SnapshotId
    DryRun: Optional[Boolean]


class RestoreSnapshotFromRecycleBinResult(TypedDict, total=False):
    SnapshotId: Optional[String]
    OutpostArn: Optional[String]
    Description: Optional[String]
    Encrypted: Optional[Boolean]
    OwnerId: Optional[String]
    Progress: Optional[String]
    StartTime: Optional[MillisecondDateTime]
    State: Optional[SnapshotState]
    VolumeId: Optional[String]
    VolumeSize: Optional[Integer]
    SseType: Optional[SSEType]


class RestoreSnapshotTierRequest(ServiceRequest):
    SnapshotId: SnapshotId
    TemporaryRestoreDays: Optional[RestoreSnapshotTierRequestTemporaryRestoreDays]
    PermanentRestore: Optional[Boolean]
    DryRun: Optional[Boolean]


class RestoreSnapshotTierResult(TypedDict, total=False):
    SnapshotId: Optional[String]
    RestoreStartTime: Optional[MillisecondDateTime]
    RestoreDuration: Optional[Integer]
    IsPermanentRestore: Optional[Boolean]


class RevokeClientVpnIngressRequest(ServiceRequest):
    ClientVpnEndpointId: ClientVpnEndpointId
    TargetNetworkCidr: String
    AccessGroupId: Optional[String]
    RevokeAllGroups: Optional[Boolean]
    DryRun: Optional[Boolean]


class RevokeClientVpnIngressResult(TypedDict, total=False):
    Status: Optional[ClientVpnAuthorizationRuleStatus]


class RevokeSecurityGroupEgressRequest(ServiceRequest):
    SecurityGroupRuleIds: Optional[SecurityGroupRuleIdList]
    DryRun: Optional[Boolean]
    GroupId: SecurityGroupId
    SourceSecurityGroupName: Optional[String]
    SourceSecurityGroupOwnerId: Optional[String]
    IpProtocol: Optional[String]
    FromPort: Optional[Integer]
    ToPort: Optional[Integer]
    CidrIp: Optional[String]
    IpPermissions: Optional[IpPermissionList]


class RevokedSecurityGroupRule(TypedDict, total=False):
    SecurityGroupRuleId: Optional[SecurityGroupRuleId]
    GroupId: Optional[SecurityGroupId]
    IsEgress: Optional[Boolean]
    IpProtocol: Optional[String]
    FromPort: Optional[Integer]
    ToPort: Optional[Integer]
    CidrIpv4: Optional[String]
    CidrIpv6: Optional[String]
    PrefixListId: Optional[PrefixListResourceId]
    ReferencedGroupId: Optional[SecurityGroupId]
    Description: Optional[String]


RevokedSecurityGroupRuleList = List[RevokedSecurityGroupRule]


class RevokeSecurityGroupEgressResult(TypedDict, total=False):
    Return: Optional[Boolean]
    UnknownIpPermissions: Optional[IpPermissionList]
    RevokedSecurityGroupRules: Optional[RevokedSecurityGroupRuleList]


class RevokeSecurityGroupIngressRequest(ServiceRequest):
    CidrIp: Optional[String]
    FromPort: Optional[Integer]
    GroupId: Optional[SecurityGroupId]
    GroupName: Optional[SecurityGroupName]
    IpPermissions: Optional[IpPermissionList]
    IpProtocol: Optional[String]
    SourceSecurityGroupName: Optional[String]
    SourceSecurityGroupOwnerId: Optional[String]
    ToPort: Optional[Integer]
    SecurityGroupRuleIds: Optional[SecurityGroupRuleIdList]
    DryRun: Optional[Boolean]


class RevokeSecurityGroupIngressResult(TypedDict, total=False):
    Return: Optional[Boolean]
    UnknownIpPermissions: Optional[IpPermissionList]
    RevokedSecurityGroupRules: Optional[RevokedSecurityGroupRuleList]


class RunInstancesRequest(ServiceRequest):
    BlockDeviceMappings: Optional[BlockDeviceMappingRequestList]
    ImageId: Optional[ImageId]
    InstanceType: Optional[InstanceType]
    Ipv6AddressCount: Optional[Integer]
    Ipv6Addresses: Optional[InstanceIpv6AddressList]
    KernelId: Optional[KernelId]
    KeyName: Optional[KeyPairName]
    MaxCount: Integer
    MinCount: Integer
    Monitoring: Optional[RunInstancesMonitoringEnabled]
    Placement: Optional[Placement]
    RamdiskId: Optional[RamdiskId]
    SecurityGroupIds: Optional[SecurityGroupIdStringList]
    SecurityGroups: Optional[SecurityGroupStringList]
    SubnetId: Optional[SubnetId]
    UserData: Optional[RunInstancesUserData]
    ElasticGpuSpecification: Optional[ElasticGpuSpecifications]
    ElasticInferenceAccelerators: Optional[ElasticInferenceAccelerators]
    TagSpecifications: Optional[TagSpecificationList]
    LaunchTemplate: Optional[LaunchTemplateSpecification]
    InstanceMarketOptions: Optional[InstanceMarketOptionsRequest]
    CreditSpecification: Optional[CreditSpecificationRequest]
    CpuOptions: Optional[CpuOptionsRequest]
    CapacityReservationSpecification: Optional[CapacityReservationSpecification]
    HibernationOptions: Optional[HibernationOptionsRequest]
    LicenseSpecifications: Optional[LicenseSpecificationListRequest]
    MetadataOptions: Optional[InstanceMetadataOptionsRequest]
    EnclaveOptions: Optional[EnclaveOptionsRequest]
    PrivateDnsNameOptions: Optional[PrivateDnsNameOptionsRequest]
    MaintenanceOptions: Optional[InstanceMaintenanceOptionsRequest]
    DisableApiStop: Optional[Boolean]
    EnablePrimaryIpv6: Optional[Boolean]
    DryRun: Optional[Boolean]
    DisableApiTermination: Optional[Boolean]
    InstanceInitiatedShutdownBehavior: Optional[ShutdownBehavior]
    PrivateIpAddress: Optional[String]
    ClientToken: Optional[String]
    AdditionalInfo: Optional[String]
    NetworkInterfaces: Optional[InstanceNetworkInterfaceSpecificationList]
    IamInstanceProfile: Optional[IamInstanceProfileSpecification]
    EbsOptimized: Optional[Boolean]


ScheduledInstancesSecurityGroupIdSet = List[SecurityGroupId]


class ScheduledInstancesPlacement(TypedDict, total=False):
    AvailabilityZone: Optional[String]
    GroupName: Optional[PlacementGroupName]


class ScheduledInstancesIpv6Address(TypedDict, total=False):
    Ipv6Address: Optional[Ipv6Address]


ScheduledInstancesIpv6AddressList = List[ScheduledInstancesIpv6Address]


class ScheduledInstancesNetworkInterface(TypedDict, total=False):
    AssociatePublicIpAddress: Optional[Boolean]
    DeleteOnTermination: Optional[Boolean]
    Description: Optional[String]
    DeviceIndex: Optional[Integer]
    Groups: Optional[ScheduledInstancesSecurityGroupIdSet]
    Ipv6AddressCount: Optional[Integer]
    Ipv6Addresses: Optional[ScheduledInstancesIpv6AddressList]
    NetworkInterfaceId: Optional[NetworkInterfaceId]
    PrivateIpAddress: Optional[String]
    PrivateIpAddressConfigs: Optional[PrivateIpAddressConfigSet]
    SecondaryPrivateIpAddressCount: Optional[Integer]
    SubnetId: Optional[SubnetId]


ScheduledInstancesNetworkInterfaceSet = List[ScheduledInstancesNetworkInterface]


class ScheduledInstancesMonitoring(TypedDict, total=False):
    Enabled: Optional[Boolean]


class ScheduledInstancesIamInstanceProfile(TypedDict, total=False):
    Arn: Optional[String]
    Name: Optional[String]


class ScheduledInstancesEbs(TypedDict, total=False):
    DeleteOnTermination: Optional[Boolean]
    Encrypted: Optional[Boolean]
    Iops: Optional[Integer]
    SnapshotId: Optional[SnapshotId]
    VolumeSize: Optional[Integer]
    VolumeType: Optional[String]


class ScheduledInstancesBlockDeviceMapping(TypedDict, total=False):
    DeviceName: Optional[String]
    Ebs: Optional[ScheduledInstancesEbs]
    NoDevice: Optional[String]
    VirtualName: Optional[String]


ScheduledInstancesBlockDeviceMappingSet = List[ScheduledInstancesBlockDeviceMapping]


class ScheduledInstancesLaunchSpecification(TypedDict, total=False):
    BlockDeviceMappings: Optional[ScheduledInstancesBlockDeviceMappingSet]
    EbsOptimized: Optional[Boolean]
    IamInstanceProfile: Optional[ScheduledInstancesIamInstanceProfile]
    ImageId: ImageId
    InstanceType: Optional[String]
    KernelId: Optional[KernelId]
    KeyName: Optional[KeyPairName]
    Monitoring: Optional[ScheduledInstancesMonitoring]
    NetworkInterfaces: Optional[ScheduledInstancesNetworkInterfaceSet]
    Placement: Optional[ScheduledInstancesPlacement]
    RamdiskId: Optional[RamdiskId]
    SecurityGroupIds: Optional[ScheduledInstancesSecurityGroupIdSet]
    SubnetId: Optional[SubnetId]
    UserData: Optional[String]


class RunScheduledInstancesRequest(ServiceRequest):
    ClientToken: Optional[String]
    DryRun: Optional[Boolean]
    InstanceCount: Optional[Integer]
    LaunchSpecification: ScheduledInstancesLaunchSpecification
    ScheduledInstanceId: ScheduledInstanceId


class RunScheduledInstancesResult(TypedDict, total=False):
    InstanceIdSet: Optional[InstanceIdSet]


class SearchLocalGatewayRoutesRequest(ServiceRequest):
    LocalGatewayRouteTableId: LocalGatewayRoutetableId
    Filters: Optional[FilterList]
    MaxResults: Optional[MaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


class SearchLocalGatewayRoutesResult(TypedDict, total=False):
    Routes: Optional[LocalGatewayRouteList]
    NextToken: Optional[String]


class SearchTransitGatewayMulticastGroupsRequest(ServiceRequest):
    TransitGatewayMulticastDomainId: TransitGatewayMulticastDomainId
    Filters: Optional[FilterList]
    MaxResults: Optional[TransitGatewayMaxResults]
    NextToken: Optional[String]
    DryRun: Optional[Boolean]


class TransitGatewayMulticastGroup(TypedDict, total=False):
    GroupIpAddress: Optional[String]
    TransitGatewayAttachmentId: Optional[String]
    SubnetId: Optional[String]
    ResourceId: Optional[String]
    ResourceType: Optional[TransitGatewayAttachmentResourceType]
    ResourceOwnerId: Optional[String]
    NetworkInterfaceId: Optional[String]
    GroupMember: Optional[Boolean]
    GroupSource: Optional[Boolean]
    MemberType: Optional[MembershipType]
    SourceType: Optional[MembershipType]


TransitGatewayMulticastGroupList = List[TransitGatewayMulticastGroup]


class SearchTransitGatewayMulticastGroupsResult(TypedDict, total=False):
    MulticastGroups: Optional[TransitGatewayMulticastGroupList]
    NextToken: Optional[String]


class SearchTransitGatewayRoutesRequest(ServiceRequest):
    TransitGatewayRouteTableId: TransitGatewayRouteTableId
    Filters: FilterList
    MaxResults: Optional[TransitGatewayMaxResults]
    DryRun: Optional[Boolean]


TransitGatewayRouteList = List[TransitGatewayRoute]


class SearchTransitGatewayRoutesResult(TypedDict, total=False):
    Routes: Optional[TransitGatewayRouteList]
    AdditionalRoutesAvailable: Optional[Boolean]


class SecurityGroupRuleDescription(TypedDict, total=False):
    SecurityGroupRuleId: Optional[String]
    Description: Optional[String]


SecurityGroupRuleDescriptionList = List[SecurityGroupRuleDescription]


class SendDiagnosticInterruptRequest(ServiceRequest):
    InstanceId: InstanceId
    DryRun: Optional[Boolean]


class StartInstancesRequest(ServiceRequest):
    InstanceIds: InstanceIdStringList
    AdditionalInfo: Optional[String]
    DryRun: Optional[Boolean]


class StartInstancesResult(TypedDict, total=False):
    StartingInstances: Optional[InstanceStateChangeList]


class StartNetworkInsightsAccessScopeAnalysisRequest(ServiceRequest):
    NetworkInsightsAccessScopeId: NetworkInsightsAccessScopeId
    DryRun: Optional[Boolean]
    TagSpecifications: Optional[TagSpecificationList]
    ClientToken: String


class StartNetworkInsightsAccessScopeAnalysisResult(TypedDict, total=False):
    NetworkInsightsAccessScopeAnalysis: Optional[NetworkInsightsAccessScopeAnalysis]


class StartNetworkInsightsAnalysisRequest(ServiceRequest):
    NetworkInsightsPathId: NetworkInsightsPathId
    AdditionalAccounts: Optional[ValueStringList]
    FilterInArns: Optional[ArnList]
    DryRun: Optional[Boolean]
    TagSpecifications: Optional[TagSpecificationList]
    ClientToken: String


class StartNetworkInsightsAnalysisResult(TypedDict, total=False):
    NetworkInsightsAnalysis: Optional[NetworkInsightsAnalysis]


class StartVpcEndpointServicePrivateDnsVerificationRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    ServiceId: VpcEndpointServiceId


class StartVpcEndpointServicePrivateDnsVerificationResult(TypedDict, total=False):
    ReturnValue: Optional[Boolean]


class StopInstancesRequest(ServiceRequest):
    InstanceIds: InstanceIdStringList
    Hibernate: Optional[Boolean]
    DryRun: Optional[Boolean]
    Force: Optional[Boolean]


class StopInstancesResult(TypedDict, total=False):
    StoppingInstances: Optional[InstanceStateChangeList]


class TerminateClientVpnConnectionsRequest(ServiceRequest):
    ClientVpnEndpointId: ClientVpnEndpointId
    ConnectionId: Optional[String]
    Username: Optional[String]
    DryRun: Optional[Boolean]


class TerminateConnectionStatus(TypedDict, total=False):
    ConnectionId: Optional[String]
    PreviousStatus: Optional[ClientVpnConnectionStatus]
    CurrentStatus: Optional[ClientVpnConnectionStatus]


TerminateConnectionStatusSet = List[TerminateConnectionStatus]


class TerminateClientVpnConnectionsResult(TypedDict, total=False):
    ClientVpnEndpointId: Optional[String]
    Username: Optional[String]
    ConnectionStatuses: Optional[TerminateConnectionStatusSet]


class TerminateInstancesRequest(ServiceRequest):
    InstanceIds: InstanceIdStringList
    DryRun: Optional[Boolean]


class TerminateInstancesResult(TypedDict, total=False):
    TerminatingInstances: Optional[InstanceStateChangeList]


class UnassignIpv6AddressesRequest(ServiceRequest):
    Ipv6Prefixes: Optional[IpPrefixList]
    NetworkInterfaceId: NetworkInterfaceId
    Ipv6Addresses: Optional[Ipv6AddressList]


class UnassignIpv6AddressesResult(TypedDict, total=False):
    NetworkInterfaceId: Optional[String]
    UnassignedIpv6Addresses: Optional[Ipv6AddressList]
    UnassignedIpv6Prefixes: Optional[IpPrefixList]


class UnassignPrivateIpAddressesRequest(ServiceRequest):
    Ipv4Prefixes: Optional[IpPrefixList]
    NetworkInterfaceId: NetworkInterfaceId
    PrivateIpAddresses: Optional[PrivateIpAddressStringList]


class UnassignPrivateNatGatewayAddressRequest(ServiceRequest):
    NatGatewayId: NatGatewayId
    PrivateIpAddresses: IpList
    MaxDrainDurationSeconds: Optional[DrainSeconds]
    DryRun: Optional[Boolean]


class UnassignPrivateNatGatewayAddressResult(TypedDict, total=False):
    NatGatewayId: Optional[NatGatewayId]
    NatGatewayAddresses: Optional[NatGatewayAddressList]


class UnlockSnapshotRequest(ServiceRequest):
    SnapshotId: SnapshotId
    DryRun: Optional[Boolean]


class UnlockSnapshotResult(TypedDict, total=False):
    SnapshotId: Optional[String]


class UnmonitorInstancesRequest(ServiceRequest):
    InstanceIds: InstanceIdStringList
    DryRun: Optional[Boolean]


class UnmonitorInstancesResult(TypedDict, total=False):
    InstanceMonitorings: Optional[InstanceMonitoringList]


class UpdateSecurityGroupRuleDescriptionsEgressRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    GroupId: Optional[SecurityGroupId]
    GroupName: Optional[SecurityGroupName]
    IpPermissions: Optional[IpPermissionList]
    SecurityGroupRuleDescriptions: Optional[SecurityGroupRuleDescriptionList]


class UpdateSecurityGroupRuleDescriptionsEgressResult(TypedDict, total=False):
    Return: Optional[Boolean]


class UpdateSecurityGroupRuleDescriptionsIngressRequest(ServiceRequest):
    DryRun: Optional[Boolean]
    GroupId: Optional[SecurityGroupId]
    GroupName: Optional[SecurityGroupName]
    IpPermissions: Optional[IpPermissionList]
    SecurityGroupRuleDescriptions: Optional[SecurityGroupRuleDescriptionList]


class UpdateSecurityGroupRuleDescriptionsIngressResult(TypedDict, total=False):
    Return: Optional[Boolean]


class WithdrawByoipCidrRequest(ServiceRequest):
    Cidr: String
    DryRun: Optional[Boolean]


class WithdrawByoipCidrResult(TypedDict, total=False):
    ByoipCidr: Optional[ByoipCidr]


class Ec2Api:
    service = "ec2"
    version = "2016-11-15"

    @handler("AcceptAddressTransfer")
    def accept_address_transfer(
        self,
        context: RequestContext,
        address: String,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AcceptAddressTransferResult:
        raise NotImplementedError

    @handler("AcceptCapacityReservationBillingOwnership")
    def accept_capacity_reservation_billing_ownership(
        self,
        context: RequestContext,
        capacity_reservation_id: CapacityReservationId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AcceptCapacityReservationBillingOwnershipResult:
        raise NotImplementedError

    @handler("AcceptReservedInstancesExchangeQuote")
    def accept_reserved_instances_exchange_quote(
        self,
        context: RequestContext,
        reserved_instance_ids: ReservedInstanceIdSet,
        dry_run: Boolean = None,
        target_configurations: TargetConfigurationRequestSet = None,
        **kwargs,
    ) -> AcceptReservedInstancesExchangeQuoteResult:
        raise NotImplementedError

    @handler("AcceptTransitGatewayMulticastDomainAssociations")
    def accept_transit_gateway_multicast_domain_associations(
        self,
        context: RequestContext,
        transit_gateway_multicast_domain_id: TransitGatewayMulticastDomainId = None,
        transit_gateway_attachment_id: TransitGatewayAttachmentId = None,
        subnet_ids: ValueStringList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AcceptTransitGatewayMulticastDomainAssociationsResult:
        raise NotImplementedError

    @handler("AcceptTransitGatewayPeeringAttachment")
    def accept_transit_gateway_peering_attachment(
        self,
        context: RequestContext,
        transit_gateway_attachment_id: TransitGatewayAttachmentId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AcceptTransitGatewayPeeringAttachmentResult:
        raise NotImplementedError

    @handler("AcceptTransitGatewayVpcAttachment")
    def accept_transit_gateway_vpc_attachment(
        self,
        context: RequestContext,
        transit_gateway_attachment_id: TransitGatewayAttachmentId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AcceptTransitGatewayVpcAttachmentResult:
        raise NotImplementedError

    @handler("AcceptVpcEndpointConnections")
    def accept_vpc_endpoint_connections(
        self,
        context: RequestContext,
        service_id: VpcEndpointServiceId,
        vpc_endpoint_ids: VpcEndpointIdList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AcceptVpcEndpointConnectionsResult:
        raise NotImplementedError

    @handler("AcceptVpcPeeringConnection")
    def accept_vpc_peering_connection(
        self,
        context: RequestContext,
        vpc_peering_connection_id: VpcPeeringConnectionIdWithResolver,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AcceptVpcPeeringConnectionResult:
        raise NotImplementedError

    @handler("AdvertiseByoipCidr")
    def advertise_byoip_cidr(
        self,
        context: RequestContext,
        cidr: String,
        asn: String = None,
        dry_run: Boolean = None,
        network_border_group: String = None,
        **kwargs,
    ) -> AdvertiseByoipCidrResult:
        raise NotImplementedError

    @handler("AllocateAddress")
    def allocate_address(
        self,
        context: RequestContext,
        domain: DomainType = None,
        address: PublicIpAddress = None,
        public_ipv4_pool: Ipv4PoolEc2Id = None,
        network_border_group: String = None,
        customer_owned_ipv4_pool: String = None,
        tag_specifications: TagSpecificationList = None,
        ipam_pool_id: IpamPoolId = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AllocateAddressResult:
        raise NotImplementedError

    @handler("AllocateHosts")
    def allocate_hosts(
        self,
        context: RequestContext,
        availability_zone: String,
        instance_family: String = None,
        tag_specifications: TagSpecificationList = None,
        host_recovery: HostRecovery = None,
        outpost_arn: String = None,
        host_maintenance: HostMaintenance = None,
        asset_ids: AssetIdList = None,
        auto_placement: AutoPlacement = None,
        client_token: String = None,
        instance_type: String = None,
        quantity: Integer = None,
        **kwargs,
    ) -> AllocateHostsResult:
        raise NotImplementedError

    @handler("AllocateIpamPoolCidr")
    def allocate_ipam_pool_cidr(
        self,
        context: RequestContext,
        ipam_pool_id: IpamPoolId,
        dry_run: Boolean = None,
        cidr: String = None,
        netmask_length: Integer = None,
        client_token: String = None,
        description: String = None,
        preview_next_cidr: Boolean = None,
        allowed_cidrs: IpamPoolAllocationAllowedCidrs = None,
        disallowed_cidrs: IpamPoolAllocationDisallowedCidrs = None,
        **kwargs,
    ) -> AllocateIpamPoolCidrResult:
        raise NotImplementedError

    @handler("ApplySecurityGroupsToClientVpnTargetNetwork")
    def apply_security_groups_to_client_vpn_target_network(
        self,
        context: RequestContext,
        client_vpn_endpoint_id: ClientVpnEndpointId,
        vpc_id: VpcId,
        security_group_ids: ClientVpnSecurityGroupIdSet,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ApplySecurityGroupsToClientVpnTargetNetworkResult:
        raise NotImplementedError

    @handler("AssignIpv6Addresses")
    def assign_ipv6_addresses(
        self,
        context: RequestContext,
        network_interface_id: NetworkInterfaceId,
        ipv6_prefix_count: Integer = None,
        ipv6_prefixes: IpPrefixList = None,
        ipv6_addresses: Ipv6AddressList = None,
        ipv6_address_count: Integer = None,
        **kwargs,
    ) -> AssignIpv6AddressesResult:
        raise NotImplementedError

    @handler("AssignPrivateIpAddresses")
    def assign_private_ip_addresses(
        self,
        context: RequestContext,
        network_interface_id: NetworkInterfaceId,
        ipv4_prefixes: IpPrefixList = None,
        ipv4_prefix_count: Integer = None,
        private_ip_addresses: PrivateIpAddressStringList = None,
        secondary_private_ip_address_count: Integer = None,
        allow_reassignment: Boolean = None,
        **kwargs,
    ) -> AssignPrivateIpAddressesResult:
        raise NotImplementedError

    @handler("AssignPrivateNatGatewayAddress")
    def assign_private_nat_gateway_address(
        self,
        context: RequestContext,
        nat_gateway_id: NatGatewayId,
        private_ip_addresses: IpList = None,
        private_ip_address_count: PrivateIpAddressCount = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AssignPrivateNatGatewayAddressResult:
        raise NotImplementedError

    @handler("AssociateAddress")
    def associate_address(
        self,
        context: RequestContext,
        allocation_id: AllocationId = None,
        instance_id: InstanceId = None,
        public_ip: EipAllocationPublicIp = None,
        dry_run: Boolean = None,
        network_interface_id: NetworkInterfaceId = None,
        private_ip_address: String = None,
        allow_reassociation: Boolean = None,
        **kwargs,
    ) -> AssociateAddressResult:
        raise NotImplementedError

    @handler("AssociateCapacityReservationBillingOwner")
    def associate_capacity_reservation_billing_owner(
        self,
        context: RequestContext,
        capacity_reservation_id: CapacityReservationId,
        unused_reservation_billing_owner_id: AccountID,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AssociateCapacityReservationBillingOwnerResult:
        raise NotImplementedError

    @handler("AssociateClientVpnTargetNetwork")
    def associate_client_vpn_target_network(
        self,
        context: RequestContext,
        client_vpn_endpoint_id: ClientVpnEndpointId,
        subnet_id: SubnetId,
        client_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AssociateClientVpnTargetNetworkResult:
        raise NotImplementedError

    @handler("AssociateDhcpOptions")
    def associate_dhcp_options(
        self,
        context: RequestContext,
        dhcp_options_id: DefaultingDhcpOptionsId,
        vpc_id: VpcId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("AssociateEnclaveCertificateIamRole")
    def associate_enclave_certificate_iam_role(
        self,
        context: RequestContext,
        certificate_arn: CertificateId,
        role_arn: RoleId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AssociateEnclaveCertificateIamRoleResult:
        raise NotImplementedError

    @handler("AssociateIamInstanceProfile")
    def associate_iam_instance_profile(
        self,
        context: RequestContext,
        iam_instance_profile: IamInstanceProfileSpecification,
        instance_id: InstanceId,
        **kwargs,
    ) -> AssociateIamInstanceProfileResult:
        raise NotImplementedError

    @handler("AssociateInstanceEventWindow")
    def associate_instance_event_window(
        self,
        context: RequestContext,
        instance_event_window_id: InstanceEventWindowId,
        association_target: InstanceEventWindowAssociationRequest,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AssociateInstanceEventWindowResult:
        raise NotImplementedError

    @handler("AssociateIpamByoasn")
    def associate_ipam_byoasn(
        self, context: RequestContext, asn: String, cidr: String, dry_run: Boolean = None, **kwargs
    ) -> AssociateIpamByoasnResult:
        raise NotImplementedError

    @handler("AssociateIpamResourceDiscovery")
    def associate_ipam_resource_discovery(
        self,
        context: RequestContext,
        ipam_id: IpamId,
        ipam_resource_discovery_id: IpamResourceDiscoveryId,
        dry_run: Boolean = None,
        tag_specifications: TagSpecificationList = None,
        client_token: String = None,
        **kwargs,
    ) -> AssociateIpamResourceDiscoveryResult:
        raise NotImplementedError

    @handler("AssociateNatGatewayAddress")
    def associate_nat_gateway_address(
        self,
        context: RequestContext,
        nat_gateway_id: NatGatewayId,
        allocation_ids: AllocationIdList,
        private_ip_addresses: IpList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AssociateNatGatewayAddressResult:
        raise NotImplementedError

    @handler("AssociateRouteTable")
    def associate_route_table(
        self,
        context: RequestContext,
        route_table_id: RouteTableId,
        gateway_id: RouteGatewayId = None,
        dry_run: Boolean = None,
        subnet_id: SubnetId = None,
        **kwargs,
    ) -> AssociateRouteTableResult:
        raise NotImplementedError

    @handler("AssociateSecurityGroupVpc")
    def associate_security_group_vpc(
        self,
        context: RequestContext,
        group_id: SecurityGroupId,
        vpc_id: VpcId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AssociateSecurityGroupVpcResult:
        raise NotImplementedError

    @handler("AssociateSubnetCidrBlock")
    def associate_subnet_cidr_block(
        self,
        context: RequestContext,
        subnet_id: SubnetId,
        ipv6_ipam_pool_id: IpamPoolId = None,
        ipv6_netmask_length: NetmaskLength = None,
        ipv6_cidr_block: String = None,
        **kwargs,
    ) -> AssociateSubnetCidrBlockResult:
        raise NotImplementedError

    @handler("AssociateTransitGatewayMulticastDomain")
    def associate_transit_gateway_multicast_domain(
        self,
        context: RequestContext,
        transit_gateway_multicast_domain_id: TransitGatewayMulticastDomainId,
        transit_gateway_attachment_id: TransitGatewayAttachmentId,
        subnet_ids: TransitGatewaySubnetIdList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AssociateTransitGatewayMulticastDomainResult:
        raise NotImplementedError

    @handler("AssociateTransitGatewayPolicyTable")
    def associate_transit_gateway_policy_table(
        self,
        context: RequestContext,
        transit_gateway_policy_table_id: TransitGatewayPolicyTableId,
        transit_gateway_attachment_id: TransitGatewayAttachmentId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AssociateTransitGatewayPolicyTableResult:
        raise NotImplementedError

    @handler("AssociateTransitGatewayRouteTable")
    def associate_transit_gateway_route_table(
        self,
        context: RequestContext,
        transit_gateway_route_table_id: TransitGatewayRouteTableId,
        transit_gateway_attachment_id: TransitGatewayAttachmentId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AssociateTransitGatewayRouteTableResult:
        raise NotImplementedError

    @handler("AssociateTrunkInterface")
    def associate_trunk_interface(
        self,
        context: RequestContext,
        branch_interface_id: NetworkInterfaceId,
        trunk_interface_id: NetworkInterfaceId,
        vlan_id: Integer = None,
        gre_key: Integer = None,
        client_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AssociateTrunkInterfaceResult:
        raise NotImplementedError

    @handler("AssociateVpcCidrBlock")
    def associate_vpc_cidr_block(
        self,
        context: RequestContext,
        vpc_id: VpcId,
        cidr_block: String = None,
        ipv6_cidr_block_network_border_group: String = None,
        ipv6_pool: Ipv6PoolEc2Id = None,
        ipv6_cidr_block: String = None,
        ipv4_ipam_pool_id: IpamPoolId = None,
        ipv4_netmask_length: NetmaskLength = None,
        ipv6_ipam_pool_id: IpamPoolId = None,
        ipv6_netmask_length: NetmaskLength = None,
        amazon_provided_ipv6_cidr_block: Boolean = None,
        **kwargs,
    ) -> AssociateVpcCidrBlockResult:
        raise NotImplementedError

    @handler("AttachClassicLinkVpc")
    def attach_classic_link_vpc(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        vpc_id: VpcId,
        groups: GroupIdStringList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AttachClassicLinkVpcResult:
        raise NotImplementedError

    @handler("AttachInternetGateway")
    def attach_internet_gateway(
        self,
        context: RequestContext,
        internet_gateway_id: InternetGatewayId,
        vpc_id: VpcId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("AttachNetworkInterface")
    def attach_network_interface(
        self,
        context: RequestContext,
        network_interface_id: NetworkInterfaceId,
        instance_id: InstanceId,
        device_index: Integer,
        network_card_index: Integer = None,
        ena_srd_specification: EnaSrdSpecification = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AttachNetworkInterfaceResult:
        raise NotImplementedError

    @handler("AttachVerifiedAccessTrustProvider")
    def attach_verified_access_trust_provider(
        self,
        context: RequestContext,
        verified_access_instance_id: VerifiedAccessInstanceId,
        verified_access_trust_provider_id: VerifiedAccessTrustProviderId,
        client_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AttachVerifiedAccessTrustProviderResult:
        raise NotImplementedError

    @handler("AttachVolume")
    def attach_volume(
        self,
        context: RequestContext,
        device: String,
        instance_id: InstanceId,
        volume_id: VolumeId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> VolumeAttachment:
        raise NotImplementedError

    @handler("AttachVpnGateway")
    def attach_vpn_gateway(
        self,
        context: RequestContext,
        vpc_id: VpcId,
        vpn_gateway_id: VpnGatewayId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AttachVpnGatewayResult:
        raise NotImplementedError

    @handler("AuthorizeClientVpnIngress")
    def authorize_client_vpn_ingress(
        self,
        context: RequestContext,
        client_vpn_endpoint_id: ClientVpnEndpointId,
        target_network_cidr: String,
        access_group_id: String = None,
        authorize_all_groups: Boolean = None,
        description: String = None,
        client_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AuthorizeClientVpnIngressResult:
        raise NotImplementedError

    @handler("AuthorizeSecurityGroupEgress")
    def authorize_security_group_egress(
        self,
        context: RequestContext,
        group_id: SecurityGroupId,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        source_security_group_name: String = None,
        source_security_group_owner_id: String = None,
        ip_protocol: String = None,
        from_port: Integer = None,
        to_port: Integer = None,
        cidr_ip: String = None,
        ip_permissions: IpPermissionList = None,
        **kwargs,
    ) -> AuthorizeSecurityGroupEgressResult:
        raise NotImplementedError

    @handler("AuthorizeSecurityGroupIngress")
    def authorize_security_group_ingress(
        self,
        context: RequestContext,
        cidr_ip: String = None,
        from_port: Integer = None,
        group_id: SecurityGroupId = None,
        group_name: SecurityGroupName = None,
        ip_permissions: IpPermissionList = None,
        ip_protocol: String = None,
        source_security_group_name: String = None,
        source_security_group_owner_id: String = None,
        to_port: Integer = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> AuthorizeSecurityGroupIngressResult:
        raise NotImplementedError

    @handler("BundleInstance")
    def bundle_instance(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        storage: Storage,
        dry_run: Boolean = None,
        **kwargs,
    ) -> BundleInstanceResult:
        raise NotImplementedError

    @handler("CancelBundleTask")
    def cancel_bundle_task(
        self, context: RequestContext, bundle_id: BundleId, dry_run: Boolean = None, **kwargs
    ) -> CancelBundleTaskResult:
        raise NotImplementedError

    @handler("CancelCapacityReservation")
    def cancel_capacity_reservation(
        self,
        context: RequestContext,
        capacity_reservation_id: CapacityReservationId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CancelCapacityReservationResult:
        raise NotImplementedError

    @handler("CancelCapacityReservationFleets")
    def cancel_capacity_reservation_fleets(
        self,
        context: RequestContext,
        capacity_reservation_fleet_ids: CapacityReservationFleetIdSet,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CancelCapacityReservationFleetsResult:
        raise NotImplementedError

    @handler("CancelConversionTask")
    def cancel_conversion_task(
        self,
        context: RequestContext,
        conversion_task_id: ConversionTaskId,
        dry_run: Boolean = None,
        reason_message: String = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("CancelExportTask")
    def cancel_export_task(
        self, context: RequestContext, export_task_id: ExportVmTaskId, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("CancelImageLaunchPermission")
    def cancel_image_launch_permission(
        self, context: RequestContext, image_id: ImageId, dry_run: Boolean = None, **kwargs
    ) -> CancelImageLaunchPermissionResult:
        raise NotImplementedError

    @handler("CancelImportTask")
    def cancel_import_task(
        self,
        context: RequestContext,
        cancel_reason: String = None,
        dry_run: Boolean = None,
        import_task_id: ImportTaskId = None,
        **kwargs,
    ) -> CancelImportTaskResult:
        raise NotImplementedError

    @handler("CancelReservedInstancesListing")
    def cancel_reserved_instances_listing(
        self,
        context: RequestContext,
        reserved_instances_listing_id: ReservedInstancesListingId,
        **kwargs,
    ) -> CancelReservedInstancesListingResult:
        raise NotImplementedError

    @handler("CancelSpotFleetRequests")
    def cancel_spot_fleet_requests(
        self,
        context: RequestContext,
        spot_fleet_request_ids: SpotFleetRequestIdList,
        terminate_instances: Boolean,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CancelSpotFleetRequestsResponse:
        raise NotImplementedError

    @handler("CancelSpotInstanceRequests")
    def cancel_spot_instance_requests(
        self,
        context: RequestContext,
        spot_instance_request_ids: SpotInstanceRequestIdList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CancelSpotInstanceRequestsResult:
        raise NotImplementedError

    @handler("ConfirmProductInstance")
    def confirm_product_instance(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        product_code: String,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ConfirmProductInstanceResult:
        raise NotImplementedError

    @handler("CopyFpgaImage")
    def copy_fpga_image(
        self,
        context: RequestContext,
        source_fpga_image_id: String,
        source_region: String,
        dry_run: Boolean = None,
        description: String = None,
        name: String = None,
        client_token: String = None,
        **kwargs,
    ) -> CopyFpgaImageResult:
        raise NotImplementedError

    @handler("CopyImage")
    def copy_image(
        self,
        context: RequestContext,
        name: String,
        source_image_id: String,
        source_region: String,
        client_token: String = None,
        description: String = None,
        encrypted: Boolean = None,
        kms_key_id: KmsKeyId = None,
        destination_outpost_arn: String = None,
        copy_image_tags: Boolean = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CopyImageResult:
        raise NotImplementedError

    @handler("CopySnapshot")
    def copy_snapshot(
        self,
        context: RequestContext,
        source_region: String,
        source_snapshot_id: String,
        description: String = None,
        destination_outpost_arn: String = None,
        destination_region: String = None,
        encrypted: Boolean = None,
        kms_key_id: KmsKeyId = None,
        presigned_url: CopySnapshotRequestPSU = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CopySnapshotResult:
        raise NotImplementedError

    @handler("CreateCapacityReservation")
    def create_capacity_reservation(
        self,
        context: RequestContext,
        instance_type: String,
        instance_platform: CapacityReservationInstancePlatform,
        instance_count: Integer,
        client_token: String = None,
        availability_zone: AvailabilityZoneName = None,
        availability_zone_id: AvailabilityZoneId = None,
        tenancy: CapacityReservationTenancy = None,
        ebs_optimized: Boolean = None,
        ephemeral_storage: Boolean = None,
        end_date: DateTime = None,
        end_date_type: EndDateType = None,
        instance_match_criteria: InstanceMatchCriteria = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        outpost_arn: OutpostArn = None,
        placement_group_arn: PlacementGroupArn = None,
        **kwargs,
    ) -> CreateCapacityReservationResult:
        raise NotImplementedError

    @handler("CreateCapacityReservationBySplitting")
    def create_capacity_reservation_by_splitting(
        self,
        context: RequestContext,
        source_capacity_reservation_id: CapacityReservationId,
        instance_count: Integer,
        dry_run: Boolean = None,
        client_token: String = None,
        tag_specifications: TagSpecificationList = None,
        **kwargs,
    ) -> CreateCapacityReservationBySplittingResult:
        raise NotImplementedError

    @handler("CreateCapacityReservationFleet")
    def create_capacity_reservation_fleet(
        self,
        context: RequestContext,
        instance_type_specifications: ReservationFleetInstanceSpecificationList,
        total_target_capacity: Integer,
        allocation_strategy: String = None,
        client_token: String = None,
        tenancy: FleetCapacityReservationTenancy = None,
        end_date: MillisecondDateTime = None,
        instance_match_criteria: FleetInstanceMatchCriteria = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateCapacityReservationFleetResult:
        raise NotImplementedError

    @handler("CreateCarrierGateway")
    def create_carrier_gateway(
        self,
        context: RequestContext,
        vpc_id: VpcId,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        client_token: String = None,
        **kwargs,
    ) -> CreateCarrierGatewayResult:
        raise NotImplementedError

    @handler("CreateClientVpnEndpoint")
    def create_client_vpn_endpoint(
        self,
        context: RequestContext,
        client_cidr_block: String,
        server_certificate_arn: String,
        authentication_options: ClientVpnAuthenticationRequestList,
        connection_log_options: ConnectionLogOptions,
        dns_servers: ValueStringList = None,
        transport_protocol: TransportProtocol = None,
        vpn_port: Integer = None,
        description: String = None,
        split_tunnel: Boolean = None,
        dry_run: Boolean = None,
        client_token: String = None,
        tag_specifications: TagSpecificationList = None,
        security_group_ids: ClientVpnSecurityGroupIdSet = None,
        vpc_id: VpcId = None,
        self_service_portal: SelfServicePortal = None,
        client_connect_options: ClientConnectOptions = None,
        session_timeout_hours: Integer = None,
        client_login_banner_options: ClientLoginBannerOptions = None,
        **kwargs,
    ) -> CreateClientVpnEndpointResult:
        raise NotImplementedError

    @handler("CreateClientVpnRoute")
    def create_client_vpn_route(
        self,
        context: RequestContext,
        client_vpn_endpoint_id: ClientVpnEndpointId,
        destination_cidr_block: String,
        target_vpc_subnet_id: SubnetId,
        description: String = None,
        client_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateClientVpnRouteResult:
        raise NotImplementedError

    @handler("CreateCoipCidr")
    def create_coip_cidr(
        self,
        context: RequestContext,
        cidr: String,
        coip_pool_id: Ipv4PoolCoipId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateCoipCidrResult:
        raise NotImplementedError

    @handler("CreateCoipPool")
    def create_coip_pool(
        self,
        context: RequestContext,
        local_gateway_route_table_id: LocalGatewayRoutetableId,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateCoipPoolResult:
        raise NotImplementedError

    @handler("CreateCustomerGateway", expand=False)
    def create_customer_gateway(
        self, context: RequestContext, request: CreateCustomerGatewayRequest, **kwargs
    ) -> CreateCustomerGatewayResult:
        raise NotImplementedError

    @handler("CreateDefaultSubnet")
    def create_default_subnet(
        self,
        context: RequestContext,
        availability_zone: AvailabilityZoneName,
        dry_run: Boolean = None,
        ipv6_native: Boolean = None,
        **kwargs,
    ) -> CreateDefaultSubnetResult:
        raise NotImplementedError

    @handler("CreateDefaultVpc")
    def create_default_vpc(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> CreateDefaultVpcResult:
        raise NotImplementedError

    @handler("CreateDhcpOptions")
    def create_dhcp_options(
        self,
        context: RequestContext,
        dhcp_configurations: NewDhcpConfigurationList,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateDhcpOptionsResult:
        raise NotImplementedError

    @handler("CreateEgressOnlyInternetGateway")
    def create_egress_only_internet_gateway(
        self,
        context: RequestContext,
        vpc_id: VpcId,
        client_token: String = None,
        dry_run: Boolean = None,
        tag_specifications: TagSpecificationList = None,
        **kwargs,
    ) -> CreateEgressOnlyInternetGatewayResult:
        raise NotImplementedError

    @handler("CreateFleet", expand=False)
    def create_fleet(
        self, context: RequestContext, request: CreateFleetRequest, **kwargs
    ) -> CreateFleetResult:
        raise NotImplementedError

    @handler("CreateFlowLogs")
    def create_flow_logs(
        self,
        context: RequestContext,
        resource_ids: FlowLogResourceIds,
        resource_type: FlowLogsResourceType,
        dry_run: Boolean = None,
        client_token: String = None,
        deliver_logs_permission_arn: String = None,
        deliver_cross_account_role: String = None,
        log_group_name: String = None,
        traffic_type: TrafficType = None,
        log_destination_type: LogDestinationType = None,
        log_destination: String = None,
        log_format: String = None,
        tag_specifications: TagSpecificationList = None,
        max_aggregation_interval: Integer = None,
        destination_options: DestinationOptionsRequest = None,
        **kwargs,
    ) -> CreateFlowLogsResult:
        raise NotImplementedError

    @handler("CreateFpgaImage")
    def create_fpga_image(
        self,
        context: RequestContext,
        input_storage_location: StorageLocation,
        dry_run: Boolean = None,
        logs_storage_location: StorageLocation = None,
        description: String = None,
        name: String = None,
        client_token: String = None,
        tag_specifications: TagSpecificationList = None,
        **kwargs,
    ) -> CreateFpgaImageResult:
        raise NotImplementedError

    @handler("CreateImage")
    def create_image(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        name: String,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        description: String = None,
        no_reboot: Boolean = None,
        block_device_mappings: BlockDeviceMappingRequestList = None,
        **kwargs,
    ) -> CreateImageResult:
        raise NotImplementedError

    @handler("CreateInstanceConnectEndpoint")
    def create_instance_connect_endpoint(
        self,
        context: RequestContext,
        subnet_id: SubnetId,
        dry_run: Boolean = None,
        security_group_ids: SecurityGroupIdStringListRequest = None,
        preserve_client_ip: Boolean = None,
        client_token: String = None,
        tag_specifications: TagSpecificationList = None,
        **kwargs,
    ) -> CreateInstanceConnectEndpointResult:
        raise NotImplementedError

    @handler("CreateInstanceEventWindow")
    def create_instance_event_window(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        name: String = None,
        time_ranges: InstanceEventWindowTimeRangeRequestSet = None,
        cron_expression: InstanceEventWindowCronExpression = None,
        tag_specifications: TagSpecificationList = None,
        **kwargs,
    ) -> CreateInstanceEventWindowResult:
        raise NotImplementedError

    @handler("CreateInstanceExportTask")
    def create_instance_export_task(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        target_environment: ExportEnvironment,
        export_to_s3_task: ExportToS3TaskSpecification,
        tag_specifications: TagSpecificationList = None,
        description: String = None,
        **kwargs,
    ) -> CreateInstanceExportTaskResult:
        raise NotImplementedError

    @handler("CreateInternetGateway")
    def create_internet_gateway(
        self,
        context: RequestContext,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateInternetGatewayResult:
        raise NotImplementedError

    @handler("CreateIpam")
    def create_ipam(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        description: String = None,
        operating_regions: AddIpamOperatingRegionSet = None,
        tag_specifications: TagSpecificationList = None,
        client_token: String = None,
        tier: IpamTier = None,
        enable_private_gua: Boolean = None,
        **kwargs,
    ) -> CreateIpamResult:
        raise NotImplementedError

    @handler("CreateIpamExternalResourceVerificationToken")
    def create_ipam_external_resource_verification_token(
        self,
        context: RequestContext,
        ipam_id: IpamId,
        dry_run: Boolean = None,
        tag_specifications: TagSpecificationList = None,
        client_token: String = None,
        **kwargs,
    ) -> CreateIpamExternalResourceVerificationTokenResult:
        raise NotImplementedError

    @handler("CreateIpamPool")
    def create_ipam_pool(
        self,
        context: RequestContext,
        ipam_scope_id: IpamScopeId,
        address_family: AddressFamily,
        dry_run: Boolean = None,
        locale: String = None,
        source_ipam_pool_id: IpamPoolId = None,
        description: String = None,
        auto_import: Boolean = None,
        publicly_advertisable: Boolean = None,
        allocation_min_netmask_length: IpamNetmaskLength = None,
        allocation_max_netmask_length: IpamNetmaskLength = None,
        allocation_default_netmask_length: IpamNetmaskLength = None,
        allocation_resource_tags: RequestIpamResourceTagList = None,
        tag_specifications: TagSpecificationList = None,
        client_token: String = None,
        aws_service: IpamPoolAwsService = None,
        public_ip_source: IpamPoolPublicIpSource = None,
        source_resource: IpamPoolSourceResourceRequest = None,
        **kwargs,
    ) -> CreateIpamPoolResult:
        raise NotImplementedError

    @handler("CreateIpamResourceDiscovery")
    def create_ipam_resource_discovery(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        description: String = None,
        operating_regions: AddIpamOperatingRegionSet = None,
        tag_specifications: TagSpecificationList = None,
        client_token: String = None,
        **kwargs,
    ) -> CreateIpamResourceDiscoveryResult:
        raise NotImplementedError

    @handler("CreateIpamScope")
    def create_ipam_scope(
        self,
        context: RequestContext,
        ipam_id: IpamId,
        dry_run: Boolean = None,
        description: String = None,
        tag_specifications: TagSpecificationList = None,
        client_token: String = None,
        **kwargs,
    ) -> CreateIpamScopeResult:
        raise NotImplementedError

    @handler("CreateKeyPair")
    def create_key_pair(
        self,
        context: RequestContext,
        key_name: String,
        key_type: KeyType = None,
        tag_specifications: TagSpecificationList = None,
        key_format: KeyFormat = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> KeyPair:
        raise NotImplementedError

    @handler("CreateLaunchTemplate")
    def create_launch_template(
        self,
        context: RequestContext,
        launch_template_name: LaunchTemplateName,
        launch_template_data: RequestLaunchTemplateData,
        dry_run: Boolean = None,
        client_token: String = None,
        version_description: VersionDescription = None,
        tag_specifications: TagSpecificationList = None,
        **kwargs,
    ) -> CreateLaunchTemplateResult:
        raise NotImplementedError

    @handler("CreateLaunchTemplateVersion")
    def create_launch_template_version(
        self,
        context: RequestContext,
        launch_template_data: RequestLaunchTemplateData,
        dry_run: Boolean = None,
        client_token: String = None,
        launch_template_id: LaunchTemplateId = None,
        launch_template_name: LaunchTemplateName = None,
        source_version: String = None,
        version_description: VersionDescription = None,
        resolve_alias: Boolean = None,
        **kwargs,
    ) -> CreateLaunchTemplateVersionResult:
        raise NotImplementedError

    @handler("CreateLocalGatewayRoute")
    def create_local_gateway_route(
        self,
        context: RequestContext,
        local_gateway_route_table_id: LocalGatewayRoutetableId,
        destination_cidr_block: String = None,
        local_gateway_virtual_interface_group_id: LocalGatewayVirtualInterfaceGroupId = None,
        dry_run: Boolean = None,
        network_interface_id: NetworkInterfaceId = None,
        destination_prefix_list_id: PrefixListResourceId = None,
        **kwargs,
    ) -> CreateLocalGatewayRouteResult:
        raise NotImplementedError

    @handler("CreateLocalGatewayRouteTable")
    def create_local_gateway_route_table(
        self,
        context: RequestContext,
        local_gateway_id: LocalGatewayId,
        mode: LocalGatewayRouteTableMode = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateLocalGatewayRouteTableResult:
        raise NotImplementedError

    @handler("CreateLocalGatewayRouteTableVirtualInterfaceGroupAssociation")
    def create_local_gateway_route_table_virtual_interface_group_association(
        self,
        context: RequestContext,
        local_gateway_route_table_id: LocalGatewayRoutetableId,
        local_gateway_virtual_interface_group_id: LocalGatewayVirtualInterfaceGroupId,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateLocalGatewayRouteTableVirtualInterfaceGroupAssociationResult:
        raise NotImplementedError

    @handler("CreateLocalGatewayRouteTableVpcAssociation")
    def create_local_gateway_route_table_vpc_association(
        self,
        context: RequestContext,
        local_gateway_route_table_id: LocalGatewayRoutetableId,
        vpc_id: VpcId,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateLocalGatewayRouteTableVpcAssociationResult:
        raise NotImplementedError

    @handler("CreateManagedPrefixList")
    def create_managed_prefix_list(
        self,
        context: RequestContext,
        prefix_list_name: String,
        max_entries: Integer,
        address_family: String,
        dry_run: Boolean = None,
        entries: AddPrefixListEntries = None,
        tag_specifications: TagSpecificationList = None,
        client_token: String = None,
        **kwargs,
    ) -> CreateManagedPrefixListResult:
        raise NotImplementedError

    @handler("CreateNatGateway")
    def create_nat_gateway(
        self,
        context: RequestContext,
        subnet_id: SubnetId,
        allocation_id: AllocationId = None,
        client_token: String = None,
        dry_run: Boolean = None,
        tag_specifications: TagSpecificationList = None,
        connectivity_type: ConnectivityType = None,
        private_ip_address: String = None,
        secondary_allocation_ids: AllocationIdList = None,
        secondary_private_ip_addresses: IpList = None,
        secondary_private_ip_address_count: PrivateIpAddressCount = None,
        **kwargs,
    ) -> CreateNatGatewayResult:
        raise NotImplementedError

    @handler("CreateNetworkAcl")
    def create_network_acl(
        self,
        context: RequestContext,
        vpc_id: VpcId,
        tag_specifications: TagSpecificationList = None,
        client_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateNetworkAclResult:
        raise NotImplementedError

    @handler("CreateNetworkAclEntry")
    def create_network_acl_entry(
        self,
        context: RequestContext,
        network_acl_id: NetworkAclId,
        rule_number: Integer,
        protocol: String,
        rule_action: RuleAction,
        egress: Boolean,
        dry_run: Boolean = None,
        cidr_block: String = None,
        ipv6_cidr_block: String = None,
        icmp_type_code: IcmpTypeCode = None,
        port_range: PortRange = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("CreateNetworkInsightsAccessScope")
    def create_network_insights_access_scope(
        self,
        context: RequestContext,
        client_token: String,
        match_paths: AccessScopePathListRequest = None,
        exclude_paths: AccessScopePathListRequest = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateNetworkInsightsAccessScopeResult:
        raise NotImplementedError

    @handler("CreateNetworkInsightsPath")
    def create_network_insights_path(
        self,
        context: RequestContext,
        source: NetworkInsightsResourceId,
        protocol: Protocol,
        client_token: String,
        source_ip: IpAddress = None,
        destination_ip: IpAddress = None,
        destination: NetworkInsightsResourceId = None,
        destination_port: Port = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        filter_at_source: PathRequestFilter = None,
        filter_at_destination: PathRequestFilter = None,
        **kwargs,
    ) -> CreateNetworkInsightsPathResult:
        raise NotImplementedError

    @handler("CreateNetworkInterface")
    def create_network_interface(
        self,
        context: RequestContext,
        subnet_id: SubnetId,
        ipv4_prefixes: Ipv4PrefixList = None,
        ipv4_prefix_count: Integer = None,
        ipv6_prefixes: Ipv6PrefixList = None,
        ipv6_prefix_count: Integer = None,
        interface_type: NetworkInterfaceCreationType = None,
        tag_specifications: TagSpecificationList = None,
        client_token: String = None,
        enable_primary_ipv6: Boolean = None,
        connection_tracking_specification: ConnectionTrackingSpecificationRequest = None,
        description: String = None,
        private_ip_address: String = None,
        groups: SecurityGroupIdStringList = None,
        private_ip_addresses: PrivateIpAddressSpecificationList = None,
        secondary_private_ip_address_count: Integer = None,
        ipv6_addresses: InstanceIpv6AddressList = None,
        ipv6_address_count: Integer = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateNetworkInterfaceResult:
        raise NotImplementedError

    @handler("CreateNetworkInterfacePermission")
    def create_network_interface_permission(
        self,
        context: RequestContext,
        network_interface_id: NetworkInterfaceId,
        permission: InterfacePermissionType,
        aws_account_id: String = None,
        aws_service: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateNetworkInterfacePermissionResult:
        raise NotImplementedError

    @handler("CreatePlacementGroup")
    def create_placement_group(
        self,
        context: RequestContext,
        partition_count: Integer = None,
        tag_specifications: TagSpecificationList = None,
        spread_level: SpreadLevel = None,
        dry_run: Boolean = None,
        group_name: String = None,
        strategy: PlacementStrategy = None,
        **kwargs,
    ) -> CreatePlacementGroupResult:
        raise NotImplementedError

    @handler("CreatePublicIpv4Pool")
    def create_public_ipv4_pool(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        tag_specifications: TagSpecificationList = None,
        network_border_group: String = None,
        **kwargs,
    ) -> CreatePublicIpv4PoolResult:
        raise NotImplementedError

    @handler("CreateReplaceRootVolumeTask")
    def create_replace_root_volume_task(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        snapshot_id: SnapshotId = None,
        client_token: String = None,
        dry_run: Boolean = None,
        tag_specifications: TagSpecificationList = None,
        image_id: ImageId = None,
        delete_replaced_root_volume: Boolean = None,
        **kwargs,
    ) -> CreateReplaceRootVolumeTaskResult:
        raise NotImplementedError

    @handler("CreateReservedInstancesListing")
    def create_reserved_instances_listing(
        self,
        context: RequestContext,
        reserved_instances_id: ReservationId,
        instance_count: Integer,
        price_schedules: PriceScheduleSpecificationList,
        client_token: String,
        **kwargs,
    ) -> CreateReservedInstancesListingResult:
        raise NotImplementedError

    @handler("CreateRestoreImageTask")
    def create_restore_image_task(
        self,
        context: RequestContext,
        bucket: String,
        object_key: String,
        name: String = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateRestoreImageTaskResult:
        raise NotImplementedError

    @handler("CreateRoute")
    def create_route(
        self,
        context: RequestContext,
        route_table_id: RouteTableId,
        destination_prefix_list_id: PrefixListResourceId = None,
        vpc_endpoint_id: VpcEndpointId = None,
        transit_gateway_id: TransitGatewayId = None,
        local_gateway_id: LocalGatewayId = None,
        carrier_gateway_id: CarrierGatewayId = None,
        core_network_arn: CoreNetworkArn = None,
        dry_run: Boolean = None,
        destination_cidr_block: String = None,
        gateway_id: RouteGatewayId = None,
        destination_ipv6_cidr_block: String = None,
        egress_only_internet_gateway_id: EgressOnlyInternetGatewayId = None,
        instance_id: InstanceId = None,
        network_interface_id: NetworkInterfaceId = None,
        vpc_peering_connection_id: VpcPeeringConnectionId = None,
        nat_gateway_id: NatGatewayId = None,
        **kwargs,
    ) -> CreateRouteResult:
        raise NotImplementedError

    @handler("CreateRouteTable")
    def create_route_table(
        self,
        context: RequestContext,
        vpc_id: VpcId,
        tag_specifications: TagSpecificationList = None,
        client_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateRouteTableResult:
        raise NotImplementedError

    @handler("CreateSecurityGroup")
    def create_security_group(
        self,
        context: RequestContext,
        description: String,
        group_name: String,
        vpc_id: VpcId = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateSecurityGroupResult:
        raise NotImplementedError

    @handler("CreateSnapshot")
    def create_snapshot(
        self,
        context: RequestContext,
        volume_id: VolumeId,
        description: String = None,
        outpost_arn: String = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> Snapshot:
        raise NotImplementedError

    @handler("CreateSnapshots")
    def create_snapshots(
        self,
        context: RequestContext,
        instance_specification: InstanceSpecification,
        description: String = None,
        outpost_arn: String = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        copy_tags_from_source: CopyTagsFromSource = None,
        **kwargs,
    ) -> CreateSnapshotsResult:
        raise NotImplementedError

    @handler("CreateSpotDatafeedSubscription")
    def create_spot_datafeed_subscription(
        self,
        context: RequestContext,
        bucket: String,
        dry_run: Boolean = None,
        prefix: String = None,
        **kwargs,
    ) -> CreateSpotDatafeedSubscriptionResult:
        raise NotImplementedError

    @handler("CreateStoreImageTask")
    def create_store_image_task(
        self,
        context: RequestContext,
        image_id: ImageId,
        bucket: String,
        s3_object_tags: S3ObjectTagList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateStoreImageTaskResult:
        raise NotImplementedError

    @handler("CreateSubnet")
    def create_subnet(
        self,
        context: RequestContext,
        vpc_id: VpcId,
        tag_specifications: TagSpecificationList = None,
        availability_zone: String = None,
        availability_zone_id: String = None,
        cidr_block: String = None,
        ipv6_cidr_block: String = None,
        outpost_arn: String = None,
        ipv6_native: Boolean = None,
        ipv4_ipam_pool_id: IpamPoolId = None,
        ipv4_netmask_length: NetmaskLength = None,
        ipv6_ipam_pool_id: IpamPoolId = None,
        ipv6_netmask_length: NetmaskLength = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateSubnetResult:
        raise NotImplementedError

    @handler("CreateSubnetCidrReservation")
    def create_subnet_cidr_reservation(
        self,
        context: RequestContext,
        subnet_id: SubnetId,
        cidr: String,
        reservation_type: SubnetCidrReservationType,
        description: String = None,
        dry_run: Boolean = None,
        tag_specifications: TagSpecificationList = None,
        **kwargs,
    ) -> CreateSubnetCidrReservationResult:
        raise NotImplementedError

    @handler("CreateTags")
    def create_tags(
        self,
        context: RequestContext,
        resources: ResourceIdList,
        tags: TagList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("CreateTrafficMirrorFilter")
    def create_traffic_mirror_filter(
        self,
        context: RequestContext,
        description: String = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        client_token: String = None,
        **kwargs,
    ) -> CreateTrafficMirrorFilterResult:
        raise NotImplementedError

    @handler("CreateTrafficMirrorFilterRule")
    def create_traffic_mirror_filter_rule(
        self,
        context: RequestContext,
        traffic_mirror_filter_id: TrafficMirrorFilterId,
        traffic_direction: TrafficDirection,
        rule_number: Integer,
        rule_action: TrafficMirrorRuleAction,
        destination_cidr_block: String,
        source_cidr_block: String,
        destination_port_range: TrafficMirrorPortRangeRequest = None,
        source_port_range: TrafficMirrorPortRangeRequest = None,
        protocol: Integer = None,
        description: String = None,
        dry_run: Boolean = None,
        client_token: String = None,
        tag_specifications: TagSpecificationList = None,
        **kwargs,
    ) -> CreateTrafficMirrorFilterRuleResult:
        raise NotImplementedError

    @handler("CreateTrafficMirrorSession")
    def create_traffic_mirror_session(
        self,
        context: RequestContext,
        network_interface_id: NetworkInterfaceId,
        traffic_mirror_target_id: TrafficMirrorTargetId,
        traffic_mirror_filter_id: TrafficMirrorFilterId,
        session_number: Integer,
        packet_length: Integer = None,
        virtual_network_id: Integer = None,
        description: String = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        client_token: String = None,
        **kwargs,
    ) -> CreateTrafficMirrorSessionResult:
        raise NotImplementedError

    @handler("CreateTrafficMirrorTarget")
    def create_traffic_mirror_target(
        self,
        context: RequestContext,
        network_interface_id: NetworkInterfaceId = None,
        network_load_balancer_arn: String = None,
        description: String = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        client_token: String = None,
        gateway_load_balancer_endpoint_id: VpcEndpointId = None,
        **kwargs,
    ) -> CreateTrafficMirrorTargetResult:
        raise NotImplementedError

    @handler("CreateTransitGateway")
    def create_transit_gateway(
        self,
        context: RequestContext,
        description: String = None,
        options: TransitGatewayRequestOptions = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateTransitGatewayResult:
        raise NotImplementedError

    @handler("CreateTransitGatewayConnect")
    def create_transit_gateway_connect(
        self,
        context: RequestContext,
        transport_transit_gateway_attachment_id: TransitGatewayAttachmentId,
        options: CreateTransitGatewayConnectRequestOptions,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateTransitGatewayConnectResult:
        raise NotImplementedError

    @handler("CreateTransitGatewayConnectPeer")
    def create_transit_gateway_connect_peer(
        self,
        context: RequestContext,
        transit_gateway_attachment_id: TransitGatewayAttachmentId,
        peer_address: String,
        inside_cidr_blocks: InsideCidrBlocksStringList,
        transit_gateway_address: String = None,
        bgp_options: TransitGatewayConnectRequestBgpOptions = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateTransitGatewayConnectPeerResult:
        raise NotImplementedError

    @handler("CreateTransitGatewayMulticastDomain")
    def create_transit_gateway_multicast_domain(
        self,
        context: RequestContext,
        transit_gateway_id: TransitGatewayId,
        options: CreateTransitGatewayMulticastDomainRequestOptions = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateTransitGatewayMulticastDomainResult:
        raise NotImplementedError

    @handler("CreateTransitGatewayPeeringAttachment")
    def create_transit_gateway_peering_attachment(
        self,
        context: RequestContext,
        transit_gateway_id: TransitGatewayId,
        peer_transit_gateway_id: TransitAssociationGatewayId,
        peer_account_id: String,
        peer_region: String,
        options: CreateTransitGatewayPeeringAttachmentRequestOptions = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateTransitGatewayPeeringAttachmentResult:
        raise NotImplementedError

    @handler("CreateTransitGatewayPolicyTable")
    def create_transit_gateway_policy_table(
        self,
        context: RequestContext,
        transit_gateway_id: TransitGatewayId,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateTransitGatewayPolicyTableResult:
        raise NotImplementedError

    @handler("CreateTransitGatewayPrefixListReference")
    def create_transit_gateway_prefix_list_reference(
        self,
        context: RequestContext,
        transit_gateway_route_table_id: TransitGatewayRouteTableId,
        prefix_list_id: PrefixListResourceId,
        transit_gateway_attachment_id: TransitGatewayAttachmentId = None,
        blackhole: Boolean = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateTransitGatewayPrefixListReferenceResult:
        raise NotImplementedError

    @handler("CreateTransitGatewayRoute")
    def create_transit_gateway_route(
        self,
        context: RequestContext,
        destination_cidr_block: String,
        transit_gateway_route_table_id: TransitGatewayRouteTableId,
        transit_gateway_attachment_id: TransitGatewayAttachmentId = None,
        blackhole: Boolean = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateTransitGatewayRouteResult:
        raise NotImplementedError

    @handler("CreateTransitGatewayRouteTable")
    def create_transit_gateway_route_table(
        self,
        context: RequestContext,
        transit_gateway_id: TransitGatewayId,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateTransitGatewayRouteTableResult:
        raise NotImplementedError

    @handler("CreateTransitGatewayRouteTableAnnouncement")
    def create_transit_gateway_route_table_announcement(
        self,
        context: RequestContext,
        transit_gateway_route_table_id: TransitGatewayRouteTableId,
        peering_attachment_id: TransitGatewayAttachmentId,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateTransitGatewayRouteTableAnnouncementResult:
        raise NotImplementedError

    @handler("CreateTransitGatewayVpcAttachment")
    def create_transit_gateway_vpc_attachment(
        self,
        context: RequestContext,
        transit_gateway_id: TransitGatewayId,
        vpc_id: VpcId,
        subnet_ids: TransitGatewaySubnetIdList,
        options: CreateTransitGatewayVpcAttachmentRequestOptions = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> CreateTransitGatewayVpcAttachmentResult:
        raise NotImplementedError

    @handler("CreateVerifiedAccessEndpoint")
    def create_verified_access_endpoint(
        self,
        context: RequestContext,
        verified_access_group_id: VerifiedAccessGroupId,
        endpoint_type: VerifiedAccessEndpointType,
        attachment_type: VerifiedAccessEndpointAttachmentType,
        domain_certificate_arn: CertificateArn,
        application_domain: String,
        endpoint_domain_prefix: String,
        security_group_ids: SecurityGroupIdList = None,
        load_balancer_options: CreateVerifiedAccessEndpointLoadBalancerOptions = None,
        network_interface_options: CreateVerifiedAccessEndpointEniOptions = None,
        description: String = None,
        policy_document: String = None,
        tag_specifications: TagSpecificationList = None,
        client_token: String = None,
        dry_run: Boolean = None,
        sse_specification: VerifiedAccessSseSpecificationRequest = None,
        **kwargs,
    ) -> CreateVerifiedAccessEndpointResult:
        raise NotImplementedError

    @handler("CreateVerifiedAccessGroup")
    def create_verified_access_group(
        self,
        context: RequestContext,
        verified_access_instance_id: VerifiedAccessInstanceId,
        description: String = None,
        policy_document: String = None,
        tag_specifications: TagSpecificationList = None,
        client_token: String = None,
        dry_run: Boolean = None,
        sse_specification: VerifiedAccessSseSpecificationRequest = None,
        **kwargs,
    ) -> CreateVerifiedAccessGroupResult:
        raise NotImplementedError

    @handler("CreateVerifiedAccessInstance")
    def create_verified_access_instance(
        self,
        context: RequestContext,
        description: String = None,
        tag_specifications: TagSpecificationList = None,
        client_token: String = None,
        dry_run: Boolean = None,
        fips_enabled: Boolean = None,
        **kwargs,
    ) -> CreateVerifiedAccessInstanceResult:
        raise NotImplementedError

    @handler("CreateVerifiedAccessTrustProvider")
    def create_verified_access_trust_provider(
        self,
        context: RequestContext,
        trust_provider_type: TrustProviderType,
        policy_reference_name: String,
        user_trust_provider_type: UserTrustProviderType = None,
        device_trust_provider_type: DeviceTrustProviderType = None,
        oidc_options: CreateVerifiedAccessTrustProviderOidcOptions = None,
        device_options: CreateVerifiedAccessTrustProviderDeviceOptions = None,
        description: String = None,
        tag_specifications: TagSpecificationList = None,
        client_token: String = None,
        dry_run: Boolean = None,
        sse_specification: VerifiedAccessSseSpecificationRequest = None,
        **kwargs,
    ) -> CreateVerifiedAccessTrustProviderResult:
        raise NotImplementedError

    @handler("CreateVolume")
    def create_volume(
        self,
        context: RequestContext,
        availability_zone: AvailabilityZoneName,
        encrypted: Boolean = None,
        iops: Integer = None,
        kms_key_id: KmsKeyId = None,
        outpost_arn: String = None,
        size: Integer = None,
        snapshot_id: SnapshotId = None,
        volume_type: VolumeType = None,
        tag_specifications: TagSpecificationList = None,
        multi_attach_enabled: Boolean = None,
        throughput: Integer = None,
        client_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> Volume:
        raise NotImplementedError

    @handler("CreateVpc")
    def create_vpc(
        self,
        context: RequestContext,
        cidr_block: String = None,
        ipv6_pool: Ipv6PoolEc2Id = None,
        ipv6_cidr_block: String = None,
        ipv4_ipam_pool_id: IpamPoolId = None,
        ipv4_netmask_length: NetmaskLength = None,
        ipv6_ipam_pool_id: IpamPoolId = None,
        ipv6_netmask_length: NetmaskLength = None,
        ipv6_cidr_block_network_border_group: String = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        instance_tenancy: Tenancy = None,
        amazon_provided_ipv6_cidr_block: Boolean = None,
        **kwargs,
    ) -> CreateVpcResult:
        raise NotImplementedError

    @handler("CreateVpcEndpoint")
    def create_vpc_endpoint(
        self,
        context: RequestContext,
        vpc_id: VpcId,
        service_name: String,
        dry_run: Boolean = None,
        vpc_endpoint_type: VpcEndpointType = None,
        policy_document: String = None,
        route_table_ids: VpcEndpointRouteTableIdList = None,
        subnet_ids: VpcEndpointSubnetIdList = None,
        security_group_ids: VpcEndpointSecurityGroupIdList = None,
        ip_address_type: IpAddressType = None,
        dns_options: DnsOptionsSpecification = None,
        client_token: String = None,
        private_dns_enabled: Boolean = None,
        tag_specifications: TagSpecificationList = None,
        subnet_configurations: SubnetConfigurationsList = None,
        **kwargs,
    ) -> CreateVpcEndpointResult:
        raise NotImplementedError

    @handler("CreateVpcEndpointConnectionNotification")
    def create_vpc_endpoint_connection_notification(
        self,
        context: RequestContext,
        connection_notification_arn: String,
        connection_events: ValueStringList,
        dry_run: Boolean = None,
        service_id: VpcEndpointServiceId = None,
        vpc_endpoint_id: VpcEndpointId = None,
        client_token: String = None,
        **kwargs,
    ) -> CreateVpcEndpointConnectionNotificationResult:
        raise NotImplementedError

    @handler("CreateVpcEndpointServiceConfiguration")
    def create_vpc_endpoint_service_configuration(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        acceptance_required: Boolean = None,
        private_dns_name: String = None,
        network_load_balancer_arns: ValueStringList = None,
        gateway_load_balancer_arns: ValueStringList = None,
        supported_ip_address_types: ValueStringList = None,
        client_token: String = None,
        tag_specifications: TagSpecificationList = None,
        **kwargs,
    ) -> CreateVpcEndpointServiceConfigurationResult:
        raise NotImplementedError

    @handler("CreateVpcPeeringConnection")
    def create_vpc_peering_connection(
        self,
        context: RequestContext,
        vpc_id: VpcId,
        peer_region: String = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        peer_vpc_id: String = None,
        peer_owner_id: String = None,
        **kwargs,
    ) -> CreateVpcPeeringConnectionResult:
        raise NotImplementedError

    @handler("CreateVpnConnection", expand=False)
    def create_vpn_connection(
        self, context: RequestContext, request: CreateVpnConnectionRequest, **kwargs
    ) -> CreateVpnConnectionResult:
        raise NotImplementedError

    @handler("CreateVpnConnectionRoute")
    def create_vpn_connection_route(
        self,
        context: RequestContext,
        destination_cidr_block: String,
        vpn_connection_id: VpnConnectionId,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("CreateVpnGateway", expand=False)
    def create_vpn_gateway(
        self, context: RequestContext, request: CreateVpnGatewayRequest, **kwargs
    ) -> CreateVpnGatewayResult:
        raise NotImplementedError

    @handler("DeleteCarrierGateway")
    def delete_carrier_gateway(
        self,
        context: RequestContext,
        carrier_gateway_id: CarrierGatewayId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteCarrierGatewayResult:
        raise NotImplementedError

    @handler("DeleteClientVpnEndpoint")
    def delete_client_vpn_endpoint(
        self,
        context: RequestContext,
        client_vpn_endpoint_id: ClientVpnEndpointId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteClientVpnEndpointResult:
        raise NotImplementedError

    @handler("DeleteClientVpnRoute")
    def delete_client_vpn_route(
        self,
        context: RequestContext,
        client_vpn_endpoint_id: ClientVpnEndpointId,
        destination_cidr_block: String,
        target_vpc_subnet_id: SubnetId = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteClientVpnRouteResult:
        raise NotImplementedError

    @handler("DeleteCoipCidr")
    def delete_coip_cidr(
        self,
        context: RequestContext,
        cidr: String,
        coip_pool_id: Ipv4PoolCoipId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteCoipCidrResult:
        raise NotImplementedError

    @handler("DeleteCoipPool")
    def delete_coip_pool(
        self,
        context: RequestContext,
        coip_pool_id: Ipv4PoolCoipId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteCoipPoolResult:
        raise NotImplementedError

    @handler("DeleteCustomerGateway")
    def delete_customer_gateway(
        self,
        context: RequestContext,
        customer_gateway_id: CustomerGatewayId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteDhcpOptions")
    def delete_dhcp_options(
        self,
        context: RequestContext,
        dhcp_options_id: DhcpOptionsId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteEgressOnlyInternetGateway")
    def delete_egress_only_internet_gateway(
        self,
        context: RequestContext,
        egress_only_internet_gateway_id: EgressOnlyInternetGatewayId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteEgressOnlyInternetGatewayResult:
        raise NotImplementedError

    @handler("DeleteFleets")
    def delete_fleets(
        self,
        context: RequestContext,
        fleet_ids: FleetIdSet,
        terminate_instances: Boolean,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteFleetsResult:
        raise NotImplementedError

    @handler("DeleteFlowLogs")
    def delete_flow_logs(
        self,
        context: RequestContext,
        flow_log_ids: FlowLogIdList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteFlowLogsResult:
        raise NotImplementedError

    @handler("DeleteFpgaImage")
    def delete_fpga_image(
        self, context: RequestContext, fpga_image_id: FpgaImageId, dry_run: Boolean = None, **kwargs
    ) -> DeleteFpgaImageResult:
        raise NotImplementedError

    @handler("DeleteInstanceConnectEndpoint")
    def delete_instance_connect_endpoint(
        self,
        context: RequestContext,
        instance_connect_endpoint_id: InstanceConnectEndpointId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteInstanceConnectEndpointResult:
        raise NotImplementedError

    @handler("DeleteInstanceEventWindow")
    def delete_instance_event_window(
        self,
        context: RequestContext,
        instance_event_window_id: InstanceEventWindowId,
        dry_run: Boolean = None,
        force_delete: Boolean = None,
        **kwargs,
    ) -> DeleteInstanceEventWindowResult:
        raise NotImplementedError

    @handler("DeleteInternetGateway")
    def delete_internet_gateway(
        self,
        context: RequestContext,
        internet_gateway_id: InternetGatewayId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteIpam")
    def delete_ipam(
        self,
        context: RequestContext,
        ipam_id: IpamId,
        dry_run: Boolean = None,
        cascade: Boolean = None,
        **kwargs,
    ) -> DeleteIpamResult:
        raise NotImplementedError

    @handler("DeleteIpamExternalResourceVerificationToken")
    def delete_ipam_external_resource_verification_token(
        self,
        context: RequestContext,
        ipam_external_resource_verification_token_id: IpamExternalResourceVerificationTokenId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteIpamExternalResourceVerificationTokenResult:
        raise NotImplementedError

    @handler("DeleteIpamPool")
    def delete_ipam_pool(
        self,
        context: RequestContext,
        ipam_pool_id: IpamPoolId,
        dry_run: Boolean = None,
        cascade: Boolean = None,
        **kwargs,
    ) -> DeleteIpamPoolResult:
        raise NotImplementedError

    @handler("DeleteIpamResourceDiscovery")
    def delete_ipam_resource_discovery(
        self,
        context: RequestContext,
        ipam_resource_discovery_id: IpamResourceDiscoveryId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteIpamResourceDiscoveryResult:
        raise NotImplementedError

    @handler("DeleteIpamScope")
    def delete_ipam_scope(
        self, context: RequestContext, ipam_scope_id: IpamScopeId, dry_run: Boolean = None, **kwargs
    ) -> DeleteIpamScopeResult:
        raise NotImplementedError

    @handler("DeleteKeyPair")
    def delete_key_pair(
        self,
        context: RequestContext,
        key_name: KeyPairNameWithResolver = None,
        key_pair_id: KeyPairId = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteKeyPairResult:
        raise NotImplementedError

    @handler("DeleteLaunchTemplate")
    def delete_launch_template(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        launch_template_id: LaunchTemplateId = None,
        launch_template_name: LaunchTemplateName = None,
        **kwargs,
    ) -> DeleteLaunchTemplateResult:
        raise NotImplementedError

    @handler("DeleteLaunchTemplateVersions")
    def delete_launch_template_versions(
        self,
        context: RequestContext,
        versions: VersionStringList,
        dry_run: Boolean = None,
        launch_template_id: LaunchTemplateId = None,
        launch_template_name: LaunchTemplateName = None,
        **kwargs,
    ) -> DeleteLaunchTemplateVersionsResult:
        raise NotImplementedError

    @handler("DeleteLocalGatewayRoute")
    def delete_local_gateway_route(
        self,
        context: RequestContext,
        local_gateway_route_table_id: LocalGatewayRoutetableId,
        destination_cidr_block: String = None,
        dry_run: Boolean = None,
        destination_prefix_list_id: PrefixListResourceId = None,
        **kwargs,
    ) -> DeleteLocalGatewayRouteResult:
        raise NotImplementedError

    @handler("DeleteLocalGatewayRouteTable")
    def delete_local_gateway_route_table(
        self,
        context: RequestContext,
        local_gateway_route_table_id: LocalGatewayRoutetableId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteLocalGatewayRouteTableResult:
        raise NotImplementedError

    @handler("DeleteLocalGatewayRouteTableVirtualInterfaceGroupAssociation")
    def delete_local_gateway_route_table_virtual_interface_group_association(
        self,
        context: RequestContext,
        local_gateway_route_table_virtual_interface_group_association_id: LocalGatewayRouteTableVirtualInterfaceGroupAssociationId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteLocalGatewayRouteTableVirtualInterfaceGroupAssociationResult:
        raise NotImplementedError

    @handler("DeleteLocalGatewayRouteTableVpcAssociation")
    def delete_local_gateway_route_table_vpc_association(
        self,
        context: RequestContext,
        local_gateway_route_table_vpc_association_id: LocalGatewayRouteTableVpcAssociationId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteLocalGatewayRouteTableVpcAssociationResult:
        raise NotImplementedError

    @handler("DeleteManagedPrefixList")
    def delete_managed_prefix_list(
        self,
        context: RequestContext,
        prefix_list_id: PrefixListResourceId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteManagedPrefixListResult:
        raise NotImplementedError

    @handler("DeleteNatGateway")
    def delete_nat_gateway(
        self,
        context: RequestContext,
        nat_gateway_id: NatGatewayId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteNatGatewayResult:
        raise NotImplementedError

    @handler("DeleteNetworkAcl")
    def delete_network_acl(
        self,
        context: RequestContext,
        network_acl_id: NetworkAclId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteNetworkAclEntry")
    def delete_network_acl_entry(
        self,
        context: RequestContext,
        network_acl_id: NetworkAclId,
        rule_number: Integer,
        egress: Boolean,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteNetworkInsightsAccessScope")
    def delete_network_insights_access_scope(
        self,
        context: RequestContext,
        network_insights_access_scope_id: NetworkInsightsAccessScopeId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteNetworkInsightsAccessScopeResult:
        raise NotImplementedError

    @handler("DeleteNetworkInsightsAccessScopeAnalysis")
    def delete_network_insights_access_scope_analysis(
        self,
        context: RequestContext,
        network_insights_access_scope_analysis_id: NetworkInsightsAccessScopeAnalysisId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteNetworkInsightsAccessScopeAnalysisResult:
        raise NotImplementedError

    @handler("DeleteNetworkInsightsAnalysis")
    def delete_network_insights_analysis(
        self,
        context: RequestContext,
        network_insights_analysis_id: NetworkInsightsAnalysisId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteNetworkInsightsAnalysisResult:
        raise NotImplementedError

    @handler("DeleteNetworkInsightsPath")
    def delete_network_insights_path(
        self,
        context: RequestContext,
        network_insights_path_id: NetworkInsightsPathId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteNetworkInsightsPathResult:
        raise NotImplementedError

    @handler("DeleteNetworkInterface")
    def delete_network_interface(
        self,
        context: RequestContext,
        network_interface_id: NetworkInterfaceId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteNetworkInterfacePermission")
    def delete_network_interface_permission(
        self,
        context: RequestContext,
        network_interface_permission_id: NetworkInterfacePermissionId,
        force: Boolean = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteNetworkInterfacePermissionResult:
        raise NotImplementedError

    @handler("DeletePlacementGroup")
    def delete_placement_group(
        self,
        context: RequestContext,
        group_name: PlacementGroupName,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeletePublicIpv4Pool")
    def delete_public_ipv4_pool(
        self,
        context: RequestContext,
        pool_id: Ipv4PoolEc2Id,
        dry_run: Boolean = None,
        network_border_group: String = None,
        **kwargs,
    ) -> DeletePublicIpv4PoolResult:
        raise NotImplementedError

    @handler("DeleteQueuedReservedInstances")
    def delete_queued_reserved_instances(
        self,
        context: RequestContext,
        reserved_instances_ids: DeleteQueuedReservedInstancesIdList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteQueuedReservedInstancesResult:
        raise NotImplementedError

    @handler("DeleteRoute")
    def delete_route(
        self,
        context: RequestContext,
        route_table_id: RouteTableId,
        destination_prefix_list_id: PrefixListResourceId = None,
        dry_run: Boolean = None,
        destination_cidr_block: String = None,
        destination_ipv6_cidr_block: String = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteRouteTable")
    def delete_route_table(
        self,
        context: RequestContext,
        route_table_id: RouteTableId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteSecurityGroup")
    def delete_security_group(
        self,
        context: RequestContext,
        group_id: SecurityGroupId = None,
        group_name: SecurityGroupName = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteSnapshot")
    def delete_snapshot(
        self, context: RequestContext, snapshot_id: SnapshotId, dry_run: Boolean = None, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteSpotDatafeedSubscription")
    def delete_spot_datafeed_subscription(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteSubnet")
    def delete_subnet(
        self, context: RequestContext, subnet_id: SubnetId, dry_run: Boolean = None, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteSubnetCidrReservation")
    def delete_subnet_cidr_reservation(
        self,
        context: RequestContext,
        subnet_cidr_reservation_id: SubnetCidrReservationId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteSubnetCidrReservationResult:
        raise NotImplementedError

    @handler("DeleteTags")
    def delete_tags(
        self,
        context: RequestContext,
        resources: ResourceIdList,
        dry_run: Boolean = None,
        tags: TagList = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteTrafficMirrorFilter")
    def delete_traffic_mirror_filter(
        self,
        context: RequestContext,
        traffic_mirror_filter_id: TrafficMirrorFilterId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteTrafficMirrorFilterResult:
        raise NotImplementedError

    @handler("DeleteTrafficMirrorFilterRule")
    def delete_traffic_mirror_filter_rule(
        self,
        context: RequestContext,
        traffic_mirror_filter_rule_id: TrafficMirrorFilterRuleIdWithResolver,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteTrafficMirrorFilterRuleResult:
        raise NotImplementedError

    @handler("DeleteTrafficMirrorSession")
    def delete_traffic_mirror_session(
        self,
        context: RequestContext,
        traffic_mirror_session_id: TrafficMirrorSessionId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteTrafficMirrorSessionResult:
        raise NotImplementedError

    @handler("DeleteTrafficMirrorTarget")
    def delete_traffic_mirror_target(
        self,
        context: RequestContext,
        traffic_mirror_target_id: TrafficMirrorTargetId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteTrafficMirrorTargetResult:
        raise NotImplementedError

    @handler("DeleteTransitGateway")
    def delete_transit_gateway(
        self,
        context: RequestContext,
        transit_gateway_id: TransitGatewayId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteTransitGatewayResult:
        raise NotImplementedError

    @handler("DeleteTransitGatewayConnect")
    def delete_transit_gateway_connect(
        self,
        context: RequestContext,
        transit_gateway_attachment_id: TransitGatewayAttachmentId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteTransitGatewayConnectResult:
        raise NotImplementedError

    @handler("DeleteTransitGatewayConnectPeer")
    def delete_transit_gateway_connect_peer(
        self,
        context: RequestContext,
        transit_gateway_connect_peer_id: TransitGatewayConnectPeerId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteTransitGatewayConnectPeerResult:
        raise NotImplementedError

    @handler("DeleteTransitGatewayMulticastDomain")
    def delete_transit_gateway_multicast_domain(
        self,
        context: RequestContext,
        transit_gateway_multicast_domain_id: TransitGatewayMulticastDomainId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteTransitGatewayMulticastDomainResult:
        raise NotImplementedError

    @handler("DeleteTransitGatewayPeeringAttachment")
    def delete_transit_gateway_peering_attachment(
        self,
        context: RequestContext,
        transit_gateway_attachment_id: TransitGatewayAttachmentId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteTransitGatewayPeeringAttachmentResult:
        raise NotImplementedError

    @handler("DeleteTransitGatewayPolicyTable")
    def delete_transit_gateway_policy_table(
        self,
        context: RequestContext,
        transit_gateway_policy_table_id: TransitGatewayPolicyTableId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteTransitGatewayPolicyTableResult:
        raise NotImplementedError

    @handler("DeleteTransitGatewayPrefixListReference")
    def delete_transit_gateway_prefix_list_reference(
        self,
        context: RequestContext,
        transit_gateway_route_table_id: TransitGatewayRouteTableId,
        prefix_list_id: PrefixListResourceId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteTransitGatewayPrefixListReferenceResult:
        raise NotImplementedError

    @handler("DeleteTransitGatewayRoute")
    def delete_transit_gateway_route(
        self,
        context: RequestContext,
        transit_gateway_route_table_id: TransitGatewayRouteTableId,
        destination_cidr_block: String,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteTransitGatewayRouteResult:
        raise NotImplementedError

    @handler("DeleteTransitGatewayRouteTable")
    def delete_transit_gateway_route_table(
        self,
        context: RequestContext,
        transit_gateway_route_table_id: TransitGatewayRouteTableId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteTransitGatewayRouteTableResult:
        raise NotImplementedError

    @handler("DeleteTransitGatewayRouteTableAnnouncement")
    def delete_transit_gateway_route_table_announcement(
        self,
        context: RequestContext,
        transit_gateway_route_table_announcement_id: TransitGatewayRouteTableAnnouncementId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteTransitGatewayRouteTableAnnouncementResult:
        raise NotImplementedError

    @handler("DeleteTransitGatewayVpcAttachment")
    def delete_transit_gateway_vpc_attachment(
        self,
        context: RequestContext,
        transit_gateway_attachment_id: TransitGatewayAttachmentId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteTransitGatewayVpcAttachmentResult:
        raise NotImplementedError

    @handler("DeleteVerifiedAccessEndpoint")
    def delete_verified_access_endpoint(
        self,
        context: RequestContext,
        verified_access_endpoint_id: VerifiedAccessEndpointId,
        client_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteVerifiedAccessEndpointResult:
        raise NotImplementedError

    @handler("DeleteVerifiedAccessGroup")
    def delete_verified_access_group(
        self,
        context: RequestContext,
        verified_access_group_id: VerifiedAccessGroupId,
        client_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteVerifiedAccessGroupResult:
        raise NotImplementedError

    @handler("DeleteVerifiedAccessInstance")
    def delete_verified_access_instance(
        self,
        context: RequestContext,
        verified_access_instance_id: VerifiedAccessInstanceId,
        dry_run: Boolean = None,
        client_token: String = None,
        **kwargs,
    ) -> DeleteVerifiedAccessInstanceResult:
        raise NotImplementedError

    @handler("DeleteVerifiedAccessTrustProvider")
    def delete_verified_access_trust_provider(
        self,
        context: RequestContext,
        verified_access_trust_provider_id: VerifiedAccessTrustProviderId,
        dry_run: Boolean = None,
        client_token: String = None,
        **kwargs,
    ) -> DeleteVerifiedAccessTrustProviderResult:
        raise NotImplementedError

    @handler("DeleteVolume")
    def delete_volume(
        self, context: RequestContext, volume_id: VolumeId, dry_run: Boolean = None, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteVpc")
    def delete_vpc(
        self, context: RequestContext, vpc_id: VpcId, dry_run: Boolean = None, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeleteVpcEndpointConnectionNotifications")
    def delete_vpc_endpoint_connection_notifications(
        self,
        context: RequestContext,
        connection_notification_ids: ConnectionNotificationIdsList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteVpcEndpointConnectionNotificationsResult:
        raise NotImplementedError

    @handler("DeleteVpcEndpointServiceConfigurations")
    def delete_vpc_endpoint_service_configurations(
        self,
        context: RequestContext,
        service_ids: VpcEndpointServiceIdList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteVpcEndpointServiceConfigurationsResult:
        raise NotImplementedError

    @handler("DeleteVpcEndpoints")
    def delete_vpc_endpoints(
        self,
        context: RequestContext,
        vpc_endpoint_ids: VpcEndpointIdList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteVpcEndpointsResult:
        raise NotImplementedError

    @handler("DeleteVpcPeeringConnection")
    def delete_vpc_peering_connection(
        self,
        context: RequestContext,
        vpc_peering_connection_id: VpcPeeringConnectionId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeleteVpcPeeringConnectionResult:
        raise NotImplementedError

    @handler("DeleteVpnConnection")
    def delete_vpn_connection(
        self,
        context: RequestContext,
        vpn_connection_id: VpnConnectionId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteVpnConnectionRoute")
    def delete_vpn_connection_route(
        self,
        context: RequestContext,
        destination_cidr_block: String,
        vpn_connection_id: VpnConnectionId,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeleteVpnGateway")
    def delete_vpn_gateway(
        self,
        context: RequestContext,
        vpn_gateway_id: VpnGatewayId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DeprovisionByoipCidr")
    def deprovision_byoip_cidr(
        self, context: RequestContext, cidr: String, dry_run: Boolean = None, **kwargs
    ) -> DeprovisionByoipCidrResult:
        raise NotImplementedError

    @handler("DeprovisionIpamByoasn")
    def deprovision_ipam_byoasn(
        self,
        context: RequestContext,
        ipam_id: IpamId,
        asn: String,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeprovisionIpamByoasnResult:
        raise NotImplementedError

    @handler("DeprovisionIpamPoolCidr")
    def deprovision_ipam_pool_cidr(
        self,
        context: RequestContext,
        ipam_pool_id: IpamPoolId,
        dry_run: Boolean = None,
        cidr: String = None,
        **kwargs,
    ) -> DeprovisionIpamPoolCidrResult:
        raise NotImplementedError

    @handler("DeprovisionPublicIpv4PoolCidr")
    def deprovision_public_ipv4_pool_cidr(
        self,
        context: RequestContext,
        pool_id: Ipv4PoolEc2Id,
        cidr: String,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeprovisionPublicIpv4PoolCidrResult:
        raise NotImplementedError

    @handler("DeregisterImage")
    def deregister_image(
        self, context: RequestContext, image_id: ImageId, dry_run: Boolean = None, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("DeregisterInstanceEventNotificationAttributes")
    def deregister_instance_event_notification_attributes(
        self,
        context: RequestContext,
        instance_tag_attribute: DeregisterInstanceTagAttributeRequest,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeregisterInstanceEventNotificationAttributesResult:
        raise NotImplementedError

    @handler("DeregisterTransitGatewayMulticastGroupMembers")
    def deregister_transit_gateway_multicast_group_members(
        self,
        context: RequestContext,
        transit_gateway_multicast_domain_id: TransitGatewayMulticastDomainId = None,
        group_ip_address: String = None,
        network_interface_ids: TransitGatewayNetworkInterfaceIdList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeregisterTransitGatewayMulticastGroupMembersResult:
        raise NotImplementedError

    @handler("DeregisterTransitGatewayMulticastGroupSources")
    def deregister_transit_gateway_multicast_group_sources(
        self,
        context: RequestContext,
        transit_gateway_multicast_domain_id: TransitGatewayMulticastDomainId = None,
        group_ip_address: String = None,
        network_interface_ids: TransitGatewayNetworkInterfaceIdList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DeregisterTransitGatewayMulticastGroupSourcesResult:
        raise NotImplementedError

    @handler("DescribeAccountAttributes")
    def describe_account_attributes(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        attribute_names: AccountAttributeNameStringList = None,
        **kwargs,
    ) -> DescribeAccountAttributesResult:
        raise NotImplementedError

    @handler("DescribeAddressTransfers")
    def describe_address_transfers(
        self,
        context: RequestContext,
        allocation_ids: AllocationIdList = None,
        next_token: String = None,
        max_results: DescribeAddressTransfersMaxResults = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeAddressTransfersResult:
        raise NotImplementedError

    @handler("DescribeAddresses")
    def describe_addresses(
        self,
        context: RequestContext,
        public_ips: PublicIpStringList = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        allocation_ids: AllocationIdList = None,
        **kwargs,
    ) -> DescribeAddressesResult:
        raise NotImplementedError

    @handler("DescribeAddressesAttribute")
    def describe_addresses_attribute(
        self,
        context: RequestContext,
        allocation_ids: AllocationIds = None,
        attribute: AddressAttributeName = None,
        next_token: NextToken = None,
        max_results: AddressMaxResults = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeAddressesAttributeResult:
        raise NotImplementedError

    @handler("DescribeAggregateIdFormat")
    def describe_aggregate_id_format(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> DescribeAggregateIdFormatResult:
        raise NotImplementedError

    @handler("DescribeAvailabilityZones")
    def describe_availability_zones(
        self,
        context: RequestContext,
        zone_names: ZoneNameStringList = None,
        zone_ids: ZoneIdStringList = None,
        all_availability_zones: Boolean = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeAvailabilityZonesResult:
        raise NotImplementedError

    @handler("DescribeAwsNetworkPerformanceMetricSubscriptions")
    def describe_aws_network_performance_metric_subscriptions(
        self,
        context: RequestContext,
        max_results: MaxResultsParam = None,
        next_token: String = None,
        filters: FilterList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeAwsNetworkPerformanceMetricSubscriptionsResult:
        raise NotImplementedError

    @handler("DescribeBundleTasks")
    def describe_bundle_tasks(
        self,
        context: RequestContext,
        bundle_ids: BundleIdStringList = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeBundleTasksResult:
        raise NotImplementedError

    @handler("DescribeByoipCidrs")
    def describe_byoip_cidrs(
        self,
        context: RequestContext,
        max_results: DescribeByoipCidrsMaxResults,
        dry_run: Boolean = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeByoipCidrsResult:
        raise NotImplementedError

    @handler("DescribeCapacityBlockOfferings")
    def describe_capacity_block_offerings(
        self,
        context: RequestContext,
        capacity_duration_hours: Integer,
        dry_run: Boolean = None,
        instance_type: String = None,
        instance_count: Integer = None,
        start_date_range: MillisecondDateTime = None,
        end_date_range: MillisecondDateTime = None,
        next_token: String = None,
        max_results: DescribeCapacityBlockOfferingsMaxResults = None,
        **kwargs,
    ) -> DescribeCapacityBlockOfferingsResult:
        raise NotImplementedError

    @handler("DescribeCapacityReservationBillingRequests")
    def describe_capacity_reservation_billing_requests(
        self,
        context: RequestContext,
        role: CallerRole,
        capacity_reservation_ids: CapacityReservationIdSet = None,
        next_token: String = None,
        max_results: DescribeCapacityReservationBillingRequestsRequestMaxResults = None,
        filters: FilterList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeCapacityReservationBillingRequestsResult:
        raise NotImplementedError

    @handler("DescribeCapacityReservationFleets")
    def describe_capacity_reservation_fleets(
        self,
        context: RequestContext,
        capacity_reservation_fleet_ids: CapacityReservationFleetIdSet = None,
        next_token: String = None,
        max_results: DescribeCapacityReservationFleetsMaxResults = None,
        filters: FilterList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeCapacityReservationFleetsResult:
        raise NotImplementedError

    @handler("DescribeCapacityReservations")
    def describe_capacity_reservations(
        self,
        context: RequestContext,
        capacity_reservation_ids: CapacityReservationIdSet = None,
        next_token: String = None,
        max_results: DescribeCapacityReservationsMaxResults = None,
        filters: FilterList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeCapacityReservationsResult:
        raise NotImplementedError

    @handler("DescribeCarrierGateways")
    def describe_carrier_gateways(
        self,
        context: RequestContext,
        carrier_gateway_ids: CarrierGatewayIdSet = None,
        filters: FilterList = None,
        max_results: CarrierGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeCarrierGatewaysResult:
        raise NotImplementedError

    @handler("DescribeClassicLinkInstances")
    def describe_classic_link_instances(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        instance_ids: InstanceIdStringList = None,
        filters: FilterList = None,
        next_token: String = None,
        max_results: DescribeClassicLinkInstancesMaxResults = None,
        **kwargs,
    ) -> DescribeClassicLinkInstancesResult:
        raise NotImplementedError

    @handler("DescribeClientVpnAuthorizationRules")
    def describe_client_vpn_authorization_rules(
        self,
        context: RequestContext,
        client_vpn_endpoint_id: ClientVpnEndpointId,
        dry_run: Boolean = None,
        next_token: NextToken = None,
        filters: FilterList = None,
        max_results: DescribeClientVpnAuthorizationRulesMaxResults = None,
        **kwargs,
    ) -> DescribeClientVpnAuthorizationRulesResult:
        raise NotImplementedError

    @handler("DescribeClientVpnConnections")
    def describe_client_vpn_connections(
        self,
        context: RequestContext,
        client_vpn_endpoint_id: ClientVpnEndpointId,
        filters: FilterList = None,
        next_token: NextToken = None,
        max_results: DescribeClientVpnConnectionsMaxResults = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeClientVpnConnectionsResult:
        raise NotImplementedError

    @handler("DescribeClientVpnEndpoints")
    def describe_client_vpn_endpoints(
        self,
        context: RequestContext,
        client_vpn_endpoint_ids: ClientVpnEndpointIdList = None,
        max_results: DescribeClientVpnEndpointMaxResults = None,
        next_token: NextToken = None,
        filters: FilterList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeClientVpnEndpointsResult:
        raise NotImplementedError

    @handler("DescribeClientVpnRoutes")
    def describe_client_vpn_routes(
        self,
        context: RequestContext,
        client_vpn_endpoint_id: ClientVpnEndpointId,
        filters: FilterList = None,
        max_results: DescribeClientVpnRoutesMaxResults = None,
        next_token: NextToken = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeClientVpnRoutesResult:
        raise NotImplementedError

    @handler("DescribeClientVpnTargetNetworks")
    def describe_client_vpn_target_networks(
        self,
        context: RequestContext,
        client_vpn_endpoint_id: ClientVpnEndpointId,
        association_ids: ValueStringList = None,
        max_results: DescribeClientVpnTargetNetworksMaxResults = None,
        next_token: NextToken = None,
        filters: FilterList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeClientVpnTargetNetworksResult:
        raise NotImplementedError

    @handler("DescribeCoipPools")
    def describe_coip_pools(
        self,
        context: RequestContext,
        pool_ids: CoipPoolIdSet = None,
        filters: FilterList = None,
        max_results: CoipPoolMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeCoipPoolsResult:
        raise NotImplementedError

    @handler("DescribeConversionTasks")
    def describe_conversion_tasks(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        conversion_task_ids: ConversionIdStringList = None,
        **kwargs,
    ) -> DescribeConversionTasksResult:
        raise NotImplementedError

    @handler("DescribeCustomerGateways")
    def describe_customer_gateways(
        self,
        context: RequestContext,
        customer_gateway_ids: CustomerGatewayIdStringList = None,
        filters: FilterList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeCustomerGatewaysResult:
        raise NotImplementedError

    @handler("DescribeDhcpOptions")
    def describe_dhcp_options(
        self,
        context: RequestContext,
        dhcp_options_ids: DhcpOptionsIdStringList = None,
        next_token: String = None,
        max_results: DescribeDhcpOptionsMaxResults = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeDhcpOptionsResult:
        raise NotImplementedError

    @handler("DescribeEgressOnlyInternetGateways")
    def describe_egress_only_internet_gateways(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        egress_only_internet_gateway_ids: EgressOnlyInternetGatewayIdList = None,
        max_results: DescribeEgressOnlyInternetGatewaysMaxResults = None,
        next_token: String = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeEgressOnlyInternetGatewaysResult:
        raise NotImplementedError

    @handler("DescribeElasticGpus")
    def describe_elastic_gpus(
        self,
        context: RequestContext,
        elastic_gpu_ids: ElasticGpuIdSet = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        max_results: DescribeElasticGpusMaxResults = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeElasticGpusResult:
        raise NotImplementedError

    @handler("DescribeExportImageTasks")
    def describe_export_image_tasks(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        filters: FilterList = None,
        export_image_task_ids: ExportImageTaskIdList = None,
        max_results: DescribeExportImageTasksMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeExportImageTasksResult:
        raise NotImplementedError

    @handler("DescribeExportTasks")
    def describe_export_tasks(
        self,
        context: RequestContext,
        filters: FilterList = None,
        export_task_ids: ExportTaskIdStringList = None,
        **kwargs,
    ) -> DescribeExportTasksResult:
        raise NotImplementedError

    @handler("DescribeFastLaunchImages")
    def describe_fast_launch_images(
        self,
        context: RequestContext,
        image_ids: FastLaunchImageIdList = None,
        filters: FilterList = None,
        max_results: DescribeFastLaunchImagesRequestMaxResults = None,
        next_token: NextToken = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeFastLaunchImagesResult:
        raise NotImplementedError

    @handler("DescribeFastSnapshotRestores")
    def describe_fast_snapshot_restores(
        self,
        context: RequestContext,
        filters: FilterList = None,
        max_results: DescribeFastSnapshotRestoresMaxResults = None,
        next_token: NextToken = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeFastSnapshotRestoresResult:
        raise NotImplementedError

    @handler("DescribeFleetHistory")
    def describe_fleet_history(
        self,
        context: RequestContext,
        fleet_id: FleetId,
        start_time: DateTime,
        dry_run: Boolean = None,
        event_type: FleetEventType = None,
        max_results: Integer = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeFleetHistoryResult:
        raise NotImplementedError

    @handler("DescribeFleetInstances")
    def describe_fleet_instances(
        self,
        context: RequestContext,
        fleet_id: FleetId,
        dry_run: Boolean = None,
        max_results: Integer = None,
        next_token: String = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeFleetInstancesResult:
        raise NotImplementedError

    @handler("DescribeFleets")
    def describe_fleets(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        max_results: Integer = None,
        next_token: String = None,
        fleet_ids: FleetIdSet = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeFleetsResult:
        raise NotImplementedError

    @handler("DescribeFlowLogs")
    def describe_flow_logs(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        filter: FilterList = None,
        flow_log_ids: FlowLogIdList = None,
        max_results: Integer = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeFlowLogsResult:
        raise NotImplementedError

    @handler("DescribeFpgaImageAttribute")
    def describe_fpga_image_attribute(
        self,
        context: RequestContext,
        fpga_image_id: FpgaImageId,
        attribute: FpgaImageAttributeName,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeFpgaImageAttributeResult:
        raise NotImplementedError

    @handler("DescribeFpgaImages")
    def describe_fpga_images(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        fpga_image_ids: FpgaImageIdList = None,
        owners: OwnerStringList = None,
        filters: FilterList = None,
        next_token: NextToken = None,
        max_results: DescribeFpgaImagesMaxResults = None,
        **kwargs,
    ) -> DescribeFpgaImagesResult:
        raise NotImplementedError

    @handler("DescribeHostReservationOfferings")
    def describe_host_reservation_offerings(
        self,
        context: RequestContext,
        filter: FilterList = None,
        max_duration: Integer = None,
        max_results: DescribeHostReservationsMaxResults = None,
        min_duration: Integer = None,
        next_token: String = None,
        offering_id: OfferingId = None,
        **kwargs,
    ) -> DescribeHostReservationOfferingsResult:
        raise NotImplementedError

    @handler("DescribeHostReservations")
    def describe_host_reservations(
        self,
        context: RequestContext,
        filter: FilterList = None,
        host_reservation_id_set: HostReservationIdSet = None,
        max_results: Integer = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeHostReservationsResult:
        raise NotImplementedError

    @handler("DescribeHosts")
    def describe_hosts(
        self,
        context: RequestContext,
        host_ids: RequestHostIdList = None,
        next_token: String = None,
        max_results: Integer = None,
        filter: FilterList = None,
        **kwargs,
    ) -> DescribeHostsResult:
        raise NotImplementedError

    @handler("DescribeIamInstanceProfileAssociations")
    def describe_iam_instance_profile_associations(
        self,
        context: RequestContext,
        association_ids: AssociationIdList = None,
        filters: FilterList = None,
        max_results: DescribeIamInstanceProfileAssociationsMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeIamInstanceProfileAssociationsResult:
        raise NotImplementedError

    @handler("DescribeIdFormat")
    def describe_id_format(
        self, context: RequestContext, resource: String = None, **kwargs
    ) -> DescribeIdFormatResult:
        raise NotImplementedError

    @handler("DescribeIdentityIdFormat")
    def describe_identity_id_format(
        self, context: RequestContext, principal_arn: String, resource: String = None, **kwargs
    ) -> DescribeIdentityIdFormatResult:
        raise NotImplementedError

    @handler("DescribeImageAttribute")
    def describe_image_attribute(
        self,
        context: RequestContext,
        attribute: ImageAttributeName,
        image_id: ImageId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ImageAttribute:
        raise NotImplementedError

    @handler("DescribeImages")
    def describe_images(
        self,
        context: RequestContext,
        executable_users: ExecutableByStringList = None,
        image_ids: ImageIdStringList = None,
        owners: OwnerStringList = None,
        include_deprecated: Boolean = None,
        include_disabled: Boolean = None,
        max_results: Integer = None,
        next_token: String = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeImagesResult:
        raise NotImplementedError

    @handler("DescribeImportImageTasks")
    def describe_import_image_tasks(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        filters: FilterList = None,
        import_task_ids: ImportTaskIdList = None,
        max_results: Integer = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeImportImageTasksResult:
        raise NotImplementedError

    @handler("DescribeImportSnapshotTasks")
    def describe_import_snapshot_tasks(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        filters: FilterList = None,
        import_task_ids: ImportSnapshotTaskIdList = None,
        max_results: Integer = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeImportSnapshotTasksResult:
        raise NotImplementedError

    @handler("DescribeInstanceAttribute")
    def describe_instance_attribute(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        attribute: InstanceAttributeName,
        dry_run: Boolean = None,
        **kwargs,
    ) -> InstanceAttribute:
        raise NotImplementedError

    @handler("DescribeInstanceConnectEndpoints")
    def describe_instance_connect_endpoints(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        max_results: InstanceConnectEndpointMaxResults = None,
        next_token: NextToken = None,
        filters: FilterList = None,
        instance_connect_endpoint_ids: ValueStringList = None,
        **kwargs,
    ) -> DescribeInstanceConnectEndpointsResult:
        raise NotImplementedError

    @handler("DescribeInstanceCreditSpecifications")
    def describe_instance_credit_specifications(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        filters: FilterList = None,
        instance_ids: InstanceIdStringList = None,
        max_results: DescribeInstanceCreditSpecificationsMaxResults = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeInstanceCreditSpecificationsResult:
        raise NotImplementedError

    @handler("DescribeInstanceEventNotificationAttributes")
    def describe_instance_event_notification_attributes(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> DescribeInstanceEventNotificationAttributesResult:
        raise NotImplementedError

    @handler("DescribeInstanceEventWindows")
    def describe_instance_event_windows(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        instance_event_window_ids: InstanceEventWindowIdSet = None,
        filters: FilterList = None,
        max_results: ResultRange = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeInstanceEventWindowsResult:
        raise NotImplementedError

    @handler("DescribeInstanceImageMetadata")
    def describe_instance_image_metadata(
        self,
        context: RequestContext,
        filters: FilterList = None,
        instance_ids: InstanceIdStringList = None,
        max_results: DescribeInstanceImageMetadataMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeInstanceImageMetadataResult:
        raise NotImplementedError

    @handler("DescribeInstanceStatus")
    def describe_instance_status(
        self,
        context: RequestContext,
        instance_ids: InstanceIdStringList = None,
        max_results: Integer = None,
        next_token: String = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        include_all_instances: Boolean = None,
        **kwargs,
    ) -> DescribeInstanceStatusResult:
        raise NotImplementedError

    @handler("DescribeInstanceTopology")
    def describe_instance_topology(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        next_token: String = None,
        max_results: DescribeInstanceTopologyMaxResults = None,
        instance_ids: DescribeInstanceTopologyInstanceIdSet = None,
        group_names: DescribeInstanceTopologyGroupNameSet = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeInstanceTopologyResult:
        raise NotImplementedError

    @handler("DescribeInstanceTypeOfferings")
    def describe_instance_type_offerings(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        location_type: LocationType = None,
        filters: FilterList = None,
        max_results: DITOMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeInstanceTypeOfferingsResult:
        raise NotImplementedError

    @handler("DescribeInstanceTypes")
    def describe_instance_types(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        instance_types: RequestInstanceTypeList = None,
        filters: FilterList = None,
        max_results: DITMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeInstanceTypesResult:
        raise NotImplementedError

    @handler("DescribeInstances")
    def describe_instances(
        self,
        context: RequestContext,
        instance_ids: InstanceIdStringList = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        next_token: String = None,
        max_results: Integer = None,
        **kwargs,
    ) -> DescribeInstancesResult:
        raise NotImplementedError

    @handler("DescribeInternetGateways")
    def describe_internet_gateways(
        self,
        context: RequestContext,
        next_token: String = None,
        max_results: DescribeInternetGatewaysMaxResults = None,
        dry_run: Boolean = None,
        internet_gateway_ids: InternetGatewayIdList = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeInternetGatewaysResult:
        raise NotImplementedError

    @handler("DescribeIpamByoasn")
    def describe_ipam_byoasn(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        max_results: DescribeIpamByoasnMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeIpamByoasnResult:
        raise NotImplementedError

    @handler("DescribeIpamExternalResourceVerificationTokens")
    def describe_ipam_external_resource_verification_tokens(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        filters: FilterList = None,
        next_token: NextToken = None,
        max_results: IpamMaxResults = None,
        ipam_external_resource_verification_token_ids: ValueStringList = None,
        **kwargs,
    ) -> DescribeIpamExternalResourceVerificationTokensResult:
        raise NotImplementedError

    @handler("DescribeIpamPools")
    def describe_ipam_pools(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        filters: FilterList = None,
        max_results: IpamMaxResults = None,
        next_token: NextToken = None,
        ipam_pool_ids: ValueStringList = None,
        **kwargs,
    ) -> DescribeIpamPoolsResult:
        raise NotImplementedError

    @handler("DescribeIpamResourceDiscoveries")
    def describe_ipam_resource_discoveries(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        ipam_resource_discovery_ids: ValueStringList = None,
        next_token: NextToken = None,
        max_results: IpamMaxResults = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeIpamResourceDiscoveriesResult:
        raise NotImplementedError

    @handler("DescribeIpamResourceDiscoveryAssociations")
    def describe_ipam_resource_discovery_associations(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        ipam_resource_discovery_association_ids: ValueStringList = None,
        next_token: NextToken = None,
        max_results: IpamMaxResults = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeIpamResourceDiscoveryAssociationsResult:
        raise NotImplementedError

    @handler("DescribeIpamScopes")
    def describe_ipam_scopes(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        filters: FilterList = None,
        max_results: IpamMaxResults = None,
        next_token: NextToken = None,
        ipam_scope_ids: ValueStringList = None,
        **kwargs,
    ) -> DescribeIpamScopesResult:
        raise NotImplementedError

    @handler("DescribeIpams")
    def describe_ipams(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        filters: FilterList = None,
        max_results: IpamMaxResults = None,
        next_token: NextToken = None,
        ipam_ids: ValueStringList = None,
        **kwargs,
    ) -> DescribeIpamsResult:
        raise NotImplementedError

    @handler("DescribeIpv6Pools")
    def describe_ipv6_pools(
        self,
        context: RequestContext,
        pool_ids: Ipv6PoolIdList = None,
        next_token: NextToken = None,
        max_results: Ipv6PoolMaxResults = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeIpv6PoolsResult:
        raise NotImplementedError

    @handler("DescribeKeyPairs")
    def describe_key_pairs(
        self,
        context: RequestContext,
        key_names: KeyNameStringList = None,
        key_pair_ids: KeyPairIdStringList = None,
        include_public_key: Boolean = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeKeyPairsResult:
        raise NotImplementedError

    @handler("DescribeLaunchTemplateVersions")
    def describe_launch_template_versions(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        launch_template_id: LaunchTemplateId = None,
        launch_template_name: LaunchTemplateName = None,
        versions: VersionStringList = None,
        min_version: String = None,
        max_version: String = None,
        next_token: String = None,
        max_results: Integer = None,
        filters: FilterList = None,
        resolve_alias: Boolean = None,
        **kwargs,
    ) -> DescribeLaunchTemplateVersionsResult:
        raise NotImplementedError

    @handler("DescribeLaunchTemplates")
    def describe_launch_templates(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        launch_template_ids: LaunchTemplateIdStringList = None,
        launch_template_names: LaunchTemplateNameStringList = None,
        filters: FilterList = None,
        next_token: String = None,
        max_results: DescribeLaunchTemplatesMaxResults = None,
        **kwargs,
    ) -> DescribeLaunchTemplatesResult:
        raise NotImplementedError

    @handler("DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociations")
    def describe_local_gateway_route_table_virtual_interface_group_associations(
        self,
        context: RequestContext,
        local_gateway_route_table_virtual_interface_group_association_ids: LocalGatewayRouteTableVirtualInterfaceGroupAssociationIdSet = None,
        filters: FilterList = None,
        max_results: LocalGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeLocalGatewayRouteTableVirtualInterfaceGroupAssociationsResult:
        raise NotImplementedError

    @handler("DescribeLocalGatewayRouteTableVpcAssociations")
    def describe_local_gateway_route_table_vpc_associations(
        self,
        context: RequestContext,
        local_gateway_route_table_vpc_association_ids: LocalGatewayRouteTableVpcAssociationIdSet = None,
        filters: FilterList = None,
        max_results: LocalGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeLocalGatewayRouteTableVpcAssociationsResult:
        raise NotImplementedError

    @handler("DescribeLocalGatewayRouteTables")
    def describe_local_gateway_route_tables(
        self,
        context: RequestContext,
        local_gateway_route_table_ids: LocalGatewayRouteTableIdSet = None,
        filters: FilterList = None,
        max_results: LocalGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeLocalGatewayRouteTablesResult:
        raise NotImplementedError

    @handler("DescribeLocalGatewayVirtualInterfaceGroups")
    def describe_local_gateway_virtual_interface_groups(
        self,
        context: RequestContext,
        local_gateway_virtual_interface_group_ids: LocalGatewayVirtualInterfaceGroupIdSet = None,
        filters: FilterList = None,
        max_results: LocalGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeLocalGatewayVirtualInterfaceGroupsResult:
        raise NotImplementedError

    @handler("DescribeLocalGatewayVirtualInterfaces")
    def describe_local_gateway_virtual_interfaces(
        self,
        context: RequestContext,
        local_gateway_virtual_interface_ids: LocalGatewayVirtualInterfaceIdSet = None,
        filters: FilterList = None,
        max_results: LocalGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeLocalGatewayVirtualInterfacesResult:
        raise NotImplementedError

    @handler("DescribeLocalGateways")
    def describe_local_gateways(
        self,
        context: RequestContext,
        local_gateway_ids: LocalGatewayIdSet = None,
        filters: FilterList = None,
        max_results: LocalGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeLocalGatewaysResult:
        raise NotImplementedError

    @handler("DescribeLockedSnapshots")
    def describe_locked_snapshots(
        self,
        context: RequestContext,
        filters: FilterList = None,
        max_results: DescribeLockedSnapshotsMaxResults = None,
        next_token: String = None,
        snapshot_ids: SnapshotIdStringList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeLockedSnapshotsResult:
        raise NotImplementedError

    @handler("DescribeMacHosts")
    def describe_mac_hosts(
        self,
        context: RequestContext,
        filters: FilterList = None,
        host_ids: RequestHostIdList = None,
        max_results: DescribeMacHostsRequestMaxResults = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeMacHostsResult:
        raise NotImplementedError

    @handler("DescribeManagedPrefixLists")
    def describe_managed_prefix_lists(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        filters: FilterList = None,
        max_results: PrefixListMaxResults = None,
        next_token: NextToken = None,
        prefix_list_ids: ValueStringList = None,
        **kwargs,
    ) -> DescribeManagedPrefixListsResult:
        raise NotImplementedError

    @handler("DescribeMovingAddresses")
    def describe_moving_addresses(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        public_ips: ValueStringList = None,
        next_token: String = None,
        filters: FilterList = None,
        max_results: DescribeMovingAddressesMaxResults = None,
        **kwargs,
    ) -> DescribeMovingAddressesResult:
        raise NotImplementedError

    @handler("DescribeNatGateways")
    def describe_nat_gateways(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        filter: FilterList = None,
        max_results: DescribeNatGatewaysMaxResults = None,
        nat_gateway_ids: NatGatewayIdStringList = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeNatGatewaysResult:
        raise NotImplementedError

    @handler("DescribeNetworkAcls")
    def describe_network_acls(
        self,
        context: RequestContext,
        next_token: String = None,
        max_results: DescribeNetworkAclsMaxResults = None,
        dry_run: Boolean = None,
        network_acl_ids: NetworkAclIdStringList = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeNetworkAclsResult:
        raise NotImplementedError

    @handler("DescribeNetworkInsightsAccessScopeAnalyses")
    def describe_network_insights_access_scope_analyses(
        self,
        context: RequestContext,
        network_insights_access_scope_analysis_ids: NetworkInsightsAccessScopeAnalysisIdList = None,
        network_insights_access_scope_id: NetworkInsightsAccessScopeId = None,
        analysis_start_time_begin: MillisecondDateTime = None,
        analysis_start_time_end: MillisecondDateTime = None,
        filters: FilterList = None,
        max_results: NetworkInsightsMaxResults = None,
        dry_run: Boolean = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeNetworkInsightsAccessScopeAnalysesResult:
        raise NotImplementedError

    @handler("DescribeNetworkInsightsAccessScopes")
    def describe_network_insights_access_scopes(
        self,
        context: RequestContext,
        network_insights_access_scope_ids: NetworkInsightsAccessScopeIdList = None,
        filters: FilterList = None,
        max_results: NetworkInsightsMaxResults = None,
        dry_run: Boolean = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeNetworkInsightsAccessScopesResult:
        raise NotImplementedError

    @handler("DescribeNetworkInsightsAnalyses")
    def describe_network_insights_analyses(
        self,
        context: RequestContext,
        network_insights_analysis_ids: NetworkInsightsAnalysisIdList = None,
        network_insights_path_id: NetworkInsightsPathId = None,
        analysis_start_time: MillisecondDateTime = None,
        analysis_end_time: MillisecondDateTime = None,
        filters: FilterList = None,
        max_results: NetworkInsightsMaxResults = None,
        dry_run: Boolean = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeNetworkInsightsAnalysesResult:
        raise NotImplementedError

    @handler("DescribeNetworkInsightsPaths")
    def describe_network_insights_paths(
        self,
        context: RequestContext,
        network_insights_path_ids: NetworkInsightsPathIdList = None,
        filters: FilterList = None,
        max_results: NetworkInsightsMaxResults = None,
        dry_run: Boolean = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeNetworkInsightsPathsResult:
        raise NotImplementedError

    @handler("DescribeNetworkInterfaceAttribute")
    def describe_network_interface_attribute(
        self,
        context: RequestContext,
        network_interface_id: NetworkInterfaceId,
        dry_run: Boolean = None,
        attribute: NetworkInterfaceAttribute = None,
        **kwargs,
    ) -> DescribeNetworkInterfaceAttributeResult:
        raise NotImplementedError

    @handler("DescribeNetworkInterfacePermissions")
    def describe_network_interface_permissions(
        self,
        context: RequestContext,
        network_interface_permission_ids: NetworkInterfacePermissionIdList = None,
        filters: FilterList = None,
        next_token: String = None,
        max_results: DescribeNetworkInterfacePermissionsMaxResults = None,
        **kwargs,
    ) -> DescribeNetworkInterfacePermissionsResult:
        raise NotImplementedError

    @handler("DescribeNetworkInterfaces")
    def describe_network_interfaces(
        self,
        context: RequestContext,
        next_token: String = None,
        max_results: DescribeNetworkInterfacesMaxResults = None,
        dry_run: Boolean = None,
        network_interface_ids: NetworkInterfaceIdList = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeNetworkInterfacesResult:
        raise NotImplementedError

    @handler("DescribePlacementGroups")
    def describe_placement_groups(
        self,
        context: RequestContext,
        group_ids: PlacementGroupIdStringList = None,
        dry_run: Boolean = None,
        group_names: PlacementGroupStringList = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribePlacementGroupsResult:
        raise NotImplementedError

    @handler("DescribePrefixLists")
    def describe_prefix_lists(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        filters: FilterList = None,
        max_results: Integer = None,
        next_token: String = None,
        prefix_list_ids: PrefixListResourceIdStringList = None,
        **kwargs,
    ) -> DescribePrefixListsResult:
        raise NotImplementedError

    @handler("DescribePrincipalIdFormat")
    def describe_principal_id_format(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        resources: ResourceList = None,
        max_results: DescribePrincipalIdFormatMaxResults = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribePrincipalIdFormatResult:
        raise NotImplementedError

    @handler("DescribePublicIpv4Pools")
    def describe_public_ipv4_pools(
        self,
        context: RequestContext,
        pool_ids: PublicIpv4PoolIdStringList = None,
        next_token: NextToken = None,
        max_results: PoolMaxResults = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribePublicIpv4PoolsResult:
        raise NotImplementedError

    @handler("DescribeRegions")
    def describe_regions(
        self,
        context: RequestContext,
        region_names: RegionNameStringList = None,
        all_regions: Boolean = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeRegionsResult:
        raise NotImplementedError

    @handler("DescribeReplaceRootVolumeTasks")
    def describe_replace_root_volume_tasks(
        self,
        context: RequestContext,
        replace_root_volume_task_ids: ReplaceRootVolumeTaskIds = None,
        filters: FilterList = None,
        max_results: DescribeReplaceRootVolumeTasksMaxResults = None,
        next_token: NextToken = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeReplaceRootVolumeTasksResult:
        raise NotImplementedError

    @handler("DescribeReservedInstances")
    def describe_reserved_instances(
        self,
        context: RequestContext,
        offering_class: OfferingClassType = None,
        reserved_instances_ids: ReservedInstancesIdStringList = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        offering_type: OfferingTypeValues = None,
        **kwargs,
    ) -> DescribeReservedInstancesResult:
        raise NotImplementedError

    @handler("DescribeReservedInstancesListings")
    def describe_reserved_instances_listings(
        self,
        context: RequestContext,
        reserved_instances_id: ReservationId = None,
        reserved_instances_listing_id: ReservedInstancesListingId = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeReservedInstancesListingsResult:
        raise NotImplementedError

    @handler("DescribeReservedInstancesModifications")
    def describe_reserved_instances_modifications(
        self,
        context: RequestContext,
        reserved_instances_modification_ids: ReservedInstancesModificationIdStringList = None,
        next_token: String = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeReservedInstancesModificationsResult:
        raise NotImplementedError

    @handler("DescribeReservedInstancesOfferings")
    def describe_reserved_instances_offerings(
        self,
        context: RequestContext,
        availability_zone: String = None,
        include_marketplace: Boolean = None,
        instance_type: InstanceType = None,
        max_duration: Long = None,
        max_instance_count: Integer = None,
        min_duration: Long = None,
        offering_class: OfferingClassType = None,
        product_description: RIProductDescription = None,
        reserved_instances_offering_ids: ReservedInstancesOfferingIdStringList = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        instance_tenancy: Tenancy = None,
        offering_type: OfferingTypeValues = None,
        next_token: String = None,
        max_results: Integer = None,
        **kwargs,
    ) -> DescribeReservedInstancesOfferingsResult:
        raise NotImplementedError

    @handler("DescribeRouteTables")
    def describe_route_tables(
        self,
        context: RequestContext,
        next_token: String = None,
        max_results: DescribeRouteTablesMaxResults = None,
        dry_run: Boolean = None,
        route_table_ids: RouteTableIdStringList = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeRouteTablesResult:
        raise NotImplementedError

    @handler("DescribeScheduledInstanceAvailability")
    def describe_scheduled_instance_availability(
        self,
        context: RequestContext,
        first_slot_start_time_range: SlotDateTimeRangeRequest,
        recurrence: ScheduledInstanceRecurrenceRequest,
        dry_run: Boolean = None,
        filters: FilterList = None,
        max_results: DescribeScheduledInstanceAvailabilityMaxResults = None,
        max_slot_duration_in_hours: Integer = None,
        min_slot_duration_in_hours: Integer = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeScheduledInstanceAvailabilityResult:
        raise NotImplementedError

    @handler("DescribeScheduledInstances")
    def describe_scheduled_instances(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        filters: FilterList = None,
        max_results: Integer = None,
        next_token: String = None,
        scheduled_instance_ids: ScheduledInstanceIdRequestSet = None,
        slot_start_time_range: SlotStartTimeRangeRequest = None,
        **kwargs,
    ) -> DescribeScheduledInstancesResult:
        raise NotImplementedError

    @handler("DescribeSecurityGroupReferences")
    def describe_security_group_references(
        self, context: RequestContext, group_id: GroupIds, dry_run: Boolean = None, **kwargs
    ) -> DescribeSecurityGroupReferencesResult:
        raise NotImplementedError

    @handler("DescribeSecurityGroupRules")
    def describe_security_group_rules(
        self,
        context: RequestContext,
        filters: FilterList = None,
        security_group_rule_ids: SecurityGroupRuleIdList = None,
        dry_run: Boolean = None,
        next_token: String = None,
        max_results: DescribeSecurityGroupRulesMaxResults = None,
        **kwargs,
    ) -> DescribeSecurityGroupRulesResult:
        raise NotImplementedError

    @handler("DescribeSecurityGroupVpcAssociations")
    def describe_security_group_vpc_associations(
        self,
        context: RequestContext,
        filters: FilterList = None,
        next_token: String = None,
        max_results: DescribeSecurityGroupVpcAssociationsMaxResults = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeSecurityGroupVpcAssociationsResult:
        raise NotImplementedError

    @handler("DescribeSecurityGroups")
    def describe_security_groups(
        self,
        context: RequestContext,
        group_ids: GroupIdStringList = None,
        group_names: GroupNameStringList = None,
        next_token: String = None,
        max_results: DescribeSecurityGroupsMaxResults = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeSecurityGroupsResult:
        raise NotImplementedError

    @handler("DescribeSnapshotAttribute")
    def describe_snapshot_attribute(
        self,
        context: RequestContext,
        attribute: SnapshotAttributeName,
        snapshot_id: SnapshotId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeSnapshotAttributeResult:
        raise NotImplementedError

    @handler("DescribeSnapshotTierStatus")
    def describe_snapshot_tier_status(
        self,
        context: RequestContext,
        filters: FilterList = None,
        dry_run: Boolean = None,
        next_token: String = None,
        max_results: DescribeSnapshotTierStatusMaxResults = None,
        **kwargs,
    ) -> DescribeSnapshotTierStatusResult:
        raise NotImplementedError

    @handler("DescribeSnapshots")
    def describe_snapshots(
        self,
        context: RequestContext,
        max_results: Integer = None,
        next_token: String = None,
        owner_ids: OwnerStringList = None,
        restorable_by_user_ids: RestorableByStringList = None,
        snapshot_ids: SnapshotIdStringList = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeSnapshotsResult:
        raise NotImplementedError

    @handler("DescribeSpotDatafeedSubscription")
    def describe_spot_datafeed_subscription(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> DescribeSpotDatafeedSubscriptionResult:
        raise NotImplementedError

    @handler("DescribeSpotFleetInstances")
    def describe_spot_fleet_instances(
        self,
        context: RequestContext,
        spot_fleet_request_id: SpotFleetRequestId,
        dry_run: Boolean = None,
        next_token: String = None,
        max_results: DescribeSpotFleetInstancesMaxResults = None,
        **kwargs,
    ) -> DescribeSpotFleetInstancesResponse:
        raise NotImplementedError

    @handler("DescribeSpotFleetRequestHistory")
    def describe_spot_fleet_request_history(
        self,
        context: RequestContext,
        spot_fleet_request_id: SpotFleetRequestId,
        start_time: DateTime,
        dry_run: Boolean = None,
        event_type: EventType = None,
        next_token: String = None,
        max_results: DescribeSpotFleetRequestHistoryMaxResults = None,
        **kwargs,
    ) -> DescribeSpotFleetRequestHistoryResponse:
        raise NotImplementedError

    @handler("DescribeSpotFleetRequests")
    def describe_spot_fleet_requests(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        spot_fleet_request_ids: SpotFleetRequestIdList = None,
        next_token: String = None,
        max_results: Integer = None,
        **kwargs,
    ) -> DescribeSpotFleetRequestsResponse:
        raise NotImplementedError

    @handler("DescribeSpotInstanceRequests")
    def describe_spot_instance_requests(
        self,
        context: RequestContext,
        next_token: String = None,
        max_results: Integer = None,
        dry_run: Boolean = None,
        spot_instance_request_ids: SpotInstanceRequestIdList = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeSpotInstanceRequestsResult:
        raise NotImplementedError

    @handler("DescribeSpotPriceHistory")
    def describe_spot_price_history(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        start_time: DateTime = None,
        end_time: DateTime = None,
        instance_types: InstanceTypeList = None,
        product_descriptions: ProductDescriptionList = None,
        filters: FilterList = None,
        availability_zone: String = None,
        max_results: Integer = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeSpotPriceHistoryResult:
        raise NotImplementedError

    @handler("DescribeStaleSecurityGroups")
    def describe_stale_security_groups(
        self,
        context: RequestContext,
        vpc_id: VpcId,
        dry_run: Boolean = None,
        max_results: DescribeStaleSecurityGroupsMaxResults = None,
        next_token: DescribeStaleSecurityGroupsNextToken = None,
        **kwargs,
    ) -> DescribeStaleSecurityGroupsResult:
        raise NotImplementedError

    @handler("DescribeStoreImageTasks")
    def describe_store_image_tasks(
        self,
        context: RequestContext,
        image_ids: ImageIdList = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        next_token: String = None,
        max_results: DescribeStoreImageTasksRequestMaxResults = None,
        **kwargs,
    ) -> DescribeStoreImageTasksResult:
        raise NotImplementedError

    @handler("DescribeSubnets")
    def describe_subnets(
        self,
        context: RequestContext,
        filters: FilterList = None,
        subnet_ids: SubnetIdStringList = None,
        next_token: String = None,
        max_results: DescribeSubnetsMaxResults = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeSubnetsResult:
        raise NotImplementedError

    @handler("DescribeTags")
    def describe_tags(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        filters: FilterList = None,
        max_results: Integer = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeTagsResult:
        raise NotImplementedError

    @handler("DescribeTrafficMirrorFilterRules")
    def describe_traffic_mirror_filter_rules(
        self,
        context: RequestContext,
        traffic_mirror_filter_rule_ids: TrafficMirrorFilterRuleIdList = None,
        traffic_mirror_filter_id: TrafficMirrorFilterId = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        max_results: TrafficMirroringMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeTrafficMirrorFilterRulesResult:
        raise NotImplementedError

    @handler("DescribeTrafficMirrorFilters")
    def describe_traffic_mirror_filters(
        self,
        context: RequestContext,
        traffic_mirror_filter_ids: TrafficMirrorFilterIdList = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        max_results: TrafficMirroringMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeTrafficMirrorFiltersResult:
        raise NotImplementedError

    @handler("DescribeTrafficMirrorSessions")
    def describe_traffic_mirror_sessions(
        self,
        context: RequestContext,
        traffic_mirror_session_ids: TrafficMirrorSessionIdList = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        max_results: TrafficMirroringMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeTrafficMirrorSessionsResult:
        raise NotImplementedError

    @handler("DescribeTrafficMirrorTargets")
    def describe_traffic_mirror_targets(
        self,
        context: RequestContext,
        traffic_mirror_target_ids: TrafficMirrorTargetIdList = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        max_results: TrafficMirroringMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeTrafficMirrorTargetsResult:
        raise NotImplementedError

    @handler("DescribeTransitGatewayAttachments")
    def describe_transit_gateway_attachments(
        self,
        context: RequestContext,
        transit_gateway_attachment_ids: TransitGatewayAttachmentIdStringList = None,
        filters: FilterList = None,
        max_results: TransitGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeTransitGatewayAttachmentsResult:
        raise NotImplementedError

    @handler("DescribeTransitGatewayConnectPeers")
    def describe_transit_gateway_connect_peers(
        self,
        context: RequestContext,
        transit_gateway_connect_peer_ids: TransitGatewayConnectPeerIdStringList = None,
        filters: FilterList = None,
        max_results: TransitGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeTransitGatewayConnectPeersResult:
        raise NotImplementedError

    @handler("DescribeTransitGatewayConnects")
    def describe_transit_gateway_connects(
        self,
        context: RequestContext,
        transit_gateway_attachment_ids: TransitGatewayAttachmentIdStringList = None,
        filters: FilterList = None,
        max_results: TransitGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeTransitGatewayConnectsResult:
        raise NotImplementedError

    @handler("DescribeTransitGatewayMulticastDomains")
    def describe_transit_gateway_multicast_domains(
        self,
        context: RequestContext,
        transit_gateway_multicast_domain_ids: TransitGatewayMulticastDomainIdStringList = None,
        filters: FilterList = None,
        max_results: TransitGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeTransitGatewayMulticastDomainsResult:
        raise NotImplementedError

    @handler("DescribeTransitGatewayPeeringAttachments")
    def describe_transit_gateway_peering_attachments(
        self,
        context: RequestContext,
        transit_gateway_attachment_ids: TransitGatewayAttachmentIdStringList = None,
        filters: FilterList = None,
        max_results: TransitGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeTransitGatewayPeeringAttachmentsResult:
        raise NotImplementedError

    @handler("DescribeTransitGatewayPolicyTables")
    def describe_transit_gateway_policy_tables(
        self,
        context: RequestContext,
        transit_gateway_policy_table_ids: TransitGatewayPolicyTableIdStringList = None,
        filters: FilterList = None,
        max_results: TransitGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeTransitGatewayPolicyTablesResult:
        raise NotImplementedError

    @handler("DescribeTransitGatewayRouteTableAnnouncements")
    def describe_transit_gateway_route_table_announcements(
        self,
        context: RequestContext,
        transit_gateway_route_table_announcement_ids: TransitGatewayRouteTableAnnouncementIdStringList = None,
        filters: FilterList = None,
        max_results: TransitGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeTransitGatewayRouteTableAnnouncementsResult:
        raise NotImplementedError

    @handler("DescribeTransitGatewayRouteTables")
    def describe_transit_gateway_route_tables(
        self,
        context: RequestContext,
        transit_gateway_route_table_ids: TransitGatewayRouteTableIdStringList = None,
        filters: FilterList = None,
        max_results: TransitGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeTransitGatewayRouteTablesResult:
        raise NotImplementedError

    @handler("DescribeTransitGatewayVpcAttachments")
    def describe_transit_gateway_vpc_attachments(
        self,
        context: RequestContext,
        transit_gateway_attachment_ids: TransitGatewayAttachmentIdStringList = None,
        filters: FilterList = None,
        max_results: TransitGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeTransitGatewayVpcAttachmentsResult:
        raise NotImplementedError

    @handler("DescribeTransitGateways")
    def describe_transit_gateways(
        self,
        context: RequestContext,
        transit_gateway_ids: TransitGatewayIdStringList = None,
        filters: FilterList = None,
        max_results: TransitGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeTransitGatewaysResult:
        raise NotImplementedError

    @handler("DescribeTrunkInterfaceAssociations")
    def describe_trunk_interface_associations(
        self,
        context: RequestContext,
        association_ids: TrunkInterfaceAssociationIdList = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        next_token: String = None,
        max_results: DescribeTrunkInterfaceAssociationsMaxResults = None,
        **kwargs,
    ) -> DescribeTrunkInterfaceAssociationsResult:
        raise NotImplementedError

    @handler("DescribeVerifiedAccessEndpoints")
    def describe_verified_access_endpoints(
        self,
        context: RequestContext,
        verified_access_endpoint_ids: VerifiedAccessEndpointIdList = None,
        verified_access_instance_id: VerifiedAccessInstanceId = None,
        verified_access_group_id: VerifiedAccessGroupId = None,
        max_results: DescribeVerifiedAccessEndpointsMaxResults = None,
        next_token: NextToken = None,
        filters: FilterList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeVerifiedAccessEndpointsResult:
        raise NotImplementedError

    @handler("DescribeVerifiedAccessGroups")
    def describe_verified_access_groups(
        self,
        context: RequestContext,
        verified_access_group_ids: VerifiedAccessGroupIdList = None,
        verified_access_instance_id: VerifiedAccessInstanceId = None,
        max_results: DescribeVerifiedAccessGroupMaxResults = None,
        next_token: NextToken = None,
        filters: FilterList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeVerifiedAccessGroupsResult:
        raise NotImplementedError

    @handler("DescribeVerifiedAccessInstanceLoggingConfigurations")
    def describe_verified_access_instance_logging_configurations(
        self,
        context: RequestContext,
        verified_access_instance_ids: VerifiedAccessInstanceIdList = None,
        max_results: DescribeVerifiedAccessInstanceLoggingConfigurationsMaxResults = None,
        next_token: NextToken = None,
        filters: FilterList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeVerifiedAccessInstanceLoggingConfigurationsResult:
        raise NotImplementedError

    @handler("DescribeVerifiedAccessInstances")
    def describe_verified_access_instances(
        self,
        context: RequestContext,
        verified_access_instance_ids: VerifiedAccessInstanceIdList = None,
        max_results: DescribeVerifiedAccessInstancesMaxResults = None,
        next_token: NextToken = None,
        filters: FilterList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeVerifiedAccessInstancesResult:
        raise NotImplementedError

    @handler("DescribeVerifiedAccessTrustProviders")
    def describe_verified_access_trust_providers(
        self,
        context: RequestContext,
        verified_access_trust_provider_ids: VerifiedAccessTrustProviderIdList = None,
        max_results: DescribeVerifiedAccessTrustProvidersMaxResults = None,
        next_token: NextToken = None,
        filters: FilterList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeVerifiedAccessTrustProvidersResult:
        raise NotImplementedError

    @handler("DescribeVolumeAttribute")
    def describe_volume_attribute(
        self,
        context: RequestContext,
        attribute: VolumeAttributeName,
        volume_id: VolumeId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeVolumeAttributeResult:
        raise NotImplementedError

    @handler("DescribeVolumeStatus")
    def describe_volume_status(
        self,
        context: RequestContext,
        max_results: Integer = None,
        next_token: String = None,
        volume_ids: VolumeIdStringList = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeVolumeStatusResult:
        raise NotImplementedError

    @handler("DescribeVolumes")
    def describe_volumes(
        self,
        context: RequestContext,
        volume_ids: VolumeIdStringList = None,
        dry_run: Boolean = None,
        filters: FilterList = None,
        next_token: String = None,
        max_results: Integer = None,
        **kwargs,
    ) -> DescribeVolumesResult:
        raise NotImplementedError

    @handler("DescribeVolumesModifications")
    def describe_volumes_modifications(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        volume_ids: VolumeIdStringList = None,
        filters: FilterList = None,
        next_token: String = None,
        max_results: Integer = None,
        **kwargs,
    ) -> DescribeVolumesModificationsResult:
        raise NotImplementedError

    @handler("DescribeVpcAttribute")
    def describe_vpc_attribute(
        self,
        context: RequestContext,
        attribute: VpcAttributeName,
        vpc_id: VpcId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeVpcAttributeResult:
        raise NotImplementedError

    @handler("DescribeVpcClassicLink")
    def describe_vpc_classic_link(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        vpc_ids: VpcClassicLinkIdList = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeVpcClassicLinkResult:
        raise NotImplementedError

    @handler("DescribeVpcClassicLinkDnsSupport")
    def describe_vpc_classic_link_dns_support(
        self,
        context: RequestContext,
        vpc_ids: VpcClassicLinkIdList = None,
        max_results: DescribeVpcClassicLinkDnsSupportMaxResults = None,
        next_token: DescribeVpcClassicLinkDnsSupportNextToken = None,
        **kwargs,
    ) -> DescribeVpcClassicLinkDnsSupportResult:
        raise NotImplementedError

    @handler("DescribeVpcEndpointConnectionNotifications")
    def describe_vpc_endpoint_connection_notifications(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        connection_notification_id: ConnectionNotificationId = None,
        filters: FilterList = None,
        max_results: Integer = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeVpcEndpointConnectionNotificationsResult:
        raise NotImplementedError

    @handler("DescribeVpcEndpointConnections")
    def describe_vpc_endpoint_connections(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        filters: FilterList = None,
        max_results: Integer = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeVpcEndpointConnectionsResult:
        raise NotImplementedError

    @handler("DescribeVpcEndpointServiceConfigurations")
    def describe_vpc_endpoint_service_configurations(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        service_ids: VpcEndpointServiceIdList = None,
        filters: FilterList = None,
        max_results: Integer = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeVpcEndpointServiceConfigurationsResult:
        raise NotImplementedError

    @handler("DescribeVpcEndpointServicePermissions")
    def describe_vpc_endpoint_service_permissions(
        self,
        context: RequestContext,
        service_id: VpcEndpointServiceId,
        dry_run: Boolean = None,
        filters: FilterList = None,
        max_results: Integer = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeVpcEndpointServicePermissionsResult:
        raise NotImplementedError

    @handler("DescribeVpcEndpointServices")
    def describe_vpc_endpoint_services(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        service_names: ValueStringList = None,
        filters: FilterList = None,
        max_results: Integer = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeVpcEndpointServicesResult:
        raise NotImplementedError

    @handler("DescribeVpcEndpoints")
    def describe_vpc_endpoints(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        vpc_endpoint_ids: VpcEndpointIdList = None,
        filters: FilterList = None,
        max_results: Integer = None,
        next_token: String = None,
        **kwargs,
    ) -> DescribeVpcEndpointsResult:
        raise NotImplementedError

    @handler("DescribeVpcPeeringConnections")
    def describe_vpc_peering_connections(
        self,
        context: RequestContext,
        next_token: String = None,
        max_results: DescribeVpcPeeringConnectionsMaxResults = None,
        dry_run: Boolean = None,
        vpc_peering_connection_ids: VpcPeeringConnectionIdList = None,
        filters: FilterList = None,
        **kwargs,
    ) -> DescribeVpcPeeringConnectionsResult:
        raise NotImplementedError

    @handler("DescribeVpcs")
    def describe_vpcs(
        self,
        context: RequestContext,
        filters: FilterList = None,
        vpc_ids: VpcIdStringList = None,
        next_token: String = None,
        max_results: DescribeVpcsMaxResults = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeVpcsResult:
        raise NotImplementedError

    @handler("DescribeVpnConnections")
    def describe_vpn_connections(
        self,
        context: RequestContext,
        filters: FilterList = None,
        vpn_connection_ids: VpnConnectionIdStringList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeVpnConnectionsResult:
        raise NotImplementedError

    @handler("DescribeVpnGateways")
    def describe_vpn_gateways(
        self,
        context: RequestContext,
        filters: FilterList = None,
        vpn_gateway_ids: VpnGatewayIdStringList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DescribeVpnGatewaysResult:
        raise NotImplementedError

    @handler("DetachClassicLinkVpc")
    def detach_classic_link_vpc(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        vpc_id: VpcId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DetachClassicLinkVpcResult:
        raise NotImplementedError

    @handler("DetachInternetGateway")
    def detach_internet_gateway(
        self,
        context: RequestContext,
        internet_gateway_id: InternetGatewayId,
        vpc_id: VpcId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DetachNetworkInterface")
    def detach_network_interface(
        self,
        context: RequestContext,
        attachment_id: NetworkInterfaceAttachmentId,
        dry_run: Boolean = None,
        force: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DetachVerifiedAccessTrustProvider")
    def detach_verified_access_trust_provider(
        self,
        context: RequestContext,
        verified_access_instance_id: VerifiedAccessInstanceId,
        verified_access_trust_provider_id: VerifiedAccessTrustProviderId,
        client_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DetachVerifiedAccessTrustProviderResult:
        raise NotImplementedError

    @handler("DetachVolume")
    def detach_volume(
        self,
        context: RequestContext,
        volume_id: VolumeIdWithResolver,
        device: String = None,
        force: Boolean = None,
        instance_id: InstanceIdForResolver = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> VolumeAttachment:
        raise NotImplementedError

    @handler("DetachVpnGateway")
    def detach_vpn_gateway(
        self,
        context: RequestContext,
        vpc_id: VpcId,
        vpn_gateway_id: VpnGatewayId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DisableAddressTransfer")
    def disable_address_transfer(
        self,
        context: RequestContext,
        allocation_id: AllocationId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DisableAddressTransferResult:
        raise NotImplementedError

    @handler("DisableAwsNetworkPerformanceMetricSubscription")
    def disable_aws_network_performance_metric_subscription(
        self,
        context: RequestContext,
        source: String = None,
        destination: String = None,
        metric: MetricType = None,
        statistic: StatisticType = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DisableAwsNetworkPerformanceMetricSubscriptionResult:
        raise NotImplementedError

    @handler("DisableEbsEncryptionByDefault")
    def disable_ebs_encryption_by_default(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> DisableEbsEncryptionByDefaultResult:
        raise NotImplementedError

    @handler("DisableFastLaunch")
    def disable_fast_launch(
        self,
        context: RequestContext,
        image_id: ImageId,
        force: Boolean = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DisableFastLaunchResult:
        raise NotImplementedError

    @handler("DisableFastSnapshotRestores")
    def disable_fast_snapshot_restores(
        self,
        context: RequestContext,
        availability_zones: AvailabilityZoneStringList,
        source_snapshot_ids: SnapshotIdStringList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DisableFastSnapshotRestoresResult:
        raise NotImplementedError

    @handler("DisableImage")
    def disable_image(
        self, context: RequestContext, image_id: ImageId, dry_run: Boolean = None, **kwargs
    ) -> DisableImageResult:
        raise NotImplementedError

    @handler("DisableImageBlockPublicAccess")
    def disable_image_block_public_access(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> DisableImageBlockPublicAccessResult:
        raise NotImplementedError

    @handler("DisableImageDeprecation")
    def disable_image_deprecation(
        self, context: RequestContext, image_id: ImageId, dry_run: Boolean = None, **kwargs
    ) -> DisableImageDeprecationResult:
        raise NotImplementedError

    @handler("DisableImageDeregistrationProtection")
    def disable_image_deregistration_protection(
        self, context: RequestContext, image_id: ImageId, dry_run: Boolean = None, **kwargs
    ) -> DisableImageDeregistrationProtectionResult:
        raise NotImplementedError

    @handler("DisableIpamOrganizationAdminAccount")
    def disable_ipam_organization_admin_account(
        self,
        context: RequestContext,
        delegated_admin_account_id: String,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DisableIpamOrganizationAdminAccountResult:
        raise NotImplementedError

    @handler("DisableSerialConsoleAccess")
    def disable_serial_console_access(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> DisableSerialConsoleAccessResult:
        raise NotImplementedError

    @handler("DisableSnapshotBlockPublicAccess")
    def disable_snapshot_block_public_access(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> DisableSnapshotBlockPublicAccessResult:
        raise NotImplementedError

    @handler("DisableTransitGatewayRouteTablePropagation")
    def disable_transit_gateway_route_table_propagation(
        self,
        context: RequestContext,
        transit_gateway_route_table_id: TransitGatewayRouteTableId,
        transit_gateway_attachment_id: TransitGatewayAttachmentId = None,
        dry_run: Boolean = None,
        transit_gateway_route_table_announcement_id: TransitGatewayRouteTableAnnouncementId = None,
        **kwargs,
    ) -> DisableTransitGatewayRouteTablePropagationResult:
        raise NotImplementedError

    @handler("DisableVgwRoutePropagation")
    def disable_vgw_route_propagation(
        self,
        context: RequestContext,
        gateway_id: VpnGatewayId,
        route_table_id: RouteTableId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DisableVpcClassicLink")
    def disable_vpc_classic_link(
        self, context: RequestContext, vpc_id: VpcId, dry_run: Boolean = None, **kwargs
    ) -> DisableVpcClassicLinkResult:
        raise NotImplementedError

    @handler("DisableVpcClassicLinkDnsSupport")
    def disable_vpc_classic_link_dns_support(
        self, context: RequestContext, vpc_id: VpcId = None, **kwargs
    ) -> DisableVpcClassicLinkDnsSupportResult:
        raise NotImplementedError

    @handler("DisassociateAddress")
    def disassociate_address(
        self,
        context: RequestContext,
        association_id: ElasticIpAssociationId = None,
        public_ip: EipAllocationPublicIp = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DisassociateCapacityReservationBillingOwner")
    def disassociate_capacity_reservation_billing_owner(
        self,
        context: RequestContext,
        capacity_reservation_id: CapacityReservationId,
        unused_reservation_billing_owner_id: AccountID,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DisassociateCapacityReservationBillingOwnerResult:
        raise NotImplementedError

    @handler("DisassociateClientVpnTargetNetwork")
    def disassociate_client_vpn_target_network(
        self,
        context: RequestContext,
        client_vpn_endpoint_id: ClientVpnEndpointId,
        association_id: String,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DisassociateClientVpnTargetNetworkResult:
        raise NotImplementedError

    @handler("DisassociateEnclaveCertificateIamRole")
    def disassociate_enclave_certificate_iam_role(
        self,
        context: RequestContext,
        certificate_arn: CertificateId,
        role_arn: RoleId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DisassociateEnclaveCertificateIamRoleResult:
        raise NotImplementedError

    @handler("DisassociateIamInstanceProfile")
    def disassociate_iam_instance_profile(
        self, context: RequestContext, association_id: IamInstanceProfileAssociationId, **kwargs
    ) -> DisassociateIamInstanceProfileResult:
        raise NotImplementedError

    @handler("DisassociateInstanceEventWindow")
    def disassociate_instance_event_window(
        self,
        context: RequestContext,
        instance_event_window_id: InstanceEventWindowId,
        association_target: InstanceEventWindowDisassociationRequest,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DisassociateInstanceEventWindowResult:
        raise NotImplementedError

    @handler("DisassociateIpamByoasn")
    def disassociate_ipam_byoasn(
        self, context: RequestContext, asn: String, cidr: String, dry_run: Boolean = None, **kwargs
    ) -> DisassociateIpamByoasnResult:
        raise NotImplementedError

    @handler("DisassociateIpamResourceDiscovery")
    def disassociate_ipam_resource_discovery(
        self,
        context: RequestContext,
        ipam_resource_discovery_association_id: IpamResourceDiscoveryAssociationId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DisassociateIpamResourceDiscoveryResult:
        raise NotImplementedError

    @handler("DisassociateNatGatewayAddress")
    def disassociate_nat_gateway_address(
        self,
        context: RequestContext,
        nat_gateway_id: NatGatewayId,
        association_ids: EipAssociationIdList,
        max_drain_duration_seconds: DrainSeconds = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DisassociateNatGatewayAddressResult:
        raise NotImplementedError

    @handler("DisassociateRouteTable")
    def disassociate_route_table(
        self,
        context: RequestContext,
        association_id: RouteTableAssociationId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("DisassociateSecurityGroupVpc")
    def disassociate_security_group_vpc(
        self,
        context: RequestContext,
        group_id: DisassociateSecurityGroupVpcSecurityGroupId,
        vpc_id: String,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DisassociateSecurityGroupVpcResult:
        raise NotImplementedError

    @handler("DisassociateSubnetCidrBlock")
    def disassociate_subnet_cidr_block(
        self, context: RequestContext, association_id: SubnetCidrAssociationId, **kwargs
    ) -> DisassociateSubnetCidrBlockResult:
        raise NotImplementedError

    @handler("DisassociateTransitGatewayMulticastDomain")
    def disassociate_transit_gateway_multicast_domain(
        self,
        context: RequestContext,
        transit_gateway_multicast_domain_id: TransitGatewayMulticastDomainId,
        transit_gateway_attachment_id: TransitGatewayAttachmentId,
        subnet_ids: TransitGatewaySubnetIdList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DisassociateTransitGatewayMulticastDomainResult:
        raise NotImplementedError

    @handler("DisassociateTransitGatewayPolicyTable")
    def disassociate_transit_gateway_policy_table(
        self,
        context: RequestContext,
        transit_gateway_policy_table_id: TransitGatewayPolicyTableId,
        transit_gateway_attachment_id: TransitGatewayAttachmentId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DisassociateTransitGatewayPolicyTableResult:
        raise NotImplementedError

    @handler("DisassociateTransitGatewayRouteTable")
    def disassociate_transit_gateway_route_table(
        self,
        context: RequestContext,
        transit_gateway_route_table_id: TransitGatewayRouteTableId,
        transit_gateway_attachment_id: TransitGatewayAttachmentId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DisassociateTransitGatewayRouteTableResult:
        raise NotImplementedError

    @handler("DisassociateTrunkInterface")
    def disassociate_trunk_interface(
        self,
        context: RequestContext,
        association_id: TrunkInterfaceAssociationId,
        client_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> DisassociateTrunkInterfaceResult:
        raise NotImplementedError

    @handler("DisassociateVpcCidrBlock")
    def disassociate_vpc_cidr_block(
        self, context: RequestContext, association_id: VpcCidrAssociationId, **kwargs
    ) -> DisassociateVpcCidrBlockResult:
        raise NotImplementedError

    @handler("EnableAddressTransfer")
    def enable_address_transfer(
        self,
        context: RequestContext,
        allocation_id: AllocationId,
        transfer_account_id: String,
        dry_run: Boolean = None,
        **kwargs,
    ) -> EnableAddressTransferResult:
        raise NotImplementedError

    @handler("EnableAwsNetworkPerformanceMetricSubscription")
    def enable_aws_network_performance_metric_subscription(
        self,
        context: RequestContext,
        source: String = None,
        destination: String = None,
        metric: MetricType = None,
        statistic: StatisticType = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> EnableAwsNetworkPerformanceMetricSubscriptionResult:
        raise NotImplementedError

    @handler("EnableEbsEncryptionByDefault")
    def enable_ebs_encryption_by_default(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> EnableEbsEncryptionByDefaultResult:
        raise NotImplementedError

    @handler("EnableFastLaunch")
    def enable_fast_launch(
        self,
        context: RequestContext,
        image_id: ImageId,
        resource_type: String = None,
        snapshot_configuration: FastLaunchSnapshotConfigurationRequest = None,
        launch_template: FastLaunchLaunchTemplateSpecificationRequest = None,
        max_parallel_launches: Integer = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> EnableFastLaunchResult:
        raise NotImplementedError

    @handler("EnableFastSnapshotRestores")
    def enable_fast_snapshot_restores(
        self,
        context: RequestContext,
        availability_zones: AvailabilityZoneStringList,
        source_snapshot_ids: SnapshotIdStringList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> EnableFastSnapshotRestoresResult:
        raise NotImplementedError

    @handler("EnableImage")
    def enable_image(
        self, context: RequestContext, image_id: ImageId, dry_run: Boolean = None, **kwargs
    ) -> EnableImageResult:
        raise NotImplementedError

    @handler("EnableImageBlockPublicAccess")
    def enable_image_block_public_access(
        self,
        context: RequestContext,
        image_block_public_access_state: ImageBlockPublicAccessEnabledState,
        dry_run: Boolean = None,
        **kwargs,
    ) -> EnableImageBlockPublicAccessResult:
        raise NotImplementedError

    @handler("EnableImageDeprecation")
    def enable_image_deprecation(
        self,
        context: RequestContext,
        image_id: ImageId,
        deprecate_at: MillisecondDateTime,
        dry_run: Boolean = None,
        **kwargs,
    ) -> EnableImageDeprecationResult:
        raise NotImplementedError

    @handler("EnableImageDeregistrationProtection")
    def enable_image_deregistration_protection(
        self,
        context: RequestContext,
        image_id: ImageId,
        with_cooldown: Boolean = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> EnableImageDeregistrationProtectionResult:
        raise NotImplementedError

    @handler("EnableIpamOrganizationAdminAccount")
    def enable_ipam_organization_admin_account(
        self,
        context: RequestContext,
        delegated_admin_account_id: String,
        dry_run: Boolean = None,
        **kwargs,
    ) -> EnableIpamOrganizationAdminAccountResult:
        raise NotImplementedError

    @handler("EnableReachabilityAnalyzerOrganizationSharing")
    def enable_reachability_analyzer_organization_sharing(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> EnableReachabilityAnalyzerOrganizationSharingResult:
        raise NotImplementedError

    @handler("EnableSerialConsoleAccess")
    def enable_serial_console_access(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> EnableSerialConsoleAccessResult:
        raise NotImplementedError

    @handler("EnableSnapshotBlockPublicAccess")
    def enable_snapshot_block_public_access(
        self,
        context: RequestContext,
        state: SnapshotBlockPublicAccessState,
        dry_run: Boolean = None,
        **kwargs,
    ) -> EnableSnapshotBlockPublicAccessResult:
        raise NotImplementedError

    @handler("EnableTransitGatewayRouteTablePropagation")
    def enable_transit_gateway_route_table_propagation(
        self,
        context: RequestContext,
        transit_gateway_route_table_id: TransitGatewayRouteTableId,
        transit_gateway_attachment_id: TransitGatewayAttachmentId = None,
        dry_run: Boolean = None,
        transit_gateway_route_table_announcement_id: TransitGatewayRouteTableAnnouncementId = None,
        **kwargs,
    ) -> EnableTransitGatewayRouteTablePropagationResult:
        raise NotImplementedError

    @handler("EnableVgwRoutePropagation")
    def enable_vgw_route_propagation(
        self,
        context: RequestContext,
        gateway_id: VpnGatewayId,
        route_table_id: RouteTableId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("EnableVolumeIO")
    def enable_volume_io(
        self, context: RequestContext, volume_id: VolumeId, dry_run: Boolean = None, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("EnableVpcClassicLink")
    def enable_vpc_classic_link(
        self, context: RequestContext, vpc_id: VpcId, dry_run: Boolean = None, **kwargs
    ) -> EnableVpcClassicLinkResult:
        raise NotImplementedError

    @handler("EnableVpcClassicLinkDnsSupport")
    def enable_vpc_classic_link_dns_support(
        self, context: RequestContext, vpc_id: VpcId = None, **kwargs
    ) -> EnableVpcClassicLinkDnsSupportResult:
        raise NotImplementedError

    @handler("ExportClientVpnClientCertificateRevocationList")
    def export_client_vpn_client_certificate_revocation_list(
        self,
        context: RequestContext,
        client_vpn_endpoint_id: ClientVpnEndpointId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ExportClientVpnClientCertificateRevocationListResult:
        raise NotImplementedError

    @handler("ExportClientVpnClientConfiguration")
    def export_client_vpn_client_configuration(
        self,
        context: RequestContext,
        client_vpn_endpoint_id: ClientVpnEndpointId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ExportClientVpnClientConfigurationResult:
        raise NotImplementedError

    @handler("ExportImage")
    def export_image(
        self,
        context: RequestContext,
        disk_image_format: DiskImageFormat,
        image_id: ImageId,
        s3_export_location: ExportTaskS3LocationRequest,
        client_token: String = None,
        description: String = None,
        dry_run: Boolean = None,
        role_name: String = None,
        tag_specifications: TagSpecificationList = None,
        **kwargs,
    ) -> ExportImageResult:
        raise NotImplementedError

    @handler("ExportTransitGatewayRoutes")
    def export_transit_gateway_routes(
        self,
        context: RequestContext,
        transit_gateway_route_table_id: TransitGatewayRouteTableId,
        s3_bucket: String,
        filters: FilterList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ExportTransitGatewayRoutesResult:
        raise NotImplementedError

    @handler("GetAssociatedEnclaveCertificateIamRoles")
    def get_associated_enclave_certificate_iam_roles(
        self,
        context: RequestContext,
        certificate_arn: CertificateId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetAssociatedEnclaveCertificateIamRolesResult:
        raise NotImplementedError

    @handler("GetAssociatedIpv6PoolCidrs")
    def get_associated_ipv6_pool_cidrs(
        self,
        context: RequestContext,
        pool_id: Ipv6PoolEc2Id,
        next_token: NextToken = None,
        max_results: Ipv6PoolMaxResults = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetAssociatedIpv6PoolCidrsResult:
        raise NotImplementedError

    @handler("GetAwsNetworkPerformanceData")
    def get_aws_network_performance_data(
        self,
        context: RequestContext,
        data_queries: DataQueries = None,
        start_time: MillisecondDateTime = None,
        end_time: MillisecondDateTime = None,
        max_results: Integer = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetAwsNetworkPerformanceDataResult:
        raise NotImplementedError

    @handler("GetCapacityReservationUsage")
    def get_capacity_reservation_usage(
        self,
        context: RequestContext,
        capacity_reservation_id: CapacityReservationId,
        next_token: String = None,
        max_results: GetCapacityReservationUsageRequestMaxResults = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetCapacityReservationUsageResult:
        raise NotImplementedError

    @handler("GetCoipPoolUsage")
    def get_coip_pool_usage(
        self,
        context: RequestContext,
        pool_id: Ipv4PoolCoipId,
        filters: FilterList = None,
        max_results: CoipPoolMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetCoipPoolUsageResult:
        raise NotImplementedError

    @handler("GetConsoleOutput")
    def get_console_output(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        latest: Boolean = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetConsoleOutputResult:
        raise NotImplementedError

    @handler("GetConsoleScreenshot")
    def get_console_screenshot(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        dry_run: Boolean = None,
        wake_up: Boolean = None,
        **kwargs,
    ) -> GetConsoleScreenshotResult:
        raise NotImplementedError

    @handler("GetDefaultCreditSpecification")
    def get_default_credit_specification(
        self,
        context: RequestContext,
        instance_family: UnlimitedSupportedInstanceFamily,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetDefaultCreditSpecificationResult:
        raise NotImplementedError

    @handler("GetEbsDefaultKmsKeyId")
    def get_ebs_default_kms_key_id(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> GetEbsDefaultKmsKeyIdResult:
        raise NotImplementedError

    @handler("GetEbsEncryptionByDefault")
    def get_ebs_encryption_by_default(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> GetEbsEncryptionByDefaultResult:
        raise NotImplementedError

    @handler("GetFlowLogsIntegrationTemplate")
    def get_flow_logs_integration_template(
        self,
        context: RequestContext,
        flow_log_id: VpcFlowLogId,
        config_delivery_s3_destination_arn: String,
        integrate_services: IntegrateServices,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetFlowLogsIntegrationTemplateResult:
        raise NotImplementedError

    @handler("GetGroupsForCapacityReservation")
    def get_groups_for_capacity_reservation(
        self,
        context: RequestContext,
        capacity_reservation_id: CapacityReservationId,
        next_token: String = None,
        max_results: GetGroupsForCapacityReservationRequestMaxResults = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetGroupsForCapacityReservationResult:
        raise NotImplementedError

    @handler("GetHostReservationPurchasePreview")
    def get_host_reservation_purchase_preview(
        self,
        context: RequestContext,
        host_id_set: RequestHostIdSet,
        offering_id: OfferingId,
        **kwargs,
    ) -> GetHostReservationPurchasePreviewResult:
        raise NotImplementedError

    @handler("GetImageBlockPublicAccessState")
    def get_image_block_public_access_state(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> GetImageBlockPublicAccessStateResult:
        raise NotImplementedError

    @handler("GetInstanceMetadataDefaults")
    def get_instance_metadata_defaults(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> GetInstanceMetadataDefaultsResult:
        raise NotImplementedError

    @handler("GetInstanceTpmEkPub")
    def get_instance_tpm_ek_pub(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        key_type: EkPubKeyType,
        key_format: EkPubKeyFormat,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetInstanceTpmEkPubResult:
        raise NotImplementedError

    @handler("GetInstanceTypesFromInstanceRequirements")
    def get_instance_types_from_instance_requirements(
        self,
        context: RequestContext,
        architecture_types: ArchitectureTypeSet,
        virtualization_types: VirtualizationTypeSet,
        instance_requirements: InstanceRequirementsRequest,
        dry_run: Boolean = None,
        max_results: Integer = None,
        next_token: String = None,
        **kwargs,
    ) -> GetInstanceTypesFromInstanceRequirementsResult:
        raise NotImplementedError

    @handler("GetInstanceUefiData")
    def get_instance_uefi_data(
        self, context: RequestContext, instance_id: InstanceId, dry_run: Boolean = None, **kwargs
    ) -> GetInstanceUefiDataResult:
        raise NotImplementedError

    @handler("GetIpamAddressHistory")
    def get_ipam_address_history(
        self,
        context: RequestContext,
        cidr: String,
        ipam_scope_id: IpamScopeId,
        dry_run: Boolean = None,
        vpc_id: String = None,
        start_time: MillisecondDateTime = None,
        end_time: MillisecondDateTime = None,
        max_results: IpamAddressHistoryMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> GetIpamAddressHistoryResult:
        raise NotImplementedError

    @handler("GetIpamDiscoveredAccounts")
    def get_ipam_discovered_accounts(
        self,
        context: RequestContext,
        ipam_resource_discovery_id: IpamResourceDiscoveryId,
        discovery_region: String,
        dry_run: Boolean = None,
        filters: FilterList = None,
        next_token: NextToken = None,
        max_results: IpamMaxResults = None,
        **kwargs,
    ) -> GetIpamDiscoveredAccountsResult:
        raise NotImplementedError

    @handler("GetIpamDiscoveredPublicAddresses")
    def get_ipam_discovered_public_addresses(
        self,
        context: RequestContext,
        ipam_resource_discovery_id: IpamResourceDiscoveryId,
        address_region: String,
        dry_run: Boolean = None,
        filters: FilterList = None,
        next_token: NextToken = None,
        max_results: IpamMaxResults = None,
        **kwargs,
    ) -> GetIpamDiscoveredPublicAddressesResult:
        raise NotImplementedError

    @handler("GetIpamDiscoveredResourceCidrs")
    def get_ipam_discovered_resource_cidrs(
        self,
        context: RequestContext,
        ipam_resource_discovery_id: IpamResourceDiscoveryId,
        resource_region: String,
        dry_run: Boolean = None,
        filters: FilterList = None,
        next_token: NextToken = None,
        max_results: IpamMaxResults = None,
        **kwargs,
    ) -> GetIpamDiscoveredResourceCidrsResult:
        raise NotImplementedError

    @handler("GetIpamPoolAllocations")
    def get_ipam_pool_allocations(
        self,
        context: RequestContext,
        ipam_pool_id: IpamPoolId,
        dry_run: Boolean = None,
        ipam_pool_allocation_id: IpamPoolAllocationId = None,
        filters: FilterList = None,
        max_results: GetIpamPoolAllocationsMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> GetIpamPoolAllocationsResult:
        raise NotImplementedError

    @handler("GetIpamPoolCidrs")
    def get_ipam_pool_cidrs(
        self,
        context: RequestContext,
        ipam_pool_id: IpamPoolId,
        dry_run: Boolean = None,
        filters: FilterList = None,
        max_results: IpamMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> GetIpamPoolCidrsResult:
        raise NotImplementedError

    @handler("GetIpamResourceCidrs")
    def get_ipam_resource_cidrs(
        self,
        context: RequestContext,
        ipam_scope_id: IpamScopeId,
        dry_run: Boolean = None,
        filters: FilterList = None,
        max_results: IpamMaxResults = None,
        next_token: NextToken = None,
        ipam_pool_id: IpamPoolId = None,
        resource_id: String = None,
        resource_type: IpamResourceType = None,
        resource_tag: RequestIpamResourceTag = None,
        resource_owner: String = None,
        **kwargs,
    ) -> GetIpamResourceCidrsResult:
        raise NotImplementedError

    @handler("GetLaunchTemplateData")
    def get_launch_template_data(
        self, context: RequestContext, instance_id: InstanceId, dry_run: Boolean = None, **kwargs
    ) -> GetLaunchTemplateDataResult:
        raise NotImplementedError

    @handler("GetManagedPrefixListAssociations")
    def get_managed_prefix_list_associations(
        self,
        context: RequestContext,
        prefix_list_id: PrefixListResourceId,
        dry_run: Boolean = None,
        max_results: GetManagedPrefixListAssociationsMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> GetManagedPrefixListAssociationsResult:
        raise NotImplementedError

    @handler("GetManagedPrefixListEntries")
    def get_managed_prefix_list_entries(
        self,
        context: RequestContext,
        prefix_list_id: PrefixListResourceId,
        dry_run: Boolean = None,
        target_version: Long = None,
        max_results: PrefixListMaxResults = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> GetManagedPrefixListEntriesResult:
        raise NotImplementedError

    @handler("GetNetworkInsightsAccessScopeAnalysisFindings")
    def get_network_insights_access_scope_analysis_findings(
        self,
        context: RequestContext,
        network_insights_access_scope_analysis_id: NetworkInsightsAccessScopeAnalysisId,
        max_results: GetNetworkInsightsAccessScopeAnalysisFindingsMaxResults = None,
        next_token: NextToken = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetNetworkInsightsAccessScopeAnalysisFindingsResult:
        raise NotImplementedError

    @handler("GetNetworkInsightsAccessScopeContent")
    def get_network_insights_access_scope_content(
        self,
        context: RequestContext,
        network_insights_access_scope_id: NetworkInsightsAccessScopeId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetNetworkInsightsAccessScopeContentResult:
        raise NotImplementedError

    @handler("GetPasswordData")
    def get_password_data(
        self, context: RequestContext, instance_id: InstanceId, dry_run: Boolean = None, **kwargs
    ) -> GetPasswordDataResult:
        raise NotImplementedError

    @handler("GetReservedInstancesExchangeQuote")
    def get_reserved_instances_exchange_quote(
        self,
        context: RequestContext,
        reserved_instance_ids: ReservedInstanceIdSet,
        dry_run: Boolean = None,
        target_configurations: TargetConfigurationRequestSet = None,
        **kwargs,
    ) -> GetReservedInstancesExchangeQuoteResult:
        raise NotImplementedError

    @handler("GetSecurityGroupsForVpc")
    def get_security_groups_for_vpc(
        self,
        context: RequestContext,
        vpc_id: VpcId,
        next_token: String = None,
        max_results: GetSecurityGroupsForVpcRequestMaxResults = None,
        filters: FilterList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetSecurityGroupsForVpcResult:
        raise NotImplementedError

    @handler("GetSerialConsoleAccessStatus")
    def get_serial_console_access_status(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> GetSerialConsoleAccessStatusResult:
        raise NotImplementedError

    @handler("GetSnapshotBlockPublicAccessState")
    def get_snapshot_block_public_access_state(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> GetSnapshotBlockPublicAccessStateResult:
        raise NotImplementedError

    @handler("GetSpotPlacementScores")
    def get_spot_placement_scores(
        self,
        context: RequestContext,
        target_capacity: SpotPlacementScoresTargetCapacity,
        instance_types: InstanceTypes = None,
        target_capacity_unit_type: TargetCapacityUnitType = None,
        single_availability_zone: Boolean = None,
        region_names: RegionNames = None,
        instance_requirements_with_metadata: InstanceRequirementsWithMetadataRequest = None,
        dry_run: Boolean = None,
        max_results: SpotPlacementScoresMaxResults = None,
        next_token: String = None,
        **kwargs,
    ) -> GetSpotPlacementScoresResult:
        raise NotImplementedError

    @handler("GetSubnetCidrReservations")
    def get_subnet_cidr_reservations(
        self,
        context: RequestContext,
        subnet_id: SubnetId,
        filters: FilterList = None,
        dry_run: Boolean = None,
        next_token: String = None,
        max_results: GetSubnetCidrReservationsMaxResults = None,
        **kwargs,
    ) -> GetSubnetCidrReservationsResult:
        raise NotImplementedError

    @handler("GetTransitGatewayAttachmentPropagations")
    def get_transit_gateway_attachment_propagations(
        self,
        context: RequestContext,
        transit_gateway_attachment_id: TransitGatewayAttachmentId,
        filters: FilterList = None,
        max_results: TransitGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetTransitGatewayAttachmentPropagationsResult:
        raise NotImplementedError

    @handler("GetTransitGatewayMulticastDomainAssociations")
    def get_transit_gateway_multicast_domain_associations(
        self,
        context: RequestContext,
        transit_gateway_multicast_domain_id: TransitGatewayMulticastDomainId,
        filters: FilterList = None,
        max_results: TransitGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetTransitGatewayMulticastDomainAssociationsResult:
        raise NotImplementedError

    @handler("GetTransitGatewayPolicyTableAssociations")
    def get_transit_gateway_policy_table_associations(
        self,
        context: RequestContext,
        transit_gateway_policy_table_id: TransitGatewayPolicyTableId,
        filters: FilterList = None,
        max_results: TransitGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetTransitGatewayPolicyTableAssociationsResult:
        raise NotImplementedError

    @handler("GetTransitGatewayPolicyTableEntries")
    def get_transit_gateway_policy_table_entries(
        self,
        context: RequestContext,
        transit_gateway_policy_table_id: TransitGatewayPolicyTableId,
        filters: FilterList = None,
        max_results: TransitGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetTransitGatewayPolicyTableEntriesResult:
        raise NotImplementedError

    @handler("GetTransitGatewayPrefixListReferences")
    def get_transit_gateway_prefix_list_references(
        self,
        context: RequestContext,
        transit_gateway_route_table_id: TransitGatewayRouteTableId,
        filters: FilterList = None,
        max_results: TransitGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetTransitGatewayPrefixListReferencesResult:
        raise NotImplementedError

    @handler("GetTransitGatewayRouteTableAssociations")
    def get_transit_gateway_route_table_associations(
        self,
        context: RequestContext,
        transit_gateway_route_table_id: TransitGatewayRouteTableId,
        filters: FilterList = None,
        max_results: TransitGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetTransitGatewayRouteTableAssociationsResult:
        raise NotImplementedError

    @handler("GetTransitGatewayRouteTablePropagations")
    def get_transit_gateway_route_table_propagations(
        self,
        context: RequestContext,
        transit_gateway_route_table_id: TransitGatewayRouteTableId,
        filters: FilterList = None,
        max_results: TransitGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetTransitGatewayRouteTablePropagationsResult:
        raise NotImplementedError

    @handler("GetVerifiedAccessEndpointPolicy")
    def get_verified_access_endpoint_policy(
        self,
        context: RequestContext,
        verified_access_endpoint_id: VerifiedAccessEndpointId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetVerifiedAccessEndpointPolicyResult:
        raise NotImplementedError

    @handler("GetVerifiedAccessGroupPolicy")
    def get_verified_access_group_policy(
        self,
        context: RequestContext,
        verified_access_group_id: VerifiedAccessGroupId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetVerifiedAccessGroupPolicyResult:
        raise NotImplementedError

    @handler("GetVpnConnectionDeviceSampleConfiguration")
    def get_vpn_connection_device_sample_configuration(
        self,
        context: RequestContext,
        vpn_connection_id: VpnConnectionId,
        vpn_connection_device_type_id: VpnConnectionDeviceTypeId,
        internet_key_exchange_version: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetVpnConnectionDeviceSampleConfigurationResult:
        raise NotImplementedError

    @handler("GetVpnConnectionDeviceTypes")
    def get_vpn_connection_device_types(
        self,
        context: RequestContext,
        max_results: GVCDMaxResults = None,
        next_token: NextToken = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetVpnConnectionDeviceTypesResult:
        raise NotImplementedError

    @handler("GetVpnTunnelReplacementStatus")
    def get_vpn_tunnel_replacement_status(
        self,
        context: RequestContext,
        vpn_connection_id: VpnConnectionId,
        vpn_tunnel_outside_ip_address: String,
        dry_run: Boolean = None,
        **kwargs,
    ) -> GetVpnTunnelReplacementStatusResult:
        raise NotImplementedError

    @handler("ImportClientVpnClientCertificateRevocationList")
    def import_client_vpn_client_certificate_revocation_list(
        self,
        context: RequestContext,
        client_vpn_endpoint_id: ClientVpnEndpointId,
        certificate_revocation_list: String,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ImportClientVpnClientCertificateRevocationListResult:
        raise NotImplementedError

    @handler("ImportImage")
    def import_image(
        self,
        context: RequestContext,
        architecture: String = None,
        client_data: ClientData = None,
        client_token: String = None,
        description: String = None,
        disk_containers: ImageDiskContainerList = None,
        dry_run: Boolean = None,
        encrypted: Boolean = None,
        hypervisor: String = None,
        kms_key_id: KmsKeyId = None,
        license_type: String = None,
        platform: String = None,
        role_name: String = None,
        license_specifications: ImportImageLicenseSpecificationListRequest = None,
        tag_specifications: TagSpecificationList = None,
        usage_operation: String = None,
        boot_mode: BootModeValues = None,
        **kwargs,
    ) -> ImportImageResult:
        raise NotImplementedError

    @handler("ImportInstance")
    def import_instance(
        self,
        context: RequestContext,
        platform: PlatformValues,
        dry_run: Boolean = None,
        description: String = None,
        launch_specification: ImportInstanceLaunchSpecification = None,
        disk_images: DiskImageList = None,
        **kwargs,
    ) -> ImportInstanceResult:
        raise NotImplementedError

    @handler("ImportKeyPair")
    def import_key_pair(
        self,
        context: RequestContext,
        key_name: String,
        public_key_material: Blob,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ImportKeyPairResult:
        raise NotImplementedError

    @handler("ImportSnapshot")
    def import_snapshot(
        self,
        context: RequestContext,
        client_data: ClientData = None,
        client_token: String = None,
        description: String = None,
        disk_container: SnapshotDiskContainer = None,
        dry_run: Boolean = None,
        encrypted: Boolean = None,
        kms_key_id: KmsKeyId = None,
        role_name: String = None,
        tag_specifications: TagSpecificationList = None,
        **kwargs,
    ) -> ImportSnapshotResult:
        raise NotImplementedError

    @handler("ImportVolume")
    def import_volume(
        self,
        context: RequestContext,
        availability_zone: String,
        image: DiskImageDetail,
        volume: VolumeDetail,
        dry_run: Boolean = None,
        description: String = None,
        **kwargs,
    ) -> ImportVolumeResult:
        raise NotImplementedError

    @handler("ListImagesInRecycleBin")
    def list_images_in_recycle_bin(
        self,
        context: RequestContext,
        image_ids: ImageIdStringList = None,
        next_token: String = None,
        max_results: ListImagesInRecycleBinMaxResults = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ListImagesInRecycleBinResult:
        raise NotImplementedError

    @handler("ListSnapshotsInRecycleBin")
    def list_snapshots_in_recycle_bin(
        self,
        context: RequestContext,
        max_results: ListSnapshotsInRecycleBinMaxResults = None,
        next_token: String = None,
        snapshot_ids: SnapshotIdStringList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ListSnapshotsInRecycleBinResult:
        raise NotImplementedError

    @handler("LockSnapshot")
    def lock_snapshot(
        self,
        context: RequestContext,
        snapshot_id: SnapshotId,
        lock_mode: LockMode,
        dry_run: Boolean = None,
        cool_off_period: CoolOffPeriodRequestHours = None,
        lock_duration: RetentionPeriodRequestDays = None,
        expiration_date: MillisecondDateTime = None,
        **kwargs,
    ) -> LockSnapshotResult:
        raise NotImplementedError

    @handler("ModifyAddressAttribute")
    def modify_address_attribute(
        self,
        context: RequestContext,
        allocation_id: AllocationId,
        domain_name: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyAddressAttributeResult:
        raise NotImplementedError

    @handler("ModifyAvailabilityZoneGroup")
    def modify_availability_zone_group(
        self,
        context: RequestContext,
        group_name: String,
        opt_in_status: ModifyAvailabilityZoneOptInStatus,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyAvailabilityZoneGroupResult:
        raise NotImplementedError

    @handler("ModifyCapacityReservation")
    def modify_capacity_reservation(
        self,
        context: RequestContext,
        capacity_reservation_id: CapacityReservationId,
        instance_count: Integer = None,
        end_date: DateTime = None,
        end_date_type: EndDateType = None,
        accept: Boolean = None,
        dry_run: Boolean = None,
        additional_info: String = None,
        instance_match_criteria: InstanceMatchCriteria = None,
        **kwargs,
    ) -> ModifyCapacityReservationResult:
        raise NotImplementedError

    @handler("ModifyCapacityReservationFleet")
    def modify_capacity_reservation_fleet(
        self,
        context: RequestContext,
        capacity_reservation_fleet_id: CapacityReservationFleetId,
        total_target_capacity: Integer = None,
        end_date: MillisecondDateTime = None,
        dry_run: Boolean = None,
        remove_end_date: Boolean = None,
        **kwargs,
    ) -> ModifyCapacityReservationFleetResult:
        raise NotImplementedError

    @handler("ModifyClientVpnEndpoint")
    def modify_client_vpn_endpoint(
        self,
        context: RequestContext,
        client_vpn_endpoint_id: ClientVpnEndpointId,
        server_certificate_arn: String = None,
        connection_log_options: ConnectionLogOptions = None,
        dns_servers: DnsServersOptionsModifyStructure = None,
        vpn_port: Integer = None,
        description: String = None,
        split_tunnel: Boolean = None,
        dry_run: Boolean = None,
        security_group_ids: ClientVpnSecurityGroupIdSet = None,
        vpc_id: VpcId = None,
        self_service_portal: SelfServicePortal = None,
        client_connect_options: ClientConnectOptions = None,
        session_timeout_hours: Integer = None,
        client_login_banner_options: ClientLoginBannerOptions = None,
        **kwargs,
    ) -> ModifyClientVpnEndpointResult:
        raise NotImplementedError

    @handler("ModifyDefaultCreditSpecification")
    def modify_default_credit_specification(
        self,
        context: RequestContext,
        instance_family: UnlimitedSupportedInstanceFamily,
        cpu_credits: String,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyDefaultCreditSpecificationResult:
        raise NotImplementedError

    @handler("ModifyEbsDefaultKmsKeyId")
    def modify_ebs_default_kms_key_id(
        self, context: RequestContext, kms_key_id: KmsKeyId, dry_run: Boolean = None, **kwargs
    ) -> ModifyEbsDefaultKmsKeyIdResult:
        raise NotImplementedError

    @handler("ModifyFleet", expand=False)
    def modify_fleet(
        self, context: RequestContext, request: ModifyFleetRequest, **kwargs
    ) -> ModifyFleetResult:
        raise NotImplementedError

    @handler("ModifyFpgaImageAttribute")
    def modify_fpga_image_attribute(
        self,
        context: RequestContext,
        fpga_image_id: FpgaImageId,
        dry_run: Boolean = None,
        attribute: FpgaImageAttributeName = None,
        operation_type: OperationType = None,
        user_ids: UserIdStringList = None,
        user_groups: UserGroupStringList = None,
        product_codes: ProductCodeStringList = None,
        load_permission: LoadPermissionModifications = None,
        description: String = None,
        name: String = None,
        **kwargs,
    ) -> ModifyFpgaImageAttributeResult:
        raise NotImplementedError

    @handler("ModifyHosts")
    def modify_hosts(
        self,
        context: RequestContext,
        host_ids: RequestHostIdList,
        host_recovery: HostRecovery = None,
        instance_type: String = None,
        instance_family: String = None,
        host_maintenance: HostMaintenance = None,
        auto_placement: AutoPlacement = None,
        **kwargs,
    ) -> ModifyHostsResult:
        raise NotImplementedError

    @handler("ModifyIdFormat")
    def modify_id_format(
        self, context: RequestContext, resource: String, use_long_ids: Boolean, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("ModifyIdentityIdFormat")
    def modify_identity_id_format(
        self,
        context: RequestContext,
        resource: String,
        use_long_ids: Boolean,
        principal_arn: String,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ModifyImageAttribute")
    def modify_image_attribute(
        self,
        context: RequestContext,
        image_id: ImageId,
        attribute: String = None,
        description: AttributeValue = None,
        launch_permission: LaunchPermissionModifications = None,
        operation_type: OperationType = None,
        product_codes: ProductCodeStringList = None,
        user_groups: UserGroupStringList = None,
        user_ids: UserIdStringList = None,
        value: String = None,
        organization_arns: OrganizationArnStringList = None,
        organizational_unit_arns: OrganizationalUnitArnStringList = None,
        imds_support: AttributeValue = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ModifyInstanceAttribute")
    def modify_instance_attribute(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        source_dest_check: AttributeBooleanValue = None,
        disable_api_stop: AttributeBooleanValue = None,
        dry_run: Boolean = None,
        attribute: InstanceAttributeName = None,
        value: String = None,
        block_device_mappings: InstanceBlockDeviceMappingSpecificationList = None,
        disable_api_termination: AttributeBooleanValue = None,
        instance_type: AttributeValue = None,
        kernel: AttributeValue = None,
        ramdisk: AttributeValue = None,
        user_data: BlobAttributeValue = None,
        instance_initiated_shutdown_behavior: AttributeValue = None,
        groups: GroupIdStringList = None,
        ebs_optimized: AttributeBooleanValue = None,
        sriov_net_support: AttributeValue = None,
        ena_support: AttributeBooleanValue = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ModifyInstanceCapacityReservationAttributes")
    def modify_instance_capacity_reservation_attributes(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        capacity_reservation_specification: CapacityReservationSpecification,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyInstanceCapacityReservationAttributesResult:
        raise NotImplementedError

    @handler("ModifyInstanceCpuOptions")
    def modify_instance_cpu_options(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        core_count: Integer,
        threads_per_core: Integer,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyInstanceCpuOptionsResult:
        raise NotImplementedError

    @handler("ModifyInstanceCreditSpecification")
    def modify_instance_credit_specification(
        self,
        context: RequestContext,
        instance_credit_specifications: InstanceCreditSpecificationListRequest,
        dry_run: Boolean = None,
        client_token: String = None,
        **kwargs,
    ) -> ModifyInstanceCreditSpecificationResult:
        raise NotImplementedError

    @handler("ModifyInstanceEventStartTime")
    def modify_instance_event_start_time(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        instance_event_id: String,
        not_before: DateTime,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyInstanceEventStartTimeResult:
        raise NotImplementedError

    @handler("ModifyInstanceEventWindow")
    def modify_instance_event_window(
        self,
        context: RequestContext,
        instance_event_window_id: InstanceEventWindowId,
        dry_run: Boolean = None,
        name: String = None,
        time_ranges: InstanceEventWindowTimeRangeRequestSet = None,
        cron_expression: InstanceEventWindowCronExpression = None,
        **kwargs,
    ) -> ModifyInstanceEventWindowResult:
        raise NotImplementedError

    @handler("ModifyInstanceMaintenanceOptions")
    def modify_instance_maintenance_options(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        auto_recovery: InstanceAutoRecoveryState = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyInstanceMaintenanceOptionsResult:
        raise NotImplementedError

    @handler("ModifyInstanceMetadataDefaults")
    def modify_instance_metadata_defaults(
        self,
        context: RequestContext,
        http_tokens: MetadataDefaultHttpTokensState = None,
        http_put_response_hop_limit: BoxedInteger = None,
        http_endpoint: DefaultInstanceMetadataEndpointState = None,
        instance_metadata_tags: DefaultInstanceMetadataTagsState = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyInstanceMetadataDefaultsResult:
        raise NotImplementedError

    @handler("ModifyInstanceMetadataOptions")
    def modify_instance_metadata_options(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        http_tokens: HttpTokensState = None,
        http_put_response_hop_limit: Integer = None,
        http_endpoint: InstanceMetadataEndpointState = None,
        dry_run: Boolean = None,
        http_protocol_ipv6: InstanceMetadataProtocolState = None,
        instance_metadata_tags: InstanceMetadataTagsState = None,
        **kwargs,
    ) -> ModifyInstanceMetadataOptionsResult:
        raise NotImplementedError

    @handler("ModifyInstancePlacement")
    def modify_instance_placement(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        group_name: PlacementGroupName = None,
        partition_number: Integer = None,
        host_resource_group_arn: String = None,
        group_id: PlacementGroupId = None,
        tenancy: HostTenancy = None,
        affinity: Affinity = None,
        host_id: DedicatedHostId = None,
        **kwargs,
    ) -> ModifyInstancePlacementResult:
        raise NotImplementedError

    @handler("ModifyIpam")
    def modify_ipam(
        self,
        context: RequestContext,
        ipam_id: IpamId,
        dry_run: Boolean = None,
        description: String = None,
        add_operating_regions: AddIpamOperatingRegionSet = None,
        remove_operating_regions: RemoveIpamOperatingRegionSet = None,
        tier: IpamTier = None,
        enable_private_gua: Boolean = None,
        **kwargs,
    ) -> ModifyIpamResult:
        raise NotImplementedError

    @handler("ModifyIpamPool")
    def modify_ipam_pool(
        self,
        context: RequestContext,
        ipam_pool_id: IpamPoolId,
        dry_run: Boolean = None,
        description: String = None,
        auto_import: Boolean = None,
        allocation_min_netmask_length: IpamNetmaskLength = None,
        allocation_max_netmask_length: IpamNetmaskLength = None,
        allocation_default_netmask_length: IpamNetmaskLength = None,
        clear_allocation_default_netmask_length: Boolean = None,
        add_allocation_resource_tags: RequestIpamResourceTagList = None,
        remove_allocation_resource_tags: RequestIpamResourceTagList = None,
        **kwargs,
    ) -> ModifyIpamPoolResult:
        raise NotImplementedError

    @handler("ModifyIpamResourceCidr")
    def modify_ipam_resource_cidr(
        self,
        context: RequestContext,
        resource_id: String,
        resource_cidr: String,
        resource_region: String,
        current_ipam_scope_id: IpamScopeId,
        monitored: Boolean,
        dry_run: Boolean = None,
        destination_ipam_scope_id: IpamScopeId = None,
        **kwargs,
    ) -> ModifyIpamResourceCidrResult:
        raise NotImplementedError

    @handler("ModifyIpamResourceDiscovery")
    def modify_ipam_resource_discovery(
        self,
        context: RequestContext,
        ipam_resource_discovery_id: IpamResourceDiscoveryId,
        dry_run: Boolean = None,
        description: String = None,
        add_operating_regions: AddIpamOperatingRegionSet = None,
        remove_operating_regions: RemoveIpamOperatingRegionSet = None,
        **kwargs,
    ) -> ModifyIpamResourceDiscoveryResult:
        raise NotImplementedError

    @handler("ModifyIpamScope")
    def modify_ipam_scope(
        self,
        context: RequestContext,
        ipam_scope_id: IpamScopeId,
        dry_run: Boolean = None,
        description: String = None,
        **kwargs,
    ) -> ModifyIpamScopeResult:
        raise NotImplementedError

    @handler("ModifyLaunchTemplate")
    def modify_launch_template(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        client_token: String = None,
        launch_template_id: LaunchTemplateId = None,
        launch_template_name: LaunchTemplateName = None,
        default_version: String = None,
        **kwargs,
    ) -> ModifyLaunchTemplateResult:
        raise NotImplementedError

    @handler("ModifyLocalGatewayRoute")
    def modify_local_gateway_route(
        self,
        context: RequestContext,
        local_gateway_route_table_id: LocalGatewayRoutetableId,
        destination_cidr_block: String = None,
        local_gateway_virtual_interface_group_id: LocalGatewayVirtualInterfaceGroupId = None,
        network_interface_id: NetworkInterfaceId = None,
        dry_run: Boolean = None,
        destination_prefix_list_id: PrefixListResourceId = None,
        **kwargs,
    ) -> ModifyLocalGatewayRouteResult:
        raise NotImplementedError

    @handler("ModifyManagedPrefixList")
    def modify_managed_prefix_list(
        self,
        context: RequestContext,
        prefix_list_id: PrefixListResourceId,
        dry_run: Boolean = None,
        current_version: Long = None,
        prefix_list_name: String = None,
        add_entries: AddPrefixListEntries = None,
        remove_entries: RemovePrefixListEntries = None,
        max_entries: Integer = None,
        **kwargs,
    ) -> ModifyManagedPrefixListResult:
        raise NotImplementedError

    @handler("ModifyNetworkInterfaceAttribute")
    def modify_network_interface_attribute(
        self,
        context: RequestContext,
        network_interface_id: NetworkInterfaceId,
        ena_srd_specification: EnaSrdSpecification = None,
        enable_primary_ipv6: Boolean = None,
        connection_tracking_specification: ConnectionTrackingSpecificationRequest = None,
        associate_public_ip_address: Boolean = None,
        dry_run: Boolean = None,
        description: AttributeValue = None,
        source_dest_check: AttributeBooleanValue = None,
        groups: SecurityGroupIdStringList = None,
        attachment: NetworkInterfaceAttachmentChanges = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ModifyPrivateDnsNameOptions")
    def modify_private_dns_name_options(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        dry_run: Boolean = None,
        private_dns_hostname_type: HostnameType = None,
        enable_resource_name_dns_a_record: Boolean = None,
        enable_resource_name_dns_aaaa_record: Boolean = None,
        **kwargs,
    ) -> ModifyPrivateDnsNameOptionsResult:
        raise NotImplementedError

    @handler("ModifyReservedInstances")
    def modify_reserved_instances(
        self,
        context: RequestContext,
        reserved_instances_ids: ReservedInstancesIdStringList,
        target_configurations: ReservedInstancesConfigurationList,
        client_token: String = None,
        **kwargs,
    ) -> ModifyReservedInstancesResult:
        raise NotImplementedError

    @handler("ModifySecurityGroupRules")
    def modify_security_group_rules(
        self,
        context: RequestContext,
        group_id: SecurityGroupId,
        security_group_rules: SecurityGroupRuleUpdateList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifySecurityGroupRulesResult:
        raise NotImplementedError

    @handler("ModifySnapshotAttribute")
    def modify_snapshot_attribute(
        self,
        context: RequestContext,
        snapshot_id: SnapshotId,
        attribute: SnapshotAttributeName = None,
        create_volume_permission: CreateVolumePermissionModifications = None,
        group_names: GroupNameStringList = None,
        operation_type: OperationType = None,
        user_ids: UserIdStringList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ModifySnapshotTier")
    def modify_snapshot_tier(
        self,
        context: RequestContext,
        snapshot_id: SnapshotId,
        storage_tier: TargetStorageTier = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifySnapshotTierResult:
        raise NotImplementedError

    @handler("ModifySpotFleetRequest", expand=False)
    def modify_spot_fleet_request(
        self, context: RequestContext, request: ModifySpotFleetRequestRequest, **kwargs
    ) -> ModifySpotFleetRequestResponse:
        raise NotImplementedError

    @handler("ModifySubnetAttribute")
    def modify_subnet_attribute(
        self,
        context: RequestContext,
        subnet_id: SubnetId,
        assign_ipv6_address_on_creation: AttributeBooleanValue = None,
        map_public_ip_on_launch: AttributeBooleanValue = None,
        map_customer_owned_ip_on_launch: AttributeBooleanValue = None,
        customer_owned_ipv4_pool: CoipPoolId = None,
        enable_dns64: AttributeBooleanValue = None,
        private_dns_hostname_type_on_launch: HostnameType = None,
        enable_resource_name_dns_a_record_on_launch: AttributeBooleanValue = None,
        enable_resource_name_dns_aaaa_record_on_launch: AttributeBooleanValue = None,
        enable_lni_at_device_index: Integer = None,
        disable_lni_at_device_index: AttributeBooleanValue = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ModifyTrafficMirrorFilterNetworkServices")
    def modify_traffic_mirror_filter_network_services(
        self,
        context: RequestContext,
        traffic_mirror_filter_id: TrafficMirrorFilterId,
        add_network_services: TrafficMirrorNetworkServiceList = None,
        remove_network_services: TrafficMirrorNetworkServiceList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyTrafficMirrorFilterNetworkServicesResult:
        raise NotImplementedError

    @handler("ModifyTrafficMirrorFilterRule")
    def modify_traffic_mirror_filter_rule(
        self,
        context: RequestContext,
        traffic_mirror_filter_rule_id: TrafficMirrorFilterRuleIdWithResolver,
        traffic_direction: TrafficDirection = None,
        rule_number: Integer = None,
        rule_action: TrafficMirrorRuleAction = None,
        destination_port_range: TrafficMirrorPortRangeRequest = None,
        source_port_range: TrafficMirrorPortRangeRequest = None,
        protocol: Integer = None,
        destination_cidr_block: String = None,
        source_cidr_block: String = None,
        description: String = None,
        remove_fields: TrafficMirrorFilterRuleFieldList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyTrafficMirrorFilterRuleResult:
        raise NotImplementedError

    @handler("ModifyTrafficMirrorSession")
    def modify_traffic_mirror_session(
        self,
        context: RequestContext,
        traffic_mirror_session_id: TrafficMirrorSessionId,
        traffic_mirror_target_id: TrafficMirrorTargetId = None,
        traffic_mirror_filter_id: TrafficMirrorFilterId = None,
        packet_length: Integer = None,
        session_number: Integer = None,
        virtual_network_id: Integer = None,
        description: String = None,
        remove_fields: TrafficMirrorSessionFieldList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyTrafficMirrorSessionResult:
        raise NotImplementedError

    @handler("ModifyTransitGateway")
    def modify_transit_gateway(
        self,
        context: RequestContext,
        transit_gateway_id: TransitGatewayId,
        description: String = None,
        options: ModifyTransitGatewayOptions = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyTransitGatewayResult:
        raise NotImplementedError

    @handler("ModifyTransitGatewayPrefixListReference")
    def modify_transit_gateway_prefix_list_reference(
        self,
        context: RequestContext,
        transit_gateway_route_table_id: TransitGatewayRouteTableId,
        prefix_list_id: PrefixListResourceId,
        transit_gateway_attachment_id: TransitGatewayAttachmentId = None,
        blackhole: Boolean = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyTransitGatewayPrefixListReferenceResult:
        raise NotImplementedError

    @handler("ModifyTransitGatewayVpcAttachment")
    def modify_transit_gateway_vpc_attachment(
        self,
        context: RequestContext,
        transit_gateway_attachment_id: TransitGatewayAttachmentId,
        add_subnet_ids: TransitGatewaySubnetIdList = None,
        remove_subnet_ids: TransitGatewaySubnetIdList = None,
        options: ModifyTransitGatewayVpcAttachmentRequestOptions = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyTransitGatewayVpcAttachmentResult:
        raise NotImplementedError

    @handler("ModifyVerifiedAccessEndpoint")
    def modify_verified_access_endpoint(
        self,
        context: RequestContext,
        verified_access_endpoint_id: VerifiedAccessEndpointId,
        verified_access_group_id: VerifiedAccessGroupId = None,
        load_balancer_options: ModifyVerifiedAccessEndpointLoadBalancerOptions = None,
        network_interface_options: ModifyVerifiedAccessEndpointEniOptions = None,
        description: String = None,
        client_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyVerifiedAccessEndpointResult:
        raise NotImplementedError

    @handler("ModifyVerifiedAccessEndpointPolicy")
    def modify_verified_access_endpoint_policy(
        self,
        context: RequestContext,
        verified_access_endpoint_id: VerifiedAccessEndpointId,
        policy_enabled: Boolean = None,
        policy_document: String = None,
        client_token: String = None,
        dry_run: Boolean = None,
        sse_specification: VerifiedAccessSseSpecificationRequest = None,
        **kwargs,
    ) -> ModifyVerifiedAccessEndpointPolicyResult:
        raise NotImplementedError

    @handler("ModifyVerifiedAccessGroup")
    def modify_verified_access_group(
        self,
        context: RequestContext,
        verified_access_group_id: VerifiedAccessGroupId,
        verified_access_instance_id: VerifiedAccessInstanceId = None,
        description: String = None,
        client_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyVerifiedAccessGroupResult:
        raise NotImplementedError

    @handler("ModifyVerifiedAccessGroupPolicy")
    def modify_verified_access_group_policy(
        self,
        context: RequestContext,
        verified_access_group_id: VerifiedAccessGroupId,
        policy_enabled: Boolean = None,
        policy_document: String = None,
        client_token: String = None,
        dry_run: Boolean = None,
        sse_specification: VerifiedAccessSseSpecificationRequest = None,
        **kwargs,
    ) -> ModifyVerifiedAccessGroupPolicyResult:
        raise NotImplementedError

    @handler("ModifyVerifiedAccessInstance")
    def modify_verified_access_instance(
        self,
        context: RequestContext,
        verified_access_instance_id: VerifiedAccessInstanceId,
        description: String = None,
        dry_run: Boolean = None,
        client_token: String = None,
        **kwargs,
    ) -> ModifyVerifiedAccessInstanceResult:
        raise NotImplementedError

    @handler("ModifyVerifiedAccessInstanceLoggingConfiguration")
    def modify_verified_access_instance_logging_configuration(
        self,
        context: RequestContext,
        verified_access_instance_id: VerifiedAccessInstanceId,
        access_logs: VerifiedAccessLogOptions,
        dry_run: Boolean = None,
        client_token: String = None,
        **kwargs,
    ) -> ModifyVerifiedAccessInstanceLoggingConfigurationResult:
        raise NotImplementedError

    @handler("ModifyVerifiedAccessTrustProvider")
    def modify_verified_access_trust_provider(
        self,
        context: RequestContext,
        verified_access_trust_provider_id: VerifiedAccessTrustProviderId,
        oidc_options: ModifyVerifiedAccessTrustProviderOidcOptions = None,
        device_options: ModifyVerifiedAccessTrustProviderDeviceOptions = None,
        description: String = None,
        dry_run: Boolean = None,
        client_token: String = None,
        sse_specification: VerifiedAccessSseSpecificationRequest = None,
        **kwargs,
    ) -> ModifyVerifiedAccessTrustProviderResult:
        raise NotImplementedError

    @handler("ModifyVolume")
    def modify_volume(
        self,
        context: RequestContext,
        volume_id: VolumeId,
        dry_run: Boolean = None,
        size: Integer = None,
        volume_type: VolumeType = None,
        iops: Integer = None,
        throughput: Integer = None,
        multi_attach_enabled: Boolean = None,
        **kwargs,
    ) -> ModifyVolumeResult:
        raise NotImplementedError

    @handler("ModifyVolumeAttribute")
    def modify_volume_attribute(
        self,
        context: RequestContext,
        volume_id: VolumeId,
        auto_enable_io: AttributeBooleanValue = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ModifyVpcAttribute")
    def modify_vpc_attribute(
        self,
        context: RequestContext,
        vpc_id: VpcId,
        enable_dns_hostnames: AttributeBooleanValue = None,
        enable_dns_support: AttributeBooleanValue = None,
        enable_network_address_usage_metrics: AttributeBooleanValue = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ModifyVpcEndpoint")
    def modify_vpc_endpoint(
        self,
        context: RequestContext,
        vpc_endpoint_id: VpcEndpointId,
        dry_run: Boolean = None,
        reset_policy: Boolean = None,
        policy_document: String = None,
        add_route_table_ids: VpcEndpointRouteTableIdList = None,
        remove_route_table_ids: VpcEndpointRouteTableIdList = None,
        add_subnet_ids: VpcEndpointSubnetIdList = None,
        remove_subnet_ids: VpcEndpointSubnetIdList = None,
        add_security_group_ids: VpcEndpointSecurityGroupIdList = None,
        remove_security_group_ids: VpcEndpointSecurityGroupIdList = None,
        ip_address_type: IpAddressType = None,
        dns_options: DnsOptionsSpecification = None,
        private_dns_enabled: Boolean = None,
        subnet_configurations: SubnetConfigurationsList = None,
        **kwargs,
    ) -> ModifyVpcEndpointResult:
        raise NotImplementedError

    @handler("ModifyVpcEndpointConnectionNotification")
    def modify_vpc_endpoint_connection_notification(
        self,
        context: RequestContext,
        connection_notification_id: ConnectionNotificationId,
        dry_run: Boolean = None,
        connection_notification_arn: String = None,
        connection_events: ValueStringList = None,
        **kwargs,
    ) -> ModifyVpcEndpointConnectionNotificationResult:
        raise NotImplementedError

    @handler("ModifyVpcEndpointServiceConfiguration")
    def modify_vpc_endpoint_service_configuration(
        self,
        context: RequestContext,
        service_id: VpcEndpointServiceId,
        dry_run: Boolean = None,
        private_dns_name: String = None,
        remove_private_dns_name: Boolean = None,
        acceptance_required: Boolean = None,
        add_network_load_balancer_arns: ValueStringList = None,
        remove_network_load_balancer_arns: ValueStringList = None,
        add_gateway_load_balancer_arns: ValueStringList = None,
        remove_gateway_load_balancer_arns: ValueStringList = None,
        add_supported_ip_address_types: ValueStringList = None,
        remove_supported_ip_address_types: ValueStringList = None,
        **kwargs,
    ) -> ModifyVpcEndpointServiceConfigurationResult:
        raise NotImplementedError

    @handler("ModifyVpcEndpointServicePayerResponsibility")
    def modify_vpc_endpoint_service_payer_responsibility(
        self,
        context: RequestContext,
        service_id: VpcEndpointServiceId,
        payer_responsibility: PayerResponsibility,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyVpcEndpointServicePayerResponsibilityResult:
        raise NotImplementedError

    @handler("ModifyVpcEndpointServicePermissions")
    def modify_vpc_endpoint_service_permissions(
        self,
        context: RequestContext,
        service_id: VpcEndpointServiceId,
        dry_run: Boolean = None,
        add_allowed_principals: ValueStringList = None,
        remove_allowed_principals: ValueStringList = None,
        **kwargs,
    ) -> ModifyVpcEndpointServicePermissionsResult:
        raise NotImplementedError

    @handler("ModifyVpcPeeringConnectionOptions")
    def modify_vpc_peering_connection_options(
        self,
        context: RequestContext,
        vpc_peering_connection_id: VpcPeeringConnectionId,
        accepter_peering_connection_options: PeeringConnectionOptionsRequest = None,
        dry_run: Boolean = None,
        requester_peering_connection_options: PeeringConnectionOptionsRequest = None,
        **kwargs,
    ) -> ModifyVpcPeeringConnectionOptionsResult:
        raise NotImplementedError

    @handler("ModifyVpcTenancy")
    def modify_vpc_tenancy(
        self,
        context: RequestContext,
        vpc_id: VpcId,
        instance_tenancy: VpcTenancy,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyVpcTenancyResult:
        raise NotImplementedError

    @handler("ModifyVpnConnection")
    def modify_vpn_connection(
        self,
        context: RequestContext,
        vpn_connection_id: VpnConnectionId,
        transit_gateway_id: TransitGatewayId = None,
        customer_gateway_id: CustomerGatewayId = None,
        vpn_gateway_id: VpnGatewayId = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyVpnConnectionResult:
        raise NotImplementedError

    @handler("ModifyVpnConnectionOptions")
    def modify_vpn_connection_options(
        self,
        context: RequestContext,
        vpn_connection_id: VpnConnectionId,
        local_ipv4_network_cidr: String = None,
        remote_ipv4_network_cidr: String = None,
        local_ipv6_network_cidr: String = None,
        remote_ipv6_network_cidr: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyVpnConnectionOptionsResult:
        raise NotImplementedError

    @handler("ModifyVpnTunnelCertificate")
    def modify_vpn_tunnel_certificate(
        self,
        context: RequestContext,
        vpn_connection_id: VpnConnectionId,
        vpn_tunnel_outside_ip_address: String,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ModifyVpnTunnelCertificateResult:
        raise NotImplementedError

    @handler("ModifyVpnTunnelOptions")
    def modify_vpn_tunnel_options(
        self,
        context: RequestContext,
        vpn_connection_id: VpnConnectionId,
        vpn_tunnel_outside_ip_address: String,
        tunnel_options: ModifyVpnTunnelOptionsSpecification,
        dry_run: Boolean = None,
        skip_tunnel_replacement: Boolean = None,
        **kwargs,
    ) -> ModifyVpnTunnelOptionsResult:
        raise NotImplementedError

    @handler("MonitorInstances")
    def monitor_instances(
        self,
        context: RequestContext,
        instance_ids: InstanceIdStringList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> MonitorInstancesResult:
        raise NotImplementedError

    @handler("MoveAddressToVpc")
    def move_address_to_vpc(
        self, context: RequestContext, public_ip: String, dry_run: Boolean = None, **kwargs
    ) -> MoveAddressToVpcResult:
        raise NotImplementedError

    @handler("MoveByoipCidrToIpam")
    def move_byoip_cidr_to_ipam(
        self,
        context: RequestContext,
        cidr: String,
        ipam_pool_id: IpamPoolId,
        ipam_pool_owner: String,
        dry_run: Boolean = None,
        **kwargs,
    ) -> MoveByoipCidrToIpamResult:
        raise NotImplementedError

    @handler("MoveCapacityReservationInstances")
    def move_capacity_reservation_instances(
        self,
        context: RequestContext,
        source_capacity_reservation_id: CapacityReservationId,
        destination_capacity_reservation_id: CapacityReservationId,
        instance_count: Integer,
        dry_run: Boolean = None,
        client_token: String = None,
        **kwargs,
    ) -> MoveCapacityReservationInstancesResult:
        raise NotImplementedError

    @handler("ProvisionByoipCidr")
    def provision_byoip_cidr(
        self,
        context: RequestContext,
        cidr: String,
        cidr_authorization_context: CidrAuthorizationContext = None,
        publicly_advertisable: Boolean = None,
        description: String = None,
        dry_run: Boolean = None,
        pool_tag_specifications: TagSpecificationList = None,
        multi_region: Boolean = None,
        network_border_group: String = None,
        **kwargs,
    ) -> ProvisionByoipCidrResult:
        raise NotImplementedError

    @handler("ProvisionIpamByoasn")
    def provision_ipam_byoasn(
        self,
        context: RequestContext,
        ipam_id: IpamId,
        asn: String,
        asn_authorization_context: AsnAuthorizationContext,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ProvisionIpamByoasnResult:
        raise NotImplementedError

    @handler("ProvisionIpamPoolCidr")
    def provision_ipam_pool_cidr(
        self,
        context: RequestContext,
        ipam_pool_id: IpamPoolId,
        dry_run: Boolean = None,
        cidr: String = None,
        cidr_authorization_context: IpamCidrAuthorizationContext = None,
        netmask_length: Integer = None,
        client_token: String = None,
        verification_method: VerificationMethod = None,
        ipam_external_resource_verification_token_id: IpamExternalResourceVerificationTokenId = None,
        **kwargs,
    ) -> ProvisionIpamPoolCidrResult:
        raise NotImplementedError

    @handler("ProvisionPublicIpv4PoolCidr")
    def provision_public_ipv4_pool_cidr(
        self,
        context: RequestContext,
        ipam_pool_id: IpamPoolId,
        pool_id: Ipv4PoolEc2Id,
        netmask_length: Integer,
        dry_run: Boolean = None,
        network_border_group: String = None,
        **kwargs,
    ) -> ProvisionPublicIpv4PoolCidrResult:
        raise NotImplementedError

    @handler("PurchaseCapacityBlock")
    def purchase_capacity_block(
        self,
        context: RequestContext,
        capacity_block_offering_id: OfferingId,
        instance_platform: CapacityReservationInstancePlatform,
        dry_run: Boolean = None,
        tag_specifications: TagSpecificationList = None,
        **kwargs,
    ) -> PurchaseCapacityBlockResult:
        raise NotImplementedError

    @handler("PurchaseHostReservation")
    def purchase_host_reservation(
        self,
        context: RequestContext,
        host_id_set: RequestHostIdSet,
        offering_id: OfferingId,
        client_token: String = None,
        currency_code: CurrencyCodeValues = None,
        limit_price: String = None,
        tag_specifications: TagSpecificationList = None,
        **kwargs,
    ) -> PurchaseHostReservationResult:
        raise NotImplementedError

    @handler("PurchaseReservedInstancesOffering")
    def purchase_reserved_instances_offering(
        self,
        context: RequestContext,
        instance_count: Integer,
        reserved_instances_offering_id: ReservedInstancesOfferingId,
        purchase_time: DateTime = None,
        dry_run: Boolean = None,
        limit_price: ReservedInstanceLimitPrice = None,
        **kwargs,
    ) -> PurchaseReservedInstancesOfferingResult:
        raise NotImplementedError

    @handler("PurchaseScheduledInstances")
    def purchase_scheduled_instances(
        self,
        context: RequestContext,
        purchase_requests: PurchaseRequestSet,
        client_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> PurchaseScheduledInstancesResult:
        raise NotImplementedError

    @handler("RebootInstances")
    def reboot_instances(
        self,
        context: RequestContext,
        instance_ids: InstanceIdStringList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RegisterImage")
    def register_image(
        self,
        context: RequestContext,
        name: String,
        image_location: String = None,
        billing_products: BillingProductList = None,
        boot_mode: BootModeValues = None,
        tpm_support: TpmSupportValues = None,
        uefi_data: StringType = None,
        imds_support: ImdsSupportValues = None,
        tag_specifications: TagSpecificationList = None,
        dry_run: Boolean = None,
        description: String = None,
        architecture: ArchitectureValues = None,
        kernel_id: KernelId = None,
        ramdisk_id: RamdiskId = None,
        root_device_name: String = None,
        block_device_mappings: BlockDeviceMappingRequestList = None,
        virtualization_type: String = None,
        sriov_net_support: String = None,
        ena_support: Boolean = None,
        **kwargs,
    ) -> RegisterImageResult:
        raise NotImplementedError

    @handler("RegisterInstanceEventNotificationAttributes")
    def register_instance_event_notification_attributes(
        self,
        context: RequestContext,
        instance_tag_attribute: RegisterInstanceTagAttributeRequest,
        dry_run: Boolean = None,
        **kwargs,
    ) -> RegisterInstanceEventNotificationAttributesResult:
        raise NotImplementedError

    @handler("RegisterTransitGatewayMulticastGroupMembers")
    def register_transit_gateway_multicast_group_members(
        self,
        context: RequestContext,
        transit_gateway_multicast_domain_id: TransitGatewayMulticastDomainId,
        network_interface_ids: TransitGatewayNetworkInterfaceIdList,
        group_ip_address: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> RegisterTransitGatewayMulticastGroupMembersResult:
        raise NotImplementedError

    @handler("RegisterTransitGatewayMulticastGroupSources")
    def register_transit_gateway_multicast_group_sources(
        self,
        context: RequestContext,
        transit_gateway_multicast_domain_id: TransitGatewayMulticastDomainId,
        network_interface_ids: TransitGatewayNetworkInterfaceIdList,
        group_ip_address: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> RegisterTransitGatewayMulticastGroupSourcesResult:
        raise NotImplementedError

    @handler("RejectCapacityReservationBillingOwnership")
    def reject_capacity_reservation_billing_ownership(
        self,
        context: RequestContext,
        capacity_reservation_id: CapacityReservationId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> RejectCapacityReservationBillingOwnershipResult:
        raise NotImplementedError

    @handler("RejectTransitGatewayMulticastDomainAssociations")
    def reject_transit_gateway_multicast_domain_associations(
        self,
        context: RequestContext,
        transit_gateway_multicast_domain_id: TransitGatewayMulticastDomainId = None,
        transit_gateway_attachment_id: TransitGatewayAttachmentId = None,
        subnet_ids: ValueStringList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> RejectTransitGatewayMulticastDomainAssociationsResult:
        raise NotImplementedError

    @handler("RejectTransitGatewayPeeringAttachment")
    def reject_transit_gateway_peering_attachment(
        self,
        context: RequestContext,
        transit_gateway_attachment_id: TransitGatewayAttachmentId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> RejectTransitGatewayPeeringAttachmentResult:
        raise NotImplementedError

    @handler("RejectTransitGatewayVpcAttachment")
    def reject_transit_gateway_vpc_attachment(
        self,
        context: RequestContext,
        transit_gateway_attachment_id: TransitGatewayAttachmentId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> RejectTransitGatewayVpcAttachmentResult:
        raise NotImplementedError

    @handler("RejectVpcEndpointConnections")
    def reject_vpc_endpoint_connections(
        self,
        context: RequestContext,
        service_id: VpcEndpointServiceId,
        vpc_endpoint_ids: VpcEndpointIdList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> RejectVpcEndpointConnectionsResult:
        raise NotImplementedError

    @handler("RejectVpcPeeringConnection")
    def reject_vpc_peering_connection(
        self,
        context: RequestContext,
        vpc_peering_connection_id: VpcPeeringConnectionId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> RejectVpcPeeringConnectionResult:
        raise NotImplementedError

    @handler("ReleaseAddress")
    def release_address(
        self,
        context: RequestContext,
        allocation_id: AllocationId = None,
        public_ip: String = None,
        network_border_group: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ReleaseHosts")
    def release_hosts(
        self, context: RequestContext, host_ids: RequestHostIdList, **kwargs
    ) -> ReleaseHostsResult:
        raise NotImplementedError

    @handler("ReleaseIpamPoolAllocation")
    def release_ipam_pool_allocation(
        self,
        context: RequestContext,
        ipam_pool_id: IpamPoolId,
        cidr: String,
        ipam_pool_allocation_id: IpamPoolAllocationId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ReleaseIpamPoolAllocationResult:
        raise NotImplementedError

    @handler("ReplaceIamInstanceProfileAssociation")
    def replace_iam_instance_profile_association(
        self,
        context: RequestContext,
        iam_instance_profile: IamInstanceProfileSpecification,
        association_id: IamInstanceProfileAssociationId,
        **kwargs,
    ) -> ReplaceIamInstanceProfileAssociationResult:
        raise NotImplementedError

    @handler("ReplaceNetworkAclAssociation")
    def replace_network_acl_association(
        self,
        context: RequestContext,
        association_id: NetworkAclAssociationId,
        network_acl_id: NetworkAclId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ReplaceNetworkAclAssociationResult:
        raise NotImplementedError

    @handler("ReplaceNetworkAclEntry")
    def replace_network_acl_entry(
        self,
        context: RequestContext,
        network_acl_id: NetworkAclId,
        rule_number: Integer,
        protocol: String,
        rule_action: RuleAction,
        egress: Boolean,
        dry_run: Boolean = None,
        cidr_block: String = None,
        ipv6_cidr_block: String = None,
        icmp_type_code: IcmpTypeCode = None,
        port_range: PortRange = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ReplaceRoute")
    def replace_route(
        self,
        context: RequestContext,
        route_table_id: RouteTableId,
        destination_prefix_list_id: PrefixListResourceId = None,
        vpc_endpoint_id: VpcEndpointId = None,
        local_target: Boolean = None,
        transit_gateway_id: TransitGatewayId = None,
        local_gateway_id: LocalGatewayId = None,
        carrier_gateway_id: CarrierGatewayId = None,
        core_network_arn: CoreNetworkArn = None,
        dry_run: Boolean = None,
        destination_cidr_block: String = None,
        gateway_id: RouteGatewayId = None,
        destination_ipv6_cidr_block: String = None,
        egress_only_internet_gateway_id: EgressOnlyInternetGatewayId = None,
        instance_id: InstanceId = None,
        network_interface_id: NetworkInterfaceId = None,
        vpc_peering_connection_id: VpcPeeringConnectionId = None,
        nat_gateway_id: NatGatewayId = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ReplaceRouteTableAssociation")
    def replace_route_table_association(
        self,
        context: RequestContext,
        association_id: RouteTableAssociationId,
        route_table_id: RouteTableId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ReplaceRouteTableAssociationResult:
        raise NotImplementedError

    @handler("ReplaceTransitGatewayRoute")
    def replace_transit_gateway_route(
        self,
        context: RequestContext,
        destination_cidr_block: String,
        transit_gateway_route_table_id: TransitGatewayRouteTableId,
        transit_gateway_attachment_id: TransitGatewayAttachmentId = None,
        blackhole: Boolean = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ReplaceTransitGatewayRouteResult:
        raise NotImplementedError

    @handler("ReplaceVpnTunnel")
    def replace_vpn_tunnel(
        self,
        context: RequestContext,
        vpn_connection_id: VpnConnectionId,
        vpn_tunnel_outside_ip_address: String,
        apply_pending_maintenance: Boolean = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ReplaceVpnTunnelResult:
        raise NotImplementedError

    @handler("ReportInstanceStatus")
    def report_instance_status(
        self,
        context: RequestContext,
        instances: InstanceIdStringList,
        status: ReportStatusType,
        reason_codes: ReasonCodesList,
        dry_run: Boolean = None,
        start_time: DateTime = None,
        end_time: DateTime = None,
        description: ReportInstanceStatusRequestDescription = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RequestSpotFleet")
    def request_spot_fleet(
        self,
        context: RequestContext,
        spot_fleet_request_config: SpotFleetRequestConfigData,
        dry_run: Boolean = None,
        **kwargs,
    ) -> RequestSpotFleetResponse:
        raise NotImplementedError

    @handler("RequestSpotInstances", expand=False)
    def request_spot_instances(
        self, context: RequestContext, request: RequestSpotInstancesRequest, **kwargs
    ) -> RequestSpotInstancesResult:
        raise NotImplementedError

    @handler("ResetAddressAttribute")
    def reset_address_attribute(
        self,
        context: RequestContext,
        allocation_id: AllocationId,
        attribute: AddressAttributeName,
        dry_run: Boolean = None,
        **kwargs,
    ) -> ResetAddressAttributeResult:
        raise NotImplementedError

    @handler("ResetEbsDefaultKmsKeyId")
    def reset_ebs_default_kms_key_id(
        self, context: RequestContext, dry_run: Boolean = None, **kwargs
    ) -> ResetEbsDefaultKmsKeyIdResult:
        raise NotImplementedError

    @handler("ResetFpgaImageAttribute")
    def reset_fpga_image_attribute(
        self,
        context: RequestContext,
        fpga_image_id: FpgaImageId,
        dry_run: Boolean = None,
        attribute: ResetFpgaImageAttributeName = None,
        **kwargs,
    ) -> ResetFpgaImageAttributeResult:
        raise NotImplementedError

    @handler("ResetImageAttribute")
    def reset_image_attribute(
        self,
        context: RequestContext,
        attribute: ResetImageAttributeName,
        image_id: ImageId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ResetInstanceAttribute")
    def reset_instance_attribute(
        self,
        context: RequestContext,
        instance_id: InstanceId,
        attribute: InstanceAttributeName,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ResetNetworkInterfaceAttribute")
    def reset_network_interface_attribute(
        self,
        context: RequestContext,
        network_interface_id: NetworkInterfaceId,
        dry_run: Boolean = None,
        source_dest_check: String = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("ResetSnapshotAttribute")
    def reset_snapshot_attribute(
        self,
        context: RequestContext,
        attribute: SnapshotAttributeName,
        snapshot_id: SnapshotId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("RestoreAddressToClassic")
    def restore_address_to_classic(
        self, context: RequestContext, public_ip: String, dry_run: Boolean = None, **kwargs
    ) -> RestoreAddressToClassicResult:
        raise NotImplementedError

    @handler("RestoreImageFromRecycleBin")
    def restore_image_from_recycle_bin(
        self, context: RequestContext, image_id: ImageId, dry_run: Boolean = None, **kwargs
    ) -> RestoreImageFromRecycleBinResult:
        raise NotImplementedError

    @handler("RestoreManagedPrefixListVersion")
    def restore_managed_prefix_list_version(
        self,
        context: RequestContext,
        prefix_list_id: PrefixListResourceId,
        previous_version: Long,
        current_version: Long,
        dry_run: Boolean = None,
        **kwargs,
    ) -> RestoreManagedPrefixListVersionResult:
        raise NotImplementedError

    @handler("RestoreSnapshotFromRecycleBin")
    def restore_snapshot_from_recycle_bin(
        self, context: RequestContext, snapshot_id: SnapshotId, dry_run: Boolean = None, **kwargs
    ) -> RestoreSnapshotFromRecycleBinResult:
        raise NotImplementedError

    @handler("RestoreSnapshotTier")
    def restore_snapshot_tier(
        self,
        context: RequestContext,
        snapshot_id: SnapshotId,
        temporary_restore_days: RestoreSnapshotTierRequestTemporaryRestoreDays = None,
        permanent_restore: Boolean = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> RestoreSnapshotTierResult:
        raise NotImplementedError

    @handler("RevokeClientVpnIngress")
    def revoke_client_vpn_ingress(
        self,
        context: RequestContext,
        client_vpn_endpoint_id: ClientVpnEndpointId,
        target_network_cidr: String,
        access_group_id: String = None,
        revoke_all_groups: Boolean = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> RevokeClientVpnIngressResult:
        raise NotImplementedError

    @handler("RevokeSecurityGroupEgress")
    def revoke_security_group_egress(
        self,
        context: RequestContext,
        group_id: SecurityGroupId,
        security_group_rule_ids: SecurityGroupRuleIdList = None,
        dry_run: Boolean = None,
        source_security_group_name: String = None,
        source_security_group_owner_id: String = None,
        ip_protocol: String = None,
        from_port: Integer = None,
        to_port: Integer = None,
        cidr_ip: String = None,
        ip_permissions: IpPermissionList = None,
        **kwargs,
    ) -> RevokeSecurityGroupEgressResult:
        raise NotImplementedError

    @handler("RevokeSecurityGroupIngress")
    def revoke_security_group_ingress(
        self,
        context: RequestContext,
        cidr_ip: String = None,
        from_port: Integer = None,
        group_id: SecurityGroupId = None,
        group_name: SecurityGroupName = None,
        ip_permissions: IpPermissionList = None,
        ip_protocol: String = None,
        source_security_group_name: String = None,
        source_security_group_owner_id: String = None,
        to_port: Integer = None,
        security_group_rule_ids: SecurityGroupRuleIdList = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> RevokeSecurityGroupIngressResult:
        raise NotImplementedError

    @handler("RunInstances")
    def run_instances(
        self,
        context: RequestContext,
        max_count: Integer,
        min_count: Integer,
        block_device_mappings: BlockDeviceMappingRequestList = None,
        image_id: ImageId = None,
        instance_type: InstanceType = None,
        ipv6_address_count: Integer = None,
        ipv6_addresses: InstanceIpv6AddressList = None,
        kernel_id: KernelId = None,
        key_name: KeyPairName = None,
        monitoring: RunInstancesMonitoringEnabled = None,
        placement: Placement = None,
        ramdisk_id: RamdiskId = None,
        security_group_ids: SecurityGroupIdStringList = None,
        security_groups: SecurityGroupStringList = None,
        subnet_id: SubnetId = None,
        user_data: RunInstancesUserData = None,
        elastic_gpu_specification: ElasticGpuSpecifications = None,
        elastic_inference_accelerators: ElasticInferenceAccelerators = None,
        tag_specifications: TagSpecificationList = None,
        launch_template: LaunchTemplateSpecification = None,
        instance_market_options: InstanceMarketOptionsRequest = None,
        credit_specification: CreditSpecificationRequest = None,
        cpu_options: CpuOptionsRequest = None,
        capacity_reservation_specification: CapacityReservationSpecification = None,
        hibernation_options: HibernationOptionsRequest = None,
        license_specifications: LicenseSpecificationListRequest = None,
        metadata_options: InstanceMetadataOptionsRequest = None,
        enclave_options: EnclaveOptionsRequest = None,
        private_dns_name_options: PrivateDnsNameOptionsRequest = None,
        maintenance_options: InstanceMaintenanceOptionsRequest = None,
        disable_api_stop: Boolean = None,
        enable_primary_ipv6: Boolean = None,
        dry_run: Boolean = None,
        disable_api_termination: Boolean = None,
        instance_initiated_shutdown_behavior: ShutdownBehavior = None,
        private_ip_address: String = None,
        client_token: String = None,
        additional_info: String = None,
        network_interfaces: InstanceNetworkInterfaceSpecificationList = None,
        iam_instance_profile: IamInstanceProfileSpecification = None,
        ebs_optimized: Boolean = None,
        **kwargs,
    ) -> Reservation:
        raise NotImplementedError

    @handler("RunScheduledInstances")
    def run_scheduled_instances(
        self,
        context: RequestContext,
        launch_specification: ScheduledInstancesLaunchSpecification,
        scheduled_instance_id: ScheduledInstanceId,
        client_token: String = None,
        dry_run: Boolean = None,
        instance_count: Integer = None,
        **kwargs,
    ) -> RunScheduledInstancesResult:
        raise NotImplementedError

    @handler("SearchLocalGatewayRoutes")
    def search_local_gateway_routes(
        self,
        context: RequestContext,
        local_gateway_route_table_id: LocalGatewayRoutetableId,
        filters: FilterList = None,
        max_results: MaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> SearchLocalGatewayRoutesResult:
        raise NotImplementedError

    @handler("SearchTransitGatewayMulticastGroups")
    def search_transit_gateway_multicast_groups(
        self,
        context: RequestContext,
        transit_gateway_multicast_domain_id: TransitGatewayMulticastDomainId,
        filters: FilterList = None,
        max_results: TransitGatewayMaxResults = None,
        next_token: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> SearchTransitGatewayMulticastGroupsResult:
        raise NotImplementedError

    @handler("SearchTransitGatewayRoutes")
    def search_transit_gateway_routes(
        self,
        context: RequestContext,
        transit_gateway_route_table_id: TransitGatewayRouteTableId,
        filters: FilterList,
        max_results: TransitGatewayMaxResults = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> SearchTransitGatewayRoutesResult:
        raise NotImplementedError

    @handler("SendDiagnosticInterrupt")
    def send_diagnostic_interrupt(
        self, context: RequestContext, instance_id: InstanceId, dry_run: Boolean = None, **kwargs
    ) -> None:
        raise NotImplementedError

    @handler("StartInstances")
    def start_instances(
        self,
        context: RequestContext,
        instance_ids: InstanceIdStringList,
        additional_info: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> StartInstancesResult:
        raise NotImplementedError

    @handler("StartNetworkInsightsAccessScopeAnalysis")
    def start_network_insights_access_scope_analysis(
        self,
        context: RequestContext,
        network_insights_access_scope_id: NetworkInsightsAccessScopeId,
        client_token: String,
        dry_run: Boolean = None,
        tag_specifications: TagSpecificationList = None,
        **kwargs,
    ) -> StartNetworkInsightsAccessScopeAnalysisResult:
        raise NotImplementedError

    @handler("StartNetworkInsightsAnalysis")
    def start_network_insights_analysis(
        self,
        context: RequestContext,
        network_insights_path_id: NetworkInsightsPathId,
        client_token: String,
        additional_accounts: ValueStringList = None,
        filter_in_arns: ArnList = None,
        dry_run: Boolean = None,
        tag_specifications: TagSpecificationList = None,
        **kwargs,
    ) -> StartNetworkInsightsAnalysisResult:
        raise NotImplementedError

    @handler("StartVpcEndpointServicePrivateDnsVerification")
    def start_vpc_endpoint_service_private_dns_verification(
        self,
        context: RequestContext,
        service_id: VpcEndpointServiceId,
        dry_run: Boolean = None,
        **kwargs,
    ) -> StartVpcEndpointServicePrivateDnsVerificationResult:
        raise NotImplementedError

    @handler("StopInstances")
    def stop_instances(
        self,
        context: RequestContext,
        instance_ids: InstanceIdStringList,
        hibernate: Boolean = None,
        dry_run: Boolean = None,
        force: Boolean = None,
        **kwargs,
    ) -> StopInstancesResult:
        raise NotImplementedError

    @handler("TerminateClientVpnConnections")
    def terminate_client_vpn_connections(
        self,
        context: RequestContext,
        client_vpn_endpoint_id: ClientVpnEndpointId,
        connection_id: String = None,
        username: String = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> TerminateClientVpnConnectionsResult:
        raise NotImplementedError

    @handler("TerminateInstances")
    def terminate_instances(
        self,
        context: RequestContext,
        instance_ids: InstanceIdStringList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> TerminateInstancesResult:
        raise NotImplementedError

    @handler("UnassignIpv6Addresses")
    def unassign_ipv6_addresses(
        self,
        context: RequestContext,
        network_interface_id: NetworkInterfaceId,
        ipv6_prefixes: IpPrefixList = None,
        ipv6_addresses: Ipv6AddressList = None,
        **kwargs,
    ) -> UnassignIpv6AddressesResult:
        raise NotImplementedError

    @handler("UnassignPrivateIpAddresses")
    def unassign_private_ip_addresses(
        self,
        context: RequestContext,
        network_interface_id: NetworkInterfaceId,
        ipv4_prefixes: IpPrefixList = None,
        private_ip_addresses: PrivateIpAddressStringList = None,
        **kwargs,
    ) -> None:
        raise NotImplementedError

    @handler("UnassignPrivateNatGatewayAddress")
    def unassign_private_nat_gateway_address(
        self,
        context: RequestContext,
        nat_gateway_id: NatGatewayId,
        private_ip_addresses: IpList,
        max_drain_duration_seconds: DrainSeconds = None,
        dry_run: Boolean = None,
        **kwargs,
    ) -> UnassignPrivateNatGatewayAddressResult:
        raise NotImplementedError

    @handler("UnlockSnapshot")
    def unlock_snapshot(
        self, context: RequestContext, snapshot_id: SnapshotId, dry_run: Boolean = None, **kwargs
    ) -> UnlockSnapshotResult:
        raise NotImplementedError

    @handler("UnmonitorInstances")
    def unmonitor_instances(
        self,
        context: RequestContext,
        instance_ids: InstanceIdStringList,
        dry_run: Boolean = None,
        **kwargs,
    ) -> UnmonitorInstancesResult:
        raise NotImplementedError

    @handler("UpdateSecurityGroupRuleDescriptionsEgress")
    def update_security_group_rule_descriptions_egress(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        group_id: SecurityGroupId = None,
        group_name: SecurityGroupName = None,
        ip_permissions: IpPermissionList = None,
        security_group_rule_descriptions: SecurityGroupRuleDescriptionList = None,
        **kwargs,
    ) -> UpdateSecurityGroupRuleDescriptionsEgressResult:
        raise NotImplementedError

    @handler("UpdateSecurityGroupRuleDescriptionsIngress")
    def update_security_group_rule_descriptions_ingress(
        self,
        context: RequestContext,
        dry_run: Boolean = None,
        group_id: SecurityGroupId = None,
        group_name: SecurityGroupName = None,
        ip_permissions: IpPermissionList = None,
        security_group_rule_descriptions: SecurityGroupRuleDescriptionList = None,
        **kwargs,
    ) -> UpdateSecurityGroupRuleDescriptionsIngressResult:
        raise NotImplementedError

    @handler("WithdrawByoipCidr")
    def withdraw_byoip_cidr(
        self, context: RequestContext, cidr: String, dry_run: Boolean = None, **kwargs
    ) -> WithdrawByoipCidrResult:
        raise NotImplementedError

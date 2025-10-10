from datetime import datetime
from enum import StrEnum
from typing import IO, Dict, Iterable, Iterator, List, Optional, TypedDict, Union

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AWSRegion = str
AnyArn = str
Boolean = bool
BucketArn = str
CapabilityArn = str
ComponentTypeString = str
ConfigArn = str
CustomerEphemerisPriority = int
DataflowEndpointGroupArn = str
DataflowEndpointGroupDurationInSeconds = int
DataflowEndpointMtuInteger = int
Double = float
DurationInSeconds = int
EphemerisPriority = int
GroundStationName = str
InstanceId = str
InstanceType = str
Integer = int
IpV4Address = str
JsonString = str
KeyAliasArn = str
KeyAliasName = str
KeyArn = str
MissionProfileArn = str
Month = int
PaginationMaxResults = int
PaginationToken = str
PositiveDurationInSeconds = int
RangedConnectionDetailsMtuInteger = int
RoleArn = str
S3BucketName = str
S3KeyPrefix = str
S3ObjectKey = str
S3VersionId = str
SafeName = str
String = str
TleLineOne = str
TleLineTwo = str
UnboundedString = str
Uuid = str
VersionString = str
Year = int
noradSatelliteID = int
satelliteArn = str


class AgentStatus(StrEnum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class AngleUnits(StrEnum):
    DEGREE_ANGLE = "DEGREE_ANGLE"
    RADIAN = "RADIAN"


class AuditResults(StrEnum):
    HEALTHY = "HEALTHY"
    UNHEALTHY = "UNHEALTHY"


class BandwidthUnits(StrEnum):
    GHz = "GHz"
    MHz = "MHz"
    kHz = "kHz"


class CapabilityHealth(StrEnum):
    HEALTHY = "HEALTHY"
    UNHEALTHY = "UNHEALTHY"


class CapabilityHealthReason(StrEnum):
    NO_REGISTERED_AGENT = "NO_REGISTERED_AGENT"
    INVALID_IP_OWNERSHIP = "INVALID_IP_OWNERSHIP"
    NOT_AUTHORIZED_TO_CREATE_SLR = "NOT_AUTHORIZED_TO_CREATE_SLR"
    UNVERIFIED_IP_OWNERSHIP = "UNVERIFIED_IP_OWNERSHIP"
    INITIALIZING_DATAPLANE = "INITIALIZING_DATAPLANE"
    DATAPLANE_FAILURE = "DATAPLANE_FAILURE"
    HEALTHY = "HEALTHY"


class ConfigCapabilityType(StrEnum):
    antenna_downlink = "antenna-downlink"
    antenna_downlink_demod_decode = "antenna-downlink-demod-decode"
    tracking = "tracking"
    dataflow_endpoint = "dataflow-endpoint"
    antenna_uplink = "antenna-uplink"
    uplink_echo = "uplink-echo"
    s3_recording = "s3-recording"


class ContactStatus(StrEnum):
    SCHEDULING = "SCHEDULING"
    FAILED_TO_SCHEDULE = "FAILED_TO_SCHEDULE"
    SCHEDULED = "SCHEDULED"
    CANCELLED = "CANCELLED"
    AWS_CANCELLED = "AWS_CANCELLED"
    PREPASS = "PREPASS"
    PASS = "PASS"
    POSTPASS = "POSTPASS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    AVAILABLE = "AVAILABLE"
    CANCELLING = "CANCELLING"
    AWS_FAILED = "AWS_FAILED"


class Criticality(StrEnum):
    REQUIRED = "REQUIRED"
    PREFERRED = "PREFERRED"
    REMOVED = "REMOVED"


class EirpUnits(StrEnum):
    dBW = "dBW"


class EndpointStatus(StrEnum):
    created = "created"
    creating = "creating"
    deleted = "deleted"
    deleting = "deleting"
    failed = "failed"


class EphemerisInvalidReason(StrEnum):
    METADATA_INVALID = "METADATA_INVALID"
    TIME_RANGE_INVALID = "TIME_RANGE_INVALID"
    TRAJECTORY_INVALID = "TRAJECTORY_INVALID"
    KMS_KEY_INVALID = "KMS_KEY_INVALID"
    VALIDATION_ERROR = "VALIDATION_ERROR"


class EphemerisSource(StrEnum):
    CUSTOMER_PROVIDED = "CUSTOMER_PROVIDED"
    SPACE_TRACK = "SPACE_TRACK"


class EphemerisStatus(StrEnum):
    VALIDATING = "VALIDATING"
    INVALID = "INVALID"
    ERROR = "ERROR"
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    EXPIRED = "EXPIRED"


class FrequencyUnits(StrEnum):
    GHz = "GHz"
    MHz = "MHz"
    kHz = "kHz"


class Polarization(StrEnum):
    RIGHT_HAND = "RIGHT_HAND"
    LEFT_HAND = "LEFT_HAND"
    NONE = "NONE"


class DependencyException(ServiceException):
    code: str = "DependencyException"
    sender_fault: bool = False
    status_code: int = 531
    parameterName: Optional[String]


class InvalidParameterException(ServiceException):
    code: str = "InvalidParameterException"
    sender_fault: bool = True
    status_code: int = 431
    parameterName: Optional[String]


class ResourceLimitExceededException(ServiceException):
    code: str = "ResourceLimitExceededException"
    sender_fault: bool = True
    status_code: int = 429
    parameterName: Optional[String]


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = True
    status_code: int = 434


AgentCpuCoresList = List[Integer]
VersionStringList = List[VersionString]


class ComponentVersion(TypedDict, total=False):
    componentType: ComponentTypeString
    versions: VersionStringList


ComponentVersionList = List[ComponentVersion]


class AgentDetails(TypedDict, total=False):
    agentCpuCores: Optional[AgentCpuCoresList]
    agentVersion: VersionString
    componentVersions: ComponentVersionList
    instanceId: InstanceId
    instanceType: InstanceType
    reservedCpuCores: Optional[AgentCpuCoresList]


SignatureMap = Dict[String, Boolean]


class AggregateStatus(TypedDict, total=False):
    signatureMap: Optional[SignatureMap]
    status: AgentStatus


class AntennaDemodDecodeDetails(TypedDict, total=False):
    outputNode: Optional[String]


class Frequency(TypedDict, total=False):
    units: FrequencyUnits
    value: Double


class FrequencyBandwidth(TypedDict, total=False):
    units: BandwidthUnits
    value: Double


class SpectrumConfig(TypedDict, total=False):
    bandwidth: FrequencyBandwidth
    centerFrequency: Frequency
    polarization: Optional[Polarization]


class AntennaDownlinkConfig(TypedDict, total=False):
    spectrumConfig: SpectrumConfig


class DemodulationConfig(TypedDict, total=False):
    unvalidatedJSON: JsonString


class DecodeConfig(TypedDict, total=False):
    unvalidatedJSON: JsonString


class AntennaDownlinkDemodDecodeConfig(TypedDict, total=False):
    decodeConfig: DecodeConfig
    demodulationConfig: DemodulationConfig
    spectrumConfig: SpectrumConfig


class Eirp(TypedDict, total=False):
    units: EirpUnits
    value: Double


class UplinkSpectrumConfig(TypedDict, total=False):
    centerFrequency: Frequency
    polarization: Optional[Polarization]


class AntennaUplinkConfig(TypedDict, total=False):
    spectrumConfig: UplinkSpectrumConfig
    targetEirp: Eirp
    transmitDisabled: Optional[Boolean]


class IntegerRange(TypedDict, total=False):
    maximum: Integer
    minimum: Integer


class RangedSocketAddress(TypedDict, total=False):
    name: IpV4Address
    portRange: IntegerRange


class RangedConnectionDetails(TypedDict, total=False):
    mtu: Optional[RangedConnectionDetailsMtuInteger]
    socketAddress: RangedSocketAddress


class SocketAddress(TypedDict, total=False):
    name: String
    port: Integer


class ConnectionDetails(TypedDict, total=False):
    mtu: Optional[Integer]
    socketAddress: SocketAddress


class AwsGroundStationAgentEndpoint(TypedDict, total=False):
    agentStatus: Optional[AgentStatus]
    auditResults: Optional[AuditResults]
    egressAddress: ConnectionDetails
    ingressAddress: RangedConnectionDetails
    name: SafeName


class CancelContactRequest(ServiceRequest):
    contactId: Uuid


CapabilityArnList = List[CapabilityArn]
CapabilityHealthReasonList = List[CapabilityHealthReason]
Long = int


class ComponentStatusData(TypedDict, total=False):
    bytesReceived: Optional[Long]
    bytesSent: Optional[Long]
    capabilityArn: CapabilityArn
    componentType: ComponentTypeString
    dataflowId: Uuid
    packetsDropped: Optional[Long]
    status: AgentStatus


ComponentStatusList = List[ComponentStatusData]


class S3RecordingDetails(TypedDict, total=False):
    bucketArn: Optional[BucketArn]
    keyTemplate: Optional[String]


SubnetList = List[String]
SecurityGroupIdList = List[String]


class SecurityDetails(TypedDict, total=False):
    roleArn: RoleArn
    securityGroupIds: SecurityGroupIdList
    subnetIds: SubnetList


class DataflowEndpoint(TypedDict, total=False):
    address: Optional[SocketAddress]
    mtu: Optional[DataflowEndpointMtuInteger]
    name: Optional[SafeName]
    status: Optional[EndpointStatus]


class EndpointDetails(TypedDict, total=False):
    awsGroundStationAgentEndpoint: Optional[AwsGroundStationAgentEndpoint]
    endpoint: Optional[DataflowEndpoint]
    healthReasons: Optional[CapabilityHealthReasonList]
    healthStatus: Optional[CapabilityHealth]
    securityDetails: Optional[SecurityDetails]


class ConfigDetails(TypedDict, total=False):
    antennaDemodDecodeDetails: Optional[AntennaDemodDecodeDetails]
    endpointDetails: Optional[EndpointDetails]
    s3RecordingDetails: Optional[S3RecordingDetails]


class ConfigIdResponse(TypedDict, total=False):
    configArn: Optional[ConfigArn]
    configId: Optional[String]
    configType: Optional[ConfigCapabilityType]


class ConfigListItem(TypedDict, total=False):
    configArn: Optional[ConfigArn]
    configId: Optional[String]
    configType: Optional[ConfigCapabilityType]
    name: Optional[String]


ConfigList = List[ConfigListItem]


class UplinkEchoConfig(TypedDict, total=False):
    antennaUplinkConfigArn: ConfigArn
    enabled: Boolean


class TrackingConfig(TypedDict, total=False):
    autotrack: Criticality


class S3RecordingConfig(TypedDict, total=False):
    bucketArn: BucketArn
    prefix: Optional[S3KeyPrefix]
    roleArn: RoleArn


class DataflowEndpointConfig(TypedDict, total=False):
    dataflowEndpointName: String
    dataflowEndpointRegion: Optional[String]


class ConfigTypeData(TypedDict, total=False):
    antennaDownlinkConfig: Optional[AntennaDownlinkConfig]
    antennaDownlinkDemodDecodeConfig: Optional[AntennaDownlinkDemodDecodeConfig]
    antennaUplinkConfig: Optional[AntennaUplinkConfig]
    dataflowEndpointConfig: Optional[DataflowEndpointConfig]
    s3RecordingConfig: Optional[S3RecordingConfig]
    trackingConfig: Optional[TrackingConfig]
    uplinkEchoConfig: Optional[UplinkEchoConfig]


Timestamp = datetime
TagsMap = Dict[String, String]


class Elevation(TypedDict, total=False):
    unit: AngleUnits
    value: Double


class ContactData(TypedDict, total=False):
    contactId: Optional[Uuid]
    contactStatus: Optional[ContactStatus]
    endTime: Optional[Timestamp]
    errorMessage: Optional[String]
    groundStation: Optional[String]
    maximumElevation: Optional[Elevation]
    missionProfileArn: Optional[MissionProfileArn]
    postPassEndTime: Optional[Timestamp]
    prePassStartTime: Optional[Timestamp]
    region: Optional[String]
    satelliteArn: Optional[satelliteArn]
    startTime: Optional[Timestamp]
    tags: Optional[TagsMap]
    visibilityEndTime: Optional[Timestamp]
    visibilityStartTime: Optional[Timestamp]


class ContactIdResponse(TypedDict, total=False):
    contactId: Optional[Uuid]


ContactList = List[ContactData]


class CreateConfigRequest(ServiceRequest):
    configData: ConfigTypeData
    name: SafeName
    tags: Optional[TagsMap]


EndpointDetailsList = List[EndpointDetails]


class CreateDataflowEndpointGroupRequest(ServiceRequest):
    contactPostPassDurationSeconds: Optional[DataflowEndpointGroupDurationInSeconds]
    contactPrePassDurationSeconds: Optional[DataflowEndpointGroupDurationInSeconds]
    endpointDetails: EndpointDetailsList
    tags: Optional[TagsMap]


class TimeRange(TypedDict, total=False):
    endTime: Timestamp
    startTime: Timestamp


class TLEData(TypedDict, total=False):
    tleLine1: TleLineOne
    tleLine2: TleLineTwo
    validTimeRange: TimeRange


TLEDataList = List[TLEData]


class S3Object(TypedDict, total=False):
    bucket: Optional[S3BucketName]
    key: Optional[S3ObjectKey]
    version: Optional[S3VersionId]


class TLEEphemeris(TypedDict, total=False):
    s3Object: Optional[S3Object]
    tleData: Optional[TLEDataList]


class OEMEphemeris(TypedDict, total=False):
    oemData: Optional[UnboundedString]
    s3Object: Optional[S3Object]


class EphemerisData(TypedDict, total=False):
    oem: Optional[OEMEphemeris]
    tle: Optional[TLEEphemeris]


class CreateEphemerisRequest(ServiceRequest):
    enabled: Optional[Boolean]
    ephemeris: Optional[EphemerisData]
    expirationTime: Optional[Timestamp]
    kmsKeyArn: Optional[KeyArn]
    name: SafeName
    priority: Optional[CustomerEphemerisPriority]
    satelliteId: Uuid
    tags: Optional[TagsMap]


class KmsKey(TypedDict, total=False):
    kmsAliasArn: Optional[KeyAliasArn]
    kmsAliasName: Optional[KeyAliasName]
    kmsKeyArn: Optional[KeyArn]


DataflowEdge = List[ConfigArn]
DataflowEdgeList = List[DataflowEdge]


class CreateMissionProfileRequest(ServiceRequest):
    contactPostPassDurationSeconds: Optional[DurationInSeconds]
    contactPrePassDurationSeconds: Optional[DurationInSeconds]
    dataflowEdges: DataflowEdgeList
    minimumViableContactDurationSeconds: PositiveDurationInSeconds
    name: SafeName
    streamsKmsKey: Optional[KmsKey]
    streamsKmsRole: Optional[RoleArn]
    tags: Optional[TagsMap]
    trackingConfigArn: ConfigArn


class Source(TypedDict, total=False):
    configDetails: Optional[ConfigDetails]
    configId: Optional[String]
    configType: Optional[ConfigCapabilityType]
    dataflowSourceRegion: Optional[String]


class Destination(TypedDict, total=False):
    configDetails: Optional[ConfigDetails]
    configId: Optional[Uuid]
    configType: Optional[ConfigCapabilityType]
    dataflowDestinationRegion: Optional[String]


class DataflowDetail(TypedDict, total=False):
    destination: Optional[Destination]
    errorMessage: Optional[String]
    source: Optional[Source]


class DataflowEndpointGroupIdResponse(TypedDict, total=False):
    dataflowEndpointGroupId: Optional[Uuid]


class DataflowEndpointListItem(TypedDict, total=False):
    dataflowEndpointGroupArn: Optional[DataflowEndpointGroupArn]
    dataflowEndpointGroupId: Optional[Uuid]


DataflowEndpointGroupList = List[DataflowEndpointListItem]
DataflowList = List[DataflowDetail]


class DeleteConfigRequest(ServiceRequest):
    configId: Uuid
    configType: ConfigCapabilityType


class DeleteDataflowEndpointGroupRequest(ServiceRequest):
    dataflowEndpointGroupId: Uuid


class DeleteEphemerisRequest(ServiceRequest):
    ephemerisId: Uuid


class DeleteMissionProfileRequest(ServiceRequest):
    missionProfileId: Uuid


class DescribeContactRequest(ServiceRequest):
    contactId: Uuid


class DescribeContactResponse(TypedDict, total=False):
    contactId: Optional[Uuid]
    contactStatus: Optional[ContactStatus]
    dataflowList: Optional[DataflowList]
    endTime: Optional[Timestamp]
    errorMessage: Optional[String]
    groundStation: Optional[String]
    maximumElevation: Optional[Elevation]
    missionProfileArn: Optional[MissionProfileArn]
    postPassEndTime: Optional[Timestamp]
    prePassStartTime: Optional[Timestamp]
    region: Optional[String]
    satelliteArn: Optional[satelliteArn]
    startTime: Optional[Timestamp]
    tags: Optional[TagsMap]
    visibilityEndTime: Optional[Timestamp]
    visibilityStartTime: Optional[Timestamp]


class DescribeEphemerisRequest(ServiceRequest):
    ephemerisId: Uuid


class EphemerisDescription(TypedDict, total=False):
    ephemerisData: Optional[UnboundedString]
    sourceS3Object: Optional[S3Object]


class EphemerisTypeDescription(TypedDict, total=False):
    oem: Optional[EphemerisDescription]
    tle: Optional[EphemerisDescription]


class DescribeEphemerisResponse(TypedDict, total=False):
    creationTime: Optional[Timestamp]
    enabled: Optional[Boolean]
    ephemerisId: Optional[Uuid]
    invalidReason: Optional[EphemerisInvalidReason]
    name: Optional[SafeName]
    priority: Optional[EphemerisPriority]
    satelliteId: Optional[Uuid]
    status: Optional[EphemerisStatus]
    suppliedData: Optional[EphemerisTypeDescription]
    tags: Optional[TagsMap]


IpAddressList = List[IpV4Address]


class DiscoveryData(TypedDict, total=False):
    capabilityArns: CapabilityArnList
    privateIpAddresses: IpAddressList
    publicIpAddresses: IpAddressList


class EphemerisItem(TypedDict, total=False):
    creationTime: Optional[Timestamp]
    enabled: Optional[Boolean]
    ephemerisId: Optional[Uuid]
    name: Optional[SafeName]
    priority: Optional[EphemerisPriority]
    sourceS3Object: Optional[S3Object]
    status: Optional[EphemerisStatus]


EphemeridesList = List[EphemerisItem]


class EphemerisIdResponse(TypedDict, total=False):
    ephemerisId: Optional[Uuid]


class EphemerisMetaData(TypedDict, total=False):
    ephemerisId: Optional[Uuid]
    epoch: Optional[Timestamp]
    name: Optional[SafeName]
    source: EphemerisSource


EphemerisStatusList = List[EphemerisStatus]


class GetAgentConfigurationRequest(ServiceRequest):
    agentId: Uuid


class GetAgentConfigurationResponse(TypedDict, total=False):
    agentId: Optional[Uuid]
    taskingDocument: Optional[String]


class GetConfigRequest(ServiceRequest):
    configId: Uuid
    configType: ConfigCapabilityType


class GetConfigResponse(TypedDict, total=False):
    configArn: ConfigArn
    configData: ConfigTypeData
    configId: String
    configType: Optional[ConfigCapabilityType]
    name: String
    tags: Optional[TagsMap]


class GetDataflowEndpointGroupRequest(ServiceRequest):
    dataflowEndpointGroupId: Uuid


class GetDataflowEndpointGroupResponse(TypedDict, total=False):
    contactPostPassDurationSeconds: Optional[DataflowEndpointGroupDurationInSeconds]
    contactPrePassDurationSeconds: Optional[DataflowEndpointGroupDurationInSeconds]
    dataflowEndpointGroupArn: Optional[DataflowEndpointGroupArn]
    dataflowEndpointGroupId: Optional[Uuid]
    endpointsDetails: Optional[EndpointDetailsList]
    tags: Optional[TagsMap]


class GetMinuteUsageRequest(ServiceRequest):
    month: Month
    year: Year


class GetMinuteUsageResponse(TypedDict, total=False):
    estimatedMinutesRemaining: Optional[Integer]
    isReservedMinutesCustomer: Optional[Boolean]
    totalReservedMinuteAllocation: Optional[Integer]
    totalScheduledMinutes: Optional[Integer]
    upcomingMinutesScheduled: Optional[Integer]


class GetMissionProfileRequest(ServiceRequest):
    missionProfileId: Uuid


class GetMissionProfileResponse(TypedDict, total=False):
    contactPostPassDurationSeconds: Optional[DurationInSeconds]
    contactPrePassDurationSeconds: Optional[DurationInSeconds]
    dataflowEdges: Optional[DataflowEdgeList]
    minimumViableContactDurationSeconds: Optional[PositiveDurationInSeconds]
    missionProfileArn: Optional[MissionProfileArn]
    missionProfileId: Optional[Uuid]
    name: Optional[SafeName]
    region: Optional[AWSRegion]
    streamsKmsKey: Optional[KmsKey]
    streamsKmsRole: Optional[RoleArn]
    tags: Optional[TagsMap]
    trackingConfigArn: Optional[ConfigArn]


class GetSatelliteRequest(ServiceRequest):
    satelliteId: Uuid


GroundStationIdList = List[GroundStationName]


class GetSatelliteResponse(TypedDict, total=False):
    currentEphemeris: Optional[EphemerisMetaData]
    groundStations: Optional[GroundStationIdList]
    noradSatelliteID: Optional[noradSatelliteID]
    satelliteArn: Optional[satelliteArn]
    satelliteId: Optional[Uuid]


class GroundStationData(TypedDict, total=False):
    groundStationId: Optional[GroundStationName]
    groundStationName: Optional[GroundStationName]
    region: Optional[AWSRegion]


GroundStationList = List[GroundStationData]


class ListConfigsRequest(ServiceRequest):
    maxResults: Optional[PaginationMaxResults]
    nextToken: Optional[PaginationToken]


class ListConfigsResponse(TypedDict, total=False):
    configList: Optional[ConfigList]
    nextToken: Optional[PaginationToken]


StatusList = List[ContactStatus]


class ListContactsRequest(ServiceRequest):
    endTime: Timestamp
    groundStation: Optional[GroundStationName]
    maxResults: Optional[PaginationMaxResults]
    missionProfileArn: Optional[MissionProfileArn]
    nextToken: Optional[PaginationToken]
    satelliteArn: Optional[satelliteArn]
    startTime: Timestamp
    statusList: StatusList


class ListContactsResponse(TypedDict, total=False):
    contactList: Optional[ContactList]
    nextToken: Optional[PaginationToken]


class ListDataflowEndpointGroupsRequest(ServiceRequest):
    maxResults: Optional[PaginationMaxResults]
    nextToken: Optional[PaginationToken]


class ListDataflowEndpointGroupsResponse(TypedDict, total=False):
    dataflowEndpointGroupList: Optional[DataflowEndpointGroupList]
    nextToken: Optional[PaginationToken]


class ListEphemeridesRequest(ServiceRequest):
    endTime: Timestamp
    maxResults: Optional[PaginationMaxResults]
    nextToken: Optional[PaginationToken]
    satelliteId: Uuid
    startTime: Timestamp
    statusList: Optional[EphemerisStatusList]


class ListEphemeridesResponse(TypedDict, total=False):
    ephemerides: Optional[EphemeridesList]
    nextToken: Optional[PaginationToken]


class ListGroundStationsRequest(ServiceRequest):
    maxResults: Optional[PaginationMaxResults]
    nextToken: Optional[PaginationToken]
    satelliteId: Optional[Uuid]


class ListGroundStationsResponse(TypedDict, total=False):
    groundStationList: Optional[GroundStationList]
    nextToken: Optional[PaginationToken]


class ListMissionProfilesRequest(ServiceRequest):
    maxResults: Optional[PaginationMaxResults]
    nextToken: Optional[PaginationToken]


class MissionProfileListItem(TypedDict, total=False):
    missionProfileArn: Optional[MissionProfileArn]
    missionProfileId: Optional[Uuid]
    name: Optional[SafeName]
    region: Optional[AWSRegion]


MissionProfileList = List[MissionProfileListItem]


class ListMissionProfilesResponse(TypedDict, total=False):
    missionProfileList: Optional[MissionProfileList]
    nextToken: Optional[PaginationToken]


class ListSatellitesRequest(ServiceRequest):
    maxResults: Optional[PaginationMaxResults]
    nextToken: Optional[PaginationToken]


class SatelliteListItem(TypedDict, total=False):
    currentEphemeris: Optional[EphemerisMetaData]
    groundStations: Optional[GroundStationIdList]
    noradSatelliteID: Optional[noradSatelliteID]
    satelliteArn: Optional[satelliteArn]
    satelliteId: Optional[Uuid]


SatelliteList = List[SatelliteListItem]


class ListSatellitesResponse(TypedDict, total=False):
    nextToken: Optional[PaginationToken]
    satellites: Optional[SatelliteList]


class ListTagsForResourceRequest(ServiceRequest):
    resourceArn: AnyArn


class ListTagsForResourceResponse(TypedDict, total=False):
    tags: Optional[TagsMap]


class MissionProfileIdResponse(TypedDict, total=False):
    missionProfileId: Optional[Uuid]


class RegisterAgentRequest(ServiceRequest):
    agentDetails: AgentDetails
    discoveryData: DiscoveryData
    tags: Optional[TagsMap]


class RegisterAgentResponse(TypedDict, total=False):
    agentId: Optional[Uuid]


class ReserveContactRequest(ServiceRequest):
    endTime: Timestamp
    groundStation: GroundStationName
    missionProfileArn: MissionProfileArn
    satelliteArn: satelliteArn
    startTime: Timestamp
    tags: Optional[TagsMap]


TagKeys = List[UnboundedString]


class TagResourceRequest(ServiceRequest):
    resourceArn: AnyArn
    tags: TagsMap


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    resourceArn: AnyArn
    tagKeys: TagKeys


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateAgentStatusRequest(ServiceRequest):
    agentId: Uuid
    aggregateStatus: AggregateStatus
    componentStatuses: ComponentStatusList
    taskId: Uuid


class UpdateAgentStatusResponse(TypedDict, total=False):
    agentId: Uuid


class UpdateConfigRequest(ServiceRequest):
    configData: ConfigTypeData
    configId: Uuid
    configType: ConfigCapabilityType
    name: SafeName


class UpdateEphemerisRequest(ServiceRequest):
    enabled: Boolean
    ephemerisId: Uuid
    name: Optional[SafeName]
    priority: Optional[EphemerisPriority]


class UpdateMissionProfileRequest(ServiceRequest):
    contactPostPassDurationSeconds: Optional[DurationInSeconds]
    contactPrePassDurationSeconds: Optional[DurationInSeconds]
    dataflowEdges: Optional[DataflowEdgeList]
    minimumViableContactDurationSeconds: Optional[PositiveDurationInSeconds]
    missionProfileId: Uuid
    name: Optional[SafeName]
    streamsKmsKey: Optional[KmsKey]
    streamsKmsRole: Optional[RoleArn]
    trackingConfigArn: Optional[ConfigArn]


class GroundstationApi:
    service = "groundstation"
    version = "2019-05-23"

    @handler("CancelContact")
    def cancel_contact(
        self, context: RequestContext, contact_id: Uuid, **kwargs
    ) -> ContactIdResponse:
        raise NotImplementedError

    @handler("CreateConfig")
    def create_config(
        self,
        context: RequestContext,
        config_data: ConfigTypeData,
        name: SafeName,
        tags: TagsMap | None = None,
        **kwargs,
    ) -> ConfigIdResponse:
        raise NotImplementedError

    @handler("CreateDataflowEndpointGroup")
    def create_dataflow_endpoint_group(
        self,
        context: RequestContext,
        endpoint_details: EndpointDetailsList,
        contact_post_pass_duration_seconds: DataflowEndpointGroupDurationInSeconds | None = None,
        contact_pre_pass_duration_seconds: DataflowEndpointGroupDurationInSeconds | None = None,
        tags: TagsMap | None = None,
        **kwargs,
    ) -> DataflowEndpointGroupIdResponse:
        raise NotImplementedError

    @handler("CreateEphemeris")
    def create_ephemeris(
        self,
        context: RequestContext,
        name: SafeName,
        satellite_id: Uuid,
        enabled: Boolean | None = None,
        ephemeris: EphemerisData | None = None,
        expiration_time: Timestamp | None = None,
        kms_key_arn: KeyArn | None = None,
        priority: CustomerEphemerisPriority | None = None,
        tags: TagsMap | None = None,
        **kwargs,
    ) -> EphemerisIdResponse:
        raise NotImplementedError

    @handler("CreateMissionProfile")
    def create_mission_profile(
        self,
        context: RequestContext,
        dataflow_edges: DataflowEdgeList,
        minimum_viable_contact_duration_seconds: PositiveDurationInSeconds,
        name: SafeName,
        tracking_config_arn: ConfigArn,
        contact_post_pass_duration_seconds: DurationInSeconds | None = None,
        contact_pre_pass_duration_seconds: DurationInSeconds | None = None,
        streams_kms_key: KmsKey | None = None,
        streams_kms_role: RoleArn | None = None,
        tags: TagsMap | None = None,
        **kwargs,
    ) -> MissionProfileIdResponse:
        raise NotImplementedError

    @handler("DeleteConfig")
    def delete_config(
        self, context: RequestContext, config_id: Uuid, config_type: ConfigCapabilityType, **kwargs
    ) -> ConfigIdResponse:
        raise NotImplementedError

    @handler("DeleteDataflowEndpointGroup")
    def delete_dataflow_endpoint_group(
        self, context: RequestContext, dataflow_endpoint_group_id: Uuid, **kwargs
    ) -> DataflowEndpointGroupIdResponse:
        raise NotImplementedError

    @handler("DeleteEphemeris")
    def delete_ephemeris(
        self, context: RequestContext, ephemeris_id: Uuid, **kwargs
    ) -> EphemerisIdResponse:
        raise NotImplementedError

    @handler("DeleteMissionProfile")
    def delete_mission_profile(
        self, context: RequestContext, mission_profile_id: Uuid, **kwargs
    ) -> MissionProfileIdResponse:
        raise NotImplementedError

    @handler("DescribeContact")
    def describe_contact(
        self, context: RequestContext, contact_id: Uuid, **kwargs
    ) -> DescribeContactResponse:
        raise NotImplementedError

    @handler("DescribeEphemeris")
    def describe_ephemeris(
        self, context: RequestContext, ephemeris_id: Uuid, **kwargs
    ) -> DescribeEphemerisResponse:
        raise NotImplementedError

    @handler("GetAgentConfiguration")
    def get_agent_configuration(
        self, context: RequestContext, agent_id: Uuid, **kwargs
    ) -> GetAgentConfigurationResponse:
        raise NotImplementedError

    @handler("GetConfig")
    def get_config(
        self, context: RequestContext, config_id: Uuid, config_type: ConfigCapabilityType, **kwargs
    ) -> GetConfigResponse:
        raise NotImplementedError

    @handler("GetDataflowEndpointGroup")
    def get_dataflow_endpoint_group(
        self, context: RequestContext, dataflow_endpoint_group_id: Uuid, **kwargs
    ) -> GetDataflowEndpointGroupResponse:
        raise NotImplementedError

    @handler("GetMinuteUsage")
    def get_minute_usage(
        self, context: RequestContext, month: Month, year: Year, **kwargs
    ) -> GetMinuteUsageResponse:
        raise NotImplementedError

    @handler("GetMissionProfile")
    def get_mission_profile(
        self, context: RequestContext, mission_profile_id: Uuid, **kwargs
    ) -> GetMissionProfileResponse:
        raise NotImplementedError

    @handler("GetSatellite")
    def get_satellite(
        self, context: RequestContext, satellite_id: Uuid, **kwargs
    ) -> GetSatelliteResponse:
        raise NotImplementedError

    @handler("ListConfigs")
    def list_configs(
        self,
        context: RequestContext,
        max_results: PaginationMaxResults | None = None,
        next_token: PaginationToken | None = None,
        **kwargs,
    ) -> ListConfigsResponse:
        raise NotImplementedError

    @handler("ListContacts")
    def list_contacts(
        self,
        context: RequestContext,
        end_time: Timestamp,
        start_time: Timestamp,
        status_list: StatusList,
        ground_station: GroundStationName | None = None,
        max_results: PaginationMaxResults | None = None,
        mission_profile_arn: MissionProfileArn | None = None,
        next_token: PaginationToken | None = None,
        satellite_arn: satelliteArn | None = None,
        **kwargs,
    ) -> ListContactsResponse:
        raise NotImplementedError

    @handler("ListDataflowEndpointGroups")
    def list_dataflow_endpoint_groups(
        self,
        context: RequestContext,
        max_results: PaginationMaxResults | None = None,
        next_token: PaginationToken | None = None,
        **kwargs,
    ) -> ListDataflowEndpointGroupsResponse:
        raise NotImplementedError

    @handler("ListEphemerides")
    def list_ephemerides(
        self,
        context: RequestContext,
        end_time: Timestamp,
        satellite_id: Uuid,
        start_time: Timestamp,
        max_results: PaginationMaxResults | None = None,
        next_token: PaginationToken | None = None,
        status_list: EphemerisStatusList | None = None,
        **kwargs,
    ) -> ListEphemeridesResponse:
        raise NotImplementedError

    @handler("ListGroundStations")
    def list_ground_stations(
        self,
        context: RequestContext,
        max_results: PaginationMaxResults | None = None,
        next_token: PaginationToken | None = None,
        satellite_id: Uuid | None = None,
        **kwargs,
    ) -> ListGroundStationsResponse:
        raise NotImplementedError

    @handler("ListMissionProfiles")
    def list_mission_profiles(
        self,
        context: RequestContext,
        max_results: PaginationMaxResults | None = None,
        next_token: PaginationToken | None = None,
        **kwargs,
    ) -> ListMissionProfilesResponse:
        raise NotImplementedError

    @handler("ListSatellites")
    def list_satellites(
        self,
        context: RequestContext,
        max_results: PaginationMaxResults | None = None,
        next_token: PaginationToken | None = None,
        **kwargs,
    ) -> ListSatellitesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AnyArn, **kwargs
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("RegisterAgent")
    def register_agent(
        self,
        context: RequestContext,
        agent_details: AgentDetails,
        discovery_data: DiscoveryData,
        tags: TagsMap | None = None,
        **kwargs,
    ) -> RegisterAgentResponse:
        raise NotImplementedError

    @handler("ReserveContact")
    def reserve_contact(
        self,
        context: RequestContext,
        end_time: Timestamp,
        ground_station: GroundStationName,
        mission_profile_arn: MissionProfileArn,
        satellite_arn: satelliteArn,
        start_time: Timestamp,
        tags: TagsMap | None = None,
        **kwargs,
    ) -> ContactIdResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: AnyArn, tags: TagsMap, **kwargs
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: AnyArn, tag_keys: TagKeys, **kwargs
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateAgentStatus")
    def update_agent_status(
        self,
        context: RequestContext,
        agent_id: Uuid,
        aggregate_status: AggregateStatus,
        component_statuses: ComponentStatusList,
        task_id: Uuid,
        **kwargs,
    ) -> UpdateAgentStatusResponse:
        raise NotImplementedError

    @handler("UpdateConfig")
    def update_config(
        self,
        context: RequestContext,
        config_data: ConfigTypeData,
        config_id: Uuid,
        config_type: ConfigCapabilityType,
        name: SafeName,
        **kwargs,
    ) -> ConfigIdResponse:
        raise NotImplementedError

    @handler("UpdateEphemeris")
    def update_ephemeris(
        self,
        context: RequestContext,
        enabled: Boolean,
        ephemeris_id: Uuid,
        name: SafeName | None = None,
        priority: EphemerisPriority | None = None,
        **kwargs,
    ) -> EphemerisIdResponse:
        raise NotImplementedError

    @handler("UpdateMissionProfile")
    def update_mission_profile(
        self,
        context: RequestContext,
        mission_profile_id: Uuid,
        contact_post_pass_duration_seconds: DurationInSeconds | None = None,
        contact_pre_pass_duration_seconds: DurationInSeconds | None = None,
        dataflow_edges: DataflowEdgeList | None = None,
        minimum_viable_contact_duration_seconds: PositiveDurationInSeconds | None = None,
        name: SafeName | None = None,
        streams_kms_key: KmsKey | None = None,
        streams_kms_role: RoleArn | None = None,
        tracking_config_arn: ConfigArn | None = None,
        **kwargs,
    ) -> MissionProfileIdResponse:
        raise NotImplementedError

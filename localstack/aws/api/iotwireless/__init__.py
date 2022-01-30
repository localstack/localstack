import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AccountLinked = bool
AddGwMetadata = bool
AmazonId = str
AmazonResourceName = str
AppEui = str
AppKey = str
AppSKey = str
AppServerPrivateKey = str
AutoCreateTasks = bool
CertificatePEM = str
CertificateValue = str
ChannelMask = str
ClassBTimeout = int
ClassCTimeout = int
ClientRequestToken = str
Description = str
DestinationArn = str
DestinationName = str
DevAddr = str
DevEui = str
DevStatusReqFreq = int
DeviceProfileArn = str
DeviceProfileId = str
DeviceProfileName = str
DlBucketSize = int
DlDr = int
DlFreq = int
DlRate = int
DlRatePolicy = str
Double = float
DrMax = int
DrMin = int
EndPoint = str
Expression = str
FNwkSIntKey = str
FPort = int
Fingerprint = str
FirmwareUpdateImage = str
FirmwareUpdateRole = str
FuotaTaskArn = str
FuotaTaskId = str
FuotaTaskName = str
GatewayEui = str
GenAppKey = str
HrAllowed = bool
ISODateTimeString = str
Identifier = str
Integer = int
IotCertificateId = str
JoinEui = str
MacVersion = str
MaxDutyCycle = int
MaxEirp = int
MaxResults = int
McGroupId = int
Message = str
MessageId = str
MinGwDiversity = int
Model = str
MulticastDeviceStatus = str
MulticastGroupArn = str
MulticastGroupId = str
MulticastGroupMessageId = str
MulticastGroupName = str
MulticastGroupStatus = str
NetId = str
NetworkAnalyzerConfigurationName = str
NextToken = str
NumberOfDevicesInGroup = int
NumberOfDevicesRequested = int
NwkGeoLoc = bool
NwkKey = str
NwkSEncKey = str
NwkSKey = str
PackageVersion = str
PartnerAccountArn = str
PartnerAccountId = str
PayloadData = str
PingSlotDr = int
PingSlotFreq = int
PingSlotPeriod = int
PrAllowed = bool
PresetFreq = int
QueryString = str
RaAllowed = bool
RegParamsRevision = str
ReportDevStatusBattery = bool
ReportDevStatusMargin = bool
ResourceId = str
ResourceIdentifier = str
ResourceType = str
Result = str
RfRegion = str
RoleArn = str
RxDataRate2 = int
RxDelay1 = int
RxDrOffset1 = int
RxFreq2 = int
SNwkSIntKey = str
Seq = int
ServiceProfileArn = str
ServiceProfileId = str
ServiceProfileName = str
SessionTimeout = int
SidewalkId = str
SidewalkManufacturingSn = str
Station = str
SubBand = int
Supports32BitFCnt = bool
SupportsClassB = bool
SupportsClassC = bool
SupportsJoin = bool
TagKey = str
TagValue = str
TargetPer = int
ThingArn = str
ThingName = str
TransmitMode = int
UlBucketSize = int
UlRate = int
UlRatePolicy = str
UpdateDataSource = str
UpdateSignature = str
WirelessDeviceArn = str
WirelessDeviceId = str
WirelessDeviceName = str
WirelessGatewayArn = str
WirelessGatewayId = str
WirelessGatewayName = str
WirelessGatewayTaskDefinitionArn = str
WirelessGatewayTaskDefinitionId = str
WirelessGatewayTaskName = str


class BatteryLevel(str):
    normal = "normal"
    low = "low"
    critical = "critical"


class ConnectionStatus(str):
    Connected = "Connected"
    Disconnected = "Disconnected"


class DeviceState(str):
    Provisioned = "Provisioned"
    RegisteredNotSeen = "RegisteredNotSeen"
    RegisteredReachable = "RegisteredReachable"
    RegisteredUnreachable = "RegisteredUnreachable"


class DlClass(str):
    ClassB = "ClassB"
    ClassC = "ClassC"


class Event(str):
    discovered = "discovered"
    lost = "lost"
    ack = "ack"
    nack = "nack"
    passthrough = "passthrough"


class EventNotificationPartnerType(str):
    Sidewalk = "Sidewalk"


class EventNotificationTopicStatus(str):
    Enabled = "Enabled"
    Disabled = "Disabled"


class ExpressionType(str):
    RuleName = "RuleName"
    MqttTopic = "MqttTopic"


class FuotaDeviceStatus(str):
    Initial = "Initial"
    Package_Not_Supported = "Package_Not_Supported"
    FragAlgo_unsupported = "FragAlgo_unsupported"
    Not_enough_memory = "Not_enough_memory"
    FragIndex_unsupported = "FragIndex_unsupported"
    Wrong_descriptor = "Wrong_descriptor"
    SessionCnt_replay = "SessionCnt_replay"
    MissingFrag = "MissingFrag"
    MemoryError = "MemoryError"
    MICError = "MICError"
    Successful = "Successful"


class FuotaTaskStatus(str):
    Pending = "Pending"
    FuotaSession_Waiting = "FuotaSession_Waiting"
    In_FuotaSession = "In_FuotaSession"
    FuotaDone = "FuotaDone"
    Delete_Waiting = "Delete_Waiting"


class IdentifierType(str):
    PartnerAccountId = "PartnerAccountId"


class LogLevel(str):
    INFO = "INFO"
    ERROR = "ERROR"
    DISABLED = "DISABLED"


class MessageType(str):
    CUSTOM_COMMAND_ID_NOTIFY = "CUSTOM_COMMAND_ID_NOTIFY"
    CUSTOM_COMMAND_ID_GET = "CUSTOM_COMMAND_ID_GET"
    CUSTOM_COMMAND_ID_SET = "CUSTOM_COMMAND_ID_SET"
    CUSTOM_COMMAND_ID_RESP = "CUSTOM_COMMAND_ID_RESP"


class PartnerType(str):
    Sidewalk = "Sidewalk"


class SigningAlg(str):
    Ed25519 = "Ed25519"
    P256r1 = "P256r1"


class SupportedRfRegion(str):
    EU868 = "EU868"
    US915 = "US915"
    AU915 = "AU915"
    AS923_1 = "AS923-1"


class WirelessDeviceEvent(str):
    Join = "Join"
    Rejoin = "Rejoin"
    Uplink_Data = "Uplink_Data"
    Downlink_Data = "Downlink_Data"
    Registration = "Registration"


class WirelessDeviceFrameInfo(str):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class WirelessDeviceIdType(str):
    WirelessDeviceId = "WirelessDeviceId"
    DevEui = "DevEui"
    ThingName = "ThingName"
    SidewalkManufacturingSn = "SidewalkManufacturingSn"


class WirelessDeviceType(str):
    Sidewalk = "Sidewalk"
    LoRaWAN = "LoRaWAN"


class WirelessGatewayEvent(str):
    CUPS_Request = "CUPS_Request"
    Certificate = "Certificate"


class WirelessGatewayIdType(str):
    GatewayEui = "GatewayEui"
    WirelessGatewayId = "WirelessGatewayId"
    ThingName = "ThingName"


class WirelessGatewayServiceType(str):
    CUPS = "CUPS"
    LNS = "LNS"


class WirelessGatewayTaskDefinitionType(str):
    UPDATE = "UPDATE"


class WirelessGatewayTaskStatus(str):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    FIRST_RETRY = "FIRST_RETRY"
    SECOND_RETRY = "SECOND_RETRY"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class WirelessGatewayType(str):
    LoRaWAN = "LoRaWAN"


class AccessDeniedException(ServiceException):
    Message: Optional[Message]


class ConflictException(ServiceException):
    Message: Optional[Message]
    ResourceId: Optional[ResourceId]
    ResourceType: Optional[ResourceType]


class InternalServerException(ServiceException):
    Message: Optional[Message]


class ResourceNotFoundException(ServiceException):
    Message: Optional[Message]
    ResourceId: Optional[ResourceId]
    ResourceType: Optional[ResourceType]


class ThrottlingException(ServiceException):
    Message: Optional[Message]


class TooManyTagsException(ServiceException):
    Message: Optional[Message]
    ResourceName: Optional[AmazonResourceName]


class ValidationException(ServiceException):
    Message: Optional[Message]


class SessionKeysAbpV1_0_x(TypedDict, total=False):
    NwkSKey: Optional[NwkSKey]
    AppSKey: Optional[AppSKey]


class AbpV1_0_x(TypedDict, total=False):
    DevAddr: Optional[DevAddr]
    SessionKeys: Optional[SessionKeysAbpV1_0_x]


class SessionKeysAbpV1_1(TypedDict, total=False):
    FNwkSIntKey: Optional[FNwkSIntKey]
    SNwkSIntKey: Optional[SNwkSIntKey]
    NwkSEncKey: Optional[NwkSEncKey]
    AppSKey: Optional[AppSKey]


class AbpV1_1(TypedDict, total=False):
    DevAddr: Optional[DevAddr]
    SessionKeys: Optional[SessionKeysAbpV1_1]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = List[Tag]


class SidewalkAccountInfo(TypedDict, total=False):
    AmazonId: Optional[AmazonId]
    AppServerPrivateKey: Optional[AppServerPrivateKey]


class AssociateAwsAccountWithPartnerAccountRequest(ServiceRequest):
    Sidewalk: SidewalkAccountInfo
    ClientRequestToken: Optional[ClientRequestToken]
    Tags: Optional[TagList]


class AssociateAwsAccountWithPartnerAccountResponse(TypedDict, total=False):
    Sidewalk: Optional[SidewalkAccountInfo]
    Arn: Optional[PartnerAccountArn]


class AssociateMulticastGroupWithFuotaTaskRequest(ServiceRequest):
    Id: FuotaTaskId
    MulticastGroupId: MulticastGroupId


class AssociateMulticastGroupWithFuotaTaskResponse(TypedDict, total=False):
    pass


class AssociateWirelessDeviceWithFuotaTaskRequest(ServiceRequest):
    Id: FuotaTaskId
    WirelessDeviceId: WirelessDeviceId


class AssociateWirelessDeviceWithFuotaTaskResponse(TypedDict, total=False):
    pass


class AssociateWirelessDeviceWithMulticastGroupRequest(ServiceRequest):
    Id: MulticastGroupId
    WirelessDeviceId: WirelessDeviceId


class AssociateWirelessDeviceWithMulticastGroupResponse(TypedDict, total=False):
    pass


class AssociateWirelessDeviceWithThingRequest(ServiceRequest):
    Id: WirelessDeviceId
    ThingArn: ThingArn


class AssociateWirelessDeviceWithThingResponse(TypedDict, total=False):
    pass


class AssociateWirelessGatewayWithCertificateRequest(ServiceRequest):
    Id: WirelessGatewayId
    IotCertificateId: IotCertificateId


class AssociateWirelessGatewayWithCertificateResponse(TypedDict, total=False):
    IotCertificateId: Optional[IotCertificateId]


class AssociateWirelessGatewayWithThingRequest(ServiceRequest):
    Id: WirelessGatewayId
    ThingArn: ThingArn


class AssociateWirelessGatewayWithThingResponse(TypedDict, total=False):
    pass


class CancelMulticastGroupSessionRequest(ServiceRequest):
    Id: MulticastGroupId


class CancelMulticastGroupSessionResponse(TypedDict, total=False):
    pass


class CertificateList(TypedDict, total=False):
    SigningAlg: SigningAlg
    Value: CertificateValue


Crc = int


class CreateDestinationRequest(ServiceRequest):
    Name: DestinationName
    ExpressionType: ExpressionType
    Expression: Expression
    Description: Optional[Description]
    RoleArn: RoleArn
    Tags: Optional[TagList]
    ClientRequestToken: Optional[ClientRequestToken]


class CreateDestinationResponse(TypedDict, total=False):
    Arn: Optional[DestinationArn]
    Name: Optional[DestinationName]


FactoryPresetFreqsList = List[PresetFreq]


class LoRaWANDeviceProfile(TypedDict, total=False):
    SupportsClassB: Optional[SupportsClassB]
    ClassBTimeout: Optional[ClassBTimeout]
    PingSlotPeriod: Optional[PingSlotPeriod]
    PingSlotDr: Optional[PingSlotDr]
    PingSlotFreq: Optional[PingSlotFreq]
    SupportsClassC: Optional[SupportsClassC]
    ClassCTimeout: Optional[ClassCTimeout]
    MacVersion: Optional[MacVersion]
    RegParamsRevision: Optional[RegParamsRevision]
    RxDelay1: Optional[RxDelay1]
    RxDrOffset1: Optional[RxDrOffset1]
    RxDataRate2: Optional[RxDataRate2]
    RxFreq2: Optional[RxFreq2]
    FactoryPresetFreqsList: Optional[FactoryPresetFreqsList]
    MaxEirp: Optional[MaxEirp]
    MaxDutyCycle: Optional[MaxDutyCycle]
    RfRegion: Optional[RfRegion]
    SupportsJoin: Optional[SupportsJoin]
    Supports32BitFCnt: Optional[Supports32BitFCnt]


class CreateDeviceProfileRequest(ServiceRequest):
    Name: Optional[DeviceProfileName]
    LoRaWAN: Optional[LoRaWANDeviceProfile]
    Tags: Optional[TagList]
    ClientRequestToken: Optional[ClientRequestToken]


class CreateDeviceProfileResponse(TypedDict, total=False):
    Arn: Optional[DeviceProfileArn]
    Id: Optional[DeviceProfileId]


class LoRaWANFuotaTask(TypedDict, total=False):
    RfRegion: Optional[SupportedRfRegion]


class CreateFuotaTaskRequest(ServiceRequest):
    Name: Optional[FuotaTaskName]
    Description: Optional[Description]
    ClientRequestToken: Optional[ClientRequestToken]
    LoRaWAN: Optional[LoRaWANFuotaTask]
    FirmwareUpdateImage: FirmwareUpdateImage
    FirmwareUpdateRole: FirmwareUpdateRole
    Tags: Optional[TagList]


class CreateFuotaTaskResponse(TypedDict, total=False):
    Arn: Optional[FuotaTaskArn]
    Id: Optional[FuotaTaskId]


class LoRaWANMulticast(TypedDict, total=False):
    RfRegion: Optional[SupportedRfRegion]
    DlClass: Optional[DlClass]


class CreateMulticastGroupRequest(ServiceRequest):
    Name: Optional[MulticastGroupName]
    Description: Optional[Description]
    ClientRequestToken: Optional[ClientRequestToken]
    LoRaWAN: LoRaWANMulticast
    Tags: Optional[TagList]


class CreateMulticastGroupResponse(TypedDict, total=False):
    Arn: Optional[MulticastGroupArn]
    Id: Optional[MulticastGroupId]


class LoRaWANServiceProfile(TypedDict, total=False):
    AddGwMetadata: Optional[AddGwMetadata]


class CreateServiceProfileRequest(ServiceRequest):
    Name: Optional[ServiceProfileName]
    LoRaWAN: Optional[LoRaWANServiceProfile]
    Tags: Optional[TagList]
    ClientRequestToken: Optional[ClientRequestToken]


class CreateServiceProfileResponse(TypedDict, total=False):
    Arn: Optional[ServiceProfileArn]
    Id: Optional[ServiceProfileId]


class FPorts(TypedDict, total=False):
    Fuota: Optional[FPort]
    Multicast: Optional[FPort]
    ClockSync: Optional[FPort]


class OtaaV1_0_x(TypedDict, total=False):
    AppKey: Optional[AppKey]
    AppEui: Optional[AppEui]
    GenAppKey: Optional[GenAppKey]


class OtaaV1_1(TypedDict, total=False):
    AppKey: Optional[AppKey]
    NwkKey: Optional[NwkKey]
    JoinEui: Optional[JoinEui]


class LoRaWANDevice(TypedDict, total=False):
    DevEui: Optional[DevEui]
    DeviceProfileId: Optional[DeviceProfileId]
    ServiceProfileId: Optional[ServiceProfileId]
    OtaaV1_1: Optional[OtaaV1_1]
    OtaaV1_0_x: Optional[OtaaV1_0_x]
    AbpV1_1: Optional[AbpV1_1]
    AbpV1_0_x: Optional[AbpV1_0_x]
    FPorts: Optional[FPorts]


class CreateWirelessDeviceRequest(ServiceRequest):
    Type: WirelessDeviceType
    Name: Optional[WirelessDeviceName]
    Description: Optional[Description]
    DestinationName: DestinationName
    ClientRequestToken: Optional[ClientRequestToken]
    LoRaWAN: Optional[LoRaWANDevice]
    Tags: Optional[TagList]


class CreateWirelessDeviceResponse(TypedDict, total=False):
    Arn: Optional[WirelessDeviceArn]
    Id: Optional[WirelessDeviceId]


SubBands = List[SubBand]
NetIdFilters = List[NetId]
JoinEuiRange = List[JoinEui]
JoinEuiFilters = List[JoinEuiRange]


class LoRaWANGateway(TypedDict, total=False):
    GatewayEui: Optional[GatewayEui]
    RfRegion: Optional[RfRegion]
    JoinEuiFilters: Optional[JoinEuiFilters]
    NetIdFilters: Optional[NetIdFilters]
    SubBands: Optional[SubBands]


class CreateWirelessGatewayRequest(ServiceRequest):
    Name: Optional[WirelessGatewayName]
    Description: Optional[Description]
    LoRaWAN: LoRaWANGateway
    Tags: Optional[TagList]
    ClientRequestToken: Optional[ClientRequestToken]


class CreateWirelessGatewayResponse(TypedDict, total=False):
    Arn: Optional[WirelessGatewayArn]
    Id: Optional[WirelessDeviceId]


class LoRaWANGatewayVersion(TypedDict, total=False):
    PackageVersion: Optional[PackageVersion]
    Model: Optional[Model]
    Station: Optional[Station]


class LoRaWANUpdateGatewayTaskCreate(TypedDict, total=False):
    UpdateSignature: Optional[UpdateSignature]
    SigKeyCrc: Optional[Crc]
    CurrentVersion: Optional[LoRaWANGatewayVersion]
    UpdateVersion: Optional[LoRaWANGatewayVersion]


class UpdateWirelessGatewayTaskCreate(TypedDict, total=False):
    UpdateDataSource: Optional[UpdateDataSource]
    UpdateDataRole: Optional[UpdateDataSource]
    LoRaWAN: Optional[LoRaWANUpdateGatewayTaskCreate]


class CreateWirelessGatewayTaskDefinitionRequest(ServiceRequest):
    AutoCreateTasks: AutoCreateTasks
    Name: Optional[WirelessGatewayTaskName]
    Update: Optional[UpdateWirelessGatewayTaskCreate]
    ClientRequestToken: Optional[ClientRequestToken]
    Tags: Optional[TagList]


class CreateWirelessGatewayTaskDefinitionResponse(TypedDict, total=False):
    Id: Optional[WirelessGatewayTaskDefinitionId]
    Arn: Optional[WirelessGatewayTaskDefinitionArn]


class CreateWirelessGatewayTaskRequest(ServiceRequest):
    Id: WirelessGatewayId
    WirelessGatewayTaskDefinitionId: WirelessGatewayTaskDefinitionId


class CreateWirelessGatewayTaskResponse(TypedDict, total=False):
    WirelessGatewayTaskDefinitionId: Optional[WirelessGatewayTaskDefinitionId]
    Status: Optional[WirelessGatewayTaskStatus]


CreatedAt = datetime


class DeleteDestinationRequest(ServiceRequest):
    Name: DestinationName


class DeleteDestinationResponse(TypedDict, total=False):
    pass


class DeleteDeviceProfileRequest(ServiceRequest):
    Id: DeviceProfileId


class DeleteDeviceProfileResponse(TypedDict, total=False):
    pass


class DeleteFuotaTaskRequest(ServiceRequest):
    Id: FuotaTaskId


class DeleteFuotaTaskResponse(TypedDict, total=False):
    pass


class DeleteMulticastGroupRequest(ServiceRequest):
    Id: MulticastGroupId


class DeleteMulticastGroupResponse(TypedDict, total=False):
    pass


class DeleteQueuedMessagesRequest(ServiceRequest):
    Id: WirelessDeviceId
    MessageId: MessageId
    WirelessDeviceType: Optional[WirelessDeviceType]


class DeleteQueuedMessagesResponse(TypedDict, total=False):
    pass


class DeleteServiceProfileRequest(ServiceRequest):
    Id: ServiceProfileId


class DeleteServiceProfileResponse(TypedDict, total=False):
    pass


class DeleteWirelessDeviceRequest(ServiceRequest):
    Id: WirelessDeviceId


class DeleteWirelessDeviceResponse(TypedDict, total=False):
    pass


class DeleteWirelessGatewayRequest(ServiceRequest):
    Id: WirelessGatewayId


class DeleteWirelessGatewayResponse(TypedDict, total=False):
    pass


class DeleteWirelessGatewayTaskDefinitionRequest(ServiceRequest):
    Id: WirelessGatewayTaskDefinitionId


class DeleteWirelessGatewayTaskDefinitionResponse(TypedDict, total=False):
    pass


class DeleteWirelessGatewayTaskRequest(ServiceRequest):
    Id: WirelessGatewayId


class DeleteWirelessGatewayTaskResponse(TypedDict, total=False):
    pass


class Destinations(TypedDict, total=False):
    Arn: Optional[DestinationArn]
    Name: Optional[DestinationName]
    ExpressionType: Optional[ExpressionType]
    Expression: Optional[Expression]
    Description: Optional[Description]
    RoleArn: Optional[RoleArn]


DestinationList = List[Destinations]
DeviceCertificateList = List[CertificateList]


class DeviceProfile(TypedDict, total=False):
    Arn: Optional[DeviceProfileArn]
    Name: Optional[DeviceProfileName]
    Id: Optional[DeviceProfileId]


DeviceProfileList = List[DeviceProfile]


class SidewalkEventNotificationConfigurations(TypedDict, total=False):
    AmazonIdEventTopic: Optional[EventNotificationTopicStatus]


class DeviceRegistrationStateEventConfiguration(TypedDict, total=False):
    Sidewalk: Optional[SidewalkEventNotificationConfigurations]


class DisassociateAwsAccountFromPartnerAccountRequest(ServiceRequest):
    PartnerAccountId: PartnerAccountId
    PartnerType: PartnerType


class DisassociateAwsAccountFromPartnerAccountResponse(TypedDict, total=False):
    pass


class DisassociateMulticastGroupFromFuotaTaskRequest(ServiceRequest):
    Id: FuotaTaskId
    MulticastGroupId: MulticastGroupId


class DisassociateMulticastGroupFromFuotaTaskResponse(TypedDict, total=False):
    pass


class DisassociateWirelessDeviceFromFuotaTaskRequest(ServiceRequest):
    Id: FuotaTaskId
    WirelessDeviceId: WirelessDeviceId


class DisassociateWirelessDeviceFromFuotaTaskResponse(TypedDict, total=False):
    pass


class DisassociateWirelessDeviceFromMulticastGroupRequest(ServiceRequest):
    Id: MulticastGroupId
    WirelessDeviceId: WirelessDeviceId


class DisassociateWirelessDeviceFromMulticastGroupResponse(TypedDict, total=False):
    pass


class DisassociateWirelessDeviceFromThingRequest(ServiceRequest):
    Id: WirelessDeviceId


class DisassociateWirelessDeviceFromThingResponse(TypedDict, total=False):
    pass


class DisassociateWirelessGatewayFromCertificateRequest(ServiceRequest):
    Id: WirelessGatewayId


class DisassociateWirelessGatewayFromCertificateResponse(TypedDict, total=False):
    pass


class DisassociateWirelessGatewayFromThingRequest(ServiceRequest):
    Id: WirelessGatewayId


class DisassociateWirelessGatewayFromThingResponse(TypedDict, total=False):
    pass


class LoRaWANSendDataToDevice(TypedDict, total=False):
    FPort: Optional[FPort]


class DownlinkQueueMessage(TypedDict, total=False):
    MessageId: Optional[MessageId]
    TransmitMode: Optional[TransmitMode]
    ReceivedAt: Optional[ISODateTimeString]
    LoRaWAN: Optional[LoRaWANSendDataToDevice]


DownlinkQueueMessagesList = List[DownlinkQueueMessage]


class FuotaTask(TypedDict, total=False):
    Id: Optional[FuotaTaskId]
    Arn: Optional[FuotaTaskArn]
    Name: Optional[FuotaTaskName]


FuotaTaskList = List[FuotaTask]


class GetDestinationRequest(ServiceRequest):
    Name: DestinationName


class GetDestinationResponse(TypedDict, total=False):
    Arn: Optional[DestinationArn]
    Name: Optional[DestinationName]
    Expression: Optional[Expression]
    ExpressionType: Optional[ExpressionType]
    Description: Optional[Description]
    RoleArn: Optional[RoleArn]


class GetDeviceProfileRequest(ServiceRequest):
    Id: DeviceProfileId


class GetDeviceProfileResponse(TypedDict, total=False):
    Arn: Optional[DeviceProfileArn]
    Name: Optional[DeviceProfileName]
    Id: Optional[DeviceProfileId]
    LoRaWAN: Optional[LoRaWANDeviceProfile]


class GetFuotaTaskRequest(ServiceRequest):
    Id: FuotaTaskId


StartTime = datetime


class LoRaWANFuotaTaskGetInfo(TypedDict, total=False):
    RfRegion: Optional[RfRegion]
    StartTime: Optional[StartTime]


class GetFuotaTaskResponse(TypedDict, total=False):
    Arn: Optional[FuotaTaskArn]
    Id: Optional[FuotaTaskId]
    Status: Optional[FuotaTaskStatus]
    Name: Optional[FuotaTaskName]
    Description: Optional[Description]
    LoRaWAN: Optional[LoRaWANFuotaTaskGetInfo]
    FirmwareUpdateImage: Optional[FirmwareUpdateImage]
    FirmwareUpdateRole: Optional[FirmwareUpdateRole]
    CreatedAt: Optional[CreatedAt]


class GetLogLevelsByResourceTypesRequest(ServiceRequest):
    pass


class WirelessDeviceEventLogOption(TypedDict, total=False):
    Event: WirelessDeviceEvent
    LogLevel: LogLevel


WirelessDeviceEventLogOptionList = List[WirelessDeviceEventLogOption]


class WirelessDeviceLogOption(TypedDict, total=False):
    Type: WirelessDeviceType
    LogLevel: LogLevel
    Events: Optional[WirelessDeviceEventLogOptionList]


WirelessDeviceLogOptionList = List[WirelessDeviceLogOption]


class WirelessGatewayEventLogOption(TypedDict, total=False):
    Event: WirelessGatewayEvent
    LogLevel: LogLevel


WirelessGatewayEventLogOptionList = List[WirelessGatewayEventLogOption]


class WirelessGatewayLogOption(TypedDict, total=False):
    Type: WirelessGatewayType
    LogLevel: LogLevel
    Events: Optional[WirelessGatewayEventLogOptionList]


WirelessGatewayLogOptionList = List[WirelessGatewayLogOption]


class GetLogLevelsByResourceTypesResponse(TypedDict, total=False):
    DefaultLogLevel: Optional[LogLevel]
    WirelessGatewayLogOptions: Optional[WirelessGatewayLogOptionList]
    WirelessDeviceLogOptions: Optional[WirelessDeviceLogOptionList]


class GetMulticastGroupRequest(ServiceRequest):
    Id: MulticastGroupId


class LoRaWANMulticastGet(TypedDict, total=False):
    RfRegion: Optional[SupportedRfRegion]
    DlClass: Optional[DlClass]
    NumberOfDevicesRequested: Optional[NumberOfDevicesRequested]
    NumberOfDevicesInGroup: Optional[NumberOfDevicesInGroup]


class GetMulticastGroupResponse(TypedDict, total=False):
    Arn: Optional[MulticastGroupArn]
    Id: Optional[MulticastGroupId]
    Name: Optional[MulticastGroupName]
    Description: Optional[Description]
    Status: Optional[MulticastGroupStatus]
    LoRaWAN: Optional[LoRaWANMulticastGet]
    CreatedAt: Optional[CreatedAt]


class GetMulticastGroupSessionRequest(ServiceRequest):
    Id: MulticastGroupId


SessionStartTimeTimestamp = datetime


class LoRaWANMulticastSession(TypedDict, total=False):
    DlDr: Optional[DlDr]
    DlFreq: Optional[DlFreq]
    SessionStartTime: Optional[SessionStartTimeTimestamp]
    SessionTimeout: Optional[SessionTimeout]


class GetMulticastGroupSessionResponse(TypedDict, total=False):
    LoRaWAN: Optional[LoRaWANMulticastSession]


class GetNetworkAnalyzerConfigurationRequest(ServiceRequest):
    ConfigurationName: NetworkAnalyzerConfigurationName


WirelessGatewayList = List[WirelessGatewayId]
WirelessDeviceList = List[WirelessDeviceId]


class TraceContent(TypedDict, total=False):
    WirelessDeviceFrameInfo: Optional[WirelessDeviceFrameInfo]
    LogLevel: Optional[LogLevel]


class GetNetworkAnalyzerConfigurationResponse(TypedDict, total=False):
    TraceContent: Optional[TraceContent]
    WirelessDevices: Optional[WirelessDeviceList]
    WirelessGateways: Optional[WirelessGatewayList]


class GetPartnerAccountRequest(ServiceRequest):
    PartnerAccountId: PartnerAccountId
    PartnerType: PartnerType


class SidewalkAccountInfoWithFingerprint(TypedDict, total=False):
    AmazonId: Optional[AmazonId]
    Fingerprint: Optional[Fingerprint]
    Arn: Optional[PartnerAccountArn]


class GetPartnerAccountResponse(TypedDict, total=False):
    Sidewalk: Optional[SidewalkAccountInfoWithFingerprint]
    AccountLinked: Optional[AccountLinked]


class GetResourceEventConfigurationRequest(ServiceRequest):
    Identifier: Identifier
    IdentifierType: IdentifierType
    PartnerType: Optional[EventNotificationPartnerType]


class ProximityEventConfiguration(TypedDict, total=False):
    Sidewalk: Optional[SidewalkEventNotificationConfigurations]


class GetResourceEventConfigurationResponse(TypedDict, total=False):
    DeviceRegistrationState: Optional[DeviceRegistrationStateEventConfiguration]
    Proximity: Optional[ProximityEventConfiguration]


class GetResourceLogLevelRequest(ServiceRequest):
    ResourceIdentifier: ResourceIdentifier
    ResourceType: ResourceType


class GetResourceLogLevelResponse(TypedDict, total=False):
    LogLevel: Optional[LogLevel]


class GetServiceEndpointRequest(ServiceRequest):
    ServiceType: Optional[WirelessGatewayServiceType]


class GetServiceEndpointResponse(TypedDict, total=False):
    ServiceType: Optional[WirelessGatewayServiceType]
    ServiceEndpoint: Optional[EndPoint]
    ServerTrust: Optional[CertificatePEM]


class GetServiceProfileRequest(ServiceRequest):
    Id: ServiceProfileId


class LoRaWANGetServiceProfileInfo(TypedDict, total=False):
    UlRate: Optional[UlRate]
    UlBucketSize: Optional[UlBucketSize]
    UlRatePolicy: Optional[UlRatePolicy]
    DlRate: Optional[DlRate]
    DlBucketSize: Optional[DlBucketSize]
    DlRatePolicy: Optional[DlRatePolicy]
    AddGwMetadata: Optional[AddGwMetadata]
    DevStatusReqFreq: Optional[DevStatusReqFreq]
    ReportDevStatusBattery: Optional[ReportDevStatusBattery]
    ReportDevStatusMargin: Optional[ReportDevStatusMargin]
    DrMin: Optional[DrMin]
    DrMax: Optional[DrMax]
    ChannelMask: Optional[ChannelMask]
    PrAllowed: Optional[PrAllowed]
    HrAllowed: Optional[HrAllowed]
    RaAllowed: Optional[RaAllowed]
    NwkGeoLoc: Optional[NwkGeoLoc]
    TargetPer: Optional[TargetPer]
    MinGwDiversity: Optional[MinGwDiversity]


class GetServiceProfileResponse(TypedDict, total=False):
    Arn: Optional[ServiceProfileArn]
    Name: Optional[ServiceProfileName]
    Id: Optional[ServiceProfileId]
    LoRaWAN: Optional[LoRaWANGetServiceProfileInfo]


class GetWirelessDeviceRequest(ServiceRequest):
    Identifier: Identifier
    IdentifierType: WirelessDeviceIdType


class SidewalkDevice(TypedDict, total=False):
    AmazonId: Optional[AmazonId]
    SidewalkId: Optional[SidewalkId]
    SidewalkManufacturingSn: Optional[SidewalkManufacturingSn]
    DeviceCertificates: Optional[DeviceCertificateList]


class GetWirelessDeviceResponse(TypedDict, total=False):
    Type: Optional[WirelessDeviceType]
    Name: Optional[WirelessDeviceName]
    Description: Optional[Description]
    DestinationName: Optional[DestinationName]
    Id: Optional[WirelessDeviceId]
    Arn: Optional[WirelessDeviceArn]
    ThingName: Optional[ThingName]
    ThingArn: Optional[ThingArn]
    LoRaWAN: Optional[LoRaWANDevice]
    Sidewalk: Optional[SidewalkDevice]


class GetWirelessDeviceStatisticsRequest(ServiceRequest):
    WirelessDeviceId: WirelessDeviceId


class SidewalkDeviceMetadata(TypedDict, total=False):
    Rssi: Optional[Integer]
    BatteryLevel: Optional[BatteryLevel]
    Event: Optional[Event]
    DeviceState: Optional[DeviceState]


class LoRaWANGatewayMetadata(TypedDict, total=False):
    GatewayEui: Optional[GatewayEui]
    Snr: Optional[Double]
    Rssi: Optional[Double]


LoRaWANGatewayMetadataList = List[LoRaWANGatewayMetadata]


class LoRaWANDeviceMetadata(TypedDict, total=False):
    DevEui: Optional[DevEui]
    FPort: Optional[Integer]
    DataRate: Optional[Integer]
    Frequency: Optional[Integer]
    Timestamp: Optional[ISODateTimeString]
    Gateways: Optional[LoRaWANGatewayMetadataList]


class GetWirelessDeviceStatisticsResponse(TypedDict, total=False):
    WirelessDeviceId: Optional[WirelessDeviceId]
    LastUplinkReceivedAt: Optional[ISODateTimeString]
    LoRaWAN: Optional[LoRaWANDeviceMetadata]
    Sidewalk: Optional[SidewalkDeviceMetadata]


class GetWirelessGatewayCertificateRequest(ServiceRequest):
    Id: WirelessGatewayId


class GetWirelessGatewayCertificateResponse(TypedDict, total=False):
    IotCertificateId: Optional[IotCertificateId]
    LoRaWANNetworkServerCertificateId: Optional[IotCertificateId]


class GetWirelessGatewayFirmwareInformationRequest(ServiceRequest):
    Id: WirelessGatewayId


class LoRaWANGatewayCurrentVersion(TypedDict, total=False):
    CurrentVersion: Optional[LoRaWANGatewayVersion]


class GetWirelessGatewayFirmwareInformationResponse(TypedDict, total=False):
    LoRaWAN: Optional[LoRaWANGatewayCurrentVersion]


class GetWirelessGatewayRequest(ServiceRequest):
    Identifier: Identifier
    IdentifierType: WirelessGatewayIdType


class GetWirelessGatewayResponse(TypedDict, total=False):
    Name: Optional[WirelessGatewayName]
    Id: Optional[WirelessGatewayId]
    Description: Optional[Description]
    LoRaWAN: Optional[LoRaWANGateway]
    Arn: Optional[WirelessGatewayArn]
    ThingName: Optional[ThingName]
    ThingArn: Optional[ThingArn]


class GetWirelessGatewayStatisticsRequest(ServiceRequest):
    WirelessGatewayId: WirelessGatewayId


class GetWirelessGatewayStatisticsResponse(TypedDict, total=False):
    WirelessGatewayId: Optional[WirelessGatewayId]
    LastUplinkReceivedAt: Optional[ISODateTimeString]
    ConnectionStatus: Optional[ConnectionStatus]


class GetWirelessGatewayTaskDefinitionRequest(ServiceRequest):
    Id: WirelessGatewayTaskDefinitionId


class GetWirelessGatewayTaskDefinitionResponse(TypedDict, total=False):
    AutoCreateTasks: Optional[AutoCreateTasks]
    Name: Optional[WirelessGatewayTaskName]
    Update: Optional[UpdateWirelessGatewayTaskCreate]
    Arn: Optional[WirelessGatewayTaskDefinitionArn]


class GetWirelessGatewayTaskRequest(ServiceRequest):
    Id: WirelessGatewayId


class GetWirelessGatewayTaskResponse(TypedDict, total=False):
    WirelessGatewayId: Optional[WirelessGatewayId]
    WirelessGatewayTaskDefinitionId: Optional[WirelessGatewayTaskDefinitionId]
    LastUplinkReceivedAt: Optional[ISODateTimeString]
    TaskCreatedAt: Optional[ISODateTimeString]
    Status: Optional[WirelessGatewayTaskStatus]


class ListDestinationsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]


class ListDestinationsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    DestinationList: Optional[DestinationList]


class ListDeviceProfilesRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListDeviceProfilesResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    DeviceProfileList: Optional[DeviceProfileList]


class ListFuotaTasksRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ListFuotaTasksResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    FuotaTaskList: Optional[FuotaTaskList]


class ListMulticastGroupsByFuotaTaskRequest(ServiceRequest):
    Id: FuotaTaskId
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class MulticastGroupByFuotaTask(TypedDict, total=False):
    Id: Optional[MulticastGroupId]


MulticastGroupListByFuotaTask = List[MulticastGroupByFuotaTask]


class ListMulticastGroupsByFuotaTaskResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    MulticastGroupList: Optional[MulticastGroupListByFuotaTask]


class ListMulticastGroupsRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class MulticastGroup(TypedDict, total=False):
    Id: Optional[MulticastGroupId]
    Arn: Optional[MulticastGroupArn]
    Name: Optional[MulticastGroupName]


MulticastGroupList = List[MulticastGroup]


class ListMulticastGroupsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    MulticastGroupList: Optional[MulticastGroupList]


class ListPartnerAccountsRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


SidewalkAccountList = List[SidewalkAccountInfoWithFingerprint]


class ListPartnerAccountsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    Sidewalk: Optional[SidewalkAccountList]


class ListQueuedMessagesRequest(ServiceRequest):
    Id: WirelessDeviceId
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]
    WirelessDeviceType: Optional[WirelessDeviceType]


class ListQueuedMessagesResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    DownlinkQueueMessagesList: Optional[DownlinkQueueMessagesList]


class ListServiceProfilesRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class ServiceProfile(TypedDict, total=False):
    Arn: Optional[ServiceProfileArn]
    Name: Optional[ServiceProfileName]
    Id: Optional[ServiceProfileId]


ServiceProfileList = List[ServiceProfile]


class ListServiceProfilesResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    ServiceProfileList: Optional[ServiceProfileList]


class ListTagsForResourceRequest(ServiceRequest):
    ResourceArn: AmazonResourceName


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: Optional[TagList]


class ListWirelessDevicesRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    DestinationName: Optional[DestinationName]
    DeviceProfileId: Optional[DeviceProfileId]
    ServiceProfileId: Optional[ServiceProfileId]
    WirelessDeviceType: Optional[WirelessDeviceType]
    FuotaTaskId: Optional[FuotaTaskId]
    MulticastGroupId: Optional[MulticastGroupId]


class SidewalkListDevice(TypedDict, total=False):
    AmazonId: Optional[AmazonId]
    SidewalkId: Optional[SidewalkId]
    SidewalkManufacturingSn: Optional[SidewalkManufacturingSn]
    DeviceCertificates: Optional[DeviceCertificateList]


class LoRaWANListDevice(TypedDict, total=False):
    DevEui: Optional[DevEui]


class WirelessDeviceStatistics(TypedDict, total=False):
    Arn: Optional[WirelessDeviceArn]
    Id: Optional[WirelessDeviceId]
    Type: Optional[WirelessDeviceType]
    Name: Optional[WirelessDeviceName]
    DestinationName: Optional[DestinationName]
    LastUplinkReceivedAt: Optional[ISODateTimeString]
    LoRaWAN: Optional[LoRaWANListDevice]
    Sidewalk: Optional[SidewalkListDevice]
    FuotaDeviceStatus: Optional[FuotaDeviceStatus]
    MulticastDeviceStatus: Optional[MulticastDeviceStatus]
    McGroupId: Optional[McGroupId]


WirelessDeviceStatisticsList = List[WirelessDeviceStatistics]


class ListWirelessDevicesResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    WirelessDeviceList: Optional[WirelessDeviceStatisticsList]


class ListWirelessGatewayTaskDefinitionsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[NextToken]
    TaskDefinitionType: Optional[WirelessGatewayTaskDefinitionType]


class LoRaWANUpdateGatewayTaskEntry(TypedDict, total=False):
    CurrentVersion: Optional[LoRaWANGatewayVersion]
    UpdateVersion: Optional[LoRaWANGatewayVersion]


class UpdateWirelessGatewayTaskEntry(TypedDict, total=False):
    Id: Optional[WirelessGatewayTaskDefinitionId]
    LoRaWAN: Optional[LoRaWANUpdateGatewayTaskEntry]
    Arn: Optional[WirelessGatewayTaskDefinitionArn]


WirelessGatewayTaskDefinitionList = List[UpdateWirelessGatewayTaskEntry]


class ListWirelessGatewayTaskDefinitionsResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    TaskDefinitions: Optional[WirelessGatewayTaskDefinitionList]


class ListWirelessGatewaysRequest(ServiceRequest):
    NextToken: Optional[NextToken]
    MaxResults: Optional[MaxResults]


class WirelessGatewayStatistics(TypedDict, total=False):
    Arn: Optional[WirelessGatewayArn]
    Id: Optional[WirelessGatewayId]
    Name: Optional[WirelessGatewayName]
    Description: Optional[Description]
    LoRaWAN: Optional[LoRaWANGateway]
    LastUplinkReceivedAt: Optional[ISODateTimeString]


WirelessGatewayStatisticsList = List[WirelessGatewayStatistics]


class ListWirelessGatewaysResponse(TypedDict, total=False):
    NextToken: Optional[NextToken]
    WirelessGatewayList: Optional[WirelessGatewayStatisticsList]


class LoRaWANMulticastMetadata(TypedDict, total=False):
    FPort: Optional[FPort]


class LoRaWANStartFuotaTask(TypedDict, total=False):
    StartTime: Optional[StartTime]


class LoRaWANUpdateDevice(TypedDict, total=False):
    DeviceProfileId: Optional[DeviceProfileId]
    ServiceProfileId: Optional[ServiceProfileId]


class MulticastWirelessMetadata(TypedDict, total=False):
    LoRaWAN: Optional[LoRaWANMulticastMetadata]


class PutResourceLogLevelRequest(ServiceRequest):
    ResourceIdentifier: ResourceIdentifier
    ResourceType: ResourceType
    LogLevel: LogLevel


class PutResourceLogLevelResponse(TypedDict, total=False):
    pass


class ResetAllResourceLogLevelsRequest(ServiceRequest):
    pass


class ResetAllResourceLogLevelsResponse(TypedDict, total=False):
    pass


class ResetResourceLogLevelRequest(ServiceRequest):
    ResourceIdentifier: ResourceIdentifier
    ResourceType: ResourceType


class ResetResourceLogLevelResponse(TypedDict, total=False):
    pass


class SendDataToMulticastGroupRequest(ServiceRequest):
    Id: MulticastGroupId
    PayloadData: PayloadData
    WirelessMetadata: MulticastWirelessMetadata


class SendDataToMulticastGroupResponse(TypedDict, total=False):
    MessageId: Optional[MulticastGroupMessageId]


class SidewalkSendDataToDevice(TypedDict, total=False):
    Seq: Optional[Seq]
    MessageType: Optional[MessageType]


class WirelessMetadata(TypedDict, total=False):
    LoRaWAN: Optional[LoRaWANSendDataToDevice]
    Sidewalk: Optional[SidewalkSendDataToDevice]


class SendDataToWirelessDeviceRequest(ServiceRequest):
    Id: WirelessDeviceId
    TransmitMode: TransmitMode
    PayloadData: PayloadData
    WirelessMetadata: Optional[WirelessMetadata]


class SendDataToWirelessDeviceResponse(TypedDict, total=False):
    MessageId: Optional[MessageId]


class SidewalkUpdateAccount(TypedDict, total=False):
    AppServerPrivateKey: Optional[AppServerPrivateKey]


class StartBulkAssociateWirelessDeviceWithMulticastGroupRequest(ServiceRequest):
    Id: MulticastGroupId
    QueryString: Optional[QueryString]
    Tags: Optional[TagList]


class StartBulkAssociateWirelessDeviceWithMulticastGroupResponse(TypedDict, total=False):
    pass


class StartBulkDisassociateWirelessDeviceFromMulticastGroupRequest(ServiceRequest):
    Id: MulticastGroupId
    QueryString: Optional[QueryString]
    Tags: Optional[TagList]


class StartBulkDisassociateWirelessDeviceFromMulticastGroupResponse(TypedDict, total=False):
    pass


class StartFuotaTaskRequest(ServiceRequest):
    Id: FuotaTaskId
    LoRaWAN: Optional[LoRaWANStartFuotaTask]


class StartFuotaTaskResponse(TypedDict, total=False):
    pass


class StartMulticastGroupSessionRequest(ServiceRequest):
    Id: MulticastGroupId
    LoRaWAN: LoRaWANMulticastSession


class StartMulticastGroupSessionResponse(TypedDict, total=False):
    pass


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    ResourceArn: AmazonResourceName
    Tags: TagList


class TagResourceResponse(TypedDict, total=False):
    pass


class TestWirelessDeviceRequest(ServiceRequest):
    Id: WirelessDeviceId


class TestWirelessDeviceResponse(TypedDict, total=False):
    Result: Optional[Result]


class UntagResourceRequest(ServiceRequest):
    ResourceArn: AmazonResourceName
    TagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateDestinationRequest(ServiceRequest):
    Name: DestinationName
    ExpressionType: Optional[ExpressionType]
    Expression: Optional[Expression]
    Description: Optional[Description]
    RoleArn: Optional[RoleArn]


class UpdateDestinationResponse(TypedDict, total=False):
    pass


class UpdateFuotaTaskRequest(ServiceRequest):
    Id: FuotaTaskId
    Name: Optional[FuotaTaskName]
    Description: Optional[Description]
    LoRaWAN: Optional[LoRaWANFuotaTask]
    FirmwareUpdateImage: Optional[FirmwareUpdateImage]
    FirmwareUpdateRole: Optional[FirmwareUpdateRole]


class UpdateFuotaTaskResponse(TypedDict, total=False):
    pass


class UpdateLogLevelsByResourceTypesRequest(ServiceRequest):
    DefaultLogLevel: Optional[LogLevel]
    WirelessDeviceLogOptions: Optional[WirelessDeviceLogOptionList]
    WirelessGatewayLogOptions: Optional[WirelessGatewayLogOptionList]


class UpdateLogLevelsByResourceTypesResponse(TypedDict, total=False):
    pass


class UpdateMulticastGroupRequest(ServiceRequest):
    Id: MulticastGroupId
    Name: Optional[MulticastGroupName]
    Description: Optional[Description]
    LoRaWAN: Optional[LoRaWANMulticast]


class UpdateMulticastGroupResponse(TypedDict, total=False):
    pass


class UpdateNetworkAnalyzerConfigurationRequest(ServiceRequest):
    ConfigurationName: NetworkAnalyzerConfigurationName
    TraceContent: Optional[TraceContent]
    WirelessDevicesToAdd: Optional[WirelessDeviceList]
    WirelessDevicesToRemove: Optional[WirelessDeviceList]
    WirelessGatewaysToAdd: Optional[WirelessGatewayList]
    WirelessGatewaysToRemove: Optional[WirelessGatewayList]


class UpdateNetworkAnalyzerConfigurationResponse(TypedDict, total=False):
    pass


class UpdatePartnerAccountRequest(ServiceRequest):
    Sidewalk: SidewalkUpdateAccount
    PartnerAccountId: PartnerAccountId
    PartnerType: PartnerType


class UpdatePartnerAccountResponse(TypedDict, total=False):
    pass


class UpdateResourceEventConfigurationRequest(ServiceRequest):
    Identifier: Identifier
    IdentifierType: IdentifierType
    PartnerType: Optional[EventNotificationPartnerType]
    DeviceRegistrationState: Optional[DeviceRegistrationStateEventConfiguration]
    Proximity: Optional[ProximityEventConfiguration]


class UpdateResourceEventConfigurationResponse(TypedDict, total=False):
    pass


class UpdateWirelessDeviceRequest(ServiceRequest):
    Id: WirelessDeviceId
    DestinationName: Optional[DestinationName]
    Name: Optional[WirelessDeviceName]
    Description: Optional[Description]
    LoRaWAN: Optional[LoRaWANUpdateDevice]


class UpdateWirelessDeviceResponse(TypedDict, total=False):
    pass


class UpdateWirelessGatewayRequest(ServiceRequest):
    Id: WirelessGatewayId
    Name: Optional[WirelessGatewayName]
    Description: Optional[Description]
    JoinEuiFilters: Optional[JoinEuiFilters]
    NetIdFilters: Optional[NetIdFilters]


class UpdateWirelessGatewayResponse(TypedDict, total=False):
    pass


class IotwirelessApi:

    service = "iotwireless"
    version = "2020-11-22"

    @handler("AssociateAwsAccountWithPartnerAccount")
    def associate_aws_account_with_partner_account(
        self,
        context: RequestContext,
        sidewalk: SidewalkAccountInfo,
        client_request_token: ClientRequestToken = None,
        tags: TagList = None,
    ) -> AssociateAwsAccountWithPartnerAccountResponse:
        raise NotImplementedError

    @handler("AssociateMulticastGroupWithFuotaTask")
    def associate_multicast_group_with_fuota_task(
        self, context: RequestContext, id: FuotaTaskId, multicast_group_id: MulticastGroupId
    ) -> AssociateMulticastGroupWithFuotaTaskResponse:
        raise NotImplementedError

    @handler("AssociateWirelessDeviceWithFuotaTask")
    def associate_wireless_device_with_fuota_task(
        self, context: RequestContext, id: FuotaTaskId, wireless_device_id: WirelessDeviceId
    ) -> AssociateWirelessDeviceWithFuotaTaskResponse:
        raise NotImplementedError

    @handler("AssociateWirelessDeviceWithMulticastGroup")
    def associate_wireless_device_with_multicast_group(
        self, context: RequestContext, id: MulticastGroupId, wireless_device_id: WirelessDeviceId
    ) -> AssociateWirelessDeviceWithMulticastGroupResponse:
        raise NotImplementedError

    @handler("AssociateWirelessDeviceWithThing")
    def associate_wireless_device_with_thing(
        self, context: RequestContext, id: WirelessDeviceId, thing_arn: ThingArn
    ) -> AssociateWirelessDeviceWithThingResponse:
        raise NotImplementedError

    @handler("AssociateWirelessGatewayWithCertificate")
    def associate_wireless_gateway_with_certificate(
        self, context: RequestContext, id: WirelessGatewayId, iot_certificate_id: IotCertificateId
    ) -> AssociateWirelessGatewayWithCertificateResponse:
        raise NotImplementedError

    @handler("AssociateWirelessGatewayWithThing")
    def associate_wireless_gateway_with_thing(
        self, context: RequestContext, id: WirelessGatewayId, thing_arn: ThingArn
    ) -> AssociateWirelessGatewayWithThingResponse:
        raise NotImplementedError

    @handler("CancelMulticastGroupSession")
    def cancel_multicast_group_session(
        self, context: RequestContext, id: MulticastGroupId
    ) -> CancelMulticastGroupSessionResponse:
        raise NotImplementedError

    @handler("CreateDestination")
    def create_destination(
        self,
        context: RequestContext,
        name: DestinationName,
        expression_type: ExpressionType,
        expression: Expression,
        role_arn: RoleArn,
        description: Description = None,
        tags: TagList = None,
        client_request_token: ClientRequestToken = None,
    ) -> CreateDestinationResponse:
        raise NotImplementedError

    @handler("CreateDeviceProfile")
    def create_device_profile(
        self,
        context: RequestContext,
        name: DeviceProfileName = None,
        lo_ra_wan: LoRaWANDeviceProfile = None,
        tags: TagList = None,
        client_request_token: ClientRequestToken = None,
    ) -> CreateDeviceProfileResponse:
        raise NotImplementedError

    @handler("CreateFuotaTask")
    def create_fuota_task(
        self,
        context: RequestContext,
        firmware_update_image: FirmwareUpdateImage,
        firmware_update_role: FirmwareUpdateRole,
        name: FuotaTaskName = None,
        description: Description = None,
        client_request_token: ClientRequestToken = None,
        lo_ra_wan: LoRaWANFuotaTask = None,
        tags: TagList = None,
    ) -> CreateFuotaTaskResponse:
        raise NotImplementedError

    @handler("CreateMulticastGroup")
    def create_multicast_group(
        self,
        context: RequestContext,
        lo_ra_wan: LoRaWANMulticast,
        name: MulticastGroupName = None,
        description: Description = None,
        client_request_token: ClientRequestToken = None,
        tags: TagList = None,
    ) -> CreateMulticastGroupResponse:
        raise NotImplementedError

    @handler("CreateServiceProfile")
    def create_service_profile(
        self,
        context: RequestContext,
        name: ServiceProfileName = None,
        lo_ra_wan: LoRaWANServiceProfile = None,
        tags: TagList = None,
        client_request_token: ClientRequestToken = None,
    ) -> CreateServiceProfileResponse:
        raise NotImplementedError

    @handler("CreateWirelessDevice", expand=False)
    def create_wireless_device(
        self, context: RequestContext, request: CreateWirelessDeviceRequest
    ) -> CreateWirelessDeviceResponse:
        raise NotImplementedError

    @handler("CreateWirelessGateway")
    def create_wireless_gateway(
        self,
        context: RequestContext,
        lo_ra_wan: LoRaWANGateway,
        name: WirelessGatewayName = None,
        description: Description = None,
        tags: TagList = None,
        client_request_token: ClientRequestToken = None,
    ) -> CreateWirelessGatewayResponse:
        raise NotImplementedError

    @handler("CreateWirelessGatewayTask")
    def create_wireless_gateway_task(
        self,
        context: RequestContext,
        id: WirelessGatewayId,
        wireless_gateway_task_definition_id: WirelessGatewayTaskDefinitionId,
    ) -> CreateWirelessGatewayTaskResponse:
        raise NotImplementedError

    @handler("CreateWirelessGatewayTaskDefinition")
    def create_wireless_gateway_task_definition(
        self,
        context: RequestContext,
        auto_create_tasks: AutoCreateTasks,
        name: WirelessGatewayTaskName = None,
        update: UpdateWirelessGatewayTaskCreate = None,
        client_request_token: ClientRequestToken = None,
        tags: TagList = None,
    ) -> CreateWirelessGatewayTaskDefinitionResponse:
        raise NotImplementedError

    @handler("DeleteDestination")
    def delete_destination(
        self, context: RequestContext, name: DestinationName
    ) -> DeleteDestinationResponse:
        raise NotImplementedError

    @handler("DeleteDeviceProfile")
    def delete_device_profile(
        self, context: RequestContext, id: DeviceProfileId
    ) -> DeleteDeviceProfileResponse:
        raise NotImplementedError

    @handler("DeleteFuotaTask")
    def delete_fuota_task(
        self, context: RequestContext, id: FuotaTaskId
    ) -> DeleteFuotaTaskResponse:
        raise NotImplementedError

    @handler("DeleteMulticastGroup")
    def delete_multicast_group(
        self, context: RequestContext, id: MulticastGroupId
    ) -> DeleteMulticastGroupResponse:
        raise NotImplementedError

    @handler("DeleteQueuedMessages")
    def delete_queued_messages(
        self,
        context: RequestContext,
        id: WirelessDeviceId,
        message_id: MessageId,
        wireless_device_type: WirelessDeviceType = None,
    ) -> DeleteQueuedMessagesResponse:
        raise NotImplementedError

    @handler("DeleteServiceProfile")
    def delete_service_profile(
        self, context: RequestContext, id: ServiceProfileId
    ) -> DeleteServiceProfileResponse:
        raise NotImplementedError

    @handler("DeleteWirelessDevice")
    def delete_wireless_device(
        self, context: RequestContext, id: WirelessDeviceId
    ) -> DeleteWirelessDeviceResponse:
        raise NotImplementedError

    @handler("DeleteWirelessGateway")
    def delete_wireless_gateway(
        self, context: RequestContext, id: WirelessGatewayId
    ) -> DeleteWirelessGatewayResponse:
        raise NotImplementedError

    @handler("DeleteWirelessGatewayTask")
    def delete_wireless_gateway_task(
        self, context: RequestContext, id: WirelessGatewayId
    ) -> DeleteWirelessGatewayTaskResponse:
        raise NotImplementedError

    @handler("DeleteWirelessGatewayTaskDefinition")
    def delete_wireless_gateway_task_definition(
        self, context: RequestContext, id: WirelessGatewayTaskDefinitionId
    ) -> DeleteWirelessGatewayTaskDefinitionResponse:
        raise NotImplementedError

    @handler("DisassociateAwsAccountFromPartnerAccount")
    def disassociate_aws_account_from_partner_account(
        self,
        context: RequestContext,
        partner_account_id: PartnerAccountId,
        partner_type: PartnerType,
    ) -> DisassociateAwsAccountFromPartnerAccountResponse:
        raise NotImplementedError

    @handler("DisassociateMulticastGroupFromFuotaTask")
    def disassociate_multicast_group_from_fuota_task(
        self, context: RequestContext, id: FuotaTaskId, multicast_group_id: MulticastGroupId
    ) -> DisassociateMulticastGroupFromFuotaTaskResponse:
        raise NotImplementedError

    @handler("DisassociateWirelessDeviceFromFuotaTask")
    def disassociate_wireless_device_from_fuota_task(
        self, context: RequestContext, id: FuotaTaskId, wireless_device_id: WirelessDeviceId
    ) -> DisassociateWirelessDeviceFromFuotaTaskResponse:
        raise NotImplementedError

    @handler("DisassociateWirelessDeviceFromMulticastGroup")
    def disassociate_wireless_device_from_multicast_group(
        self, context: RequestContext, id: MulticastGroupId, wireless_device_id: WirelessDeviceId
    ) -> DisassociateWirelessDeviceFromMulticastGroupResponse:
        raise NotImplementedError

    @handler("DisassociateWirelessDeviceFromThing")
    def disassociate_wireless_device_from_thing(
        self, context: RequestContext, id: WirelessDeviceId
    ) -> DisassociateWirelessDeviceFromThingResponse:
        raise NotImplementedError

    @handler("DisassociateWirelessGatewayFromCertificate")
    def disassociate_wireless_gateway_from_certificate(
        self, context: RequestContext, id: WirelessGatewayId
    ) -> DisassociateWirelessGatewayFromCertificateResponse:
        raise NotImplementedError

    @handler("DisassociateWirelessGatewayFromThing")
    def disassociate_wireless_gateway_from_thing(
        self, context: RequestContext, id: WirelessGatewayId
    ) -> DisassociateWirelessGatewayFromThingResponse:
        raise NotImplementedError

    @handler("GetDestination")
    def get_destination(
        self, context: RequestContext, name: DestinationName
    ) -> GetDestinationResponse:
        raise NotImplementedError

    @handler("GetDeviceProfile")
    def get_device_profile(
        self, context: RequestContext, id: DeviceProfileId
    ) -> GetDeviceProfileResponse:
        raise NotImplementedError

    @handler("GetFuotaTask")
    def get_fuota_task(self, context: RequestContext, id: FuotaTaskId) -> GetFuotaTaskResponse:
        raise NotImplementedError

    @handler("GetLogLevelsByResourceTypes")
    def get_log_levels_by_resource_types(
        self,
        context: RequestContext,
    ) -> GetLogLevelsByResourceTypesResponse:
        raise NotImplementedError

    @handler("GetMulticastGroup")
    def get_multicast_group(
        self, context: RequestContext, id: MulticastGroupId
    ) -> GetMulticastGroupResponse:
        raise NotImplementedError

    @handler("GetMulticastGroupSession")
    def get_multicast_group_session(
        self, context: RequestContext, id: MulticastGroupId
    ) -> GetMulticastGroupSessionResponse:
        raise NotImplementedError

    @handler("GetNetworkAnalyzerConfiguration")
    def get_network_analyzer_configuration(
        self, context: RequestContext, configuration_name: NetworkAnalyzerConfigurationName
    ) -> GetNetworkAnalyzerConfigurationResponse:
        raise NotImplementedError

    @handler("GetPartnerAccount")
    def get_partner_account(
        self,
        context: RequestContext,
        partner_account_id: PartnerAccountId,
        partner_type: PartnerType,
    ) -> GetPartnerAccountResponse:
        raise NotImplementedError

    @handler("GetResourceEventConfiguration")
    def get_resource_event_configuration(
        self,
        context: RequestContext,
        identifier: Identifier,
        identifier_type: IdentifierType,
        partner_type: EventNotificationPartnerType = None,
    ) -> GetResourceEventConfigurationResponse:
        raise NotImplementedError

    @handler("GetResourceLogLevel")
    def get_resource_log_level(
        self,
        context: RequestContext,
        resource_identifier: ResourceIdentifier,
        resource_type: ResourceType,
    ) -> GetResourceLogLevelResponse:
        raise NotImplementedError

    @handler("GetServiceEndpoint")
    def get_service_endpoint(
        self, context: RequestContext, service_type: WirelessGatewayServiceType = None
    ) -> GetServiceEndpointResponse:
        raise NotImplementedError

    @handler("GetServiceProfile")
    def get_service_profile(
        self, context: RequestContext, id: ServiceProfileId
    ) -> GetServiceProfileResponse:
        raise NotImplementedError

    @handler("GetWirelessDevice")
    def get_wireless_device(
        self, context: RequestContext, identifier: Identifier, identifier_type: WirelessDeviceIdType
    ) -> GetWirelessDeviceResponse:
        raise NotImplementedError

    @handler("GetWirelessDeviceStatistics")
    def get_wireless_device_statistics(
        self, context: RequestContext, wireless_device_id: WirelessDeviceId
    ) -> GetWirelessDeviceStatisticsResponse:
        raise NotImplementedError

    @handler("GetWirelessGateway")
    def get_wireless_gateway(
        self,
        context: RequestContext,
        identifier: Identifier,
        identifier_type: WirelessGatewayIdType,
    ) -> GetWirelessGatewayResponse:
        raise NotImplementedError

    @handler("GetWirelessGatewayCertificate")
    def get_wireless_gateway_certificate(
        self, context: RequestContext, id: WirelessGatewayId
    ) -> GetWirelessGatewayCertificateResponse:
        raise NotImplementedError

    @handler("GetWirelessGatewayFirmwareInformation")
    def get_wireless_gateway_firmware_information(
        self, context: RequestContext, id: WirelessGatewayId
    ) -> GetWirelessGatewayFirmwareInformationResponse:
        raise NotImplementedError

    @handler("GetWirelessGatewayStatistics")
    def get_wireless_gateway_statistics(
        self, context: RequestContext, wireless_gateway_id: WirelessGatewayId
    ) -> GetWirelessGatewayStatisticsResponse:
        raise NotImplementedError

    @handler("GetWirelessGatewayTask")
    def get_wireless_gateway_task(
        self, context: RequestContext, id: WirelessGatewayId
    ) -> GetWirelessGatewayTaskResponse:
        raise NotImplementedError

    @handler("GetWirelessGatewayTaskDefinition")
    def get_wireless_gateway_task_definition(
        self, context: RequestContext, id: WirelessGatewayTaskDefinitionId
    ) -> GetWirelessGatewayTaskDefinitionResponse:
        raise NotImplementedError

    @handler("ListDestinations")
    def list_destinations(
        self, context: RequestContext, max_results: MaxResults = None, next_token: NextToken = None
    ) -> ListDestinationsResponse:
        raise NotImplementedError

    @handler("ListDeviceProfiles")
    def list_device_profiles(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListDeviceProfilesResponse:
        raise NotImplementedError

    @handler("ListFuotaTasks")
    def list_fuota_tasks(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListFuotaTasksResponse:
        raise NotImplementedError

    @handler("ListMulticastGroups")
    def list_multicast_groups(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListMulticastGroupsResponse:
        raise NotImplementedError

    @handler("ListMulticastGroupsByFuotaTask")
    def list_multicast_groups_by_fuota_task(
        self,
        context: RequestContext,
        id: FuotaTaskId,
        next_token: NextToken = None,
        max_results: MaxResults = None,
    ) -> ListMulticastGroupsByFuotaTaskResponse:
        raise NotImplementedError

    @handler("ListPartnerAccounts")
    def list_partner_accounts(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListPartnerAccountsResponse:
        raise NotImplementedError

    @handler("ListQueuedMessages")
    def list_queued_messages(
        self,
        context: RequestContext,
        id: WirelessDeviceId,
        next_token: NextToken = None,
        max_results: MaxResults = None,
        wireless_device_type: WirelessDeviceType = None,
    ) -> ListQueuedMessagesResponse:
        raise NotImplementedError

    @handler("ListServiceProfiles")
    def list_service_profiles(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListServiceProfilesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ListWirelessDevices")
    def list_wireless_devices(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        destination_name: DestinationName = None,
        device_profile_id: DeviceProfileId = None,
        service_profile_id: ServiceProfileId = None,
        wireless_device_type: WirelessDeviceType = None,
        fuota_task_id: FuotaTaskId = None,
        multicast_group_id: MulticastGroupId = None,
    ) -> ListWirelessDevicesResponse:
        raise NotImplementedError

    @handler("ListWirelessGatewayTaskDefinitions")
    def list_wireless_gateway_task_definitions(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: NextToken = None,
        task_definition_type: WirelessGatewayTaskDefinitionType = None,
    ) -> ListWirelessGatewayTaskDefinitionsResponse:
        raise NotImplementedError

    @handler("ListWirelessGateways")
    def list_wireless_gateways(
        self, context: RequestContext, next_token: NextToken = None, max_results: MaxResults = None
    ) -> ListWirelessGatewaysResponse:
        raise NotImplementedError

    @handler("PutResourceLogLevel")
    def put_resource_log_level(
        self,
        context: RequestContext,
        resource_identifier: ResourceIdentifier,
        resource_type: ResourceType,
        log_level: LogLevel,
    ) -> PutResourceLogLevelResponse:
        raise NotImplementedError

    @handler("ResetAllResourceLogLevels")
    def reset_all_resource_log_levels(
        self,
        context: RequestContext,
    ) -> ResetAllResourceLogLevelsResponse:
        raise NotImplementedError

    @handler("ResetResourceLogLevel")
    def reset_resource_log_level(
        self,
        context: RequestContext,
        resource_identifier: ResourceIdentifier,
        resource_type: ResourceType,
    ) -> ResetResourceLogLevelResponse:
        raise NotImplementedError

    @handler("SendDataToMulticastGroup")
    def send_data_to_multicast_group(
        self,
        context: RequestContext,
        id: MulticastGroupId,
        payload_data: PayloadData,
        wireless_metadata: MulticastWirelessMetadata,
    ) -> SendDataToMulticastGroupResponse:
        raise NotImplementedError

    @handler("SendDataToWirelessDevice")
    def send_data_to_wireless_device(
        self,
        context: RequestContext,
        id: WirelessDeviceId,
        transmit_mode: TransmitMode,
        payload_data: PayloadData,
        wireless_metadata: WirelessMetadata = None,
    ) -> SendDataToWirelessDeviceResponse:
        raise NotImplementedError

    @handler("StartBulkAssociateWirelessDeviceWithMulticastGroup")
    def start_bulk_associate_wireless_device_with_multicast_group(
        self,
        context: RequestContext,
        id: MulticastGroupId,
        query_string: QueryString = None,
        tags: TagList = None,
    ) -> StartBulkAssociateWirelessDeviceWithMulticastGroupResponse:
        raise NotImplementedError

    @handler("StartBulkDisassociateWirelessDeviceFromMulticastGroup")
    def start_bulk_disassociate_wireless_device_from_multicast_group(
        self,
        context: RequestContext,
        id: MulticastGroupId,
        query_string: QueryString = None,
        tags: TagList = None,
    ) -> StartBulkDisassociateWirelessDeviceFromMulticastGroupResponse:
        raise NotImplementedError

    @handler("StartFuotaTask")
    def start_fuota_task(
        self, context: RequestContext, id: FuotaTaskId, lo_ra_wan: LoRaWANStartFuotaTask = None
    ) -> StartFuotaTaskResponse:
        raise NotImplementedError

    @handler("StartMulticastGroupSession")
    def start_multicast_group_session(
        self, context: RequestContext, id: MulticastGroupId, lo_ra_wan: LoRaWANMulticastSession
    ) -> StartMulticastGroupSessionResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: TagList
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("TestWirelessDevice")
    def test_wireless_device(
        self, context: RequestContext, id: WirelessDeviceId
    ) -> TestWirelessDeviceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateDestination")
    def update_destination(
        self,
        context: RequestContext,
        name: DestinationName,
        expression_type: ExpressionType = None,
        expression: Expression = None,
        description: Description = None,
        role_arn: RoleArn = None,
    ) -> UpdateDestinationResponse:
        raise NotImplementedError

    @handler("UpdateFuotaTask")
    def update_fuota_task(
        self,
        context: RequestContext,
        id: FuotaTaskId,
        name: FuotaTaskName = None,
        description: Description = None,
        lo_ra_wan: LoRaWANFuotaTask = None,
        firmware_update_image: FirmwareUpdateImage = None,
        firmware_update_role: FirmwareUpdateRole = None,
    ) -> UpdateFuotaTaskResponse:
        raise NotImplementedError

    @handler("UpdateLogLevelsByResourceTypes")
    def update_log_levels_by_resource_types(
        self,
        context: RequestContext,
        default_log_level: LogLevel = None,
        wireless_device_log_options: WirelessDeviceLogOptionList = None,
        wireless_gateway_log_options: WirelessGatewayLogOptionList = None,
    ) -> UpdateLogLevelsByResourceTypesResponse:
        raise NotImplementedError

    @handler("UpdateMulticastGroup")
    def update_multicast_group(
        self,
        context: RequestContext,
        id: MulticastGroupId,
        name: MulticastGroupName = None,
        description: Description = None,
        lo_ra_wan: LoRaWANMulticast = None,
    ) -> UpdateMulticastGroupResponse:
        raise NotImplementedError

    @handler("UpdateNetworkAnalyzerConfiguration")
    def update_network_analyzer_configuration(
        self,
        context: RequestContext,
        configuration_name: NetworkAnalyzerConfigurationName,
        trace_content: TraceContent = None,
        wireless_devices_to_add: WirelessDeviceList = None,
        wireless_devices_to_remove: WirelessDeviceList = None,
        wireless_gateways_to_add: WirelessGatewayList = None,
        wireless_gateways_to_remove: WirelessGatewayList = None,
    ) -> UpdateNetworkAnalyzerConfigurationResponse:
        raise NotImplementedError

    @handler("UpdatePartnerAccount")
    def update_partner_account(
        self,
        context: RequestContext,
        sidewalk: SidewalkUpdateAccount,
        partner_account_id: PartnerAccountId,
        partner_type: PartnerType,
    ) -> UpdatePartnerAccountResponse:
        raise NotImplementedError

    @handler("UpdateResourceEventConfiguration")
    def update_resource_event_configuration(
        self,
        context: RequestContext,
        identifier: Identifier,
        identifier_type: IdentifierType,
        partner_type: EventNotificationPartnerType = None,
        device_registration_state: DeviceRegistrationStateEventConfiguration = None,
        proximity: ProximityEventConfiguration = None,
    ) -> UpdateResourceEventConfigurationResponse:
        raise NotImplementedError

    @handler("UpdateWirelessDevice")
    def update_wireless_device(
        self,
        context: RequestContext,
        id: WirelessDeviceId,
        destination_name: DestinationName = None,
        name: WirelessDeviceName = None,
        description: Description = None,
        lo_ra_wan: LoRaWANUpdateDevice = None,
    ) -> UpdateWirelessDeviceResponse:
        raise NotImplementedError

    @handler("UpdateWirelessGateway")
    def update_wireless_gateway(
        self,
        context: RequestContext,
        id: WirelessGatewayId,
        name: WirelessGatewayName = None,
        description: Description = None,
        join_eui_filters: JoinEuiFilters = None,
        net_id_filters: NetIdFilters = None,
    ) -> UpdateWirelessGatewayResponse:
        raise NotImplementedError

import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AccessPointArn = str
AccessPointId = str
AvailabilityZoneId = str
AvailabilityZoneName = str
AwsAccountId = str
Backup = bool
BypassPolicyLockoutSafetyCheck = bool
ClientToken = str
CreationToken = str
Encrypted = bool
ErrorCode = str
ErrorMessage = str
FileSystemArn = str
FileSystemId = str
IpAddress = str
KmsKeyId = str
Marker = str
MaxItems = int
MaxResults = int
MountTargetCount = int
MountTargetId = str
Name = str
NetworkInterfaceId = str
Path = str
Permissions = str
Policy = str
ProvisionedThroughputInMibps = float
RegionName = str
ResourceId = str
SecurityGroup = str
SubnetId = str
TagKey = str
TagValue = str
Token = str
VpcId = str


class LifeCycleState(str):
    creating = "creating"
    available = "available"
    updating = "updating"
    deleting = "deleting"
    deleted = "deleted"
    error = "error"


class PerformanceMode(str):
    generalPurpose = "generalPurpose"
    maxIO = "maxIO"


class ReplicationStatus(str):
    ENABLED = "ENABLED"
    ENABLING = "ENABLING"
    DELETING = "DELETING"
    ERROR = "ERROR"


class Resource(str):
    FILE_SYSTEM = "FILE_SYSTEM"
    MOUNT_TARGET = "MOUNT_TARGET"


class ResourceIdType(str):
    LONG_ID = "LONG_ID"
    SHORT_ID = "SHORT_ID"


class Status(str):
    ENABLED = "ENABLED"
    ENABLING = "ENABLING"
    DISABLED = "DISABLED"
    DISABLING = "DISABLING"


class ThroughputMode(str):
    bursting = "bursting"
    provisioned = "provisioned"


class TransitionToIARules(str):
    AFTER_7_DAYS = "AFTER_7_DAYS"
    AFTER_14_DAYS = "AFTER_14_DAYS"
    AFTER_30_DAYS = "AFTER_30_DAYS"
    AFTER_60_DAYS = "AFTER_60_DAYS"
    AFTER_90_DAYS = "AFTER_90_DAYS"


class TransitionToPrimaryStorageClassRules(str):
    AFTER_1_ACCESS = "AFTER_1_ACCESS"


class AccessPointAlreadyExists(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]
    AccessPointId: AccessPointId


class AccessPointLimitExceeded(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class AccessPointNotFound(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class AvailabilityZonesMismatch(ServiceException):
    ErrorCode: Optional[ErrorCode]
    Message: Optional[ErrorMessage]


class BadRequest(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class DependencyTimeout(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class FileSystemAlreadyExists(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]
    FileSystemId: FileSystemId


class FileSystemInUse(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class FileSystemLimitExceeded(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class FileSystemNotFound(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class IncorrectFileSystemLifeCycleState(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class IncorrectMountTargetState(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class InsufficientThroughputCapacity(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class InternalServerError(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class InvalidPolicyException(ServiceException):
    ErrorCode: Optional[ErrorCode]
    Message: Optional[ErrorMessage]


class IpAddressInUse(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class MountTargetConflict(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class MountTargetNotFound(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class NetworkInterfaceLimitExceeded(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class NoFreeAddressesInSubnet(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class PolicyNotFound(ServiceException):
    ErrorCode: Optional[ErrorCode]
    Message: Optional[ErrorMessage]


class ReplicationNotFound(ServiceException):
    ErrorCode: Optional[ErrorCode]
    Message: Optional[ErrorMessage]


class SecurityGroupLimitExceeded(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class SecurityGroupNotFound(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class SubnetNotFound(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class ThroughputLimitExceeded(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class TooManyRequests(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class UnsupportedAvailabilityZone(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


class ValidationException(ServiceException):
    ErrorCode: ErrorCode
    Message: Optional[ErrorMessage]


OwnerGid = int
OwnerUid = int


class CreationInfo(TypedDict, total=False):
    OwnerUid: OwnerUid
    OwnerGid: OwnerGid
    Permissions: Permissions


class RootDirectory(TypedDict, total=False):
    Path: Optional[Path]
    CreationInfo: Optional[CreationInfo]


Gid = int
SecondaryGids = List[Gid]
Uid = int


class PosixUser(TypedDict, total=False):
    Uid: Uid
    Gid: Gid
    SecondaryGids: Optional[SecondaryGids]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


Tags = List[Tag]


class AccessPointDescription(TypedDict, total=False):
    ClientToken: Optional[ClientToken]
    Name: Optional[Name]
    Tags: Optional[Tags]
    AccessPointId: Optional[AccessPointId]
    AccessPointArn: Optional[AccessPointArn]
    FileSystemId: Optional[FileSystemId]
    PosixUser: Optional[PosixUser]
    RootDirectory: Optional[RootDirectory]
    OwnerId: Optional[AwsAccountId]
    LifeCycleState: Optional[LifeCycleState]


AccessPointDescriptions = List[AccessPointDescription]


class BackupPolicy(TypedDict, total=False):
    Status: Status


class BackupPolicyDescription(TypedDict, total=False):
    BackupPolicy: Optional[BackupPolicy]


class CreateAccessPointRequest(ServiceRequest):
    ClientToken: ClientToken
    Tags: Optional[Tags]
    FileSystemId: FileSystemId
    PosixUser: Optional[PosixUser]
    RootDirectory: Optional[RootDirectory]


class CreateFileSystemRequest(ServiceRequest):
    CreationToken: CreationToken
    PerformanceMode: Optional[PerformanceMode]
    Encrypted: Optional[Encrypted]
    KmsKeyId: Optional[KmsKeyId]
    ThroughputMode: Optional[ThroughputMode]
    ProvisionedThroughputInMibps: Optional[ProvisionedThroughputInMibps]
    AvailabilityZoneName: Optional[AvailabilityZoneName]
    Backup: Optional[Backup]
    Tags: Optional[Tags]


SecurityGroups = List[SecurityGroup]


class CreateMountTargetRequest(ServiceRequest):
    FileSystemId: FileSystemId
    SubnetId: SubnetId
    IpAddress: Optional[IpAddress]
    SecurityGroups: Optional[SecurityGroups]


class DestinationToCreate(TypedDict, total=False):
    Region: Optional[RegionName]
    AvailabilityZoneName: Optional[AvailabilityZoneName]
    KmsKeyId: Optional[KmsKeyId]


DestinationsToCreate = List[DestinationToCreate]


class CreateReplicationConfigurationRequest(ServiceRequest):
    SourceFileSystemId: FileSystemId
    Destinations: DestinationsToCreate


class CreateTagsRequest(ServiceRequest):
    FileSystemId: FileSystemId
    Tags: Tags


class DeleteAccessPointRequest(ServiceRequest):
    AccessPointId: AccessPointId


class DeleteFileSystemPolicyRequest(ServiceRequest):
    FileSystemId: FileSystemId


class DeleteFileSystemRequest(ServiceRequest):
    FileSystemId: FileSystemId


class DeleteMountTargetRequest(ServiceRequest):
    MountTargetId: MountTargetId


class DeleteReplicationConfigurationRequest(ServiceRequest):
    SourceFileSystemId: FileSystemId


TagKeys = List[TagKey]


class DeleteTagsRequest(ServiceRequest):
    FileSystemId: FileSystemId
    TagKeys: TagKeys


class DescribeAccessPointsRequest(ServiceRequest):
    MaxResults: Optional[MaxResults]
    NextToken: Optional[Token]
    AccessPointId: Optional[AccessPointId]
    FileSystemId: Optional[FileSystemId]


class DescribeAccessPointsResponse(TypedDict, total=False):
    AccessPoints: Optional[AccessPointDescriptions]
    NextToken: Optional[Token]


class DescribeAccountPreferencesRequest(ServiceRequest):
    NextToken: Optional[Token]
    MaxResults: Optional[MaxResults]


Resources = List[Resource]


class ResourceIdPreference(TypedDict, total=False):
    ResourceIdType: Optional[ResourceIdType]
    Resources: Optional[Resources]


class DescribeAccountPreferencesResponse(TypedDict, total=False):
    ResourceIdPreference: Optional[ResourceIdPreference]
    NextToken: Optional[Token]


class DescribeBackupPolicyRequest(ServiceRequest):
    FileSystemId: FileSystemId


class DescribeFileSystemPolicyRequest(ServiceRequest):
    FileSystemId: FileSystemId


class DescribeFileSystemsRequest(ServiceRequest):
    MaxItems: Optional[MaxItems]
    Marker: Optional[Marker]
    CreationToken: Optional[CreationToken]
    FileSystemId: Optional[FileSystemId]


FileSystemNullableSizeValue = int
Timestamp = datetime
FileSystemSizeValue = int


class FileSystemSize(TypedDict, total=False):
    Value: FileSystemSizeValue
    Timestamp: Optional[Timestamp]
    ValueInIA: Optional[FileSystemNullableSizeValue]
    ValueInStandard: Optional[FileSystemNullableSizeValue]


class FileSystemDescription(TypedDict, total=False):
    OwnerId: AwsAccountId
    CreationToken: CreationToken
    FileSystemId: FileSystemId
    FileSystemArn: Optional[FileSystemArn]
    CreationTime: Timestamp
    LifeCycleState: LifeCycleState
    Name: Optional[TagValue]
    NumberOfMountTargets: MountTargetCount
    SizeInBytes: FileSystemSize
    PerformanceMode: PerformanceMode
    Encrypted: Optional[Encrypted]
    KmsKeyId: Optional[KmsKeyId]
    ThroughputMode: Optional[ThroughputMode]
    ProvisionedThroughputInMibps: Optional[ProvisionedThroughputInMibps]
    AvailabilityZoneName: Optional[AvailabilityZoneName]
    AvailabilityZoneId: Optional[AvailabilityZoneId]
    Tags: Tags


FileSystemDescriptions = List[FileSystemDescription]


class DescribeFileSystemsResponse(TypedDict, total=False):
    Marker: Optional[Marker]
    FileSystems: Optional[FileSystemDescriptions]
    NextMarker: Optional[Marker]


class DescribeLifecycleConfigurationRequest(ServiceRequest):
    FileSystemId: FileSystemId


class DescribeMountTargetSecurityGroupsRequest(ServiceRequest):
    MountTargetId: MountTargetId


class DescribeMountTargetSecurityGroupsResponse(TypedDict, total=False):
    SecurityGroups: SecurityGroups


class DescribeMountTargetsRequest(ServiceRequest):
    MaxItems: Optional[MaxItems]
    Marker: Optional[Marker]
    FileSystemId: Optional[FileSystemId]
    MountTargetId: Optional[MountTargetId]
    AccessPointId: Optional[AccessPointId]


class MountTargetDescription(TypedDict, total=False):
    OwnerId: Optional[AwsAccountId]
    MountTargetId: MountTargetId
    FileSystemId: FileSystemId
    SubnetId: SubnetId
    LifeCycleState: LifeCycleState
    IpAddress: Optional[IpAddress]
    NetworkInterfaceId: Optional[NetworkInterfaceId]
    AvailabilityZoneId: Optional[AvailabilityZoneId]
    AvailabilityZoneName: Optional[AvailabilityZoneName]
    VpcId: Optional[VpcId]


MountTargetDescriptions = List[MountTargetDescription]


class DescribeMountTargetsResponse(TypedDict, total=False):
    Marker: Optional[Marker]
    MountTargets: Optional[MountTargetDescriptions]
    NextMarker: Optional[Marker]


class DescribeReplicationConfigurationsRequest(ServiceRequest):
    FileSystemId: Optional[FileSystemId]
    NextToken: Optional[Token]
    MaxResults: Optional[MaxResults]


class Destination(TypedDict, total=False):
    Status: ReplicationStatus
    FileSystemId: FileSystemId
    Region: RegionName
    LastReplicatedTimestamp: Optional[Timestamp]


Destinations = List[Destination]


class ReplicationConfigurationDescription(TypedDict, total=False):
    SourceFileSystemId: FileSystemId
    SourceFileSystemRegion: RegionName
    SourceFileSystemArn: FileSystemArn
    OriginalSourceFileSystemArn: FileSystemArn
    CreationTime: Timestamp
    Destinations: Destinations


ReplicationConfigurationDescriptions = List[ReplicationConfigurationDescription]


class DescribeReplicationConfigurationsResponse(TypedDict, total=False):
    Replications: Optional[ReplicationConfigurationDescriptions]
    NextToken: Optional[Token]


class DescribeTagsRequest(ServiceRequest):
    MaxItems: Optional[MaxItems]
    Marker: Optional[Marker]
    FileSystemId: FileSystemId


class DescribeTagsResponse(TypedDict, total=False):
    Marker: Optional[Marker]
    Tags: Tags
    NextMarker: Optional[Marker]


class FileSystemPolicyDescription(TypedDict, total=False):
    FileSystemId: Optional[FileSystemId]
    Policy: Optional[Policy]


class LifecyclePolicy(TypedDict, total=False):
    TransitionToIA: Optional[TransitionToIARules]
    TransitionToPrimaryStorageClass: Optional[TransitionToPrimaryStorageClassRules]


LifecyclePolicies = List[LifecyclePolicy]


class LifecycleConfigurationDescription(TypedDict, total=False):
    LifecyclePolicies: Optional[LifecyclePolicies]


class ListTagsForResourceRequest(ServiceRequest):
    ResourceId: ResourceId
    MaxResults: Optional[MaxResults]
    NextToken: Optional[Token]


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: Optional[Tags]
    NextToken: Optional[Token]


class ModifyMountTargetSecurityGroupsRequest(ServiceRequest):
    MountTargetId: MountTargetId
    SecurityGroups: Optional[SecurityGroups]


class PutAccountPreferencesRequest(ServiceRequest):
    ResourceIdType: ResourceIdType


class PutAccountPreferencesResponse(TypedDict, total=False):
    ResourceIdPreference: Optional[ResourceIdPreference]


class PutBackupPolicyRequest(ServiceRequest):
    FileSystemId: FileSystemId
    BackupPolicy: BackupPolicy


class PutFileSystemPolicyRequest(ServiceRequest):
    FileSystemId: FileSystemId
    Policy: Policy
    BypassPolicyLockoutSafetyCheck: Optional[BypassPolicyLockoutSafetyCheck]


class PutLifecycleConfigurationRequest(ServiceRequest):
    FileSystemId: FileSystemId
    LifecyclePolicies: LifecyclePolicies


class TagResourceRequest(ServiceRequest):
    ResourceId: ResourceId
    Tags: Tags


class UntagResourceRequest(ServiceRequest):
    ResourceId: ResourceId
    TagKeys: TagKeys


class UpdateFileSystemRequest(ServiceRequest):
    FileSystemId: FileSystemId
    ThroughputMode: Optional[ThroughputMode]
    ProvisionedThroughputInMibps: Optional[ProvisionedThroughputInMibps]


class EfsApi:

    service = "efs"
    version = "2015-02-01"

    @handler("CreateAccessPoint")
    def create_access_point(
        self,
        context: RequestContext,
        client_token: ClientToken,
        file_system_id: FileSystemId,
        tags: Tags = None,
        posix_user: PosixUser = None,
        root_directory: RootDirectory = None,
    ) -> AccessPointDescription:
        raise NotImplementedError

    @handler("CreateFileSystem")
    def create_file_system(
        self,
        context: RequestContext,
        creation_token: CreationToken,
        performance_mode: PerformanceMode = None,
        encrypted: Encrypted = None,
        kms_key_id: KmsKeyId = None,
        throughput_mode: ThroughputMode = None,
        provisioned_throughput_in_mibps: ProvisionedThroughputInMibps = None,
        availability_zone_name: AvailabilityZoneName = None,
        backup: Backup = None,
        tags: Tags = None,
    ) -> FileSystemDescription:
        raise NotImplementedError

    @handler("CreateMountTarget")
    def create_mount_target(
        self,
        context: RequestContext,
        file_system_id: FileSystemId,
        subnet_id: SubnetId,
        ip_address: IpAddress = None,
        security_groups: SecurityGroups = None,
    ) -> MountTargetDescription:
        raise NotImplementedError

    @handler("CreateReplicationConfiguration")
    def create_replication_configuration(
        self,
        context: RequestContext,
        source_file_system_id: FileSystemId,
        destinations: DestinationsToCreate,
    ) -> ReplicationConfigurationDescription:
        raise NotImplementedError

    @handler("CreateTags")
    def create_tags(
        self, context: RequestContext, file_system_id: FileSystemId, tags: Tags
    ) -> None:
        raise NotImplementedError

    @handler("DeleteAccessPoint")
    def delete_access_point(self, context: RequestContext, access_point_id: AccessPointId) -> None:
        raise NotImplementedError

    @handler("DeleteFileSystem")
    def delete_file_system(self, context: RequestContext, file_system_id: FileSystemId) -> None:
        raise NotImplementedError

    @handler("DeleteFileSystemPolicy")
    def delete_file_system_policy(
        self, context: RequestContext, file_system_id: FileSystemId
    ) -> None:
        raise NotImplementedError

    @handler("DeleteMountTarget")
    def delete_mount_target(self, context: RequestContext, mount_target_id: MountTargetId) -> None:
        raise NotImplementedError

    @handler("DeleteReplicationConfiguration")
    def delete_replication_configuration(
        self, context: RequestContext, source_file_system_id: FileSystemId
    ) -> None:
        raise NotImplementedError

    @handler("DeleteTags")
    def delete_tags(
        self, context: RequestContext, file_system_id: FileSystemId, tag_keys: TagKeys
    ) -> None:
        raise NotImplementedError

    @handler("DescribeAccessPoints")
    def describe_access_points(
        self,
        context: RequestContext,
        max_results: MaxResults = None,
        next_token: Token = None,
        access_point_id: AccessPointId = None,
        file_system_id: FileSystemId = None,
    ) -> DescribeAccessPointsResponse:
        raise NotImplementedError

    @handler("DescribeAccountPreferences")
    def describe_account_preferences(
        self, context: RequestContext, next_token: Token = None, max_results: MaxResults = None
    ) -> DescribeAccountPreferencesResponse:
        raise NotImplementedError

    @handler("DescribeBackupPolicy")
    def describe_backup_policy(
        self, context: RequestContext, file_system_id: FileSystemId
    ) -> BackupPolicyDescription:
        raise NotImplementedError

    @handler("DescribeFileSystemPolicy")
    def describe_file_system_policy(
        self, context: RequestContext, file_system_id: FileSystemId
    ) -> FileSystemPolicyDescription:
        raise NotImplementedError

    @handler("DescribeFileSystems")
    def describe_file_systems(
        self,
        context: RequestContext,
        max_items: MaxItems = None,
        marker: Marker = None,
        creation_token: CreationToken = None,
        file_system_id: FileSystemId = None,
    ) -> DescribeFileSystemsResponse:
        raise NotImplementedError

    @handler("DescribeLifecycleConfiguration")
    def describe_lifecycle_configuration(
        self, context: RequestContext, file_system_id: FileSystemId
    ) -> LifecycleConfigurationDescription:
        raise NotImplementedError

    @handler("DescribeMountTargetSecurityGroups")
    def describe_mount_target_security_groups(
        self, context: RequestContext, mount_target_id: MountTargetId
    ) -> DescribeMountTargetSecurityGroupsResponse:
        raise NotImplementedError

    @handler("DescribeMountTargets")
    def describe_mount_targets(
        self,
        context: RequestContext,
        max_items: MaxItems = None,
        marker: Marker = None,
        file_system_id: FileSystemId = None,
        mount_target_id: MountTargetId = None,
        access_point_id: AccessPointId = None,
    ) -> DescribeMountTargetsResponse:
        raise NotImplementedError

    @handler("DescribeReplicationConfigurations")
    def describe_replication_configurations(
        self,
        context: RequestContext,
        file_system_id: FileSystemId = None,
        next_token: Token = None,
        max_results: MaxResults = None,
    ) -> DescribeReplicationConfigurationsResponse:
        raise NotImplementedError

    @handler("DescribeTags")
    def describe_tags(
        self,
        context: RequestContext,
        file_system_id: FileSystemId,
        max_items: MaxItems = None,
        marker: Marker = None,
    ) -> DescribeTagsResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self,
        context: RequestContext,
        resource_id: ResourceId,
        max_results: MaxResults = None,
        next_token: Token = None,
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("ModifyMountTargetSecurityGroups")
    def modify_mount_target_security_groups(
        self,
        context: RequestContext,
        mount_target_id: MountTargetId,
        security_groups: SecurityGroups = None,
    ) -> None:
        raise NotImplementedError

    @handler("PutAccountPreferences")
    def put_account_preferences(
        self, context: RequestContext, resource_id_type: ResourceIdType
    ) -> PutAccountPreferencesResponse:
        raise NotImplementedError

    @handler("PutBackupPolicy")
    def put_backup_policy(
        self, context: RequestContext, file_system_id: FileSystemId, backup_policy: BackupPolicy
    ) -> BackupPolicyDescription:
        raise NotImplementedError

    @handler("PutFileSystemPolicy")
    def put_file_system_policy(
        self,
        context: RequestContext,
        file_system_id: FileSystemId,
        policy: Policy,
        bypass_policy_lockout_safety_check: BypassPolicyLockoutSafetyCheck = None,
    ) -> FileSystemPolicyDescription:
        raise NotImplementedError

    @handler("PutLifecycleConfiguration")
    def put_lifecycle_configuration(
        self,
        context: RequestContext,
        file_system_id: FileSystemId,
        lifecycle_policies: LifecyclePolicies,
    ) -> LifecycleConfigurationDescription:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(self, context: RequestContext, resource_id: ResourceId, tags: Tags) -> None:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_id: ResourceId, tag_keys: TagKeys
    ) -> None:
        raise NotImplementedError

    @handler("UpdateFileSystem")
    def update_file_system(
        self,
        context: RequestContext,
        file_system_id: FileSystemId,
        throughput_mode: ThroughputMode = None,
        provisioned_throughput_in_mibps: ProvisionedThroughputInMibps = None,
    ) -> FileSystemDescription:
        raise NotImplementedError

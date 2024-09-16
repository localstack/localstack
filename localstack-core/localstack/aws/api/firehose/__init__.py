from datetime import datetime
from enum import StrEnum
from typing import Dict, List, Optional, TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AWSKMSKeyARN = str
AmazonOpenSearchServerlessBufferingIntervalInSeconds = int
AmazonOpenSearchServerlessBufferingSizeInMBs = int
AmazonOpenSearchServerlessCollectionEndpoint = str
AmazonOpenSearchServerlessIndexName = str
AmazonOpenSearchServerlessRetryDurationInSeconds = int
AmazonopensearchserviceBufferingIntervalInSeconds = int
AmazonopensearchserviceBufferingSizeInMBs = int
AmazonopensearchserviceClusterEndpoint = str
AmazonopensearchserviceDomainARN = str
AmazonopensearchserviceIndexName = str
AmazonopensearchserviceRetryDurationInSeconds = int
AmazonopensearchserviceTypeName = str
BlockSizeBytes = int
BooleanObject = bool
BucketARN = str
ClusterJDBCURL = str
CopyOptions = str
CustomTimeZone = str
DataTableColumns = str
DataTableName = str
DeliveryStreamARN = str
DeliveryStreamName = str
DeliveryStreamVersionId = str
DescribeDeliveryStreamInputLimit = int
DestinationId = str
ElasticsearchBufferingIntervalInSeconds = int
ElasticsearchBufferingSizeInMBs = int
ElasticsearchClusterEndpoint = str
ElasticsearchDomainARN = str
ElasticsearchIndexName = str
ElasticsearchRetryDurationInSeconds = int
ElasticsearchTypeName = str
ErrorCode = str
ErrorMessage = str
ErrorOutputPrefix = str
FileExtension = str
GlueDataCatalogARN = str
HECAcknowledgmentTimeoutInSeconds = int
HECEndpoint = str
HECToken = str
HttpEndpointAccessKey = str
HttpEndpointAttributeName = str
HttpEndpointAttributeValue = str
HttpEndpointBufferingIntervalInSeconds = int
HttpEndpointBufferingSizeInMBs = int
HttpEndpointName = str
HttpEndpointRetryDurationInSeconds = int
HttpEndpointUrl = str
IntervalInSeconds = int
KinesisStreamARN = str
ListDeliveryStreamsInputLimit = int
ListTagsForDeliveryStreamInputLimit = int
LogGroupName = str
LogStreamName = str
MSKClusterARN = str
NonEmptyString = str
NonEmptyStringWithoutWhitespace = str
NonNegativeIntegerObject = int
OrcRowIndexStride = int
OrcStripeSizeBytes = int
ParquetPageSizeBytes = int
Password = str
Prefix = str
ProcessorParameterValue = str
Proportion = float
PutResponseRecordId = str
RedshiftRetryDurationInSeconds = int
RetryDurationInSeconds = int
RoleARN = str
SecretARN = str
SizeInMBs = int
SnowflakeAccountUrl = str
SnowflakeBufferingIntervalInSeconds = int
SnowflakeBufferingSizeInMBs = int
SnowflakeContentColumnName = str
SnowflakeDatabase = str
SnowflakeKeyPassphrase = str
SnowflakeMetaDataColumnName = str
SnowflakePrivateKey = str
SnowflakePrivateLinkVpceId = str
SnowflakeRetryDurationInSeconds = int
SnowflakeRole = str
SnowflakeSchema = str
SnowflakeTable = str
SnowflakeUser = str
SplunkBufferingIntervalInSeconds = int
SplunkBufferingSizeInMBs = int
SplunkRetryDurationInSeconds = int
TagKey = str
TagValue = str
TopicName = str
Username = str


class AmazonOpenSearchServerlessS3BackupMode(StrEnum):
    FailedDocumentsOnly = "FailedDocumentsOnly"
    AllDocuments = "AllDocuments"


class AmazonopensearchserviceIndexRotationPeriod(StrEnum):
    NoRotation = "NoRotation"
    OneHour = "OneHour"
    OneDay = "OneDay"
    OneWeek = "OneWeek"
    OneMonth = "OneMonth"


class AmazonopensearchserviceS3BackupMode(StrEnum):
    FailedDocumentsOnly = "FailedDocumentsOnly"
    AllDocuments = "AllDocuments"


class CompressionFormat(StrEnum):
    UNCOMPRESSED = "UNCOMPRESSED"
    GZIP = "GZIP"
    ZIP = "ZIP"
    Snappy = "Snappy"
    HADOOP_SNAPPY = "HADOOP_SNAPPY"


class Connectivity(StrEnum):
    PUBLIC = "PUBLIC"
    PRIVATE = "PRIVATE"


class ContentEncoding(StrEnum):
    NONE = "NONE"
    GZIP = "GZIP"


class DefaultDocumentIdFormat(StrEnum):
    FIREHOSE_DEFAULT = "FIREHOSE_DEFAULT"
    NO_DOCUMENT_ID = "NO_DOCUMENT_ID"


class DeliveryStreamEncryptionStatus(StrEnum):
    ENABLED = "ENABLED"
    ENABLING = "ENABLING"
    ENABLING_FAILED = "ENABLING_FAILED"
    DISABLED = "DISABLED"
    DISABLING = "DISABLING"
    DISABLING_FAILED = "DISABLING_FAILED"


class DeliveryStreamFailureType(StrEnum):
    RETIRE_KMS_GRANT_FAILED = "RETIRE_KMS_GRANT_FAILED"
    CREATE_KMS_GRANT_FAILED = "CREATE_KMS_GRANT_FAILED"
    KMS_ACCESS_DENIED = "KMS_ACCESS_DENIED"
    DISABLED_KMS_KEY = "DISABLED_KMS_KEY"
    INVALID_KMS_KEY = "INVALID_KMS_KEY"
    KMS_KEY_NOT_FOUND = "KMS_KEY_NOT_FOUND"
    KMS_OPT_IN_REQUIRED = "KMS_OPT_IN_REQUIRED"
    CREATE_ENI_FAILED = "CREATE_ENI_FAILED"
    DELETE_ENI_FAILED = "DELETE_ENI_FAILED"
    SUBNET_NOT_FOUND = "SUBNET_NOT_FOUND"
    SECURITY_GROUP_NOT_FOUND = "SECURITY_GROUP_NOT_FOUND"
    ENI_ACCESS_DENIED = "ENI_ACCESS_DENIED"
    SUBNET_ACCESS_DENIED = "SUBNET_ACCESS_DENIED"
    SECURITY_GROUP_ACCESS_DENIED = "SECURITY_GROUP_ACCESS_DENIED"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


class DeliveryStreamStatus(StrEnum):
    CREATING = "CREATING"
    CREATING_FAILED = "CREATING_FAILED"
    DELETING = "DELETING"
    DELETING_FAILED = "DELETING_FAILED"
    ACTIVE = "ACTIVE"


class DeliveryStreamType(StrEnum):
    DirectPut = "DirectPut"
    KinesisStreamAsSource = "KinesisStreamAsSource"
    MSKAsSource = "MSKAsSource"


class ElasticsearchIndexRotationPeriod(StrEnum):
    NoRotation = "NoRotation"
    OneHour = "OneHour"
    OneDay = "OneDay"
    OneWeek = "OneWeek"
    OneMonth = "OneMonth"


class ElasticsearchS3BackupMode(StrEnum):
    FailedDocumentsOnly = "FailedDocumentsOnly"
    AllDocuments = "AllDocuments"


class HECEndpointType(StrEnum):
    Raw = "Raw"
    Event = "Event"


class HttpEndpointS3BackupMode(StrEnum):
    FailedDataOnly = "FailedDataOnly"
    AllData = "AllData"


class IcebergS3BackupMode(StrEnum):
    FailedDataOnly = "FailedDataOnly"
    AllData = "AllData"


class KeyType(StrEnum):
    AWS_OWNED_CMK = "AWS_OWNED_CMK"
    CUSTOMER_MANAGED_CMK = "CUSTOMER_MANAGED_CMK"


class NoEncryptionConfig(StrEnum):
    NoEncryption = "NoEncryption"


class OrcCompression(StrEnum):
    NONE = "NONE"
    ZLIB = "ZLIB"
    SNAPPY = "SNAPPY"


class OrcFormatVersion(StrEnum):
    V0_11 = "V0_11"
    V0_12 = "V0_12"


class ParquetCompression(StrEnum):
    UNCOMPRESSED = "UNCOMPRESSED"
    GZIP = "GZIP"
    SNAPPY = "SNAPPY"


class ParquetWriterVersion(StrEnum):
    V1 = "V1"
    V2 = "V2"


class ProcessorParameterName(StrEnum):
    LambdaArn = "LambdaArn"
    NumberOfRetries = "NumberOfRetries"
    MetadataExtractionQuery = "MetadataExtractionQuery"
    JsonParsingEngine = "JsonParsingEngine"
    RoleArn = "RoleArn"
    BufferSizeInMBs = "BufferSizeInMBs"
    BufferIntervalInSeconds = "BufferIntervalInSeconds"
    SubRecordType = "SubRecordType"
    Delimiter = "Delimiter"
    CompressionFormat = "CompressionFormat"
    DataMessageExtraction = "DataMessageExtraction"


class ProcessorType(StrEnum):
    RecordDeAggregation = "RecordDeAggregation"
    Decompression = "Decompression"
    CloudWatchLogProcessing = "CloudWatchLogProcessing"
    Lambda = "Lambda"
    MetadataExtraction = "MetadataExtraction"
    AppendDelimiterToRecord = "AppendDelimiterToRecord"


class RedshiftS3BackupMode(StrEnum):
    Disabled = "Disabled"
    Enabled = "Enabled"


class S3BackupMode(StrEnum):
    Disabled = "Disabled"
    Enabled = "Enabled"


class SnowflakeDataLoadingOption(StrEnum):
    JSON_MAPPING = "JSON_MAPPING"
    VARIANT_CONTENT_MAPPING = "VARIANT_CONTENT_MAPPING"
    VARIANT_CONTENT_AND_METADATA_MAPPING = "VARIANT_CONTENT_AND_METADATA_MAPPING"


class SnowflakeS3BackupMode(StrEnum):
    FailedDataOnly = "FailedDataOnly"
    AllData = "AllData"


class SplunkS3BackupMode(StrEnum):
    FailedEventsOnly = "FailedEventsOnly"
    AllEvents = "AllEvents"


class ConcurrentModificationException(ServiceException):
    code: str = "ConcurrentModificationException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidArgumentException(ServiceException):
    code: str = "InvalidArgumentException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidKMSResourceException(ServiceException):
    code: str = "InvalidKMSResourceException"
    sender_fault: bool = False
    status_code: int = 400


class InvalidSourceException(ServiceException):
    code: str = "InvalidSourceException"
    sender_fault: bool = False
    status_code: int = 400


class LimitExceededException(ServiceException):
    code: str = "LimitExceededException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceInUseException(ServiceException):
    code: str = "ResourceInUseException"
    sender_fault: bool = False
    status_code: int = 400


class ResourceNotFoundException(ServiceException):
    code: str = "ResourceNotFoundException"
    sender_fault: bool = False
    status_code: int = 400


class ServiceUnavailableException(ServiceException):
    code: str = "ServiceUnavailableException"
    sender_fault: bool = False
    status_code: int = 400


class AmazonOpenSearchServerlessBufferingHints(TypedDict, total=False):
    IntervalInSeconds: Optional[AmazonOpenSearchServerlessBufferingIntervalInSeconds]
    SizeInMBs: Optional[AmazonOpenSearchServerlessBufferingSizeInMBs]


SecurityGroupIdList = List[NonEmptyStringWithoutWhitespace]
SubnetIdList = List[NonEmptyStringWithoutWhitespace]


class VpcConfiguration(TypedDict, total=False):
    SubnetIds: SubnetIdList
    RoleARN: RoleARN
    SecurityGroupIds: SecurityGroupIdList


class CloudWatchLoggingOptions(TypedDict, total=False):
    Enabled: Optional[BooleanObject]
    LogGroupName: Optional[LogGroupName]
    LogStreamName: Optional[LogStreamName]


class ProcessorParameter(TypedDict, total=False):
    ParameterName: ProcessorParameterName
    ParameterValue: ProcessorParameterValue


ProcessorParameterList = List[ProcessorParameter]


class Processor(TypedDict, total=False):
    Type: ProcessorType
    Parameters: Optional[ProcessorParameterList]


ProcessorList = List[Processor]


class ProcessingConfiguration(TypedDict, total=False):
    Enabled: Optional[BooleanObject]
    Processors: Optional[ProcessorList]


class KMSEncryptionConfig(TypedDict, total=False):
    AWSKMSKeyARN: AWSKMSKeyARN


class EncryptionConfiguration(TypedDict, total=False):
    NoEncryptionConfig: Optional[NoEncryptionConfig]
    KMSEncryptionConfig: Optional[KMSEncryptionConfig]


class BufferingHints(TypedDict, total=False):
    SizeInMBs: Optional[SizeInMBs]
    IntervalInSeconds: Optional[IntervalInSeconds]


class S3DestinationConfiguration(TypedDict, total=False):
    RoleARN: RoleARN
    BucketARN: BucketARN
    Prefix: Optional[Prefix]
    ErrorOutputPrefix: Optional[ErrorOutputPrefix]
    BufferingHints: Optional[BufferingHints]
    CompressionFormat: Optional[CompressionFormat]
    EncryptionConfiguration: Optional[EncryptionConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]


class AmazonOpenSearchServerlessRetryOptions(TypedDict, total=False):
    DurationInSeconds: Optional[AmazonOpenSearchServerlessRetryDurationInSeconds]


class AmazonOpenSearchServerlessDestinationConfiguration(TypedDict, total=False):
    RoleARN: RoleARN
    CollectionEndpoint: Optional[AmazonOpenSearchServerlessCollectionEndpoint]
    IndexName: AmazonOpenSearchServerlessIndexName
    BufferingHints: Optional[AmazonOpenSearchServerlessBufferingHints]
    RetryOptions: Optional[AmazonOpenSearchServerlessRetryOptions]
    S3BackupMode: Optional[AmazonOpenSearchServerlessS3BackupMode]
    S3Configuration: S3DestinationConfiguration
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    VpcConfiguration: Optional[VpcConfiguration]


class VpcConfigurationDescription(TypedDict, total=False):
    SubnetIds: SubnetIdList
    RoleARN: RoleARN
    SecurityGroupIds: SecurityGroupIdList
    VpcId: NonEmptyStringWithoutWhitespace


class S3DestinationDescription(TypedDict, total=False):
    RoleARN: RoleARN
    BucketARN: BucketARN
    Prefix: Optional[Prefix]
    ErrorOutputPrefix: Optional[ErrorOutputPrefix]
    BufferingHints: BufferingHints
    CompressionFormat: CompressionFormat
    EncryptionConfiguration: EncryptionConfiguration
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]


class AmazonOpenSearchServerlessDestinationDescription(TypedDict, total=False):
    RoleARN: Optional[RoleARN]
    CollectionEndpoint: Optional[AmazonOpenSearchServerlessCollectionEndpoint]
    IndexName: Optional[AmazonOpenSearchServerlessIndexName]
    BufferingHints: Optional[AmazonOpenSearchServerlessBufferingHints]
    RetryOptions: Optional[AmazonOpenSearchServerlessRetryOptions]
    S3BackupMode: Optional[AmazonOpenSearchServerlessS3BackupMode]
    S3DestinationDescription: Optional[S3DestinationDescription]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    VpcConfigurationDescription: Optional[VpcConfigurationDescription]


class S3DestinationUpdate(TypedDict, total=False):
    RoleARN: Optional[RoleARN]
    BucketARN: Optional[BucketARN]
    Prefix: Optional[Prefix]
    ErrorOutputPrefix: Optional[ErrorOutputPrefix]
    BufferingHints: Optional[BufferingHints]
    CompressionFormat: Optional[CompressionFormat]
    EncryptionConfiguration: Optional[EncryptionConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]


class AmazonOpenSearchServerlessDestinationUpdate(TypedDict, total=False):
    RoleARN: Optional[RoleARN]
    CollectionEndpoint: Optional[AmazonOpenSearchServerlessCollectionEndpoint]
    IndexName: Optional[AmazonOpenSearchServerlessIndexName]
    BufferingHints: Optional[AmazonOpenSearchServerlessBufferingHints]
    RetryOptions: Optional[AmazonOpenSearchServerlessRetryOptions]
    S3Update: Optional[S3DestinationUpdate]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]


class AmazonopensearchserviceBufferingHints(TypedDict, total=False):
    IntervalInSeconds: Optional[AmazonopensearchserviceBufferingIntervalInSeconds]
    SizeInMBs: Optional[AmazonopensearchserviceBufferingSizeInMBs]


class DocumentIdOptions(TypedDict, total=False):
    DefaultDocumentIdFormat: DefaultDocumentIdFormat


class AmazonopensearchserviceRetryOptions(TypedDict, total=False):
    DurationInSeconds: Optional[AmazonopensearchserviceRetryDurationInSeconds]


class AmazonopensearchserviceDestinationConfiguration(TypedDict, total=False):
    RoleARN: RoleARN
    DomainARN: Optional[AmazonopensearchserviceDomainARN]
    ClusterEndpoint: Optional[AmazonopensearchserviceClusterEndpoint]
    IndexName: AmazonopensearchserviceIndexName
    TypeName: Optional[AmazonopensearchserviceTypeName]
    IndexRotationPeriod: Optional[AmazonopensearchserviceIndexRotationPeriod]
    BufferingHints: Optional[AmazonopensearchserviceBufferingHints]
    RetryOptions: Optional[AmazonopensearchserviceRetryOptions]
    S3BackupMode: Optional[AmazonopensearchserviceS3BackupMode]
    S3Configuration: S3DestinationConfiguration
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    VpcConfiguration: Optional[VpcConfiguration]
    DocumentIdOptions: Optional[DocumentIdOptions]


class AmazonopensearchserviceDestinationDescription(TypedDict, total=False):
    RoleARN: Optional[RoleARN]
    DomainARN: Optional[AmazonopensearchserviceDomainARN]
    ClusterEndpoint: Optional[AmazonopensearchserviceClusterEndpoint]
    IndexName: Optional[AmazonopensearchserviceIndexName]
    TypeName: Optional[AmazonopensearchserviceTypeName]
    IndexRotationPeriod: Optional[AmazonopensearchserviceIndexRotationPeriod]
    BufferingHints: Optional[AmazonopensearchserviceBufferingHints]
    RetryOptions: Optional[AmazonopensearchserviceRetryOptions]
    S3BackupMode: Optional[AmazonopensearchserviceS3BackupMode]
    S3DestinationDescription: Optional[S3DestinationDescription]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    VpcConfigurationDescription: Optional[VpcConfigurationDescription]
    DocumentIdOptions: Optional[DocumentIdOptions]


class AmazonopensearchserviceDestinationUpdate(TypedDict, total=False):
    RoleARN: Optional[RoleARN]
    DomainARN: Optional[AmazonopensearchserviceDomainARN]
    ClusterEndpoint: Optional[AmazonopensearchserviceClusterEndpoint]
    IndexName: Optional[AmazonopensearchserviceIndexName]
    TypeName: Optional[AmazonopensearchserviceTypeName]
    IndexRotationPeriod: Optional[AmazonopensearchserviceIndexRotationPeriod]
    BufferingHints: Optional[AmazonopensearchserviceBufferingHints]
    RetryOptions: Optional[AmazonopensearchserviceRetryOptions]
    S3Update: Optional[S3DestinationUpdate]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    DocumentIdOptions: Optional[DocumentIdOptions]


class AuthenticationConfiguration(TypedDict, total=False):
    RoleARN: RoleARN
    Connectivity: Connectivity


class CatalogConfiguration(TypedDict, total=False):
    CatalogARN: Optional[GlueDataCatalogARN]


ColumnToJsonKeyMappings = Dict[NonEmptyStringWithoutWhitespace, NonEmptyString]


class CopyCommand(TypedDict, total=False):
    DataTableName: DataTableName
    DataTableColumns: Optional[DataTableColumns]
    CopyOptions: Optional[CopyOptions]


class RetryOptions(TypedDict, total=False):
    DurationInSeconds: Optional[RetryDurationInSeconds]


ListOfNonEmptyStringsWithoutWhitespace = List[NonEmptyStringWithoutWhitespace]


class DestinationTableConfiguration(TypedDict, total=False):
    DestinationTableName: NonEmptyStringWithoutWhitespace
    DestinationDatabaseName: NonEmptyStringWithoutWhitespace
    UniqueKeys: Optional[ListOfNonEmptyStringsWithoutWhitespace]
    S3ErrorOutputPrefix: Optional[ErrorOutputPrefix]


DestinationTableConfigurationList = List[DestinationTableConfiguration]


class IcebergDestinationConfiguration(TypedDict, total=False):
    DestinationTableConfigurationList: Optional[DestinationTableConfigurationList]
    BufferingHints: Optional[BufferingHints]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    S3BackupMode: Optional[IcebergS3BackupMode]
    RetryOptions: Optional[RetryOptions]
    RoleARN: RoleARN
    CatalogConfiguration: CatalogConfiguration
    S3Configuration: S3DestinationConfiguration


class SnowflakeBufferingHints(TypedDict, total=False):
    SizeInMBs: Optional[SnowflakeBufferingSizeInMBs]
    IntervalInSeconds: Optional[SnowflakeBufferingIntervalInSeconds]


class SecretsManagerConfiguration(TypedDict, total=False):
    SecretARN: Optional[SecretARN]
    RoleARN: Optional[RoleARN]
    Enabled: BooleanObject


class SnowflakeRetryOptions(TypedDict, total=False):
    DurationInSeconds: Optional[SnowflakeRetryDurationInSeconds]


class SnowflakeVpcConfiguration(TypedDict, total=False):
    PrivateLinkVpceId: SnowflakePrivateLinkVpceId


class SnowflakeRoleConfiguration(TypedDict, total=False):
    Enabled: Optional[BooleanObject]
    SnowflakeRole: Optional[SnowflakeRole]


class SnowflakeDestinationConfiguration(TypedDict, total=False):
    AccountUrl: SnowflakeAccountUrl
    PrivateKey: Optional[SnowflakePrivateKey]
    KeyPassphrase: Optional[SnowflakeKeyPassphrase]
    User: Optional[SnowflakeUser]
    Database: SnowflakeDatabase
    Schema: SnowflakeSchema
    Table: SnowflakeTable
    SnowflakeRoleConfiguration: Optional[SnowflakeRoleConfiguration]
    DataLoadingOption: Optional[SnowflakeDataLoadingOption]
    MetaDataColumnName: Optional[SnowflakeMetaDataColumnName]
    ContentColumnName: Optional[SnowflakeContentColumnName]
    SnowflakeVpcConfiguration: Optional[SnowflakeVpcConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    RoleARN: RoleARN
    RetryOptions: Optional[SnowflakeRetryOptions]
    S3BackupMode: Optional[SnowflakeS3BackupMode]
    S3Configuration: S3DestinationConfiguration
    SecretsManagerConfiguration: Optional[SecretsManagerConfiguration]
    BufferingHints: Optional[SnowflakeBufferingHints]


ReadFromTimestamp = datetime


class MSKSourceConfiguration(TypedDict, total=False):
    MSKClusterARN: MSKClusterARN
    TopicName: TopicName
    AuthenticationConfiguration: AuthenticationConfiguration
    ReadFromTimestamp: Optional[ReadFromTimestamp]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: Optional[TagValue]


TagDeliveryStreamInputTagList = List[Tag]


class HttpEndpointRetryOptions(TypedDict, total=False):
    DurationInSeconds: Optional[HttpEndpointRetryDurationInSeconds]


class HttpEndpointCommonAttribute(TypedDict, total=False):
    AttributeName: HttpEndpointAttributeName
    AttributeValue: HttpEndpointAttributeValue


HttpEndpointCommonAttributesList = List[HttpEndpointCommonAttribute]


class HttpEndpointRequestConfiguration(TypedDict, total=False):
    ContentEncoding: Optional[ContentEncoding]
    CommonAttributes: Optional[HttpEndpointCommonAttributesList]


class HttpEndpointBufferingHints(TypedDict, total=False):
    SizeInMBs: Optional[HttpEndpointBufferingSizeInMBs]
    IntervalInSeconds: Optional[HttpEndpointBufferingIntervalInSeconds]


class HttpEndpointConfiguration(TypedDict, total=False):
    Url: HttpEndpointUrl
    Name: Optional[HttpEndpointName]
    AccessKey: Optional[HttpEndpointAccessKey]


class HttpEndpointDestinationConfiguration(TypedDict, total=False):
    EndpointConfiguration: HttpEndpointConfiguration
    BufferingHints: Optional[HttpEndpointBufferingHints]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    RequestConfiguration: Optional[HttpEndpointRequestConfiguration]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    RoleARN: Optional[RoleARN]
    RetryOptions: Optional[HttpEndpointRetryOptions]
    S3BackupMode: Optional[HttpEndpointS3BackupMode]
    S3Configuration: S3DestinationConfiguration
    SecretsManagerConfiguration: Optional[SecretsManagerConfiguration]


class SplunkBufferingHints(TypedDict, total=False):
    IntervalInSeconds: Optional[SplunkBufferingIntervalInSeconds]
    SizeInMBs: Optional[SplunkBufferingSizeInMBs]


class SplunkRetryOptions(TypedDict, total=False):
    DurationInSeconds: Optional[SplunkRetryDurationInSeconds]


class SplunkDestinationConfiguration(TypedDict, total=False):
    HECEndpoint: HECEndpoint
    HECEndpointType: HECEndpointType
    HECToken: Optional[HECToken]
    HECAcknowledgmentTimeoutInSeconds: Optional[HECAcknowledgmentTimeoutInSeconds]
    RetryOptions: Optional[SplunkRetryOptions]
    S3BackupMode: Optional[SplunkS3BackupMode]
    S3Configuration: S3DestinationConfiguration
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    BufferingHints: Optional[SplunkBufferingHints]
    SecretsManagerConfiguration: Optional[SecretsManagerConfiguration]


class ElasticsearchRetryOptions(TypedDict, total=False):
    DurationInSeconds: Optional[ElasticsearchRetryDurationInSeconds]


class ElasticsearchBufferingHints(TypedDict, total=False):
    IntervalInSeconds: Optional[ElasticsearchBufferingIntervalInSeconds]
    SizeInMBs: Optional[ElasticsearchBufferingSizeInMBs]


class ElasticsearchDestinationConfiguration(TypedDict, total=False):
    RoleARN: RoleARN
    DomainARN: Optional[ElasticsearchDomainARN]
    ClusterEndpoint: Optional[ElasticsearchClusterEndpoint]
    IndexName: ElasticsearchIndexName
    TypeName: Optional[ElasticsearchTypeName]
    IndexRotationPeriod: Optional[ElasticsearchIndexRotationPeriod]
    BufferingHints: Optional[ElasticsearchBufferingHints]
    RetryOptions: Optional[ElasticsearchRetryOptions]
    S3BackupMode: Optional[ElasticsearchS3BackupMode]
    S3Configuration: S3DestinationConfiguration
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    VpcConfiguration: Optional[VpcConfiguration]
    DocumentIdOptions: Optional[DocumentIdOptions]


class RedshiftRetryOptions(TypedDict, total=False):
    DurationInSeconds: Optional[RedshiftRetryDurationInSeconds]


class RedshiftDestinationConfiguration(TypedDict, total=False):
    RoleARN: RoleARN
    ClusterJDBCURL: ClusterJDBCURL
    CopyCommand: CopyCommand
    Username: Optional[Username]
    Password: Optional[Password]
    RetryOptions: Optional[RedshiftRetryOptions]
    S3Configuration: S3DestinationConfiguration
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    S3BackupMode: Optional[RedshiftS3BackupMode]
    S3BackupConfiguration: Optional[S3DestinationConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    SecretsManagerConfiguration: Optional[SecretsManagerConfiguration]


class DynamicPartitioningConfiguration(TypedDict, total=False):
    RetryOptions: Optional[RetryOptions]
    Enabled: Optional[BooleanObject]


class OrcSerDe(TypedDict, total=False):
    StripeSizeBytes: Optional[OrcStripeSizeBytes]
    BlockSizeBytes: Optional[BlockSizeBytes]
    RowIndexStride: Optional[OrcRowIndexStride]
    EnablePadding: Optional[BooleanObject]
    PaddingTolerance: Optional[Proportion]
    Compression: Optional[OrcCompression]
    BloomFilterColumns: Optional[ListOfNonEmptyStringsWithoutWhitespace]
    BloomFilterFalsePositiveProbability: Optional[Proportion]
    DictionaryKeyThreshold: Optional[Proportion]
    FormatVersion: Optional[OrcFormatVersion]


class ParquetSerDe(TypedDict, total=False):
    BlockSizeBytes: Optional[BlockSizeBytes]
    PageSizeBytes: Optional[ParquetPageSizeBytes]
    Compression: Optional[ParquetCompression]
    EnableDictionaryCompression: Optional[BooleanObject]
    MaxPaddingBytes: Optional[NonNegativeIntegerObject]
    WriterVersion: Optional[ParquetWriterVersion]


class Serializer(TypedDict, total=False):
    ParquetSerDe: Optional[ParquetSerDe]
    OrcSerDe: Optional[OrcSerDe]


class OutputFormatConfiguration(TypedDict, total=False):
    Serializer: Optional[Serializer]


ListOfNonEmptyStrings = List[NonEmptyString]


class HiveJsonSerDe(TypedDict, total=False):
    TimestampFormats: Optional[ListOfNonEmptyStrings]


class OpenXJsonSerDe(TypedDict, total=False):
    ConvertDotsInJsonKeysToUnderscores: Optional[BooleanObject]
    CaseInsensitive: Optional[BooleanObject]
    ColumnToJsonKeyMappings: Optional[ColumnToJsonKeyMappings]


class Deserializer(TypedDict, total=False):
    OpenXJsonSerDe: Optional[OpenXJsonSerDe]
    HiveJsonSerDe: Optional[HiveJsonSerDe]


class InputFormatConfiguration(TypedDict, total=False):
    Deserializer: Optional[Deserializer]


class SchemaConfiguration(TypedDict, total=False):
    RoleARN: Optional[NonEmptyStringWithoutWhitespace]
    CatalogId: Optional[NonEmptyStringWithoutWhitespace]
    DatabaseName: Optional[NonEmptyStringWithoutWhitespace]
    TableName: Optional[NonEmptyStringWithoutWhitespace]
    Region: Optional[NonEmptyStringWithoutWhitespace]
    VersionId: Optional[NonEmptyStringWithoutWhitespace]


class DataFormatConversionConfiguration(TypedDict, total=False):
    SchemaConfiguration: Optional[SchemaConfiguration]
    InputFormatConfiguration: Optional[InputFormatConfiguration]
    OutputFormatConfiguration: Optional[OutputFormatConfiguration]
    Enabled: Optional[BooleanObject]


class ExtendedS3DestinationConfiguration(TypedDict, total=False):
    RoleARN: RoleARN
    BucketARN: BucketARN
    Prefix: Optional[Prefix]
    ErrorOutputPrefix: Optional[ErrorOutputPrefix]
    BufferingHints: Optional[BufferingHints]
    CompressionFormat: Optional[CompressionFormat]
    EncryptionConfiguration: Optional[EncryptionConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    S3BackupMode: Optional[S3BackupMode]
    S3BackupConfiguration: Optional[S3DestinationConfiguration]
    DataFormatConversionConfiguration: Optional[DataFormatConversionConfiguration]
    DynamicPartitioningConfiguration: Optional[DynamicPartitioningConfiguration]
    FileExtension: Optional[FileExtension]
    CustomTimeZone: Optional[CustomTimeZone]


class DeliveryStreamEncryptionConfigurationInput(TypedDict, total=False):
    KeyARN: Optional[AWSKMSKeyARN]
    KeyType: KeyType


class KinesisStreamSourceConfiguration(TypedDict, total=False):
    KinesisStreamARN: KinesisStreamARN
    RoleARN: RoleARN


class CreateDeliveryStreamInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    DeliveryStreamType: Optional[DeliveryStreamType]
    KinesisStreamSourceConfiguration: Optional[KinesisStreamSourceConfiguration]
    DeliveryStreamEncryptionConfigurationInput: Optional[DeliveryStreamEncryptionConfigurationInput]
    S3DestinationConfiguration: Optional[S3DestinationConfiguration]
    ExtendedS3DestinationConfiguration: Optional[ExtendedS3DestinationConfiguration]
    RedshiftDestinationConfiguration: Optional[RedshiftDestinationConfiguration]
    ElasticsearchDestinationConfiguration: Optional[ElasticsearchDestinationConfiguration]
    AmazonopensearchserviceDestinationConfiguration: Optional[
        AmazonopensearchserviceDestinationConfiguration
    ]
    SplunkDestinationConfiguration: Optional[SplunkDestinationConfiguration]
    HttpEndpointDestinationConfiguration: Optional[HttpEndpointDestinationConfiguration]
    Tags: Optional[TagDeliveryStreamInputTagList]
    AmazonOpenSearchServerlessDestinationConfiguration: Optional[
        AmazonOpenSearchServerlessDestinationConfiguration
    ]
    MSKSourceConfiguration: Optional[MSKSourceConfiguration]
    SnowflakeDestinationConfiguration: Optional[SnowflakeDestinationConfiguration]
    IcebergDestinationConfiguration: Optional[IcebergDestinationConfiguration]


class CreateDeliveryStreamOutput(TypedDict, total=False):
    DeliveryStreamARN: Optional[DeliveryStreamARN]


Data = bytes


class DeleteDeliveryStreamInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    AllowForceDelete: Optional[BooleanObject]


class DeleteDeliveryStreamOutput(TypedDict, total=False):
    pass


DeliveryStartTimestamp = datetime


class IcebergDestinationDescription(TypedDict, total=False):
    DestinationTableConfigurationList: Optional[DestinationTableConfigurationList]
    BufferingHints: Optional[BufferingHints]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    S3BackupMode: Optional[IcebergS3BackupMode]
    RetryOptions: Optional[RetryOptions]
    RoleARN: Optional[RoleARN]
    CatalogConfiguration: Optional[CatalogConfiguration]
    S3DestinationDescription: Optional[S3DestinationDescription]


class SnowflakeDestinationDescription(TypedDict, total=False):
    AccountUrl: Optional[SnowflakeAccountUrl]
    User: Optional[SnowflakeUser]
    Database: Optional[SnowflakeDatabase]
    Schema: Optional[SnowflakeSchema]
    Table: Optional[SnowflakeTable]
    SnowflakeRoleConfiguration: Optional[SnowflakeRoleConfiguration]
    DataLoadingOption: Optional[SnowflakeDataLoadingOption]
    MetaDataColumnName: Optional[SnowflakeMetaDataColumnName]
    ContentColumnName: Optional[SnowflakeContentColumnName]
    SnowflakeVpcConfiguration: Optional[SnowflakeVpcConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    RoleARN: Optional[RoleARN]
    RetryOptions: Optional[SnowflakeRetryOptions]
    S3BackupMode: Optional[SnowflakeS3BackupMode]
    S3DestinationDescription: Optional[S3DestinationDescription]
    SecretsManagerConfiguration: Optional[SecretsManagerConfiguration]
    BufferingHints: Optional[SnowflakeBufferingHints]


class HttpEndpointDescription(TypedDict, total=False):
    Url: Optional[HttpEndpointUrl]
    Name: Optional[HttpEndpointName]


class HttpEndpointDestinationDescription(TypedDict, total=False):
    EndpointConfiguration: Optional[HttpEndpointDescription]
    BufferingHints: Optional[HttpEndpointBufferingHints]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    RequestConfiguration: Optional[HttpEndpointRequestConfiguration]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    RoleARN: Optional[RoleARN]
    RetryOptions: Optional[HttpEndpointRetryOptions]
    S3BackupMode: Optional[HttpEndpointS3BackupMode]
    S3DestinationDescription: Optional[S3DestinationDescription]
    SecretsManagerConfiguration: Optional[SecretsManagerConfiguration]


class SplunkDestinationDescription(TypedDict, total=False):
    HECEndpoint: Optional[HECEndpoint]
    HECEndpointType: Optional[HECEndpointType]
    HECToken: Optional[HECToken]
    HECAcknowledgmentTimeoutInSeconds: Optional[HECAcknowledgmentTimeoutInSeconds]
    RetryOptions: Optional[SplunkRetryOptions]
    S3BackupMode: Optional[SplunkS3BackupMode]
    S3DestinationDescription: Optional[S3DestinationDescription]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    BufferingHints: Optional[SplunkBufferingHints]
    SecretsManagerConfiguration: Optional[SecretsManagerConfiguration]


class ElasticsearchDestinationDescription(TypedDict, total=False):
    RoleARN: Optional[RoleARN]
    DomainARN: Optional[ElasticsearchDomainARN]
    ClusterEndpoint: Optional[ElasticsearchClusterEndpoint]
    IndexName: Optional[ElasticsearchIndexName]
    TypeName: Optional[ElasticsearchTypeName]
    IndexRotationPeriod: Optional[ElasticsearchIndexRotationPeriod]
    BufferingHints: Optional[ElasticsearchBufferingHints]
    RetryOptions: Optional[ElasticsearchRetryOptions]
    S3BackupMode: Optional[ElasticsearchS3BackupMode]
    S3DestinationDescription: Optional[S3DestinationDescription]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    VpcConfigurationDescription: Optional[VpcConfigurationDescription]
    DocumentIdOptions: Optional[DocumentIdOptions]


class RedshiftDestinationDescription(TypedDict, total=False):
    RoleARN: RoleARN
    ClusterJDBCURL: ClusterJDBCURL
    CopyCommand: CopyCommand
    Username: Optional[Username]
    RetryOptions: Optional[RedshiftRetryOptions]
    S3DestinationDescription: S3DestinationDescription
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    S3BackupMode: Optional[RedshiftS3BackupMode]
    S3BackupDescription: Optional[S3DestinationDescription]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    SecretsManagerConfiguration: Optional[SecretsManagerConfiguration]


class ExtendedS3DestinationDescription(TypedDict, total=False):
    RoleARN: RoleARN
    BucketARN: BucketARN
    Prefix: Optional[Prefix]
    ErrorOutputPrefix: Optional[ErrorOutputPrefix]
    BufferingHints: BufferingHints
    CompressionFormat: CompressionFormat
    EncryptionConfiguration: EncryptionConfiguration
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    S3BackupMode: Optional[S3BackupMode]
    S3BackupDescription: Optional[S3DestinationDescription]
    DataFormatConversionConfiguration: Optional[DataFormatConversionConfiguration]
    DynamicPartitioningConfiguration: Optional[DynamicPartitioningConfiguration]
    FileExtension: Optional[FileExtension]
    CustomTimeZone: Optional[CustomTimeZone]


class DestinationDescription(TypedDict, total=False):
    DestinationId: DestinationId
    S3DestinationDescription: Optional[S3DestinationDescription]
    ExtendedS3DestinationDescription: Optional[ExtendedS3DestinationDescription]
    RedshiftDestinationDescription: Optional[RedshiftDestinationDescription]
    ElasticsearchDestinationDescription: Optional[ElasticsearchDestinationDescription]
    AmazonopensearchserviceDestinationDescription: Optional[
        AmazonopensearchserviceDestinationDescription
    ]
    SplunkDestinationDescription: Optional[SplunkDestinationDescription]
    HttpEndpointDestinationDescription: Optional[HttpEndpointDestinationDescription]
    SnowflakeDestinationDescription: Optional[SnowflakeDestinationDescription]
    AmazonOpenSearchServerlessDestinationDescription: Optional[
        AmazonOpenSearchServerlessDestinationDescription
    ]
    IcebergDestinationDescription: Optional[IcebergDestinationDescription]


DestinationDescriptionList = List[DestinationDescription]


class MSKSourceDescription(TypedDict, total=False):
    MSKClusterARN: Optional[MSKClusterARN]
    TopicName: Optional[TopicName]
    AuthenticationConfiguration: Optional[AuthenticationConfiguration]
    DeliveryStartTimestamp: Optional[DeliveryStartTimestamp]
    ReadFromTimestamp: Optional[ReadFromTimestamp]


class KinesisStreamSourceDescription(TypedDict, total=False):
    KinesisStreamARN: Optional[KinesisStreamARN]
    RoleARN: Optional[RoleARN]
    DeliveryStartTimestamp: Optional[DeliveryStartTimestamp]


class SourceDescription(TypedDict, total=False):
    KinesisStreamSourceDescription: Optional[KinesisStreamSourceDescription]
    MSKSourceDescription: Optional[MSKSourceDescription]


Timestamp = datetime


class FailureDescription(TypedDict, total=False):
    Type: DeliveryStreamFailureType
    Details: NonEmptyString


class DeliveryStreamEncryptionConfiguration(TypedDict, total=False):
    KeyARN: Optional[AWSKMSKeyARN]
    KeyType: Optional[KeyType]
    Status: Optional[DeliveryStreamEncryptionStatus]
    FailureDescription: Optional[FailureDescription]


class DeliveryStreamDescription(TypedDict, total=False):
    DeliveryStreamName: DeliveryStreamName
    DeliveryStreamARN: DeliveryStreamARN
    DeliveryStreamStatus: DeliveryStreamStatus
    FailureDescription: Optional[FailureDescription]
    DeliveryStreamEncryptionConfiguration: Optional[DeliveryStreamEncryptionConfiguration]
    DeliveryStreamType: DeliveryStreamType
    VersionId: DeliveryStreamVersionId
    CreateTimestamp: Optional[Timestamp]
    LastUpdateTimestamp: Optional[Timestamp]
    Source: Optional[SourceDescription]
    Destinations: DestinationDescriptionList
    HasMoreDestinations: BooleanObject


DeliveryStreamNameList = List[DeliveryStreamName]


class DescribeDeliveryStreamInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    Limit: Optional[DescribeDeliveryStreamInputLimit]
    ExclusiveStartDestinationId: Optional[DestinationId]


class DescribeDeliveryStreamOutput(TypedDict, total=False):
    DeliveryStreamDescription: DeliveryStreamDescription


class ElasticsearchDestinationUpdate(TypedDict, total=False):
    RoleARN: Optional[RoleARN]
    DomainARN: Optional[ElasticsearchDomainARN]
    ClusterEndpoint: Optional[ElasticsearchClusterEndpoint]
    IndexName: Optional[ElasticsearchIndexName]
    TypeName: Optional[ElasticsearchTypeName]
    IndexRotationPeriod: Optional[ElasticsearchIndexRotationPeriod]
    BufferingHints: Optional[ElasticsearchBufferingHints]
    RetryOptions: Optional[ElasticsearchRetryOptions]
    S3Update: Optional[S3DestinationUpdate]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    DocumentIdOptions: Optional[DocumentIdOptions]


class ExtendedS3DestinationUpdate(TypedDict, total=False):
    RoleARN: Optional[RoleARN]
    BucketARN: Optional[BucketARN]
    Prefix: Optional[Prefix]
    ErrorOutputPrefix: Optional[ErrorOutputPrefix]
    BufferingHints: Optional[BufferingHints]
    CompressionFormat: Optional[CompressionFormat]
    EncryptionConfiguration: Optional[EncryptionConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    S3BackupMode: Optional[S3BackupMode]
    S3BackupUpdate: Optional[S3DestinationUpdate]
    DataFormatConversionConfiguration: Optional[DataFormatConversionConfiguration]
    DynamicPartitioningConfiguration: Optional[DynamicPartitioningConfiguration]
    FileExtension: Optional[FileExtension]
    CustomTimeZone: Optional[CustomTimeZone]


class HttpEndpointDestinationUpdate(TypedDict, total=False):
    EndpointConfiguration: Optional[HttpEndpointConfiguration]
    BufferingHints: Optional[HttpEndpointBufferingHints]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    RequestConfiguration: Optional[HttpEndpointRequestConfiguration]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    RoleARN: Optional[RoleARN]
    RetryOptions: Optional[HttpEndpointRetryOptions]
    S3BackupMode: Optional[HttpEndpointS3BackupMode]
    S3Update: Optional[S3DestinationUpdate]
    SecretsManagerConfiguration: Optional[SecretsManagerConfiguration]


class IcebergDestinationUpdate(TypedDict, total=False):
    DestinationTableConfigurationList: Optional[DestinationTableConfigurationList]
    BufferingHints: Optional[BufferingHints]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    S3BackupMode: Optional[IcebergS3BackupMode]
    RetryOptions: Optional[RetryOptions]
    RoleARN: Optional[RoleARN]
    CatalogConfiguration: Optional[CatalogConfiguration]
    S3Configuration: Optional[S3DestinationConfiguration]


class ListDeliveryStreamsInput(ServiceRequest):
    Limit: Optional[ListDeliveryStreamsInputLimit]
    DeliveryStreamType: Optional[DeliveryStreamType]
    ExclusiveStartDeliveryStreamName: Optional[DeliveryStreamName]


class ListDeliveryStreamsOutput(TypedDict, total=False):
    DeliveryStreamNames: DeliveryStreamNameList
    HasMoreDeliveryStreams: BooleanObject


class ListTagsForDeliveryStreamInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    ExclusiveStartTagKey: Optional[TagKey]
    Limit: Optional[ListTagsForDeliveryStreamInputLimit]


ListTagsForDeliveryStreamOutputTagList = List[Tag]


class ListTagsForDeliveryStreamOutput(TypedDict, total=False):
    Tags: ListTagsForDeliveryStreamOutputTagList
    HasMoreTags: BooleanObject


class Record(TypedDict, total=False):
    Data: Data


PutRecordBatchRequestEntryList = List[Record]


class PutRecordBatchInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    Records: PutRecordBatchRequestEntryList


class PutRecordBatchResponseEntry(TypedDict, total=False):
    RecordId: Optional[PutResponseRecordId]
    ErrorCode: Optional[ErrorCode]
    ErrorMessage: Optional[ErrorMessage]


PutRecordBatchResponseEntryList = List[PutRecordBatchResponseEntry]


class PutRecordBatchOutput(TypedDict, total=False):
    FailedPutCount: NonNegativeIntegerObject
    Encrypted: Optional[BooleanObject]
    RequestResponses: PutRecordBatchResponseEntryList


class PutRecordInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    Record: Record


class PutRecordOutput(TypedDict, total=False):
    RecordId: PutResponseRecordId
    Encrypted: Optional[BooleanObject]


class RedshiftDestinationUpdate(TypedDict, total=False):
    RoleARN: Optional[RoleARN]
    ClusterJDBCURL: Optional[ClusterJDBCURL]
    CopyCommand: Optional[CopyCommand]
    Username: Optional[Username]
    Password: Optional[Password]
    RetryOptions: Optional[RedshiftRetryOptions]
    S3Update: Optional[S3DestinationUpdate]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    S3BackupMode: Optional[RedshiftS3BackupMode]
    S3BackupUpdate: Optional[S3DestinationUpdate]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    SecretsManagerConfiguration: Optional[SecretsManagerConfiguration]


class SnowflakeDestinationUpdate(TypedDict, total=False):
    AccountUrl: Optional[SnowflakeAccountUrl]
    PrivateKey: Optional[SnowflakePrivateKey]
    KeyPassphrase: Optional[SnowflakeKeyPassphrase]
    User: Optional[SnowflakeUser]
    Database: Optional[SnowflakeDatabase]
    Schema: Optional[SnowflakeSchema]
    Table: Optional[SnowflakeTable]
    SnowflakeRoleConfiguration: Optional[SnowflakeRoleConfiguration]
    DataLoadingOption: Optional[SnowflakeDataLoadingOption]
    MetaDataColumnName: Optional[SnowflakeMetaDataColumnName]
    ContentColumnName: Optional[SnowflakeContentColumnName]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    RoleARN: Optional[RoleARN]
    RetryOptions: Optional[SnowflakeRetryOptions]
    S3BackupMode: Optional[SnowflakeS3BackupMode]
    S3Update: Optional[S3DestinationUpdate]
    SecretsManagerConfiguration: Optional[SecretsManagerConfiguration]
    BufferingHints: Optional[SnowflakeBufferingHints]


class SplunkDestinationUpdate(TypedDict, total=False):
    HECEndpoint: Optional[HECEndpoint]
    HECEndpointType: Optional[HECEndpointType]
    HECToken: Optional[HECToken]
    HECAcknowledgmentTimeoutInSeconds: Optional[HECAcknowledgmentTimeoutInSeconds]
    RetryOptions: Optional[SplunkRetryOptions]
    S3BackupMode: Optional[SplunkS3BackupMode]
    S3Update: Optional[S3DestinationUpdate]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    BufferingHints: Optional[SplunkBufferingHints]
    SecretsManagerConfiguration: Optional[SecretsManagerConfiguration]


class StartDeliveryStreamEncryptionInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    DeliveryStreamEncryptionConfigurationInput: Optional[DeliveryStreamEncryptionConfigurationInput]


class StartDeliveryStreamEncryptionOutput(TypedDict, total=False):
    pass


class StopDeliveryStreamEncryptionInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName


class StopDeliveryStreamEncryptionOutput(TypedDict, total=False):
    pass


class TagDeliveryStreamInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    Tags: TagDeliveryStreamInputTagList


class TagDeliveryStreamOutput(TypedDict, total=False):
    pass


TagKeyList = List[TagKey]


class UntagDeliveryStreamInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    TagKeys: TagKeyList


class UntagDeliveryStreamOutput(TypedDict, total=False):
    pass


class UpdateDestinationInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    CurrentDeliveryStreamVersionId: DeliveryStreamVersionId
    DestinationId: DestinationId
    S3DestinationUpdate: Optional[S3DestinationUpdate]
    ExtendedS3DestinationUpdate: Optional[ExtendedS3DestinationUpdate]
    RedshiftDestinationUpdate: Optional[RedshiftDestinationUpdate]
    ElasticsearchDestinationUpdate: Optional[ElasticsearchDestinationUpdate]
    AmazonopensearchserviceDestinationUpdate: Optional[AmazonopensearchserviceDestinationUpdate]
    SplunkDestinationUpdate: Optional[SplunkDestinationUpdate]
    HttpEndpointDestinationUpdate: Optional[HttpEndpointDestinationUpdate]
    AmazonOpenSearchServerlessDestinationUpdate: Optional[
        AmazonOpenSearchServerlessDestinationUpdate
    ]
    SnowflakeDestinationUpdate: Optional[SnowflakeDestinationUpdate]
    IcebergDestinationUpdate: Optional[IcebergDestinationUpdate]


class UpdateDestinationOutput(TypedDict, total=False):
    pass


class FirehoseApi:
    service = "firehose"
    version = "2015-08-04"

    @handler("CreateDeliveryStream")
    def create_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        delivery_stream_type: DeliveryStreamType = None,
        kinesis_stream_source_configuration: KinesisStreamSourceConfiguration = None,
        delivery_stream_encryption_configuration_input: DeliveryStreamEncryptionConfigurationInput = None,
        s3_destination_configuration: S3DestinationConfiguration = None,
        extended_s3_destination_configuration: ExtendedS3DestinationConfiguration = None,
        redshift_destination_configuration: RedshiftDestinationConfiguration = None,
        elasticsearch_destination_configuration: ElasticsearchDestinationConfiguration = None,
        amazonopensearchservice_destination_configuration: AmazonopensearchserviceDestinationConfiguration = None,
        splunk_destination_configuration: SplunkDestinationConfiguration = None,
        http_endpoint_destination_configuration: HttpEndpointDestinationConfiguration = None,
        tags: TagDeliveryStreamInputTagList = None,
        amazon_open_search_serverless_destination_configuration: AmazonOpenSearchServerlessDestinationConfiguration = None,
        msk_source_configuration: MSKSourceConfiguration = None,
        snowflake_destination_configuration: SnowflakeDestinationConfiguration = None,
        iceberg_destination_configuration: IcebergDestinationConfiguration = None,
        **kwargs,
    ) -> CreateDeliveryStreamOutput:
        raise NotImplementedError

    @handler("DeleteDeliveryStream")
    def delete_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        allow_force_delete: BooleanObject = None,
        **kwargs,
    ) -> DeleteDeliveryStreamOutput:
        raise NotImplementedError

    @handler("DescribeDeliveryStream")
    def describe_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        limit: DescribeDeliveryStreamInputLimit = None,
        exclusive_start_destination_id: DestinationId = None,
        **kwargs,
    ) -> DescribeDeliveryStreamOutput:
        raise NotImplementedError

    @handler("ListDeliveryStreams")
    def list_delivery_streams(
        self,
        context: RequestContext,
        limit: ListDeliveryStreamsInputLimit = None,
        delivery_stream_type: DeliveryStreamType = None,
        exclusive_start_delivery_stream_name: DeliveryStreamName = None,
        **kwargs,
    ) -> ListDeliveryStreamsOutput:
        raise NotImplementedError

    @handler("ListTagsForDeliveryStream")
    def list_tags_for_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        exclusive_start_tag_key: TagKey = None,
        limit: ListTagsForDeliveryStreamInputLimit = None,
        **kwargs,
    ) -> ListTagsForDeliveryStreamOutput:
        raise NotImplementedError

    @handler("PutRecord")
    def put_record(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        record: Record,
        **kwargs,
    ) -> PutRecordOutput:
        raise NotImplementedError

    @handler("PutRecordBatch")
    def put_record_batch(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        records: PutRecordBatchRequestEntryList,
        **kwargs,
    ) -> PutRecordBatchOutput:
        raise NotImplementedError

    @handler("StartDeliveryStreamEncryption")
    def start_delivery_stream_encryption(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        delivery_stream_encryption_configuration_input: DeliveryStreamEncryptionConfigurationInput = None,
        **kwargs,
    ) -> StartDeliveryStreamEncryptionOutput:
        raise NotImplementedError

    @handler("StopDeliveryStreamEncryption")
    def stop_delivery_stream_encryption(
        self, context: RequestContext, delivery_stream_name: DeliveryStreamName, **kwargs
    ) -> StopDeliveryStreamEncryptionOutput:
        raise NotImplementedError

    @handler("TagDeliveryStream")
    def tag_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        tags: TagDeliveryStreamInputTagList,
        **kwargs,
    ) -> TagDeliveryStreamOutput:
        raise NotImplementedError

    @handler("UntagDeliveryStream")
    def untag_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        tag_keys: TagKeyList,
        **kwargs,
    ) -> UntagDeliveryStreamOutput:
        raise NotImplementedError

    @handler("UpdateDestination")
    def update_destination(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        current_delivery_stream_version_id: DeliveryStreamVersionId,
        destination_id: DestinationId,
        s3_destination_update: S3DestinationUpdate = None,
        extended_s3_destination_update: ExtendedS3DestinationUpdate = None,
        redshift_destination_update: RedshiftDestinationUpdate = None,
        elasticsearch_destination_update: ElasticsearchDestinationUpdate = None,
        amazonopensearchservice_destination_update: AmazonopensearchserviceDestinationUpdate = None,
        splunk_destination_update: SplunkDestinationUpdate = None,
        http_endpoint_destination_update: HttpEndpointDestinationUpdate = None,
        amazon_open_search_serverless_destination_update: AmazonOpenSearchServerlessDestinationUpdate = None,
        snowflake_destination_update: SnowflakeDestinationUpdate = None,
        iceberg_destination_update: IcebergDestinationUpdate = None,
        **kwargs,
    ) -> UpdateDestinationOutput:
        raise NotImplementedError

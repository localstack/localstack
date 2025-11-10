from datetime import datetime
from enum import StrEnum
from typing import TypedDict

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
DatabaseColumnName = str
DatabaseEndpoint = str
DatabaseName = str
DatabasePort = int
DatabaseTableName = str
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
StringWithLettersDigitsUnderscoresDots = str
TagKey = str
TagValue = str
ThroughputHintInMBs = int
TopicName = str
Username = str
VpcEndpointServiceName = str
WarehouseLocation = str


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


class DatabaseType(StrEnum):
    MySQL = "MySQL"
    PostgreSQL = "PostgreSQL"


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
    VPC_ENDPOINT_SERVICE_NAME_NOT_FOUND = "VPC_ENDPOINT_SERVICE_NAME_NOT_FOUND"
    VPC_INTERFACE_ENDPOINT_SERVICE_ACCESS_DENIED = "VPC_INTERFACE_ENDPOINT_SERVICE_ACCESS_DENIED"
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
    DatabaseAsSource = "DatabaseAsSource"


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


class SSLMode(StrEnum):
    Disabled = "Disabled"
    Enabled = "Enabled"


class SnapshotRequestedBy(StrEnum):
    USER = "USER"
    FIREHOSE = "FIREHOSE"


class SnapshotStatus(StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETE = "COMPLETE"
    SUSPENDED = "SUSPENDED"


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
    IntervalInSeconds: AmazonOpenSearchServerlessBufferingIntervalInSeconds | None
    SizeInMBs: AmazonOpenSearchServerlessBufferingSizeInMBs | None


SecurityGroupIdList = list[NonEmptyStringWithoutWhitespace]
SubnetIdList = list[NonEmptyStringWithoutWhitespace]


class VpcConfiguration(TypedDict, total=False):
    SubnetIds: SubnetIdList
    RoleARN: RoleARN
    SecurityGroupIds: SecurityGroupIdList


class CloudWatchLoggingOptions(TypedDict, total=False):
    Enabled: BooleanObject | None
    LogGroupName: LogGroupName | None
    LogStreamName: LogStreamName | None


class ProcessorParameter(TypedDict, total=False):
    ParameterName: ProcessorParameterName
    ParameterValue: ProcessorParameterValue


ProcessorParameterList = list[ProcessorParameter]


class Processor(TypedDict, total=False):
    Type: ProcessorType
    Parameters: ProcessorParameterList | None


ProcessorList = list[Processor]


class ProcessingConfiguration(TypedDict, total=False):
    Enabled: BooleanObject | None
    Processors: ProcessorList | None


class KMSEncryptionConfig(TypedDict, total=False):
    AWSKMSKeyARN: AWSKMSKeyARN


class EncryptionConfiguration(TypedDict, total=False):
    NoEncryptionConfig: NoEncryptionConfig | None
    KMSEncryptionConfig: KMSEncryptionConfig | None


class BufferingHints(TypedDict, total=False):
    SizeInMBs: SizeInMBs | None
    IntervalInSeconds: IntervalInSeconds | None


class S3DestinationConfiguration(TypedDict, total=False):
    RoleARN: RoleARN
    BucketARN: BucketARN
    Prefix: Prefix | None
    ErrorOutputPrefix: ErrorOutputPrefix | None
    BufferingHints: BufferingHints | None
    CompressionFormat: CompressionFormat | None
    EncryptionConfiguration: EncryptionConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None


class AmazonOpenSearchServerlessRetryOptions(TypedDict, total=False):
    DurationInSeconds: AmazonOpenSearchServerlessRetryDurationInSeconds | None


class AmazonOpenSearchServerlessDestinationConfiguration(TypedDict, total=False):
    RoleARN: RoleARN
    CollectionEndpoint: AmazonOpenSearchServerlessCollectionEndpoint | None
    IndexName: AmazonOpenSearchServerlessIndexName
    BufferingHints: AmazonOpenSearchServerlessBufferingHints | None
    RetryOptions: AmazonOpenSearchServerlessRetryOptions | None
    S3BackupMode: AmazonOpenSearchServerlessS3BackupMode | None
    S3Configuration: S3DestinationConfiguration
    ProcessingConfiguration: ProcessingConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    VpcConfiguration: VpcConfiguration | None


class VpcConfigurationDescription(TypedDict, total=False):
    SubnetIds: SubnetIdList
    RoleARN: RoleARN
    SecurityGroupIds: SecurityGroupIdList
    VpcId: NonEmptyStringWithoutWhitespace


class S3DestinationDescription(TypedDict, total=False):
    RoleARN: RoleARN
    BucketARN: BucketARN
    Prefix: Prefix | None
    ErrorOutputPrefix: ErrorOutputPrefix | None
    BufferingHints: BufferingHints
    CompressionFormat: CompressionFormat
    EncryptionConfiguration: EncryptionConfiguration
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None


class AmazonOpenSearchServerlessDestinationDescription(TypedDict, total=False):
    RoleARN: RoleARN | None
    CollectionEndpoint: AmazonOpenSearchServerlessCollectionEndpoint | None
    IndexName: AmazonOpenSearchServerlessIndexName | None
    BufferingHints: AmazonOpenSearchServerlessBufferingHints | None
    RetryOptions: AmazonOpenSearchServerlessRetryOptions | None
    S3BackupMode: AmazonOpenSearchServerlessS3BackupMode | None
    S3DestinationDescription: S3DestinationDescription | None
    ProcessingConfiguration: ProcessingConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    VpcConfigurationDescription: VpcConfigurationDescription | None


class S3DestinationUpdate(TypedDict, total=False):
    RoleARN: RoleARN | None
    BucketARN: BucketARN | None
    Prefix: Prefix | None
    ErrorOutputPrefix: ErrorOutputPrefix | None
    BufferingHints: BufferingHints | None
    CompressionFormat: CompressionFormat | None
    EncryptionConfiguration: EncryptionConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None


class AmazonOpenSearchServerlessDestinationUpdate(TypedDict, total=False):
    RoleARN: RoleARN | None
    CollectionEndpoint: AmazonOpenSearchServerlessCollectionEndpoint | None
    IndexName: AmazonOpenSearchServerlessIndexName | None
    BufferingHints: AmazonOpenSearchServerlessBufferingHints | None
    RetryOptions: AmazonOpenSearchServerlessRetryOptions | None
    S3Update: S3DestinationUpdate | None
    ProcessingConfiguration: ProcessingConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None


class AmazonopensearchserviceBufferingHints(TypedDict, total=False):
    IntervalInSeconds: AmazonopensearchserviceBufferingIntervalInSeconds | None
    SizeInMBs: AmazonopensearchserviceBufferingSizeInMBs | None


class DocumentIdOptions(TypedDict, total=False):
    DefaultDocumentIdFormat: DefaultDocumentIdFormat


class AmazonopensearchserviceRetryOptions(TypedDict, total=False):
    DurationInSeconds: AmazonopensearchserviceRetryDurationInSeconds | None


class AmazonopensearchserviceDestinationConfiguration(TypedDict, total=False):
    RoleARN: RoleARN
    DomainARN: AmazonopensearchserviceDomainARN | None
    ClusterEndpoint: AmazonopensearchserviceClusterEndpoint | None
    IndexName: AmazonopensearchserviceIndexName
    TypeName: AmazonopensearchserviceTypeName | None
    IndexRotationPeriod: AmazonopensearchserviceIndexRotationPeriod | None
    BufferingHints: AmazonopensearchserviceBufferingHints | None
    RetryOptions: AmazonopensearchserviceRetryOptions | None
    S3BackupMode: AmazonopensearchserviceS3BackupMode | None
    S3Configuration: S3DestinationConfiguration
    ProcessingConfiguration: ProcessingConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    VpcConfiguration: VpcConfiguration | None
    DocumentIdOptions: DocumentIdOptions | None


class AmazonopensearchserviceDestinationDescription(TypedDict, total=False):
    RoleARN: RoleARN | None
    DomainARN: AmazonopensearchserviceDomainARN | None
    ClusterEndpoint: AmazonopensearchserviceClusterEndpoint | None
    IndexName: AmazonopensearchserviceIndexName | None
    TypeName: AmazonopensearchserviceTypeName | None
    IndexRotationPeriod: AmazonopensearchserviceIndexRotationPeriod | None
    BufferingHints: AmazonopensearchserviceBufferingHints | None
    RetryOptions: AmazonopensearchserviceRetryOptions | None
    S3BackupMode: AmazonopensearchserviceS3BackupMode | None
    S3DestinationDescription: S3DestinationDescription | None
    ProcessingConfiguration: ProcessingConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    VpcConfigurationDescription: VpcConfigurationDescription | None
    DocumentIdOptions: DocumentIdOptions | None


class AmazonopensearchserviceDestinationUpdate(TypedDict, total=False):
    RoleARN: RoleARN | None
    DomainARN: AmazonopensearchserviceDomainARN | None
    ClusterEndpoint: AmazonopensearchserviceClusterEndpoint | None
    IndexName: AmazonopensearchserviceIndexName | None
    TypeName: AmazonopensearchserviceTypeName | None
    IndexRotationPeriod: AmazonopensearchserviceIndexRotationPeriod | None
    BufferingHints: AmazonopensearchserviceBufferingHints | None
    RetryOptions: AmazonopensearchserviceRetryOptions | None
    S3Update: S3DestinationUpdate | None
    ProcessingConfiguration: ProcessingConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    DocumentIdOptions: DocumentIdOptions | None


class AuthenticationConfiguration(TypedDict, total=False):
    RoleARN: RoleARN
    Connectivity: Connectivity


class CatalogConfiguration(TypedDict, total=False):
    CatalogARN: GlueDataCatalogARN | None
    WarehouseLocation: WarehouseLocation | None


ColumnToJsonKeyMappings = dict[NonEmptyStringWithoutWhitespace, NonEmptyString]


class CopyCommand(TypedDict, total=False):
    DataTableName: DataTableName
    DataTableColumns: DataTableColumns | None
    CopyOptions: CopyOptions | None


class DatabaseSourceVPCConfiguration(TypedDict, total=False):
    VpcEndpointServiceName: VpcEndpointServiceName


class SecretsManagerConfiguration(TypedDict, total=False):
    SecretARN: SecretARN | None
    RoleARN: RoleARN | None
    Enabled: BooleanObject


class DatabaseSourceAuthenticationConfiguration(TypedDict, total=False):
    SecretsManagerConfiguration: SecretsManagerConfiguration


DatabaseSurrogateKeyList = list[NonEmptyStringWithoutWhitespace]
DatabaseColumnIncludeOrExcludeList = list[DatabaseColumnName]


class DatabaseColumnList(TypedDict, total=False):
    Include: DatabaseColumnIncludeOrExcludeList | None
    Exclude: DatabaseColumnIncludeOrExcludeList | None


DatabaseTableIncludeOrExcludeList = list[DatabaseTableName]


class DatabaseTableList(TypedDict, total=False):
    Include: DatabaseTableIncludeOrExcludeList | None
    Exclude: DatabaseTableIncludeOrExcludeList | None


DatabaseIncludeOrExcludeList = list[DatabaseName]


class DatabaseList(TypedDict, total=False):
    Include: DatabaseIncludeOrExcludeList | None
    Exclude: DatabaseIncludeOrExcludeList | None


class DatabaseSourceConfiguration(TypedDict, total=False):
    Type: DatabaseType
    Endpoint: DatabaseEndpoint
    Port: DatabasePort
    SSLMode: SSLMode | None
    Databases: DatabaseList
    Tables: DatabaseTableList
    Columns: DatabaseColumnList | None
    SurrogateKeys: DatabaseSurrogateKeyList | None
    SnapshotWatermarkTable: DatabaseTableName
    DatabaseSourceAuthenticationConfiguration: DatabaseSourceAuthenticationConfiguration
    DatabaseSourceVPCConfiguration: DatabaseSourceVPCConfiguration


class RetryOptions(TypedDict, total=False):
    DurationInSeconds: RetryDurationInSeconds | None


class TableCreationConfiguration(TypedDict, total=False):
    Enabled: BooleanObject


class SchemaEvolutionConfiguration(TypedDict, total=False):
    Enabled: BooleanObject


class PartitionField(TypedDict, total=False):
    SourceName: NonEmptyStringWithoutWhitespace


PartitionFields = list[PartitionField]


class PartitionSpec(TypedDict, total=False):
    Identity: PartitionFields | None


ListOfNonEmptyStringsWithoutWhitespace = list[NonEmptyStringWithoutWhitespace]


class DestinationTableConfiguration(TypedDict, total=False):
    DestinationTableName: StringWithLettersDigitsUnderscoresDots
    DestinationDatabaseName: StringWithLettersDigitsUnderscoresDots
    UniqueKeys: ListOfNonEmptyStringsWithoutWhitespace | None
    PartitionSpec: PartitionSpec | None
    S3ErrorOutputPrefix: ErrorOutputPrefix | None


DestinationTableConfigurationList = list[DestinationTableConfiguration]


class IcebergDestinationConfiguration(TypedDict, total=False):
    DestinationTableConfigurationList: DestinationTableConfigurationList | None
    SchemaEvolutionConfiguration: SchemaEvolutionConfiguration | None
    TableCreationConfiguration: TableCreationConfiguration | None
    BufferingHints: BufferingHints | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    ProcessingConfiguration: ProcessingConfiguration | None
    S3BackupMode: IcebergS3BackupMode | None
    RetryOptions: RetryOptions | None
    RoleARN: RoleARN
    AppendOnly: BooleanObject | None
    CatalogConfiguration: CatalogConfiguration
    S3Configuration: S3DestinationConfiguration


class SnowflakeBufferingHints(TypedDict, total=False):
    SizeInMBs: SnowflakeBufferingSizeInMBs | None
    IntervalInSeconds: SnowflakeBufferingIntervalInSeconds | None


class SnowflakeRetryOptions(TypedDict, total=False):
    DurationInSeconds: SnowflakeRetryDurationInSeconds | None


class SnowflakeVpcConfiguration(TypedDict, total=False):
    PrivateLinkVpceId: SnowflakePrivateLinkVpceId


class SnowflakeRoleConfiguration(TypedDict, total=False):
    Enabled: BooleanObject | None
    SnowflakeRole: SnowflakeRole | None


class SnowflakeDestinationConfiguration(TypedDict, total=False):
    AccountUrl: SnowflakeAccountUrl
    PrivateKey: SnowflakePrivateKey | None
    KeyPassphrase: SnowflakeKeyPassphrase | None
    User: SnowflakeUser | None
    Database: SnowflakeDatabase
    Schema: SnowflakeSchema
    Table: SnowflakeTable
    SnowflakeRoleConfiguration: SnowflakeRoleConfiguration | None
    DataLoadingOption: SnowflakeDataLoadingOption | None
    MetaDataColumnName: SnowflakeMetaDataColumnName | None
    ContentColumnName: SnowflakeContentColumnName | None
    SnowflakeVpcConfiguration: SnowflakeVpcConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    ProcessingConfiguration: ProcessingConfiguration | None
    RoleARN: RoleARN
    RetryOptions: SnowflakeRetryOptions | None
    S3BackupMode: SnowflakeS3BackupMode | None
    S3Configuration: S3DestinationConfiguration
    SecretsManagerConfiguration: SecretsManagerConfiguration | None
    BufferingHints: SnowflakeBufferingHints | None


ReadFromTimestamp = datetime


class MSKSourceConfiguration(TypedDict, total=False):
    MSKClusterARN: MSKClusterARN
    TopicName: TopicName
    AuthenticationConfiguration: AuthenticationConfiguration
    ReadFromTimestamp: ReadFromTimestamp | None


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue | None


TagDeliveryStreamInputTagList = list[Tag]


class HttpEndpointRetryOptions(TypedDict, total=False):
    DurationInSeconds: HttpEndpointRetryDurationInSeconds | None


class HttpEndpointCommonAttribute(TypedDict, total=False):
    AttributeName: HttpEndpointAttributeName
    AttributeValue: HttpEndpointAttributeValue


HttpEndpointCommonAttributesList = list[HttpEndpointCommonAttribute]


class HttpEndpointRequestConfiguration(TypedDict, total=False):
    ContentEncoding: ContentEncoding | None
    CommonAttributes: HttpEndpointCommonAttributesList | None


class HttpEndpointBufferingHints(TypedDict, total=False):
    SizeInMBs: HttpEndpointBufferingSizeInMBs | None
    IntervalInSeconds: HttpEndpointBufferingIntervalInSeconds | None


class HttpEndpointConfiguration(TypedDict, total=False):
    Url: HttpEndpointUrl
    Name: HttpEndpointName | None
    AccessKey: HttpEndpointAccessKey | None


class HttpEndpointDestinationConfiguration(TypedDict, total=False):
    EndpointConfiguration: HttpEndpointConfiguration
    BufferingHints: HttpEndpointBufferingHints | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    RequestConfiguration: HttpEndpointRequestConfiguration | None
    ProcessingConfiguration: ProcessingConfiguration | None
    RoleARN: RoleARN | None
    RetryOptions: HttpEndpointRetryOptions | None
    S3BackupMode: HttpEndpointS3BackupMode | None
    S3Configuration: S3DestinationConfiguration
    SecretsManagerConfiguration: SecretsManagerConfiguration | None


class SplunkBufferingHints(TypedDict, total=False):
    IntervalInSeconds: SplunkBufferingIntervalInSeconds | None
    SizeInMBs: SplunkBufferingSizeInMBs | None


class SplunkRetryOptions(TypedDict, total=False):
    DurationInSeconds: SplunkRetryDurationInSeconds | None


class SplunkDestinationConfiguration(TypedDict, total=False):
    HECEndpoint: HECEndpoint
    HECEndpointType: HECEndpointType
    HECToken: HECToken | None
    HECAcknowledgmentTimeoutInSeconds: HECAcknowledgmentTimeoutInSeconds | None
    RetryOptions: SplunkRetryOptions | None
    S3BackupMode: SplunkS3BackupMode | None
    S3Configuration: S3DestinationConfiguration
    ProcessingConfiguration: ProcessingConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    BufferingHints: SplunkBufferingHints | None
    SecretsManagerConfiguration: SecretsManagerConfiguration | None


class ElasticsearchRetryOptions(TypedDict, total=False):
    DurationInSeconds: ElasticsearchRetryDurationInSeconds | None


class ElasticsearchBufferingHints(TypedDict, total=False):
    IntervalInSeconds: ElasticsearchBufferingIntervalInSeconds | None
    SizeInMBs: ElasticsearchBufferingSizeInMBs | None


class ElasticsearchDestinationConfiguration(TypedDict, total=False):
    RoleARN: RoleARN
    DomainARN: ElasticsearchDomainARN | None
    ClusterEndpoint: ElasticsearchClusterEndpoint | None
    IndexName: ElasticsearchIndexName
    TypeName: ElasticsearchTypeName | None
    IndexRotationPeriod: ElasticsearchIndexRotationPeriod | None
    BufferingHints: ElasticsearchBufferingHints | None
    RetryOptions: ElasticsearchRetryOptions | None
    S3BackupMode: ElasticsearchS3BackupMode | None
    S3Configuration: S3DestinationConfiguration
    ProcessingConfiguration: ProcessingConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    VpcConfiguration: VpcConfiguration | None
    DocumentIdOptions: DocumentIdOptions | None


class RedshiftRetryOptions(TypedDict, total=False):
    DurationInSeconds: RedshiftRetryDurationInSeconds | None


class RedshiftDestinationConfiguration(TypedDict, total=False):
    RoleARN: RoleARN
    ClusterJDBCURL: ClusterJDBCURL
    CopyCommand: CopyCommand
    Username: Username | None
    Password: Password | None
    RetryOptions: RedshiftRetryOptions | None
    S3Configuration: S3DestinationConfiguration
    ProcessingConfiguration: ProcessingConfiguration | None
    S3BackupMode: RedshiftS3BackupMode | None
    S3BackupConfiguration: S3DestinationConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    SecretsManagerConfiguration: SecretsManagerConfiguration | None


class DynamicPartitioningConfiguration(TypedDict, total=False):
    RetryOptions: RetryOptions | None
    Enabled: BooleanObject | None


class OrcSerDe(TypedDict, total=False):
    StripeSizeBytes: OrcStripeSizeBytes | None
    BlockSizeBytes: BlockSizeBytes | None
    RowIndexStride: OrcRowIndexStride | None
    EnablePadding: BooleanObject | None
    PaddingTolerance: Proportion | None
    Compression: OrcCompression | None
    BloomFilterColumns: ListOfNonEmptyStringsWithoutWhitespace | None
    BloomFilterFalsePositiveProbability: Proportion | None
    DictionaryKeyThreshold: Proportion | None
    FormatVersion: OrcFormatVersion | None


class ParquetSerDe(TypedDict, total=False):
    BlockSizeBytes: BlockSizeBytes | None
    PageSizeBytes: ParquetPageSizeBytes | None
    Compression: ParquetCompression | None
    EnableDictionaryCompression: BooleanObject | None
    MaxPaddingBytes: NonNegativeIntegerObject | None
    WriterVersion: ParquetWriterVersion | None


class Serializer(TypedDict, total=False):
    ParquetSerDe: ParquetSerDe | None
    OrcSerDe: OrcSerDe | None


class OutputFormatConfiguration(TypedDict, total=False):
    Serializer: Serializer | None


ListOfNonEmptyStrings = list[NonEmptyString]


class HiveJsonSerDe(TypedDict, total=False):
    TimestampFormats: ListOfNonEmptyStrings | None


class OpenXJsonSerDe(TypedDict, total=False):
    ConvertDotsInJsonKeysToUnderscores: BooleanObject | None
    CaseInsensitive: BooleanObject | None
    ColumnToJsonKeyMappings: ColumnToJsonKeyMappings | None


class Deserializer(TypedDict, total=False):
    OpenXJsonSerDe: OpenXJsonSerDe | None
    HiveJsonSerDe: HiveJsonSerDe | None


class InputFormatConfiguration(TypedDict, total=False):
    Deserializer: Deserializer | None


class SchemaConfiguration(TypedDict, total=False):
    RoleARN: NonEmptyStringWithoutWhitespace | None
    CatalogId: NonEmptyStringWithoutWhitespace | None
    DatabaseName: NonEmptyStringWithoutWhitespace | None
    TableName: NonEmptyStringWithoutWhitespace | None
    Region: NonEmptyStringWithoutWhitespace | None
    VersionId: NonEmptyStringWithoutWhitespace | None


class DataFormatConversionConfiguration(TypedDict, total=False):
    SchemaConfiguration: SchemaConfiguration | None
    InputFormatConfiguration: InputFormatConfiguration | None
    OutputFormatConfiguration: OutputFormatConfiguration | None
    Enabled: BooleanObject | None


class ExtendedS3DestinationConfiguration(TypedDict, total=False):
    RoleARN: RoleARN
    BucketARN: BucketARN
    Prefix: Prefix | None
    ErrorOutputPrefix: ErrorOutputPrefix | None
    BufferingHints: BufferingHints | None
    CompressionFormat: CompressionFormat | None
    EncryptionConfiguration: EncryptionConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    ProcessingConfiguration: ProcessingConfiguration | None
    S3BackupMode: S3BackupMode | None
    S3BackupConfiguration: S3DestinationConfiguration | None
    DataFormatConversionConfiguration: DataFormatConversionConfiguration | None
    DynamicPartitioningConfiguration: DynamicPartitioningConfiguration | None
    FileExtension: FileExtension | None
    CustomTimeZone: CustomTimeZone | None


class DeliveryStreamEncryptionConfigurationInput(TypedDict, total=False):
    KeyARN: AWSKMSKeyARN | None
    KeyType: KeyType


class KinesisStreamSourceConfiguration(TypedDict, total=False):
    KinesisStreamARN: KinesisStreamARN
    RoleARN: RoleARN


class DirectPutSourceConfiguration(TypedDict, total=False):
    ThroughputHintInMBs: ThroughputHintInMBs


class CreateDeliveryStreamInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    DeliveryStreamType: DeliveryStreamType | None
    DirectPutSourceConfiguration: DirectPutSourceConfiguration | None
    KinesisStreamSourceConfiguration: KinesisStreamSourceConfiguration | None
    DeliveryStreamEncryptionConfigurationInput: DeliveryStreamEncryptionConfigurationInput | None
    S3DestinationConfiguration: S3DestinationConfiguration | None
    ExtendedS3DestinationConfiguration: ExtendedS3DestinationConfiguration | None
    RedshiftDestinationConfiguration: RedshiftDestinationConfiguration | None
    ElasticsearchDestinationConfiguration: ElasticsearchDestinationConfiguration | None
    AmazonopensearchserviceDestinationConfiguration: (
        AmazonopensearchserviceDestinationConfiguration | None
    )
    SplunkDestinationConfiguration: SplunkDestinationConfiguration | None
    HttpEndpointDestinationConfiguration: HttpEndpointDestinationConfiguration | None
    Tags: TagDeliveryStreamInputTagList | None
    AmazonOpenSearchServerlessDestinationConfiguration: (
        AmazonOpenSearchServerlessDestinationConfiguration | None
    )
    MSKSourceConfiguration: MSKSourceConfiguration | None
    SnowflakeDestinationConfiguration: SnowflakeDestinationConfiguration | None
    IcebergDestinationConfiguration: IcebergDestinationConfiguration | None
    DatabaseSourceConfiguration: DatabaseSourceConfiguration | None


class CreateDeliveryStreamOutput(TypedDict, total=False):
    DeliveryStreamARN: DeliveryStreamARN | None


Data = bytes


class FailureDescription(TypedDict, total=False):
    Type: DeliveryStreamFailureType
    Details: NonEmptyString


Timestamp = datetime


class DatabaseSnapshotInfo(TypedDict, total=False):
    Id: NonEmptyStringWithoutWhitespace
    Table: DatabaseTableName
    RequestTimestamp: Timestamp
    RequestedBy: SnapshotRequestedBy
    Status: SnapshotStatus
    FailureDescription: FailureDescription | None


DatabaseSnapshotInfoList = list[DatabaseSnapshotInfo]


class DatabaseSourceDescription(TypedDict, total=False):
    Type: DatabaseType | None
    Endpoint: DatabaseEndpoint | None
    Port: DatabasePort | None
    SSLMode: SSLMode | None
    Databases: DatabaseList | None
    Tables: DatabaseTableList | None
    Columns: DatabaseColumnList | None
    SurrogateKeys: DatabaseColumnIncludeOrExcludeList | None
    SnapshotWatermarkTable: DatabaseTableName | None
    SnapshotInfo: DatabaseSnapshotInfoList | None
    DatabaseSourceAuthenticationConfiguration: DatabaseSourceAuthenticationConfiguration | None
    DatabaseSourceVPCConfiguration: DatabaseSourceVPCConfiguration | None


class DeleteDeliveryStreamInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    AllowForceDelete: BooleanObject | None


class DeleteDeliveryStreamOutput(TypedDict, total=False):
    pass


DeliveryStartTimestamp = datetime


class IcebergDestinationDescription(TypedDict, total=False):
    DestinationTableConfigurationList: DestinationTableConfigurationList | None
    SchemaEvolutionConfiguration: SchemaEvolutionConfiguration | None
    TableCreationConfiguration: TableCreationConfiguration | None
    BufferingHints: BufferingHints | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    ProcessingConfiguration: ProcessingConfiguration | None
    S3BackupMode: IcebergS3BackupMode | None
    RetryOptions: RetryOptions | None
    RoleARN: RoleARN | None
    AppendOnly: BooleanObject | None
    CatalogConfiguration: CatalogConfiguration | None
    S3DestinationDescription: S3DestinationDescription | None


class SnowflakeDestinationDescription(TypedDict, total=False):
    AccountUrl: SnowflakeAccountUrl | None
    User: SnowflakeUser | None
    Database: SnowflakeDatabase | None
    Schema: SnowflakeSchema | None
    Table: SnowflakeTable | None
    SnowflakeRoleConfiguration: SnowflakeRoleConfiguration | None
    DataLoadingOption: SnowflakeDataLoadingOption | None
    MetaDataColumnName: SnowflakeMetaDataColumnName | None
    ContentColumnName: SnowflakeContentColumnName | None
    SnowflakeVpcConfiguration: SnowflakeVpcConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    ProcessingConfiguration: ProcessingConfiguration | None
    RoleARN: RoleARN | None
    RetryOptions: SnowflakeRetryOptions | None
    S3BackupMode: SnowflakeS3BackupMode | None
    S3DestinationDescription: S3DestinationDescription | None
    SecretsManagerConfiguration: SecretsManagerConfiguration | None
    BufferingHints: SnowflakeBufferingHints | None


class HttpEndpointDescription(TypedDict, total=False):
    Url: HttpEndpointUrl | None
    Name: HttpEndpointName | None


class HttpEndpointDestinationDescription(TypedDict, total=False):
    EndpointConfiguration: HttpEndpointDescription | None
    BufferingHints: HttpEndpointBufferingHints | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    RequestConfiguration: HttpEndpointRequestConfiguration | None
    ProcessingConfiguration: ProcessingConfiguration | None
    RoleARN: RoleARN | None
    RetryOptions: HttpEndpointRetryOptions | None
    S3BackupMode: HttpEndpointS3BackupMode | None
    S3DestinationDescription: S3DestinationDescription | None
    SecretsManagerConfiguration: SecretsManagerConfiguration | None


class SplunkDestinationDescription(TypedDict, total=False):
    HECEndpoint: HECEndpoint | None
    HECEndpointType: HECEndpointType | None
    HECToken: HECToken | None
    HECAcknowledgmentTimeoutInSeconds: HECAcknowledgmentTimeoutInSeconds | None
    RetryOptions: SplunkRetryOptions | None
    S3BackupMode: SplunkS3BackupMode | None
    S3DestinationDescription: S3DestinationDescription | None
    ProcessingConfiguration: ProcessingConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    BufferingHints: SplunkBufferingHints | None
    SecretsManagerConfiguration: SecretsManagerConfiguration | None


class ElasticsearchDestinationDescription(TypedDict, total=False):
    RoleARN: RoleARN | None
    DomainARN: ElasticsearchDomainARN | None
    ClusterEndpoint: ElasticsearchClusterEndpoint | None
    IndexName: ElasticsearchIndexName | None
    TypeName: ElasticsearchTypeName | None
    IndexRotationPeriod: ElasticsearchIndexRotationPeriod | None
    BufferingHints: ElasticsearchBufferingHints | None
    RetryOptions: ElasticsearchRetryOptions | None
    S3BackupMode: ElasticsearchS3BackupMode | None
    S3DestinationDescription: S3DestinationDescription | None
    ProcessingConfiguration: ProcessingConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    VpcConfigurationDescription: VpcConfigurationDescription | None
    DocumentIdOptions: DocumentIdOptions | None


class RedshiftDestinationDescription(TypedDict, total=False):
    RoleARN: RoleARN
    ClusterJDBCURL: ClusterJDBCURL
    CopyCommand: CopyCommand
    Username: Username | None
    RetryOptions: RedshiftRetryOptions | None
    S3DestinationDescription: S3DestinationDescription
    ProcessingConfiguration: ProcessingConfiguration | None
    S3BackupMode: RedshiftS3BackupMode | None
    S3BackupDescription: S3DestinationDescription | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    SecretsManagerConfiguration: SecretsManagerConfiguration | None


class ExtendedS3DestinationDescription(TypedDict, total=False):
    RoleARN: RoleARN
    BucketARN: BucketARN
    Prefix: Prefix | None
    ErrorOutputPrefix: ErrorOutputPrefix | None
    BufferingHints: BufferingHints
    CompressionFormat: CompressionFormat
    EncryptionConfiguration: EncryptionConfiguration
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    ProcessingConfiguration: ProcessingConfiguration | None
    S3BackupMode: S3BackupMode | None
    S3BackupDescription: S3DestinationDescription | None
    DataFormatConversionConfiguration: DataFormatConversionConfiguration | None
    DynamicPartitioningConfiguration: DynamicPartitioningConfiguration | None
    FileExtension: FileExtension | None
    CustomTimeZone: CustomTimeZone | None


class DestinationDescription(TypedDict, total=False):
    DestinationId: DestinationId
    S3DestinationDescription: S3DestinationDescription | None
    ExtendedS3DestinationDescription: ExtendedS3DestinationDescription | None
    RedshiftDestinationDescription: RedshiftDestinationDescription | None
    ElasticsearchDestinationDescription: ElasticsearchDestinationDescription | None
    AmazonopensearchserviceDestinationDescription: (
        AmazonopensearchserviceDestinationDescription | None
    )
    SplunkDestinationDescription: SplunkDestinationDescription | None
    HttpEndpointDestinationDescription: HttpEndpointDestinationDescription | None
    SnowflakeDestinationDescription: SnowflakeDestinationDescription | None
    AmazonOpenSearchServerlessDestinationDescription: (
        AmazonOpenSearchServerlessDestinationDescription | None
    )
    IcebergDestinationDescription: IcebergDestinationDescription | None


DestinationDescriptionList = list[DestinationDescription]


class MSKSourceDescription(TypedDict, total=False):
    MSKClusterARN: MSKClusterARN | None
    TopicName: TopicName | None
    AuthenticationConfiguration: AuthenticationConfiguration | None
    DeliveryStartTimestamp: DeliveryStartTimestamp | None
    ReadFromTimestamp: ReadFromTimestamp | None


class KinesisStreamSourceDescription(TypedDict, total=False):
    KinesisStreamARN: KinesisStreamARN | None
    RoleARN: RoleARN | None
    DeliveryStartTimestamp: DeliveryStartTimestamp | None


class DirectPutSourceDescription(TypedDict, total=False):
    ThroughputHintInMBs: ThroughputHintInMBs | None


class SourceDescription(TypedDict, total=False):
    DirectPutSourceDescription: DirectPutSourceDescription | None
    KinesisStreamSourceDescription: KinesisStreamSourceDescription | None
    MSKSourceDescription: MSKSourceDescription | None
    DatabaseSourceDescription: DatabaseSourceDescription | None


class DeliveryStreamEncryptionConfiguration(TypedDict, total=False):
    KeyARN: AWSKMSKeyARN | None
    KeyType: KeyType | None
    Status: DeliveryStreamEncryptionStatus | None
    FailureDescription: FailureDescription | None


class DeliveryStreamDescription(TypedDict, total=False):
    DeliveryStreamName: DeliveryStreamName
    DeliveryStreamARN: DeliveryStreamARN
    DeliveryStreamStatus: DeliveryStreamStatus
    FailureDescription: FailureDescription | None
    DeliveryStreamEncryptionConfiguration: DeliveryStreamEncryptionConfiguration | None
    DeliveryStreamType: DeliveryStreamType
    VersionId: DeliveryStreamVersionId
    CreateTimestamp: Timestamp | None
    LastUpdateTimestamp: Timestamp | None
    Source: SourceDescription | None
    Destinations: DestinationDescriptionList
    HasMoreDestinations: BooleanObject


DeliveryStreamNameList = list[DeliveryStreamName]


class DescribeDeliveryStreamInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    Limit: DescribeDeliveryStreamInputLimit | None
    ExclusiveStartDestinationId: DestinationId | None


class DescribeDeliveryStreamOutput(TypedDict, total=False):
    DeliveryStreamDescription: DeliveryStreamDescription


class ElasticsearchDestinationUpdate(TypedDict, total=False):
    RoleARN: RoleARN | None
    DomainARN: ElasticsearchDomainARN | None
    ClusterEndpoint: ElasticsearchClusterEndpoint | None
    IndexName: ElasticsearchIndexName | None
    TypeName: ElasticsearchTypeName | None
    IndexRotationPeriod: ElasticsearchIndexRotationPeriod | None
    BufferingHints: ElasticsearchBufferingHints | None
    RetryOptions: ElasticsearchRetryOptions | None
    S3Update: S3DestinationUpdate | None
    ProcessingConfiguration: ProcessingConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    DocumentIdOptions: DocumentIdOptions | None


class ExtendedS3DestinationUpdate(TypedDict, total=False):
    RoleARN: RoleARN | None
    BucketARN: BucketARN | None
    Prefix: Prefix | None
    ErrorOutputPrefix: ErrorOutputPrefix | None
    BufferingHints: BufferingHints | None
    CompressionFormat: CompressionFormat | None
    EncryptionConfiguration: EncryptionConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    ProcessingConfiguration: ProcessingConfiguration | None
    S3BackupMode: S3BackupMode | None
    S3BackupUpdate: S3DestinationUpdate | None
    DataFormatConversionConfiguration: DataFormatConversionConfiguration | None
    DynamicPartitioningConfiguration: DynamicPartitioningConfiguration | None
    FileExtension: FileExtension | None
    CustomTimeZone: CustomTimeZone | None


class HttpEndpointDestinationUpdate(TypedDict, total=False):
    EndpointConfiguration: HttpEndpointConfiguration | None
    BufferingHints: HttpEndpointBufferingHints | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    RequestConfiguration: HttpEndpointRequestConfiguration | None
    ProcessingConfiguration: ProcessingConfiguration | None
    RoleARN: RoleARN | None
    RetryOptions: HttpEndpointRetryOptions | None
    S3BackupMode: HttpEndpointS3BackupMode | None
    S3Update: S3DestinationUpdate | None
    SecretsManagerConfiguration: SecretsManagerConfiguration | None


class IcebergDestinationUpdate(TypedDict, total=False):
    DestinationTableConfigurationList: DestinationTableConfigurationList | None
    SchemaEvolutionConfiguration: SchemaEvolutionConfiguration | None
    TableCreationConfiguration: TableCreationConfiguration | None
    BufferingHints: BufferingHints | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    ProcessingConfiguration: ProcessingConfiguration | None
    S3BackupMode: IcebergS3BackupMode | None
    RetryOptions: RetryOptions | None
    RoleARN: RoleARN | None
    AppendOnly: BooleanObject | None
    CatalogConfiguration: CatalogConfiguration | None
    S3Configuration: S3DestinationConfiguration | None


class ListDeliveryStreamsInput(ServiceRequest):
    Limit: ListDeliveryStreamsInputLimit | None
    DeliveryStreamType: DeliveryStreamType | None
    ExclusiveStartDeliveryStreamName: DeliveryStreamName | None


class ListDeliveryStreamsOutput(TypedDict, total=False):
    DeliveryStreamNames: DeliveryStreamNameList
    HasMoreDeliveryStreams: BooleanObject


class ListTagsForDeliveryStreamInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    ExclusiveStartTagKey: TagKey | None
    Limit: ListTagsForDeliveryStreamInputLimit | None


ListTagsForDeliveryStreamOutputTagList = list[Tag]


class ListTagsForDeliveryStreamOutput(TypedDict, total=False):
    Tags: ListTagsForDeliveryStreamOutputTagList
    HasMoreTags: BooleanObject


class Record(TypedDict, total=False):
    Data: Data


PutRecordBatchRequestEntryList = list[Record]


class PutRecordBatchInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    Records: PutRecordBatchRequestEntryList


class PutRecordBatchResponseEntry(TypedDict, total=False):
    RecordId: PutResponseRecordId | None
    ErrorCode: ErrorCode | None
    ErrorMessage: ErrorMessage | None


PutRecordBatchResponseEntryList = list[PutRecordBatchResponseEntry]


class PutRecordBatchOutput(TypedDict, total=False):
    FailedPutCount: NonNegativeIntegerObject
    Encrypted: BooleanObject | None
    RequestResponses: PutRecordBatchResponseEntryList


class PutRecordInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    Record: Record


class PutRecordOutput(TypedDict, total=False):
    RecordId: PutResponseRecordId
    Encrypted: BooleanObject | None


class RedshiftDestinationUpdate(TypedDict, total=False):
    RoleARN: RoleARN | None
    ClusterJDBCURL: ClusterJDBCURL | None
    CopyCommand: CopyCommand | None
    Username: Username | None
    Password: Password | None
    RetryOptions: RedshiftRetryOptions | None
    S3Update: S3DestinationUpdate | None
    ProcessingConfiguration: ProcessingConfiguration | None
    S3BackupMode: RedshiftS3BackupMode | None
    S3BackupUpdate: S3DestinationUpdate | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    SecretsManagerConfiguration: SecretsManagerConfiguration | None


class SnowflakeDestinationUpdate(TypedDict, total=False):
    AccountUrl: SnowflakeAccountUrl | None
    PrivateKey: SnowflakePrivateKey | None
    KeyPassphrase: SnowflakeKeyPassphrase | None
    User: SnowflakeUser | None
    Database: SnowflakeDatabase | None
    Schema: SnowflakeSchema | None
    Table: SnowflakeTable | None
    SnowflakeRoleConfiguration: SnowflakeRoleConfiguration | None
    DataLoadingOption: SnowflakeDataLoadingOption | None
    MetaDataColumnName: SnowflakeMetaDataColumnName | None
    ContentColumnName: SnowflakeContentColumnName | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    ProcessingConfiguration: ProcessingConfiguration | None
    RoleARN: RoleARN | None
    RetryOptions: SnowflakeRetryOptions | None
    S3BackupMode: SnowflakeS3BackupMode | None
    S3Update: S3DestinationUpdate | None
    SecretsManagerConfiguration: SecretsManagerConfiguration | None
    BufferingHints: SnowflakeBufferingHints | None


class SplunkDestinationUpdate(TypedDict, total=False):
    HECEndpoint: HECEndpoint | None
    HECEndpointType: HECEndpointType | None
    HECToken: HECToken | None
    HECAcknowledgmentTimeoutInSeconds: HECAcknowledgmentTimeoutInSeconds | None
    RetryOptions: SplunkRetryOptions | None
    S3BackupMode: SplunkS3BackupMode | None
    S3Update: S3DestinationUpdate | None
    ProcessingConfiguration: ProcessingConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    BufferingHints: SplunkBufferingHints | None
    SecretsManagerConfiguration: SecretsManagerConfiguration | None


class StartDeliveryStreamEncryptionInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    DeliveryStreamEncryptionConfigurationInput: DeliveryStreamEncryptionConfigurationInput | None


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


TagKeyList = list[TagKey]


class UntagDeliveryStreamInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    TagKeys: TagKeyList


class UntagDeliveryStreamOutput(TypedDict, total=False):
    pass


class UpdateDestinationInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    CurrentDeliveryStreamVersionId: DeliveryStreamVersionId
    DestinationId: DestinationId
    S3DestinationUpdate: S3DestinationUpdate | None
    ExtendedS3DestinationUpdate: ExtendedS3DestinationUpdate | None
    RedshiftDestinationUpdate: RedshiftDestinationUpdate | None
    ElasticsearchDestinationUpdate: ElasticsearchDestinationUpdate | None
    AmazonopensearchserviceDestinationUpdate: AmazonopensearchserviceDestinationUpdate | None
    SplunkDestinationUpdate: SplunkDestinationUpdate | None
    HttpEndpointDestinationUpdate: HttpEndpointDestinationUpdate | None
    AmazonOpenSearchServerlessDestinationUpdate: AmazonOpenSearchServerlessDestinationUpdate | None
    SnowflakeDestinationUpdate: SnowflakeDestinationUpdate | None
    IcebergDestinationUpdate: IcebergDestinationUpdate | None


class UpdateDestinationOutput(TypedDict, total=False):
    pass


class FirehoseApi:
    service: str = "firehose"
    version: str = "2015-08-04"

    @handler("CreateDeliveryStream")
    def create_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        delivery_stream_type: DeliveryStreamType | None = None,
        direct_put_source_configuration: DirectPutSourceConfiguration | None = None,
        kinesis_stream_source_configuration: KinesisStreamSourceConfiguration | None = None,
        delivery_stream_encryption_configuration_input: DeliveryStreamEncryptionConfigurationInput
        | None = None,
        s3_destination_configuration: S3DestinationConfiguration | None = None,
        extended_s3_destination_configuration: ExtendedS3DestinationConfiguration | None = None,
        redshift_destination_configuration: RedshiftDestinationConfiguration | None = None,
        elasticsearch_destination_configuration: ElasticsearchDestinationConfiguration
        | None = None,
        amazonopensearchservice_destination_configuration: AmazonopensearchserviceDestinationConfiguration
        | None = None,
        splunk_destination_configuration: SplunkDestinationConfiguration | None = None,
        http_endpoint_destination_configuration: HttpEndpointDestinationConfiguration | None = None,
        tags: TagDeliveryStreamInputTagList | None = None,
        amazon_open_search_serverless_destination_configuration: AmazonOpenSearchServerlessDestinationConfiguration
        | None = None,
        msk_source_configuration: MSKSourceConfiguration | None = None,
        snowflake_destination_configuration: SnowflakeDestinationConfiguration | None = None,
        iceberg_destination_configuration: IcebergDestinationConfiguration | None = None,
        database_source_configuration: DatabaseSourceConfiguration | None = None,
        **kwargs,
    ) -> CreateDeliveryStreamOutput:
        raise NotImplementedError

    @handler("DeleteDeliveryStream")
    def delete_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        allow_force_delete: BooleanObject | None = None,
        **kwargs,
    ) -> DeleteDeliveryStreamOutput:
        raise NotImplementedError

    @handler("DescribeDeliveryStream")
    def describe_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        limit: DescribeDeliveryStreamInputLimit | None = None,
        exclusive_start_destination_id: DestinationId | None = None,
        **kwargs,
    ) -> DescribeDeliveryStreamOutput:
        raise NotImplementedError

    @handler("ListDeliveryStreams")
    def list_delivery_streams(
        self,
        context: RequestContext,
        limit: ListDeliveryStreamsInputLimit | None = None,
        delivery_stream_type: DeliveryStreamType | None = None,
        exclusive_start_delivery_stream_name: DeliveryStreamName | None = None,
        **kwargs,
    ) -> ListDeliveryStreamsOutput:
        raise NotImplementedError

    @handler("ListTagsForDeliveryStream")
    def list_tags_for_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        exclusive_start_tag_key: TagKey | None = None,
        limit: ListTagsForDeliveryStreamInputLimit | None = None,
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
        delivery_stream_encryption_configuration_input: DeliveryStreamEncryptionConfigurationInput
        | None = None,
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
        s3_destination_update: S3DestinationUpdate | None = None,
        extended_s3_destination_update: ExtendedS3DestinationUpdate | None = None,
        redshift_destination_update: RedshiftDestinationUpdate | None = None,
        elasticsearch_destination_update: ElasticsearchDestinationUpdate | None = None,
        amazonopensearchservice_destination_update: AmazonopensearchserviceDestinationUpdate
        | None = None,
        splunk_destination_update: SplunkDestinationUpdate | None = None,
        http_endpoint_destination_update: HttpEndpointDestinationUpdate | None = None,
        amazon_open_search_serverless_destination_update: AmazonOpenSearchServerlessDestinationUpdate
        | None = None,
        snowflake_destination_update: SnowflakeDestinationUpdate | None = None,
        iceberg_destination_update: IcebergDestinationUpdate | None = None,
        **kwargs,
    ) -> UpdateDestinationOutput:
        raise NotImplementedError

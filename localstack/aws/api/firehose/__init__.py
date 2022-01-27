import sys
from datetime import datetime
from typing import Dict, List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AWSKMSKeyARN = str
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
SizeInMBs = int
SplunkRetryDurationInSeconds = int
TagKey = str
TagValue = str
Username = str


class AmazonopensearchserviceIndexRotationPeriod(str):
    NoRotation = "NoRotation"
    OneHour = "OneHour"
    OneDay = "OneDay"
    OneWeek = "OneWeek"
    OneMonth = "OneMonth"


class AmazonopensearchserviceS3BackupMode(str):
    FailedDocumentsOnly = "FailedDocumentsOnly"
    AllDocuments = "AllDocuments"


class CompressionFormat(str):
    UNCOMPRESSED = "UNCOMPRESSED"
    GZIP = "GZIP"
    ZIP = "ZIP"
    Snappy = "Snappy"
    HADOOP_SNAPPY = "HADOOP_SNAPPY"


class ContentEncoding(str):
    NONE = "NONE"
    GZIP = "GZIP"


class DeliveryStreamEncryptionStatus(str):
    ENABLED = "ENABLED"
    ENABLING = "ENABLING"
    ENABLING_FAILED = "ENABLING_FAILED"
    DISABLED = "DISABLED"
    DISABLING = "DISABLING"
    DISABLING_FAILED = "DISABLING_FAILED"


class DeliveryStreamFailureType(str):
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


class DeliveryStreamStatus(str):
    CREATING = "CREATING"
    CREATING_FAILED = "CREATING_FAILED"
    DELETING = "DELETING"
    DELETING_FAILED = "DELETING_FAILED"
    ACTIVE = "ACTIVE"


class DeliveryStreamType(str):
    DirectPut = "DirectPut"
    KinesisStreamAsSource = "KinesisStreamAsSource"


class ElasticsearchIndexRotationPeriod(str):
    NoRotation = "NoRotation"
    OneHour = "OneHour"
    OneDay = "OneDay"
    OneWeek = "OneWeek"
    OneMonth = "OneMonth"


class ElasticsearchS3BackupMode(str):
    FailedDocumentsOnly = "FailedDocumentsOnly"
    AllDocuments = "AllDocuments"


class HECEndpointType(str):
    Raw = "Raw"
    Event = "Event"


class HttpEndpointS3BackupMode(str):
    FailedDataOnly = "FailedDataOnly"
    AllData = "AllData"


class KeyType(str):
    AWS_OWNED_CMK = "AWS_OWNED_CMK"
    CUSTOMER_MANAGED_CMK = "CUSTOMER_MANAGED_CMK"


class NoEncryptionConfig(str):
    NoEncryption = "NoEncryption"


class OrcCompression(str):
    NONE = "NONE"
    ZLIB = "ZLIB"
    SNAPPY = "SNAPPY"


class OrcFormatVersion(str):
    V0_11 = "V0_11"
    V0_12 = "V0_12"


class ParquetCompression(str):
    UNCOMPRESSED = "UNCOMPRESSED"
    GZIP = "GZIP"
    SNAPPY = "SNAPPY"


class ParquetWriterVersion(str):
    V1 = "V1"
    V2 = "V2"


class ProcessorParameterName(str):
    LambdaArn = "LambdaArn"
    NumberOfRetries = "NumberOfRetries"
    MetadataExtractionQuery = "MetadataExtractionQuery"
    JsonParsingEngine = "JsonParsingEngine"
    RoleArn = "RoleArn"
    BufferSizeInMBs = "BufferSizeInMBs"
    BufferIntervalInSeconds = "BufferIntervalInSeconds"
    SubRecordType = "SubRecordType"
    Delimiter = "Delimiter"


class ProcessorType(str):
    RecordDeAggregation = "RecordDeAggregation"
    Lambda = "Lambda"
    MetadataExtraction = "MetadataExtraction"
    AppendDelimiterToRecord = "AppendDelimiterToRecord"


class RedshiftS3BackupMode(str):
    Disabled = "Disabled"
    Enabled = "Enabled"


class S3BackupMode(str):
    Disabled = "Disabled"
    Enabled = "Enabled"


class SplunkS3BackupMode(str):
    FailedEventsOnly = "FailedEventsOnly"
    AllEvents = "AllEvents"


class ConcurrentModificationException(ServiceException):
    """Another modification has already happened. Fetch ``VersionId`` again and
    use it to update the destination.
    """

    message: Optional[ErrorMessage]


class InvalidArgumentException(ServiceException):
    """The specified input parameter has a value that is not valid."""

    message: Optional[ErrorMessage]


class InvalidKMSResourceException(ServiceException):
    """Kinesis Data Firehose throws this exception when an attempt to put
    records or to start or stop delivery stream encryption fails. This
    happens when the KMS service throws one of the following exception
    types: ``AccessDeniedException``, ``InvalidStateException``,
    ``DisabledException``, or ``NotFoundException``.
    """

    code: Optional[ErrorCode]
    message: Optional[ErrorMessage]


class LimitExceededException(ServiceException):
    """You have already reached the limit for a requested resource."""

    message: Optional[ErrorMessage]


class ResourceInUseException(ServiceException):
    """The resource is already in use and not available for this operation."""

    message: Optional[ErrorMessage]


class ResourceNotFoundException(ServiceException):
    """The specified resource could not be found."""

    message: Optional[ErrorMessage]


class ServiceUnavailableException(ServiceException):
    """The service is unavailable. Back off and retry the operation. If you
    continue to see the exception, throughput limits for the delivery stream
    may have been exceeded. For more information about limits and how to
    request an increase, see `Amazon Kinesis Data Firehose
    Limits <https://docs.aws.amazon.com/firehose/latest/dev/limits.html>`__.
    """

    message: Optional[ErrorMessage]


class AmazonopensearchserviceBufferingHints(TypedDict, total=False):
    IntervalInSeconds: Optional[AmazonopensearchserviceBufferingIntervalInSeconds]
    SizeInMBs: Optional[AmazonopensearchserviceBufferingSizeInMBs]


SecurityGroupIdList = List[NonEmptyStringWithoutWhitespace]
SubnetIdList = List[NonEmptyStringWithoutWhitespace]


class VpcConfiguration(TypedDict, total=False):
    """The details of the VPC of the Amazon ES destination."""

    SubnetIds: SubnetIdList
    RoleARN: RoleARN
    SecurityGroupIds: SecurityGroupIdList


class CloudWatchLoggingOptions(TypedDict, total=False):
    """Describes the Amazon CloudWatch logging options for your delivery
    stream.
    """

    Enabled: Optional[BooleanObject]
    LogGroupName: Optional[LogGroupName]
    LogStreamName: Optional[LogStreamName]


class ProcessorParameter(TypedDict, total=False):
    """Describes the processor parameter."""

    ParameterName: ProcessorParameterName
    ParameterValue: ProcessorParameterValue


ProcessorParameterList = List[ProcessorParameter]


class Processor(TypedDict, total=False):
    """Describes a data processor."""

    Type: ProcessorType
    Parameters: Optional[ProcessorParameterList]


ProcessorList = List[Processor]


class ProcessingConfiguration(TypedDict, total=False):
    """Describes a data processing configuration."""

    Enabled: Optional[BooleanObject]
    Processors: Optional[ProcessorList]


class KMSEncryptionConfig(TypedDict, total=False):
    """Describes an encryption key for a destination in Amazon S3."""

    AWSKMSKeyARN: AWSKMSKeyARN


class EncryptionConfiguration(TypedDict, total=False):
    """Describes the encryption for a destination in Amazon S3."""

    NoEncryptionConfig: Optional[NoEncryptionConfig]
    KMSEncryptionConfig: Optional[KMSEncryptionConfig]


class BufferingHints(TypedDict, total=False):
    """Describes hints for the buffering to perform before delivering data to
    the destination. These options are treated as hints, and therefore
    Kinesis Data Firehose might choose to use different values when it is
    optimal. The ``SizeInMBs`` and ``IntervalInSeconds`` parameters are
    optional. However, if specify a value for one of them, you must also
    provide a value for the other.
    """

    SizeInMBs: Optional[SizeInMBs]
    IntervalInSeconds: Optional[IntervalInSeconds]


class S3DestinationConfiguration(TypedDict, total=False):
    """Describes the configuration of a destination in Amazon S3."""

    RoleARN: RoleARN
    BucketARN: BucketARN
    Prefix: Optional[Prefix]
    ErrorOutputPrefix: Optional[ErrorOutputPrefix]
    BufferingHints: Optional[BufferingHints]
    CompressionFormat: Optional[CompressionFormat]
    EncryptionConfiguration: Optional[EncryptionConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]


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


class VpcConfigurationDescription(TypedDict, total=False):
    """The details of the VPC of the Amazon ES destination."""

    SubnetIds: SubnetIdList
    RoleARN: RoleARN
    SecurityGroupIds: SecurityGroupIdList
    VpcId: NonEmptyStringWithoutWhitespace


class S3DestinationDescription(TypedDict, total=False):
    """Describes a destination in Amazon S3."""

    RoleARN: RoleARN
    BucketARN: BucketARN
    Prefix: Optional[Prefix]
    ErrorOutputPrefix: Optional[ErrorOutputPrefix]
    BufferingHints: BufferingHints
    CompressionFormat: CompressionFormat
    EncryptionConfiguration: EncryptionConfiguration
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]


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


class S3DestinationUpdate(TypedDict, total=False):
    """Describes an update for a destination in Amazon S3."""

    RoleARN: Optional[RoleARN]
    BucketARN: Optional[BucketARN]
    Prefix: Optional[Prefix]
    ErrorOutputPrefix: Optional[ErrorOutputPrefix]
    BufferingHints: Optional[BufferingHints]
    CompressionFormat: Optional[CompressionFormat]
    EncryptionConfiguration: Optional[EncryptionConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]


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


ColumnToJsonKeyMappings = Dict[NonEmptyStringWithoutWhitespace, NonEmptyString]


class CopyCommand(TypedDict, total=False):
    """Describes a ``COPY`` command for Amazon Redshift."""

    DataTableName: DataTableName
    DataTableColumns: Optional[DataTableColumns]
    CopyOptions: Optional[CopyOptions]


class Tag(TypedDict, total=False):
    """Metadata that you can assign to a delivery stream, consisting of a
    key-value pair.
    """

    Key: TagKey
    Value: Optional[TagValue]


TagDeliveryStreamInputTagList = List[Tag]


class HttpEndpointRetryOptions(TypedDict, total=False):
    """Describes the retry behavior in case Kinesis Data Firehose is unable to
    deliver data to the specified HTTP endpoint destination, or if it
    doesn't receive a valid acknowledgment of receipt from the specified
    HTTP endpoint destination.
    """

    DurationInSeconds: Optional[HttpEndpointRetryDurationInSeconds]


class HttpEndpointCommonAttribute(TypedDict, total=False):
    """Describes the metadata that's delivered to the specified HTTP endpoint
    destination.
    """

    AttributeName: HttpEndpointAttributeName
    AttributeValue: HttpEndpointAttributeValue


HttpEndpointCommonAttributesList = List[HttpEndpointCommonAttribute]


class HttpEndpointRequestConfiguration(TypedDict, total=False):
    """The configuration of the HTTP endpoint request."""

    ContentEncoding: Optional[ContentEncoding]
    CommonAttributes: Optional[HttpEndpointCommonAttributesList]


class HttpEndpointBufferingHints(TypedDict, total=False):
    """Describes the buffering options that can be applied before data is
    delivered to the HTTP endpoint destination. Kinesis Data Firehose treats
    these options as hints, and it might choose to use more optimal values.
    The ``SizeInMBs`` and ``IntervalInSeconds`` parameters are optional.
    However, if specify a value for one of them, you must also provide a
    value for the other.
    """

    SizeInMBs: Optional[HttpEndpointBufferingSizeInMBs]
    IntervalInSeconds: Optional[HttpEndpointBufferingIntervalInSeconds]


class HttpEndpointConfiguration(TypedDict, total=False):
    """Describes the configuration of the HTTP endpoint to which Kinesis
    Firehose delivers data.
    """

    Url: HttpEndpointUrl
    Name: Optional[HttpEndpointName]
    AccessKey: Optional[HttpEndpointAccessKey]


class HttpEndpointDestinationConfiguration(TypedDict, total=False):
    """Describes the configuration of the HTTP endpoint destination."""

    EndpointConfiguration: HttpEndpointConfiguration
    BufferingHints: Optional[HttpEndpointBufferingHints]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    RequestConfiguration: Optional[HttpEndpointRequestConfiguration]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    RoleARN: Optional[RoleARN]
    RetryOptions: Optional[HttpEndpointRetryOptions]
    S3BackupMode: Optional[HttpEndpointS3BackupMode]
    S3Configuration: S3DestinationConfiguration


class SplunkRetryOptions(TypedDict, total=False):
    """Configures retry behavior in case Kinesis Data Firehose is unable to
    deliver documents to Splunk, or if it doesn't receive an acknowledgment
    from Splunk.
    """

    DurationInSeconds: Optional[SplunkRetryDurationInSeconds]


class SplunkDestinationConfiguration(TypedDict, total=False):
    """Describes the configuration of a destination in Splunk."""

    HECEndpoint: HECEndpoint
    HECEndpointType: HECEndpointType
    HECToken: HECToken
    HECAcknowledgmentTimeoutInSeconds: Optional[HECAcknowledgmentTimeoutInSeconds]
    RetryOptions: Optional[SplunkRetryOptions]
    S3BackupMode: Optional[SplunkS3BackupMode]
    S3Configuration: S3DestinationConfiguration
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]


class ElasticsearchRetryOptions(TypedDict, total=False):
    """Configures retry behavior in case Kinesis Data Firehose is unable to
    deliver documents to Amazon ES.
    """

    DurationInSeconds: Optional[ElasticsearchRetryDurationInSeconds]


class ElasticsearchBufferingHints(TypedDict, total=False):
    """Describes the buffering to perform before delivering data to the Amazon
    ES destination.
    """

    IntervalInSeconds: Optional[ElasticsearchBufferingIntervalInSeconds]
    SizeInMBs: Optional[ElasticsearchBufferingSizeInMBs]


class ElasticsearchDestinationConfiguration(TypedDict, total=False):
    """Describes the configuration of a destination in Amazon ES."""

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


class RedshiftRetryOptions(TypedDict, total=False):
    """Configures retry behavior in case Kinesis Data Firehose is unable to
    deliver documents to Amazon Redshift.
    """

    DurationInSeconds: Optional[RedshiftRetryDurationInSeconds]


class RedshiftDestinationConfiguration(TypedDict, total=False):
    """Describes the configuration of a destination in Amazon Redshift."""

    RoleARN: RoleARN
    ClusterJDBCURL: ClusterJDBCURL
    CopyCommand: CopyCommand
    Username: Username
    Password: Password
    RetryOptions: Optional[RedshiftRetryOptions]
    S3Configuration: S3DestinationConfiguration
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    S3BackupMode: Optional[RedshiftS3BackupMode]
    S3BackupConfiguration: Optional[S3DestinationConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]


class RetryOptions(TypedDict, total=False):
    """The retry behavior in case Kinesis Data Firehose is unable to deliver
    data to an Amazon S3 prefix.
    """

    DurationInSeconds: Optional[RetryDurationInSeconds]


class DynamicPartitioningConfiguration(TypedDict, total=False):
    """The configuration of the dynamic partitioning mechanism that creates
    smaller data sets from the streaming data by partitioning it based on
    partition keys. Currently, dynamic partitioning is only supported for
    Amazon S3 destinations. For more information, see
    https://docs.aws.amazon.com/firehose/latest/dev/dynamic-partitioning.html
    """

    RetryOptions: Optional[RetryOptions]
    Enabled: Optional[BooleanObject]


ListOfNonEmptyStringsWithoutWhitespace = List[NonEmptyStringWithoutWhitespace]


class OrcSerDe(TypedDict, total=False):
    """A serializer to use for converting data to the ORC format before storing
    it in Amazon S3. For more information, see `Apache
    ORC <https://orc.apache.org/docs/>`__.
    """

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
    """A serializer to use for converting data to the Parquet format before
    storing it in Amazon S3. For more information, see `Apache
    Parquet <https://parquet.apache.org/documentation/latest/>`__.
    """

    BlockSizeBytes: Optional[BlockSizeBytes]
    PageSizeBytes: Optional[ParquetPageSizeBytes]
    Compression: Optional[ParquetCompression]
    EnableDictionaryCompression: Optional[BooleanObject]
    MaxPaddingBytes: Optional[NonNegativeIntegerObject]
    WriterVersion: Optional[ParquetWriterVersion]


class Serializer(TypedDict, total=False):
    """The serializer that you want Kinesis Data Firehose to use to convert
    data to the target format before writing it to Amazon S3. Kinesis Data
    Firehose supports two types of serializers: the `ORC
    SerDe <https://hive.apache.org/javadocs/r1.2.2/api/org/apache/hadoop/hive/ql/io/orc/OrcSerde.html>`__
    and the `Parquet
    SerDe <https://hive.apache.org/javadocs/r1.2.2/api/org/apache/hadoop/hive/ql/io/parquet/serde/ParquetHiveSerDe.html>`__.
    """

    ParquetSerDe: Optional[ParquetSerDe]
    OrcSerDe: Optional[OrcSerDe]


class OutputFormatConfiguration(TypedDict, total=False):
    """Specifies the serializer that you want Kinesis Data Firehose to use to
    convert the format of your data before it writes it to Amazon S3. This
    parameter is required if ``Enabled`` is set to true.
    """

    Serializer: Optional[Serializer]


ListOfNonEmptyStrings = List[NonEmptyString]


class HiveJsonSerDe(TypedDict, total=False):
    """The native Hive / HCatalog JsonSerDe. Used by Kinesis Data Firehose for
    deserializing data, which means converting it from the JSON format in
    preparation for serializing it to the Parquet or ORC format. This is one
    of two deserializers you can choose, depending on which one offers the
    functionality you need. The other option is the OpenX SerDe.
    """

    TimestampFormats: Optional[ListOfNonEmptyStrings]


class OpenXJsonSerDe(TypedDict, total=False):
    """The OpenX SerDe. Used by Kinesis Data Firehose for deserializing data,
    which means converting it from the JSON format in preparation for
    serializing it to the Parquet or ORC format. This is one of two
    deserializers you can choose, depending on which one offers the
    functionality you need. The other option is the native Hive / HCatalog
    JsonSerDe.
    """

    ConvertDotsInJsonKeysToUnderscores: Optional[BooleanObject]
    CaseInsensitive: Optional[BooleanObject]
    ColumnToJsonKeyMappings: Optional[ColumnToJsonKeyMappings]


class Deserializer(TypedDict, total=False):
    """The deserializer you want Kinesis Data Firehose to use for converting
    the input data from JSON. Kinesis Data Firehose then serializes the data
    to its final format using the Serializer. Kinesis Data Firehose supports
    two types of deserializers: the `Apache Hive JSON
    SerDe <https://cwiki.apache.org/confluence/display/Hive/LanguageManual+DDL#LanguageManualDDL-JSON>`__
    and the `OpenX JSON
    SerDe <https://github.com/rcongiu/Hive-JSON-Serde>`__.
    """

    OpenXJsonSerDe: Optional[OpenXJsonSerDe]
    HiveJsonSerDe: Optional[HiveJsonSerDe]


class InputFormatConfiguration(TypedDict, total=False):
    """Specifies the deserializer you want to use to convert the format of the
    input data. This parameter is required if ``Enabled`` is set to true.
    """

    Deserializer: Optional[Deserializer]


class SchemaConfiguration(TypedDict, total=False):
    """Specifies the schema to which you want Kinesis Data Firehose to
    configure your data before it writes it to Amazon S3. This parameter is
    required if ``Enabled`` is set to true.
    """

    RoleARN: Optional[NonEmptyStringWithoutWhitespace]
    CatalogId: Optional[NonEmptyStringWithoutWhitespace]
    DatabaseName: Optional[NonEmptyStringWithoutWhitespace]
    TableName: Optional[NonEmptyStringWithoutWhitespace]
    Region: Optional[NonEmptyStringWithoutWhitespace]
    VersionId: Optional[NonEmptyStringWithoutWhitespace]


class DataFormatConversionConfiguration(TypedDict, total=False):
    """Specifies that you want Kinesis Data Firehose to convert data from the
    JSON format to the Parquet or ORC format before writing it to Amazon S3.
    Kinesis Data Firehose uses the serializer and deserializer that you
    specify, in addition to the column information from the AWS Glue table,
    to deserialize your input data from JSON and then serialize it to the
    Parquet or ORC format. For more information, see `Kinesis Data Firehose
    Record Format
    Conversion <https://docs.aws.amazon.com/firehose/latest/dev/record-format-conversion.html>`__.
    """

    SchemaConfiguration: Optional[SchemaConfiguration]
    InputFormatConfiguration: Optional[InputFormatConfiguration]
    OutputFormatConfiguration: Optional[OutputFormatConfiguration]
    Enabled: Optional[BooleanObject]


class ExtendedS3DestinationConfiguration(TypedDict, total=False):
    """Describes the configuration of a destination in Amazon S3."""

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


class DeliveryStreamEncryptionConfigurationInput(TypedDict, total=False):
    """Specifies the type and Amazon Resource Name (ARN) of the CMK to use for
    Server-Side Encryption (SSE).
    """

    KeyARN: Optional[AWSKMSKeyARN]
    KeyType: KeyType


class KinesisStreamSourceConfiguration(TypedDict, total=False):
    """The stream and role Amazon Resource Names (ARNs) for a Kinesis data
    stream used as the source for a delivery stream.
    """

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


class CreateDeliveryStreamOutput(TypedDict, total=False):
    DeliveryStreamARN: Optional[DeliveryStreamARN]


Data = bytes


class DeleteDeliveryStreamInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    AllowForceDelete: Optional[BooleanObject]


class DeleteDeliveryStreamOutput(TypedDict, total=False):
    pass


DeliveryStartTimestamp = datetime


class HttpEndpointDescription(TypedDict, total=False):
    """Describes the HTTP endpoint selected as the destination."""

    Url: Optional[HttpEndpointUrl]
    Name: Optional[HttpEndpointName]


class HttpEndpointDestinationDescription(TypedDict, total=False):
    """Describes the HTTP endpoint destination."""

    EndpointConfiguration: Optional[HttpEndpointDescription]
    BufferingHints: Optional[HttpEndpointBufferingHints]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    RequestConfiguration: Optional[HttpEndpointRequestConfiguration]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    RoleARN: Optional[RoleARN]
    RetryOptions: Optional[HttpEndpointRetryOptions]
    S3BackupMode: Optional[HttpEndpointS3BackupMode]
    S3DestinationDescription: Optional[S3DestinationDescription]


class SplunkDestinationDescription(TypedDict, total=False):
    """Describes a destination in Splunk."""

    HECEndpoint: Optional[HECEndpoint]
    HECEndpointType: Optional[HECEndpointType]
    HECToken: Optional[HECToken]
    HECAcknowledgmentTimeoutInSeconds: Optional[HECAcknowledgmentTimeoutInSeconds]
    RetryOptions: Optional[SplunkRetryOptions]
    S3BackupMode: Optional[SplunkS3BackupMode]
    S3DestinationDescription: Optional[S3DestinationDescription]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]


class ElasticsearchDestinationDescription(TypedDict, total=False):
    """The destination description in Amazon ES."""

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


class RedshiftDestinationDescription(TypedDict, total=False):
    """Describes a destination in Amazon Redshift."""

    RoleARN: RoleARN
    ClusterJDBCURL: ClusterJDBCURL
    CopyCommand: CopyCommand
    Username: Username
    RetryOptions: Optional[RedshiftRetryOptions]
    S3DestinationDescription: S3DestinationDescription
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    S3BackupMode: Optional[RedshiftS3BackupMode]
    S3BackupDescription: Optional[S3DestinationDescription]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]


class ExtendedS3DestinationDescription(TypedDict, total=False):
    """Describes a destination in Amazon S3."""

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


class DestinationDescription(TypedDict, total=False):
    """Describes the destination for a delivery stream."""

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


DestinationDescriptionList = List[DestinationDescription]


class KinesisStreamSourceDescription(TypedDict, total=False):
    """Details about a Kinesis data stream used as the source for a Kinesis
    Data Firehose delivery stream.
    """

    KinesisStreamARN: Optional[KinesisStreamARN]
    RoleARN: Optional[RoleARN]
    DeliveryStartTimestamp: Optional[DeliveryStartTimestamp]


class SourceDescription(TypedDict, total=False):
    """Details about a Kinesis data stream used as the source for a Kinesis
    Data Firehose delivery stream.
    """

    KinesisStreamSourceDescription: Optional[KinesisStreamSourceDescription]


Timestamp = datetime


class FailureDescription(TypedDict, total=False):
    """Provides details in case one of the following operations fails due to an
    error related to KMS: CreateDeliveryStream, DeleteDeliveryStream,
    StartDeliveryStreamEncryption, StopDeliveryStreamEncryption.
    """

    Type: DeliveryStreamFailureType
    Details: NonEmptyString


class DeliveryStreamEncryptionConfiguration(TypedDict, total=False):
    """Contains information about the server-side encryption (SSE) status for
    the delivery stream, the type customer master key (CMK) in use, if any,
    and the ARN of the CMK. You can get
    ``DeliveryStreamEncryptionConfiguration`` by invoking the
    DescribeDeliveryStream operation.
    """

    KeyARN: Optional[AWSKMSKeyARN]
    KeyType: Optional[KeyType]
    Status: Optional[DeliveryStreamEncryptionStatus]
    FailureDescription: Optional[FailureDescription]


class DeliveryStreamDescription(TypedDict, total=False):
    """Contains information about a delivery stream."""

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
    """Describes an update for a destination in Amazon ES."""

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


class ExtendedS3DestinationUpdate(TypedDict, total=False):
    """Describes an update for a destination in Amazon S3."""

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


class HttpEndpointDestinationUpdate(TypedDict, total=False):
    """Updates the specified HTTP endpoint destination."""

    EndpointConfiguration: Optional[HttpEndpointConfiguration]
    BufferingHints: Optional[HttpEndpointBufferingHints]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    RequestConfiguration: Optional[HttpEndpointRequestConfiguration]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    RoleARN: Optional[RoleARN]
    RetryOptions: Optional[HttpEndpointRetryOptions]
    S3BackupMode: Optional[HttpEndpointS3BackupMode]
    S3Update: Optional[S3DestinationUpdate]


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
    """The unit of data in a delivery stream."""

    Data: Data


PutRecordBatchRequestEntryList = List[Record]


class PutRecordBatchInput(ServiceRequest):
    DeliveryStreamName: DeliveryStreamName
    Records: PutRecordBatchRequestEntryList


class PutRecordBatchResponseEntry(TypedDict, total=False):
    """Contains the result for an individual record from a PutRecordBatch
    request. If the record is successfully added to your delivery stream, it
    receives a record ID. If the record fails to be added to your delivery
    stream, the result includes an error code and an error message.
    """

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
    """Describes an update for a destination in Amazon Redshift."""

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


class SplunkDestinationUpdate(TypedDict, total=False):
    """Describes an update for a destination in Splunk."""

    HECEndpoint: Optional[HECEndpoint]
    HECEndpointType: Optional[HECEndpointType]
    HECToken: Optional[HECToken]
    HECAcknowledgmentTimeoutInSeconds: Optional[HECAcknowledgmentTimeoutInSeconds]
    RetryOptions: Optional[SplunkRetryOptions]
    S3BackupMode: Optional[SplunkS3BackupMode]
    S3Update: Optional[S3DestinationUpdate]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]


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
    ) -> CreateDeliveryStreamOutput:
        """Creates a Kinesis Data Firehose delivery stream.

        By default, you can create up to 50 delivery streams per AWS Region.

        This is an asynchronous operation that immediately returns. The initial
        status of the delivery stream is ``CREATING``. After the delivery stream
        is created, its status is ``ACTIVE`` and it now accepts data. If the
        delivery stream creation fails, the status transitions to
        ``CREATING_FAILED``. Attempts to send data to a delivery stream that is
        not in the ``ACTIVE`` state cause an exception. To check the state of a
        delivery stream, use DescribeDeliveryStream.

        If the status of a delivery stream is ``CREATING_FAILED``, this status
        doesn't change, and you can't invoke ``CreateDeliveryStream`` again on
        it. However, you can invoke the DeleteDeliveryStream operation to delete
        it.

        A Kinesis Data Firehose delivery stream can be configured to receive
        records directly from providers using PutRecord or PutRecordBatch, or it
        can be configured to use an existing Kinesis stream as its source. To
        specify a Kinesis data stream as input, set the ``DeliveryStreamType``
        parameter to ``KinesisStreamAsSource``, and provide the Kinesis stream
        Amazon Resource Name (ARN) and role ARN in the
        ``KinesisStreamSourceConfiguration`` parameter.

        To create a delivery stream with server-side encryption (SSE) enabled,
        include DeliveryStreamEncryptionConfigurationInput in your request. This
        is optional. You can also invoke StartDeliveryStreamEncryption to turn
        on SSE for an existing delivery stream that doesn't have SSE enabled.

        A delivery stream is configured with a single destination: Amazon S3,
        Amazon ES, Amazon Redshift, or Splunk. You must specify only one of the
        following destination configuration parameters:
        ``ExtendedS3DestinationConfiguration``, ``S3DestinationConfiguration``,
        ``ElasticsearchDestinationConfiguration``,
        ``RedshiftDestinationConfiguration``, or
        ``SplunkDestinationConfiguration``.

        When you specify ``S3DestinationConfiguration``, you can also provide
        the following optional values: BufferingHints,
        ``EncryptionConfiguration``, and ``CompressionFormat``. By default, if
        no ``BufferingHints`` value is provided, Kinesis Data Firehose buffers
        data up to 5 MB or for 5 minutes, whichever condition is satisfied
        first. ``BufferingHints`` is a hint, so there are some cases where the
        service cannot adhere to these conditions strictly. For example, record
        boundaries might be such that the size is a little over or under the
        configured buffering size. By default, no encryption is performed. We
        strongly recommend that you enable encryption to ensure secure data
        storage in Amazon S3.

        A few notes about Amazon Redshift as a destination:

        -  An Amazon Redshift destination requires an S3 bucket as intermediate
           location. Kinesis Data Firehose first delivers data to Amazon S3 and
           then uses ``COPY`` syntax to load data into an Amazon Redshift table.
           This is specified in the
           ``RedshiftDestinationConfiguration.S3Configuration`` parameter.

        -  The compression formats ``SNAPPY`` or ``ZIP`` cannot be specified in
           ``RedshiftDestinationConfiguration.S3Configuration`` because the
           Amazon Redshift ``COPY`` operation that reads from the S3 bucket
           doesn't support these compression formats.

        -  We strongly recommend that you use the user name and password you
           provide exclusively with Kinesis Data Firehose, and that the
           permissions for the account are restricted for Amazon Redshift
           ``INSERT`` permissions.

        Kinesis Data Firehose assumes the IAM role that is configured as part of
        the destination. The role should allow the Kinesis Data Firehose
        principal to assume the role, and the role should have permissions that
        allow the service to deliver the data. For more information, see `Grant
        Kinesis Data Firehose Access to an Amazon S3
        Destination <https://docs.aws.amazon.com/firehose/latest/dev/controlling-access.html#using-iam-s3>`__
        in the *Amazon Kinesis Data Firehose Developer Guide*.

        :param delivery_stream_name: The name of the delivery stream.
        :param delivery_stream_type: The delivery stream type.
        :param kinesis_stream_source_configuration: When a Kinesis data stream is used as the source for the delivery
        stream, a KinesisStreamSourceConfiguration containing the Kinesis data
        stream Amazon Resource Name (ARN) and the role ARN for the source
        stream.
        :param delivery_stream_encryption_configuration_input: Used to specify the type and Amazon Resource Name (ARN) of the KMS key
        needed for Server-Side Encryption (SSE).
        :param s3_destination_configuration: [Deprecated] The destination in Amazon S3.
        :param extended_s3_destination_configuration: The destination in Amazon S3.
        :param redshift_destination_configuration: The destination in Amazon Redshift.
        :param elasticsearch_destination_configuration: The destination in Amazon ES.
        :param amazonopensearchservice_destination_configuration: .
        :param splunk_destination_configuration: The destination in Splunk.
        :param http_endpoint_destination_configuration: Enables configuring Kinesis Firehose to deliver data to any HTTP
        endpoint destination.
        :param tags: A set of tags to assign to the delivery stream.
        :returns: CreateDeliveryStreamOutput
        :raises InvalidArgumentException:
        :raises LimitExceededException:
        :raises ResourceInUseException:
        :raises InvalidKMSResourceException:
        """
        raise NotImplementedError

    @handler("DeleteDeliveryStream")
    def delete_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        allow_force_delete: BooleanObject = None,
    ) -> DeleteDeliveryStreamOutput:
        """Deletes a delivery stream and its data.

        To check the state of a delivery stream, use DescribeDeliveryStream. You
        can delete a delivery stream only if it is in one of the following
        states: ``ACTIVE``, ``DELETING``, ``CREATING_FAILED``, or
        ``DELETING_FAILED``. You can't delete a delivery stream that is in the
        ``CREATING`` state. While the deletion request is in process, the
        delivery stream is in the ``DELETING`` state.

        While the delivery stream is in the ``DELETING`` state, the service
        might continue to accept records, but it doesn't make any guarantees
        with respect to delivering the data. Therefore, as a best practice,
        first stop any applications that are sending records before you delete a
        delivery stream.

        :param delivery_stream_name: The name of the delivery stream.
        :param allow_force_delete: Set this to true if you want to delete the delivery stream even if
        Kinesis Data Firehose is unable to retire the grant for the CMK.
        :returns: DeleteDeliveryStreamOutput
        :raises ResourceInUseException:
        :raises ResourceNotFoundException:
        """
        raise NotImplementedError

    @handler("DescribeDeliveryStream")
    def describe_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        limit: DescribeDeliveryStreamInputLimit = None,
        exclusive_start_destination_id: DestinationId = None,
    ) -> DescribeDeliveryStreamOutput:
        """Describes the specified delivery stream and its status. For example,
        after your delivery stream is created, call ``DescribeDeliveryStream``
        to see whether the delivery stream is ``ACTIVE`` and therefore ready for
        data to be sent to it.

        If the status of a delivery stream is ``CREATING_FAILED``, this status
        doesn't change, and you can't invoke CreateDeliveryStream again on it.
        However, you can invoke the DeleteDeliveryStream operation to delete it.
        If the status is ``DELETING_FAILED``, you can force deletion by invoking
        DeleteDeliveryStream again but with
        DeleteDeliveryStreamInput$AllowForceDelete set to true.

        :param delivery_stream_name: The name of the delivery stream.
        :param limit: The limit on the number of destinations to return.
        :param exclusive_start_destination_id: The ID of the destination to start returning the destination
        information.
        :returns: DescribeDeliveryStreamOutput
        :raises ResourceNotFoundException:
        """
        raise NotImplementedError

    @handler("ListDeliveryStreams")
    def list_delivery_streams(
        self,
        context: RequestContext,
        limit: ListDeliveryStreamsInputLimit = None,
        delivery_stream_type: DeliveryStreamType = None,
        exclusive_start_delivery_stream_name: DeliveryStreamName = None,
    ) -> ListDeliveryStreamsOutput:
        """Lists your delivery streams in alphabetical order of their names.

        The number of delivery streams might be too large to return using a
        single call to ``ListDeliveryStreams``. You can limit the number of
        delivery streams returned, using the ``Limit`` parameter. To determine
        whether there are more delivery streams to list, check the value of
        ``HasMoreDeliveryStreams`` in the output. If there are more delivery
        streams to list, you can request them by calling this operation again
        and setting the ``ExclusiveStartDeliveryStreamName`` parameter to the
        name of the last delivery stream returned in the last call.

        :param limit: The maximum number of delivery streams to list.
        :param delivery_stream_type: The delivery stream type.
        :param exclusive_start_delivery_stream_name: The list of delivery streams returned by this call to
        ``ListDeliveryStreams`` will start with the delivery stream whose name
        comes alphabetically immediately after the name you specify in
        ``ExclusiveStartDeliveryStreamName``.
        :returns: ListDeliveryStreamsOutput
        """
        raise NotImplementedError

    @handler("ListTagsForDeliveryStream")
    def list_tags_for_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        exclusive_start_tag_key: TagKey = None,
        limit: ListTagsForDeliveryStreamInputLimit = None,
    ) -> ListTagsForDeliveryStreamOutput:
        """Lists the tags for the specified delivery stream. This operation has a
        limit of five transactions per second per account.

        :param delivery_stream_name: The name of the delivery stream whose tags you want to list.
        :param exclusive_start_tag_key: The key to use as the starting point for the list of tags.
        :param limit: The number of tags to return.
        :returns: ListTagsForDeliveryStreamOutput
        :raises ResourceNotFoundException:
        :raises InvalidArgumentException:
        :raises LimitExceededException:
        """
        raise NotImplementedError

    @handler("PutRecord")
    def put_record(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        record: Record,
    ) -> PutRecordOutput:
        """Writes a single data record into an Amazon Kinesis Data Firehose
        delivery stream. To write multiple data records into a delivery stream,
        use PutRecordBatch. Applications using these operations are referred to
        as producers.

        By default, each delivery stream can take in up to 2,000 transactions
        per second, 5,000 records per second, or 5 MB per second. If you use
        PutRecord and PutRecordBatch, the limits are an aggregate across these
        two operations for each delivery stream. For more information about
        limits and how to request an increase, see `Amazon Kinesis Data Firehose
        Limits <https://docs.aws.amazon.com/firehose/latest/dev/limits.html>`__.

        You must specify the name of the delivery stream and the data record
        when using PutRecord. The data record consists of a data blob that can
        be up to 1,000 KiB in size, and any kind of data. For example, it can be
        a segment from a log file, geographic location data, website clickstream
        data, and so on.

        Kinesis Data Firehose buffers records before delivering them to the
        destination. To disambiguate the data blobs at the destination, a common
        solution is to use delimiters in the data, such as a newline (``\n``) or
        some other character unique within the data. This allows the consumer
        application to parse individual data items when reading the data from
        the destination.

        The ``PutRecord`` operation returns a ``RecordId``, which is a unique
        string assigned to each record. Producer applications can use this ID
        for purposes such as auditability and investigation.

        If the ``PutRecord`` operation throws a ``ServiceUnavailableException``,
        back off and retry. If the exception persists, it is possible that the
        throughput limits have been exceeded for the delivery stream.

        Data records sent to Kinesis Data Firehose are stored for 24 hours from
        the time they are added to a delivery stream as it tries to send the
        records to the destination. If the destination is unreachable for more
        than 24 hours, the data is no longer available.

        Don't concatenate two or more base64 strings to form the data fields of
        your records. Instead, concatenate the raw data, then perform base64
        encoding.

        :param delivery_stream_name: The name of the delivery stream.
        :param record: The record.
        :returns: PutRecordOutput
        :raises ResourceNotFoundException:
        :raises InvalidArgumentException:
        :raises InvalidKMSResourceException:
        :raises ServiceUnavailableException:
        """
        raise NotImplementedError

    @handler("PutRecordBatch")
    def put_record_batch(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        records: PutRecordBatchRequestEntryList,
    ) -> PutRecordBatchOutput:
        """Writes multiple data records into a delivery stream in a single call,
        which can achieve higher throughput per producer than when writing
        single records. To write single data records into a delivery stream, use
        PutRecord. Applications using these operations are referred to as
        producers.

        For information about service quota, see `Amazon Kinesis Data Firehose
        Quota <https://docs.aws.amazon.com/firehose/latest/dev/limits.html>`__.

        Each PutRecordBatch request supports up to 500 records. Each record in
        the request can be as large as 1,000 KB (before base64 encoding), up to
        a limit of 4 MB for the entire request. These limits cannot be changed.

        You must specify the name of the delivery stream and the data record
        when using PutRecord. The data record consists of a data blob that can
        be up to 1,000 KB in size, and any kind of data. For example, it could
        be a segment from a log file, geographic location data, website
        clickstream data, and so on.

        Kinesis Data Firehose buffers records before delivering them to the
        destination. To disambiguate the data blobs at the destination, a common
        solution is to use delimiters in the data, such as a newline (``\n``) or
        some other character unique within the data. This allows the consumer
        application to parse individual data items when reading the data from
        the destination.

        The PutRecordBatch response includes a count of failed records,
        ``FailedPutCount``, and an array of responses, ``RequestResponses``.
        Even if the PutRecordBatch call succeeds, the value of
        ``FailedPutCount`` may be greater than 0, indicating that there are
        records for which the operation didn't succeed. Each entry in the
        ``RequestResponses`` array provides additional information about the
        processed record. It directly correlates with a record in the request
        array using the same ordering, from the top to the bottom. The response
        array always includes the same number of records as the request array.
        ``RequestResponses`` includes both successfully and unsuccessfully
        processed records. Kinesis Data Firehose tries to process all records in
        each PutRecordBatch request. A single record failure does not stop the
        processing of subsequent records.

        A successfully processed record includes a ``RecordId`` value, which is
        unique for the record. An unsuccessfully processed record includes
        ``ErrorCode`` and ``ErrorMessage`` values. ``ErrorCode`` reflects the
        type of error, and is one of the following values:
        ``ServiceUnavailableException`` or ``InternalFailure``. ``ErrorMessage``
        provides more detailed information about the error.

        If there is an internal server error or a timeout, the write might have
        completed or it might have failed. If ``FailedPutCount`` is greater than
        0, retry the request, resending only those records that might have
        failed processing. This minimizes the possible duplicate records and
        also reduces the total bytes sent (and corresponding charges). We
        recommend that you handle any duplicates at the destination.

        If PutRecordBatch throws ``ServiceUnavailableException``, back off and
        retry. If the exception persists, it is possible that the throughput
        limits have been exceeded for the delivery stream.

        Data records sent to Kinesis Data Firehose are stored for 24 hours from
        the time they are added to a delivery stream as it attempts to send the
        records to the destination. If the destination is unreachable for more
        than 24 hours, the data is no longer available.

        Don't concatenate two or more base64 strings to form the data fields of
        your records. Instead, concatenate the raw data, then perform base64
        encoding.

        :param delivery_stream_name: The name of the delivery stream.
        :param records: One or more records.
        :returns: PutRecordBatchOutput
        :raises ResourceNotFoundException:
        :raises InvalidArgumentException:
        :raises InvalidKMSResourceException:
        :raises ServiceUnavailableException:
        """
        raise NotImplementedError

    @handler("StartDeliveryStreamEncryption")
    def start_delivery_stream_encryption(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        delivery_stream_encryption_configuration_input: DeliveryStreamEncryptionConfigurationInput = None,
    ) -> StartDeliveryStreamEncryptionOutput:
        """Enables server-side encryption (SSE) for the delivery stream.

        This operation is asynchronous. It returns immediately. When you invoke
        it, Kinesis Data Firehose first sets the encryption status of the stream
        to ``ENABLING``, and then to ``ENABLED``. The encryption status of a
        delivery stream is the ``Status`` property in
        DeliveryStreamEncryptionConfiguration. If the operation fails, the
        encryption status changes to ``ENABLING_FAILED``. You can continue to
        read and write data to your delivery stream while the encryption status
        is ``ENABLING``, but the data is not encrypted. It can take up to 5
        seconds after the encryption status changes to ``ENABLED`` before all
        records written to the delivery stream are encrypted. To find out
        whether a record or a batch of records was encrypted, check the response
        elements PutRecordOutput$Encrypted and PutRecordBatchOutput$Encrypted,
        respectively.

        To check the encryption status of a delivery stream, use
        DescribeDeliveryStream.

        Even if encryption is currently enabled for a delivery stream, you can
        still invoke this operation on it to change the ARN of the CMK or both
        its type and ARN. If you invoke this method to change the CMK, and the
        old CMK is of type ``CUSTOMER_MANAGED_CMK``, Kinesis Data Firehose
        schedules the grant it had on the old CMK for retirement. If the new CMK
        is of type ``CUSTOMER_MANAGED_CMK``, Kinesis Data Firehose creates a
        grant that enables it to use the new CMK to encrypt and decrypt data and
        to manage the grant.

        If a delivery stream already has encryption enabled and then you invoke
        this operation to change the ARN of the CMK or both its type and ARN and
        you get ``ENABLING_FAILED``, this only means that the attempt to change
        the CMK failed. In this case, encryption remains enabled with the old
        CMK.

        If the encryption status of your delivery stream is ``ENABLING_FAILED``,
        you can invoke this operation again with a valid CMK. The CMK must be
        enabled and the key policy mustn't explicitly deny the permission for
        Kinesis Data Firehose to invoke KMS encrypt and decrypt operations.

        You can enable SSE for a delivery stream only if it's a delivery stream
        that uses ``DirectPut`` as its source.

        The ``StartDeliveryStreamEncryption`` and
        ``StopDeliveryStreamEncryption`` operations have a combined limit of 25
        calls per delivery stream per 24 hours. For example, you reach the limit
        if you call ``StartDeliveryStreamEncryption`` 13 times and
        ``StopDeliveryStreamEncryption`` 12 times for the same delivery stream
        in a 24-hour period.

        :param delivery_stream_name: The name of the delivery stream for which you want to enable server-side
        encryption (SSE).
        :param delivery_stream_encryption_configuration_input: Used to specify the type and Amazon Resource Name (ARN) of the KMS key
        needed for Server-Side Encryption (SSE).
        :returns: StartDeliveryStreamEncryptionOutput
        :raises ResourceNotFoundException:
        :raises ResourceInUseException:
        :raises InvalidArgumentException:
        :raises LimitExceededException:
        :raises InvalidKMSResourceException:
        """
        raise NotImplementedError

    @handler("StopDeliveryStreamEncryption")
    def stop_delivery_stream_encryption(
        self, context: RequestContext, delivery_stream_name: DeliveryStreamName
    ) -> StopDeliveryStreamEncryptionOutput:
        """Disables server-side encryption (SSE) for the delivery stream.

        This operation is asynchronous. It returns immediately. When you invoke
        it, Kinesis Data Firehose first sets the encryption status of the stream
        to ``DISABLING``, and then to ``DISABLED``. You can continue to read and
        write data to your stream while its status is ``DISABLING``. It can take
        up to 5 seconds after the encryption status changes to ``DISABLED``
        before all records written to the delivery stream are no longer subject
        to encryption. To find out whether a record or a batch of records was
        encrypted, check the response elements PutRecordOutput$Encrypted and
        PutRecordBatchOutput$Encrypted, respectively.

        To check the encryption state of a delivery stream, use
        DescribeDeliveryStream.

        If SSE is enabled using a customer managed CMK and then you invoke
        ``StopDeliveryStreamEncryption``, Kinesis Data Firehose schedules the
        related KMS grant for retirement and then retires it after it ensures
        that it is finished delivering records to the destination.

        The ``StartDeliveryStreamEncryption`` and
        ``StopDeliveryStreamEncryption`` operations have a combined limit of 25
        calls per delivery stream per 24 hours. For example, you reach the limit
        if you call ``StartDeliveryStreamEncryption`` 13 times and
        ``StopDeliveryStreamEncryption`` 12 times for the same delivery stream
        in a 24-hour period.

        :param delivery_stream_name: The name of the delivery stream for which you want to disable
        server-side encryption (SSE).
        :returns: StopDeliveryStreamEncryptionOutput
        :raises ResourceNotFoundException:
        :raises ResourceInUseException:
        :raises InvalidArgumentException:
        :raises LimitExceededException:
        """
        raise NotImplementedError

    @handler("TagDeliveryStream")
    def tag_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        tags: TagDeliveryStreamInputTagList,
    ) -> TagDeliveryStreamOutput:
        """Adds or updates tags for the specified delivery stream. A tag is a
        key-value pair that you can define and assign to AWS resources. If you
        specify a tag that already exists, the tag value is replaced with the
        value that you specify in the request. Tags are metadata. For example,
        you can add friendly names and descriptions or other types of
        information that can help you distinguish the delivery stream. For more
        information about tags, see `Using Cost Allocation
        Tags <https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/cost-alloc-tags.html>`__
        in the *AWS Billing and Cost Management User Guide*.

        Each delivery stream can have up to 50 tags.

        This operation has a limit of five transactions per second per account.

        :param delivery_stream_name: The name of the delivery stream to which you want to add the tags.
        :param tags: A set of key-value pairs to use to create the tags.
        :returns: TagDeliveryStreamOutput
        :raises ResourceNotFoundException:
        :raises ResourceInUseException:
        :raises InvalidArgumentException:
        :raises LimitExceededException:
        """
        raise NotImplementedError

    @handler("UntagDeliveryStream")
    def untag_delivery_stream(
        self,
        context: RequestContext,
        delivery_stream_name: DeliveryStreamName,
        tag_keys: TagKeyList,
    ) -> UntagDeliveryStreamOutput:
        """Removes tags from the specified delivery stream. Removed tags are
        deleted, and you can't recover them after this operation successfully
        completes.

        If you specify a tag that doesn't exist, the operation ignores it.

        This operation has a limit of five transactions per second per account.

        :param delivery_stream_name: The name of the delivery stream.
        :param tag_keys: A list of tag keys.
        :returns: UntagDeliveryStreamOutput
        :raises ResourceNotFoundException:
        :raises ResourceInUseException:
        :raises InvalidArgumentException:
        :raises LimitExceededException:
        """
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
    ) -> UpdateDestinationOutput:
        """Updates the specified destination of the specified delivery stream.

        Use this operation to change the destination type (for example, to
        replace the Amazon S3 destination with Amazon Redshift) or change the
        parameters associated with a destination (for example, to change the
        bucket name of the Amazon S3 destination). The update might not occur
        immediately. The target delivery stream remains active while the
        configurations are updated, so data writes to the delivery stream can
        continue during this process. The updated configurations are usually
        effective within a few minutes.

        Switching between Amazon ES and other services is not supported. For an
        Amazon ES destination, you can only update to another Amazon ES
        destination.

        If the destination type is the same, Kinesis Data Firehose merges the
        configuration parameters specified with the destination configuration
        that already exists on the delivery stream. If any of the parameters are
        not specified in the call, the existing values are retained. For
        example, in the Amazon S3 destination, if EncryptionConfiguration is not
        specified, then the existing ``EncryptionConfiguration`` is maintained
        on the destination.

        If the destination type is not the same, for example, changing the
        destination from Amazon S3 to Amazon Redshift, Kinesis Data Firehose
        does not merge any parameters. In this case, all parameters must be
        specified.

        Kinesis Data Firehose uses ``CurrentDeliveryStreamVersionId`` to avoid
        race conditions and conflicting merges. This is a required field, and
        the service updates the configuration only if the existing configuration
        has a version ID that matches. After the update is applied successfully,
        the version ID is updated, and can be retrieved using
        DescribeDeliveryStream. Use the new version ID to set
        ``CurrentDeliveryStreamVersionId`` in the next call.

        :param delivery_stream_name: The name of the delivery stream.
        :param current_delivery_stream_version_id: Obtain this value from the ``VersionId`` result of
        DeliveryStreamDescription.
        :param destination_id: The ID of the destination.
        :param s3_destination_update: [Deprecated] Describes an update for a destination in Amazon S3.
        :param extended_s3_destination_update: Describes an update for a destination in Amazon S3.
        :param redshift_destination_update: Describes an update for a destination in Amazon Redshift.
        :param elasticsearch_destination_update: Describes an update for a destination in Amazon ES.
        :param amazonopensearchservice_destination_update: .
        :param splunk_destination_update: Describes an update for a destination in Splunk.
        :param http_endpoint_destination_update: Describes an update to the specified HTTP endpoint destination.
        :returns: UpdateDestinationOutput
        :raises InvalidArgumentException:
        :raises ResourceInUseException:
        :raises ResourceNotFoundException:
        :raises ConcurrentModificationException:
        """
        raise NotImplementedError

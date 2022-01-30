import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

AmazonResourceName = str
Boolean = bool
ErrorMessage = str
Integer = int
PaginationLimit = int
RecordIndex = int
ResourceCreateAPIName = str
ResourceName = str
S3BucketName = str
S3ObjectKeyPrefix = str
SchemaName = str
SchemaValue = str
String = str
StringValue2048 = str
StringValue256 = str
TagKey = str
TagValue = str


class DimensionValueType(str):
    VARCHAR = "VARCHAR"


class MeasureValueType(str):
    DOUBLE = "DOUBLE"
    BIGINT = "BIGINT"
    VARCHAR = "VARCHAR"
    BOOLEAN = "BOOLEAN"
    TIMESTAMP = "TIMESTAMP"
    MULTI = "MULTI"


class S3EncryptionOption(str):
    SSE_S3 = "SSE_S3"
    SSE_KMS = "SSE_KMS"


class TableStatus(str):
    ACTIVE = "ACTIVE"
    DELETING = "DELETING"


class TimeUnit(str):
    MILLISECONDS = "MILLISECONDS"
    SECONDS = "SECONDS"
    MICROSECONDS = "MICROSECONDS"
    NANOSECONDS = "NANOSECONDS"


class AccessDeniedException(ServiceException):
    Message: ErrorMessage


class ConflictException(ServiceException):
    Message: ErrorMessage


class InternalServerException(ServiceException):
    Message: ErrorMessage


class InvalidEndpointException(ServiceException):
    Message: Optional[ErrorMessage]


RecordVersion = int


class RejectedRecord(TypedDict, total=False):
    RecordIndex: Optional[RecordIndex]
    Reason: Optional[ErrorMessage]
    ExistingVersion: Optional[RecordVersion]


RejectedRecords = List[RejectedRecord]


class RejectedRecordsException(ServiceException):
    Message: Optional[ErrorMessage]
    RejectedRecords: Optional[RejectedRecords]


class ResourceNotFoundException(ServiceException):
    Message: Optional[ErrorMessage]


class ServiceQuotaExceededException(ServiceException):
    Message: Optional[ErrorMessage]


class ThrottlingException(ServiceException):
    Message: ErrorMessage


class ValidationException(ServiceException):
    Message: ErrorMessage


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: TagValue


TagList = List[Tag]


class CreateDatabaseRequest(ServiceRequest):
    DatabaseName: ResourceCreateAPIName
    KmsKeyId: Optional[StringValue2048]
    Tags: Optional[TagList]


Date = datetime
Long = int


class Database(TypedDict, total=False):
    Arn: Optional[String]
    DatabaseName: Optional[ResourceName]
    TableCount: Optional[Long]
    KmsKeyId: Optional[StringValue2048]
    CreationTime: Optional[Date]
    LastUpdatedTime: Optional[Date]


class CreateDatabaseResponse(TypedDict, total=False):
    Database: Optional[Database]


class S3Configuration(TypedDict, total=False):
    BucketName: Optional[S3BucketName]
    ObjectKeyPrefix: Optional[S3ObjectKeyPrefix]
    EncryptionOption: Optional[S3EncryptionOption]
    KmsKeyId: Optional[StringValue2048]


class MagneticStoreRejectedDataLocation(TypedDict, total=False):
    S3Configuration: Optional[S3Configuration]


class MagneticStoreWriteProperties(TypedDict, total=False):
    EnableMagneticStoreWrites: Boolean
    MagneticStoreRejectedDataLocation: Optional[MagneticStoreRejectedDataLocation]


MagneticStoreRetentionPeriodInDays = int
MemoryStoreRetentionPeriodInHours = int


class RetentionProperties(TypedDict, total=False):
    MemoryStoreRetentionPeriodInHours: MemoryStoreRetentionPeriodInHours
    MagneticStoreRetentionPeriodInDays: MagneticStoreRetentionPeriodInDays


class CreateTableRequest(ServiceRequest):
    DatabaseName: ResourceCreateAPIName
    TableName: ResourceCreateAPIName
    RetentionProperties: Optional[RetentionProperties]
    Tags: Optional[TagList]
    MagneticStoreWriteProperties: Optional[MagneticStoreWriteProperties]


class Table(TypedDict, total=False):
    Arn: Optional[String]
    TableName: Optional[ResourceName]
    DatabaseName: Optional[ResourceName]
    TableStatus: Optional[TableStatus]
    RetentionProperties: Optional[RetentionProperties]
    CreationTime: Optional[Date]
    LastUpdatedTime: Optional[Date]
    MagneticStoreWriteProperties: Optional[MagneticStoreWriteProperties]


class CreateTableResponse(TypedDict, total=False):
    Table: Optional[Table]


DatabaseList = List[Database]


class DeleteDatabaseRequest(ServiceRequest):
    DatabaseName: ResourceName


class DeleteTableRequest(ServiceRequest):
    DatabaseName: ResourceName
    TableName: ResourceName


class DescribeDatabaseRequest(ServiceRequest):
    DatabaseName: ResourceName


class DescribeDatabaseResponse(TypedDict, total=False):
    Database: Optional[Database]


class DescribeEndpointsRequest(ServiceRequest):
    pass


class Endpoint(TypedDict, total=False):
    Address: String
    CachePeriodInMinutes: Long


Endpoints = List[Endpoint]


class DescribeEndpointsResponse(TypedDict, total=False):
    Endpoints: Endpoints


class DescribeTableRequest(ServiceRequest):
    DatabaseName: ResourceName
    TableName: ResourceName


class DescribeTableResponse(TypedDict, total=False):
    Table: Optional[Table]


class Dimension(TypedDict, total=False):
    Name: SchemaName
    Value: SchemaValue
    DimensionValueType: Optional[DimensionValueType]


Dimensions = List[Dimension]


class ListDatabasesRequest(ServiceRequest):
    NextToken: Optional[String]
    MaxResults: Optional[PaginationLimit]


class ListDatabasesResponse(TypedDict, total=False):
    Databases: Optional[DatabaseList]
    NextToken: Optional[String]


class ListTablesRequest(ServiceRequest):
    DatabaseName: Optional[ResourceName]
    NextToken: Optional[String]
    MaxResults: Optional[PaginationLimit]


TableList = List[Table]


class ListTablesResponse(TypedDict, total=False):
    Tables: Optional[TableList]
    NextToken: Optional[String]


class ListTagsForResourceRequest(ServiceRequest):
    ResourceARN: AmazonResourceName


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: Optional[TagList]


class MeasureValue(TypedDict, total=False):
    Name: SchemaName
    Value: StringValue2048
    Type: MeasureValueType


MeasureValues = List[MeasureValue]


class Record(TypedDict, total=False):
    Dimensions: Optional[Dimensions]
    MeasureName: Optional[SchemaName]
    MeasureValue: Optional[StringValue2048]
    MeasureValueType: Optional[MeasureValueType]
    Time: Optional[StringValue256]
    TimeUnit: Optional[TimeUnit]
    Version: Optional[RecordVersion]
    MeasureValues: Optional[MeasureValues]


Records = List[Record]


class RecordsIngested(TypedDict, total=False):
    Total: Optional[Integer]
    MemoryStore: Optional[Integer]
    MagneticStore: Optional[Integer]


TagKeyList = List[TagKey]


class TagResourceRequest(ServiceRequest):
    ResourceARN: AmazonResourceName
    Tags: TagList


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    ResourceARN: AmazonResourceName
    TagKeys: TagKeyList


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateDatabaseRequest(ServiceRequest):
    DatabaseName: ResourceName
    KmsKeyId: StringValue2048


class UpdateDatabaseResponse(TypedDict, total=False):
    Database: Optional[Database]


class UpdateTableRequest(ServiceRequest):
    DatabaseName: ResourceName
    TableName: ResourceName
    RetentionProperties: Optional[RetentionProperties]
    MagneticStoreWriteProperties: Optional[MagneticStoreWriteProperties]


class UpdateTableResponse(TypedDict, total=False):
    Table: Optional[Table]


class WriteRecordsRequest(ServiceRequest):
    DatabaseName: ResourceName
    TableName: ResourceName
    CommonAttributes: Optional[Record]
    Records: Records


class WriteRecordsResponse(TypedDict, total=False):
    RecordsIngested: Optional[RecordsIngested]


class TimestreamWriteApi:

    service = "timestream-write"
    version = "2018-11-01"

    @handler("CreateDatabase")
    def create_database(
        self,
        context: RequestContext,
        database_name: ResourceCreateAPIName,
        kms_key_id: StringValue2048 = None,
        tags: TagList = None,
    ) -> CreateDatabaseResponse:
        raise NotImplementedError

    @handler("CreateTable")
    def create_table(
        self,
        context: RequestContext,
        database_name: ResourceCreateAPIName,
        table_name: ResourceCreateAPIName,
        retention_properties: RetentionProperties = None,
        tags: TagList = None,
        magnetic_store_write_properties: MagneticStoreWriteProperties = None,
    ) -> CreateTableResponse:
        raise NotImplementedError

    @handler("DeleteDatabase")
    def delete_database(self, context: RequestContext, database_name: ResourceName) -> None:
        raise NotImplementedError

    @handler("DeleteTable")
    def delete_table(
        self, context: RequestContext, database_name: ResourceName, table_name: ResourceName
    ) -> None:
        raise NotImplementedError

    @handler("DescribeDatabase")
    def describe_database(
        self, context: RequestContext, database_name: ResourceName
    ) -> DescribeDatabaseResponse:
        raise NotImplementedError

    @handler("DescribeEndpoints")
    def describe_endpoints(
        self,
        context: RequestContext,
    ) -> DescribeEndpointsResponse:
        raise NotImplementedError

    @handler("DescribeTable")
    def describe_table(
        self, context: RequestContext, database_name: ResourceName, table_name: ResourceName
    ) -> DescribeTableResponse:
        raise NotImplementedError

    @handler("ListDatabases")
    def list_databases(
        self,
        context: RequestContext,
        next_token: String = None,
        max_results: PaginationLimit = None,
    ) -> ListDatabasesResponse:
        raise NotImplementedError

    @handler("ListTables")
    def list_tables(
        self,
        context: RequestContext,
        database_name: ResourceName = None,
        next_token: String = None,
        max_results: PaginationLimit = None,
    ) -> ListTablesResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: TagList
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tag_keys: TagKeyList
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateDatabase")
    def update_database(
        self, context: RequestContext, database_name: ResourceName, kms_key_id: StringValue2048
    ) -> UpdateDatabaseResponse:
        raise NotImplementedError

    @handler("UpdateTable")
    def update_table(
        self,
        context: RequestContext,
        database_name: ResourceName,
        table_name: ResourceName,
        retention_properties: RetentionProperties = None,
        magnetic_store_write_properties: MagneticStoreWriteProperties = None,
    ) -> UpdateTableResponse:
        raise NotImplementedError

    @handler("WriteRecords")
    def write_records(
        self,
        context: RequestContext,
        database_name: ResourceName,
        table_name: ResourceName,
        records: Records,
        common_attributes: Record = None,
    ) -> WriteRecordsResponse:
        raise NotImplementedError

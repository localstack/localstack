import sys
from datetime import datetime
from typing import List, Optional

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

from localstack.aws.api import RequestContext, ServiceException, ServiceRequest, handler

ApplicationCode = str
ApplicationDescription = str
ApplicationName = str
BooleanObject = bool
BucketARN = str
ErrorMessage = str
FileKey = str
Id = str
InAppStreamName = str
InAppTableName = str
InputParallelismCount = int
KinesisAnalyticsARN = str
ListApplicationsInputLimit = int
LogStreamARN = str
ParsedInputRecordField = str
ProcessedInputRecord = str
RawInputRecord = str
RecordColumnDelimiter = str
RecordColumnMapping = str
RecordColumnName = str
RecordColumnSqlType = str
RecordEncoding = str
RecordRowDelimiter = str
RecordRowPath = str
ResourceARN = str
RoleARN = str
TagKey = str
TagValue = str


class ApplicationStatus(str):
    DELETING = "DELETING"
    STARTING = "STARTING"
    STOPPING = "STOPPING"
    READY = "READY"
    RUNNING = "RUNNING"
    UPDATING = "UPDATING"


class InputStartingPosition(str):
    NOW = "NOW"
    TRIM_HORIZON = "TRIM_HORIZON"
    LAST_STOPPED_POINT = "LAST_STOPPED_POINT"


class RecordFormatType(str):
    JSON = "JSON"
    CSV = "CSV"


class CodeValidationException(ServiceException):
    message: Optional[ErrorMessage]


class ConcurrentModificationException(ServiceException):
    message: Optional[ErrorMessage]


class InvalidApplicationConfigurationException(ServiceException):
    message: Optional[ErrorMessage]


class InvalidArgumentException(ServiceException):
    message: Optional[ErrorMessage]


class LimitExceededException(ServiceException):
    message: Optional[ErrorMessage]


class ResourceInUseException(ServiceException):
    message: Optional[ErrorMessage]


class ResourceNotFoundException(ServiceException):
    message: Optional[ErrorMessage]


class ResourceProvisionedThroughputExceededException(ServiceException):
    message: Optional[ErrorMessage]


class ServiceUnavailableException(ServiceException):
    message: Optional[ErrorMessage]


class TooManyTagsException(ServiceException):
    message: Optional[ErrorMessage]


ProcessedInputRecords = List[ProcessedInputRecord]
RawInputRecords = List[RawInputRecord]


class UnableToDetectSchemaException(ServiceException):
    message: Optional[ErrorMessage]
    RawInputRecords: Optional[RawInputRecords]
    ProcessedInputRecords: Optional[ProcessedInputRecords]


class UnsupportedOperationException(ServiceException):
    message: Optional[ErrorMessage]


class CloudWatchLoggingOption(TypedDict, total=False):
    LogStreamARN: LogStreamARN
    RoleARN: RoleARN


ApplicationVersionId = int


class AddApplicationCloudWatchLoggingOptionRequest(ServiceRequest):
    ApplicationName: ApplicationName
    CurrentApplicationVersionId: ApplicationVersionId
    CloudWatchLoggingOption: CloudWatchLoggingOption


class AddApplicationCloudWatchLoggingOptionResponse(TypedDict, total=False):
    pass


class InputLambdaProcessor(TypedDict, total=False):
    ResourceARN: ResourceARN
    RoleARN: RoleARN


class InputProcessingConfiguration(TypedDict, total=False):
    InputLambdaProcessor: InputLambdaProcessor


class AddApplicationInputProcessingConfigurationRequest(ServiceRequest):
    ApplicationName: ApplicationName
    CurrentApplicationVersionId: ApplicationVersionId
    InputId: Id
    InputProcessingConfiguration: InputProcessingConfiguration


class AddApplicationInputProcessingConfigurationResponse(TypedDict, total=False):
    pass


class RecordColumn(TypedDict, total=False):
    Name: RecordColumnName
    Mapping: Optional[RecordColumnMapping]
    SqlType: RecordColumnSqlType


RecordColumns = List[RecordColumn]


class CSVMappingParameters(TypedDict, total=False):
    RecordRowDelimiter: RecordRowDelimiter
    RecordColumnDelimiter: RecordColumnDelimiter


class JSONMappingParameters(TypedDict, total=False):
    RecordRowPath: RecordRowPath


class MappingParameters(TypedDict, total=False):
    JSONMappingParameters: Optional[JSONMappingParameters]
    CSVMappingParameters: Optional[CSVMappingParameters]


class RecordFormat(TypedDict, total=False):
    RecordFormatType: RecordFormatType
    MappingParameters: Optional[MappingParameters]


class SourceSchema(TypedDict, total=False):
    RecordFormat: RecordFormat
    RecordEncoding: Optional[RecordEncoding]
    RecordColumns: RecordColumns


class InputParallelism(TypedDict, total=False):
    Count: Optional[InputParallelismCount]


class KinesisFirehoseInput(TypedDict, total=False):
    ResourceARN: ResourceARN
    RoleARN: RoleARN


class KinesisStreamsInput(TypedDict, total=False):
    ResourceARN: ResourceARN
    RoleARN: RoleARN


class Input(TypedDict, total=False):
    NamePrefix: InAppStreamName
    InputProcessingConfiguration: Optional[InputProcessingConfiguration]
    KinesisStreamsInput: Optional[KinesisStreamsInput]
    KinesisFirehoseInput: Optional[KinesisFirehoseInput]
    InputParallelism: Optional[InputParallelism]
    InputSchema: SourceSchema


class AddApplicationInputRequest(ServiceRequest):
    ApplicationName: ApplicationName
    CurrentApplicationVersionId: ApplicationVersionId
    Input: Input


class AddApplicationInputResponse(TypedDict, total=False):
    pass


class DestinationSchema(TypedDict, total=False):
    RecordFormatType: RecordFormatType


class LambdaOutput(TypedDict, total=False):
    ResourceARN: ResourceARN
    RoleARN: RoleARN


class KinesisFirehoseOutput(TypedDict, total=False):
    ResourceARN: ResourceARN
    RoleARN: RoleARN


class KinesisStreamsOutput(TypedDict, total=False):
    ResourceARN: ResourceARN
    RoleARN: RoleARN


class Output(TypedDict, total=False):
    Name: InAppStreamName
    KinesisStreamsOutput: Optional[KinesisStreamsOutput]
    KinesisFirehoseOutput: Optional[KinesisFirehoseOutput]
    LambdaOutput: Optional[LambdaOutput]
    DestinationSchema: DestinationSchema


class AddApplicationOutputRequest(ServiceRequest):
    ApplicationName: ApplicationName
    CurrentApplicationVersionId: ApplicationVersionId
    Output: Output


class AddApplicationOutputResponse(TypedDict, total=False):
    pass


class S3ReferenceDataSource(TypedDict, total=False):
    BucketARN: BucketARN
    FileKey: FileKey
    ReferenceRoleARN: RoleARN


class ReferenceDataSource(TypedDict, total=False):
    TableName: InAppTableName
    S3ReferenceDataSource: Optional[S3ReferenceDataSource]
    ReferenceSchema: SourceSchema


class AddApplicationReferenceDataSourceRequest(ServiceRequest):
    ApplicationName: ApplicationName
    CurrentApplicationVersionId: ApplicationVersionId
    ReferenceDataSource: ReferenceDataSource


class AddApplicationReferenceDataSourceResponse(TypedDict, total=False):
    pass


class CloudWatchLoggingOptionDescription(TypedDict, total=False):
    CloudWatchLoggingOptionId: Optional[Id]
    LogStreamARN: LogStreamARN
    RoleARN: RoleARN


CloudWatchLoggingOptionDescriptions = List[CloudWatchLoggingOptionDescription]


class S3ReferenceDataSourceDescription(TypedDict, total=False):
    BucketARN: BucketARN
    FileKey: FileKey
    ReferenceRoleARN: RoleARN


class ReferenceDataSourceDescription(TypedDict, total=False):
    ReferenceId: Id
    TableName: InAppTableName
    S3ReferenceDataSourceDescription: S3ReferenceDataSourceDescription
    ReferenceSchema: Optional[SourceSchema]


ReferenceDataSourceDescriptions = List[ReferenceDataSourceDescription]


class LambdaOutputDescription(TypedDict, total=False):
    ResourceARN: Optional[ResourceARN]
    RoleARN: Optional[RoleARN]


class KinesisFirehoseOutputDescription(TypedDict, total=False):
    ResourceARN: Optional[ResourceARN]
    RoleARN: Optional[RoleARN]


class KinesisStreamsOutputDescription(TypedDict, total=False):
    ResourceARN: Optional[ResourceARN]
    RoleARN: Optional[RoleARN]


class OutputDescription(TypedDict, total=False):
    OutputId: Optional[Id]
    Name: Optional[InAppStreamName]
    KinesisStreamsOutputDescription: Optional[KinesisStreamsOutputDescription]
    KinesisFirehoseOutputDescription: Optional[KinesisFirehoseOutputDescription]
    LambdaOutputDescription: Optional[LambdaOutputDescription]
    DestinationSchema: Optional[DestinationSchema]


OutputDescriptions = List[OutputDescription]


class InputStartingPositionConfiguration(TypedDict, total=False):
    InputStartingPosition: Optional[InputStartingPosition]


class KinesisFirehoseInputDescription(TypedDict, total=False):
    ResourceARN: Optional[ResourceARN]
    RoleARN: Optional[RoleARN]


class KinesisStreamsInputDescription(TypedDict, total=False):
    ResourceARN: Optional[ResourceARN]
    RoleARN: Optional[RoleARN]


class InputLambdaProcessorDescription(TypedDict, total=False):
    ResourceARN: Optional[ResourceARN]
    RoleARN: Optional[RoleARN]


class InputProcessingConfigurationDescription(TypedDict, total=False):
    InputLambdaProcessorDescription: Optional[InputLambdaProcessorDescription]


InAppStreamNames = List[InAppStreamName]


class InputDescription(TypedDict, total=False):
    InputId: Optional[Id]
    NamePrefix: Optional[InAppStreamName]
    InAppStreamNames: Optional[InAppStreamNames]
    InputProcessingConfigurationDescription: Optional[InputProcessingConfigurationDescription]
    KinesisStreamsInputDescription: Optional[KinesisStreamsInputDescription]
    KinesisFirehoseInputDescription: Optional[KinesisFirehoseInputDescription]
    InputSchema: Optional[SourceSchema]
    InputParallelism: Optional[InputParallelism]
    InputStartingPositionConfiguration: Optional[InputStartingPositionConfiguration]


InputDescriptions = List[InputDescription]
Timestamp = datetime


class ApplicationDetail(TypedDict, total=False):
    ApplicationName: ApplicationName
    ApplicationDescription: Optional[ApplicationDescription]
    ApplicationARN: ResourceARN
    ApplicationStatus: ApplicationStatus
    CreateTimestamp: Optional[Timestamp]
    LastUpdateTimestamp: Optional[Timestamp]
    InputDescriptions: Optional[InputDescriptions]
    OutputDescriptions: Optional[OutputDescriptions]
    ReferenceDataSourceDescriptions: Optional[ReferenceDataSourceDescriptions]
    CloudWatchLoggingOptionDescriptions: Optional[CloudWatchLoggingOptionDescriptions]
    ApplicationCode: Optional[ApplicationCode]
    ApplicationVersionId: ApplicationVersionId


class ApplicationSummary(TypedDict, total=False):
    ApplicationName: ApplicationName
    ApplicationARN: ResourceARN
    ApplicationStatus: ApplicationStatus


ApplicationSummaries = List[ApplicationSummary]


class CloudWatchLoggingOptionUpdate(TypedDict, total=False):
    CloudWatchLoggingOptionId: Id
    LogStreamARNUpdate: Optional[LogStreamARN]
    RoleARNUpdate: Optional[RoleARN]


CloudWatchLoggingOptionUpdates = List[CloudWatchLoggingOptionUpdate]


class S3ReferenceDataSourceUpdate(TypedDict, total=False):
    BucketARNUpdate: Optional[BucketARN]
    FileKeyUpdate: Optional[FileKey]
    ReferenceRoleARNUpdate: Optional[RoleARN]


class ReferenceDataSourceUpdate(TypedDict, total=False):
    ReferenceId: Id
    TableNameUpdate: Optional[InAppTableName]
    S3ReferenceDataSourceUpdate: Optional[S3ReferenceDataSourceUpdate]
    ReferenceSchemaUpdate: Optional[SourceSchema]


ReferenceDataSourceUpdates = List[ReferenceDataSourceUpdate]


class LambdaOutputUpdate(TypedDict, total=False):
    ResourceARNUpdate: Optional[ResourceARN]
    RoleARNUpdate: Optional[RoleARN]


class KinesisFirehoseOutputUpdate(TypedDict, total=False):
    ResourceARNUpdate: Optional[ResourceARN]
    RoleARNUpdate: Optional[RoleARN]


class KinesisStreamsOutputUpdate(TypedDict, total=False):
    ResourceARNUpdate: Optional[ResourceARN]
    RoleARNUpdate: Optional[RoleARN]


class OutputUpdate(TypedDict, total=False):
    OutputId: Id
    NameUpdate: Optional[InAppStreamName]
    KinesisStreamsOutputUpdate: Optional[KinesisStreamsOutputUpdate]
    KinesisFirehoseOutputUpdate: Optional[KinesisFirehoseOutputUpdate]
    LambdaOutputUpdate: Optional[LambdaOutputUpdate]
    DestinationSchemaUpdate: Optional[DestinationSchema]


OutputUpdates = List[OutputUpdate]


class InputParallelismUpdate(TypedDict, total=False):
    CountUpdate: Optional[InputParallelismCount]


class InputSchemaUpdate(TypedDict, total=False):
    RecordFormatUpdate: Optional[RecordFormat]
    RecordEncodingUpdate: Optional[RecordEncoding]
    RecordColumnUpdates: Optional[RecordColumns]


class KinesisFirehoseInputUpdate(TypedDict, total=False):
    ResourceARNUpdate: Optional[ResourceARN]
    RoleARNUpdate: Optional[RoleARN]


class KinesisStreamsInputUpdate(TypedDict, total=False):
    ResourceARNUpdate: Optional[ResourceARN]
    RoleARNUpdate: Optional[RoleARN]


class InputLambdaProcessorUpdate(TypedDict, total=False):
    ResourceARNUpdate: Optional[ResourceARN]
    RoleARNUpdate: Optional[RoleARN]


class InputProcessingConfigurationUpdate(TypedDict, total=False):
    InputLambdaProcessorUpdate: InputLambdaProcessorUpdate


class InputUpdate(TypedDict, total=False):
    InputId: Id
    NamePrefixUpdate: Optional[InAppStreamName]
    InputProcessingConfigurationUpdate: Optional[InputProcessingConfigurationUpdate]
    KinesisStreamsInputUpdate: Optional[KinesisStreamsInputUpdate]
    KinesisFirehoseInputUpdate: Optional[KinesisFirehoseInputUpdate]
    InputSchemaUpdate: Optional[InputSchemaUpdate]
    InputParallelismUpdate: Optional[InputParallelismUpdate]


InputUpdates = List[InputUpdate]


class ApplicationUpdate(TypedDict, total=False):
    InputUpdates: Optional[InputUpdates]
    ApplicationCodeUpdate: Optional[ApplicationCode]
    OutputUpdates: Optional[OutputUpdates]
    ReferenceDataSourceUpdates: Optional[ReferenceDataSourceUpdates]
    CloudWatchLoggingOptionUpdates: Optional[CloudWatchLoggingOptionUpdates]


CloudWatchLoggingOptions = List[CloudWatchLoggingOption]


class Tag(TypedDict, total=False):
    Key: TagKey
    Value: Optional[TagValue]


Tags = List[Tag]
Outputs = List[Output]
Inputs = List[Input]


class CreateApplicationRequest(ServiceRequest):
    ApplicationName: ApplicationName
    ApplicationDescription: Optional[ApplicationDescription]
    Inputs: Optional[Inputs]
    Outputs: Optional[Outputs]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    ApplicationCode: Optional[ApplicationCode]
    Tags: Optional[Tags]


class CreateApplicationResponse(TypedDict, total=False):
    ApplicationSummary: ApplicationSummary


class DeleteApplicationCloudWatchLoggingOptionRequest(ServiceRequest):
    ApplicationName: ApplicationName
    CurrentApplicationVersionId: ApplicationVersionId
    CloudWatchLoggingOptionId: Id


class DeleteApplicationCloudWatchLoggingOptionResponse(TypedDict, total=False):
    pass


class DeleteApplicationInputProcessingConfigurationRequest(ServiceRequest):
    ApplicationName: ApplicationName
    CurrentApplicationVersionId: ApplicationVersionId
    InputId: Id


class DeleteApplicationInputProcessingConfigurationResponse(TypedDict, total=False):
    pass


class DeleteApplicationOutputRequest(ServiceRequest):
    ApplicationName: ApplicationName
    CurrentApplicationVersionId: ApplicationVersionId
    OutputId: Id


class DeleteApplicationOutputResponse(TypedDict, total=False):
    pass


class DeleteApplicationReferenceDataSourceRequest(ServiceRequest):
    ApplicationName: ApplicationName
    CurrentApplicationVersionId: ApplicationVersionId
    ReferenceId: Id


class DeleteApplicationReferenceDataSourceResponse(TypedDict, total=False):
    pass


class DeleteApplicationRequest(ServiceRequest):
    ApplicationName: ApplicationName
    CreateTimestamp: Timestamp


class DeleteApplicationResponse(TypedDict, total=False):
    pass


class DescribeApplicationRequest(ServiceRequest):
    ApplicationName: ApplicationName


class DescribeApplicationResponse(TypedDict, total=False):
    ApplicationDetail: ApplicationDetail


class S3Configuration(TypedDict, total=False):
    RoleARN: RoleARN
    BucketARN: BucketARN
    FileKey: FileKey


class DiscoverInputSchemaRequest(ServiceRequest):
    ResourceARN: Optional[ResourceARN]
    RoleARN: Optional[RoleARN]
    InputStartingPositionConfiguration: Optional[InputStartingPositionConfiguration]
    S3Configuration: Optional[S3Configuration]
    InputProcessingConfiguration: Optional[InputProcessingConfiguration]


ParsedInputRecord = List[ParsedInputRecordField]
ParsedInputRecords = List[ParsedInputRecord]


class DiscoverInputSchemaResponse(TypedDict, total=False):
    InputSchema: Optional[SourceSchema]
    ParsedInputRecords: Optional[ParsedInputRecords]
    ProcessedInputRecords: Optional[ProcessedInputRecords]
    RawInputRecords: Optional[RawInputRecords]


class InputConfiguration(TypedDict, total=False):
    Id: Id
    InputStartingPositionConfiguration: InputStartingPositionConfiguration


InputConfigurations = List[InputConfiguration]


class ListApplicationsRequest(ServiceRequest):
    Limit: Optional[ListApplicationsInputLimit]
    ExclusiveStartApplicationName: Optional[ApplicationName]


class ListApplicationsResponse(TypedDict, total=False):
    ApplicationSummaries: ApplicationSummaries
    HasMoreApplications: BooleanObject


class ListTagsForResourceRequest(ServiceRequest):
    ResourceARN: KinesisAnalyticsARN


class ListTagsForResourceResponse(TypedDict, total=False):
    Tags: Optional[Tags]


class StartApplicationRequest(ServiceRequest):
    ApplicationName: ApplicationName
    InputConfigurations: InputConfigurations


class StartApplicationResponse(TypedDict, total=False):
    pass


class StopApplicationRequest(ServiceRequest):
    ApplicationName: ApplicationName


class StopApplicationResponse(TypedDict, total=False):
    pass


TagKeys = List[TagKey]


class TagResourceRequest(ServiceRequest):
    ResourceARN: KinesisAnalyticsARN
    Tags: Tags


class TagResourceResponse(TypedDict, total=False):
    pass


class UntagResourceRequest(ServiceRequest):
    ResourceARN: KinesisAnalyticsARN
    TagKeys: TagKeys


class UntagResourceResponse(TypedDict, total=False):
    pass


class UpdateApplicationRequest(ServiceRequest):
    ApplicationName: ApplicationName
    CurrentApplicationVersionId: ApplicationVersionId
    ApplicationUpdate: ApplicationUpdate


class UpdateApplicationResponse(TypedDict, total=False):
    pass


class KinesisanalyticsApi:

    service = "kinesisanalytics"
    version = "2015-08-14"

    @handler("AddApplicationCloudWatchLoggingOption")
    def add_application_cloud_watch_logging_option(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        current_application_version_id: ApplicationVersionId,
        cloud_watch_logging_option: CloudWatchLoggingOption,
    ) -> AddApplicationCloudWatchLoggingOptionResponse:
        raise NotImplementedError

    @handler("AddApplicationInput")
    def add_application_input(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        current_application_version_id: ApplicationVersionId,
        input: Input,
    ) -> AddApplicationInputResponse:
        raise NotImplementedError

    @handler("AddApplicationInputProcessingConfiguration")
    def add_application_input_processing_configuration(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        current_application_version_id: ApplicationVersionId,
        input_id: Id,
        input_processing_configuration: InputProcessingConfiguration,
    ) -> AddApplicationInputProcessingConfigurationResponse:
        raise NotImplementedError

    @handler("AddApplicationOutput")
    def add_application_output(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        current_application_version_id: ApplicationVersionId,
        output: Output,
    ) -> AddApplicationOutputResponse:
        raise NotImplementedError

    @handler("AddApplicationReferenceDataSource")
    def add_application_reference_data_source(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        current_application_version_id: ApplicationVersionId,
        reference_data_source: ReferenceDataSource,
    ) -> AddApplicationReferenceDataSourceResponse:
        raise NotImplementedError

    @handler("CreateApplication")
    def create_application(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        application_description: ApplicationDescription = None,
        inputs: Inputs = None,
        outputs: Outputs = None,
        cloud_watch_logging_options: CloudWatchLoggingOptions = None,
        application_code: ApplicationCode = None,
        tags: Tags = None,
    ) -> CreateApplicationResponse:
        raise NotImplementedError

    @handler("DeleteApplication")
    def delete_application(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        create_timestamp: Timestamp,
    ) -> DeleteApplicationResponse:
        raise NotImplementedError

    @handler("DeleteApplicationCloudWatchLoggingOption")
    def delete_application_cloud_watch_logging_option(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        current_application_version_id: ApplicationVersionId,
        cloud_watch_logging_option_id: Id,
    ) -> DeleteApplicationCloudWatchLoggingOptionResponse:
        raise NotImplementedError

    @handler("DeleteApplicationInputProcessingConfiguration")
    def delete_application_input_processing_configuration(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        current_application_version_id: ApplicationVersionId,
        input_id: Id,
    ) -> DeleteApplicationInputProcessingConfigurationResponse:
        raise NotImplementedError

    @handler("DeleteApplicationOutput")
    def delete_application_output(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        current_application_version_id: ApplicationVersionId,
        output_id: Id,
    ) -> DeleteApplicationOutputResponse:
        raise NotImplementedError

    @handler("DeleteApplicationReferenceDataSource")
    def delete_application_reference_data_source(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        current_application_version_id: ApplicationVersionId,
        reference_id: Id,
    ) -> DeleteApplicationReferenceDataSourceResponse:
        raise NotImplementedError

    @handler("DescribeApplication")
    def describe_application(
        self, context: RequestContext, application_name: ApplicationName
    ) -> DescribeApplicationResponse:
        raise NotImplementedError

    @handler("DiscoverInputSchema")
    def discover_input_schema(
        self,
        context: RequestContext,
        resource_arn: ResourceARN = None,
        role_arn: RoleARN = None,
        input_starting_position_configuration: InputStartingPositionConfiguration = None,
        s3_configuration: S3Configuration = None,
        input_processing_configuration: InputProcessingConfiguration = None,
    ) -> DiscoverInputSchemaResponse:
        raise NotImplementedError

    @handler("ListApplications")
    def list_applications(
        self,
        context: RequestContext,
        limit: ListApplicationsInputLimit = None,
        exclusive_start_application_name: ApplicationName = None,
    ) -> ListApplicationsResponse:
        raise NotImplementedError

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: KinesisAnalyticsARN
    ) -> ListTagsForResourceResponse:
        raise NotImplementedError

    @handler("StartApplication")
    def start_application(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        input_configurations: InputConfigurations,
    ) -> StartApplicationResponse:
        raise NotImplementedError

    @handler("StopApplication")
    def stop_application(
        self, context: RequestContext, application_name: ApplicationName
    ) -> StopApplicationResponse:
        raise NotImplementedError

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: KinesisAnalyticsARN, tags: Tags
    ) -> TagResourceResponse:
        raise NotImplementedError

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: KinesisAnalyticsARN, tag_keys: TagKeys
    ) -> UntagResourceResponse:
        raise NotImplementedError

    @handler("UpdateApplication")
    def update_application(
        self,
        context: RequestContext,
        application_name: ApplicationName,
        current_application_version_id: ApplicationVersionId,
        application_update: ApplicationUpdate,
    ) -> UpdateApplicationResponse:
        raise NotImplementedError

# LocalStack Resource Provider Scaffolding v2
from __future__ import annotations

from pathlib import Path
from typing import TypedDict

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)


class KinesisFirehoseDeliveryStreamProperties(TypedDict):
    AmazonOpenSearchServerlessDestinationConfiguration: (
        AmazonOpenSearchServerlessDestinationConfiguration | None
    )
    AmazonopensearchserviceDestinationConfiguration: (
        AmazonopensearchserviceDestinationConfiguration | None
    )
    Arn: str | None
    DeliveryStreamEncryptionConfigurationInput: DeliveryStreamEncryptionConfigurationInput | None
    DeliveryStreamName: str | None
    DeliveryStreamType: str | None
    ElasticsearchDestinationConfiguration: ElasticsearchDestinationConfiguration | None
    ExtendedS3DestinationConfiguration: ExtendedS3DestinationConfiguration | None
    HttpEndpointDestinationConfiguration: HttpEndpointDestinationConfiguration | None
    KinesisStreamSourceConfiguration: KinesisStreamSourceConfiguration | None
    RedshiftDestinationConfiguration: RedshiftDestinationConfiguration | None
    S3DestinationConfiguration: S3DestinationConfiguration | None
    SplunkDestinationConfiguration: SplunkDestinationConfiguration | None
    Tags: list[Tag] | None


class DeliveryStreamEncryptionConfigurationInput(TypedDict):
    KeyType: str | None
    KeyARN: str | None


class ElasticsearchBufferingHints(TypedDict):
    IntervalInSeconds: int | None
    SizeInMBs: int | None


class CloudWatchLoggingOptions(TypedDict):
    Enabled: bool | None
    LogGroupName: str | None
    LogStreamName: str | None


class ProcessorParameter(TypedDict):
    ParameterName: str | None
    ParameterValue: str | None


class Processor(TypedDict):
    Type: str | None
    Parameters: list[ProcessorParameter] | None


class ProcessingConfiguration(TypedDict):
    Enabled: bool | None
    Processors: list[Processor] | None


class ElasticsearchRetryOptions(TypedDict):
    DurationInSeconds: int | None


class BufferingHints(TypedDict):
    IntervalInSeconds: int | None
    SizeInMBs: int | None


class KMSEncryptionConfig(TypedDict):
    AWSKMSKeyARN: str | None


class EncryptionConfiguration(TypedDict):
    KMSEncryptionConfig: KMSEncryptionConfig | None
    NoEncryptionConfig: str | None


class S3DestinationConfiguration(TypedDict):
    BucketARN: str | None
    RoleARN: str | None
    BufferingHints: BufferingHints | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    CompressionFormat: str | None
    EncryptionConfiguration: EncryptionConfiguration | None
    ErrorOutputPrefix: str | None
    Prefix: str | None


class VpcConfiguration(TypedDict):
    RoleARN: str | None
    SecurityGroupIds: list[str] | None
    SubnetIds: list[str] | None


class DocumentIdOptions(TypedDict):
    DefaultDocumentIdFormat: str | None


class ElasticsearchDestinationConfiguration(TypedDict):
    IndexName: str | None
    RoleARN: str | None
    S3Configuration: S3DestinationConfiguration | None
    BufferingHints: ElasticsearchBufferingHints | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    ClusterEndpoint: str | None
    DocumentIdOptions: DocumentIdOptions | None
    DomainARN: str | None
    IndexRotationPeriod: str | None
    ProcessingConfiguration: ProcessingConfiguration | None
    RetryOptions: ElasticsearchRetryOptions | None
    S3BackupMode: str | None
    TypeName: str | None
    VpcConfiguration: VpcConfiguration | None


class AmazonopensearchserviceBufferingHints(TypedDict):
    IntervalInSeconds: int | None
    SizeInMBs: int | None


class AmazonopensearchserviceRetryOptions(TypedDict):
    DurationInSeconds: int | None


class AmazonopensearchserviceDestinationConfiguration(TypedDict):
    IndexName: str | None
    RoleARN: str | None
    S3Configuration: S3DestinationConfiguration | None
    BufferingHints: AmazonopensearchserviceBufferingHints | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    ClusterEndpoint: str | None
    DocumentIdOptions: DocumentIdOptions | None
    DomainARN: str | None
    IndexRotationPeriod: str | None
    ProcessingConfiguration: ProcessingConfiguration | None
    RetryOptions: AmazonopensearchserviceRetryOptions | None
    S3BackupMode: str | None
    TypeName: str | None
    VpcConfiguration: VpcConfiguration | None


class AmazonOpenSearchServerlessBufferingHints(TypedDict):
    IntervalInSeconds: int | None
    SizeInMBs: int | None


class AmazonOpenSearchServerlessRetryOptions(TypedDict):
    DurationInSeconds: int | None


class AmazonOpenSearchServerlessDestinationConfiguration(TypedDict):
    IndexName: str | None
    RoleARN: str | None
    S3Configuration: S3DestinationConfiguration | None
    BufferingHints: AmazonOpenSearchServerlessBufferingHints | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    CollectionEndpoint: str | None
    ProcessingConfiguration: ProcessingConfiguration | None
    RetryOptions: AmazonOpenSearchServerlessRetryOptions | None
    S3BackupMode: str | None
    VpcConfiguration: VpcConfiguration | None


class HiveJsonSerDe(TypedDict):
    TimestampFormats: list[str] | None


class OpenXJsonSerDe(TypedDict):
    CaseInsensitive: bool | None
    ColumnToJsonKeyMappings: dict | None
    ConvertDotsInJsonKeysToUnderscores: bool | None


class Deserializer(TypedDict):
    HiveJsonSerDe: HiveJsonSerDe | None
    OpenXJsonSerDe: OpenXJsonSerDe | None


class InputFormatConfiguration(TypedDict):
    Deserializer: Deserializer | None


class OrcSerDe(TypedDict):
    BlockSizeBytes: int | None
    BloomFilterColumns: list[str] | None
    BloomFilterFalsePositiveProbability: float | None
    Compression: str | None
    DictionaryKeyThreshold: float | None
    EnablePadding: bool | None
    FormatVersion: str | None
    PaddingTolerance: float | None
    RowIndexStride: int | None
    StripeSizeBytes: int | None


class ParquetSerDe(TypedDict):
    BlockSizeBytes: int | None
    Compression: str | None
    EnableDictionaryCompression: bool | None
    MaxPaddingBytes: int | None
    PageSizeBytes: int | None
    WriterVersion: str | None


class Serializer(TypedDict):
    OrcSerDe: OrcSerDe | None
    ParquetSerDe: ParquetSerDe | None


class OutputFormatConfiguration(TypedDict):
    Serializer: Serializer | None


class SchemaConfiguration(TypedDict):
    CatalogId: str | None
    DatabaseName: str | None
    Region: str | None
    RoleARN: str | None
    TableName: str | None
    VersionId: str | None


class DataFormatConversionConfiguration(TypedDict):
    Enabled: bool | None
    InputFormatConfiguration: InputFormatConfiguration | None
    OutputFormatConfiguration: OutputFormatConfiguration | None
    SchemaConfiguration: SchemaConfiguration | None


class RetryOptions(TypedDict):
    DurationInSeconds: int | None


class DynamicPartitioningConfiguration(TypedDict):
    Enabled: bool | None
    RetryOptions: RetryOptions | None


class ExtendedS3DestinationConfiguration(TypedDict):
    BucketARN: str | None
    RoleARN: str | None
    BufferingHints: BufferingHints | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    CompressionFormat: str | None
    DataFormatConversionConfiguration: DataFormatConversionConfiguration | None
    DynamicPartitioningConfiguration: DynamicPartitioningConfiguration | None
    EncryptionConfiguration: EncryptionConfiguration | None
    ErrorOutputPrefix: str | None
    Prefix: str | None
    ProcessingConfiguration: ProcessingConfiguration | None
    S3BackupConfiguration: S3DestinationConfiguration | None
    S3BackupMode: str | None


class KinesisStreamSourceConfiguration(TypedDict):
    KinesisStreamARN: str | None
    RoleARN: str | None


class CopyCommand(TypedDict):
    DataTableName: str | None
    CopyOptions: str | None
    DataTableColumns: str | None


class RedshiftRetryOptions(TypedDict):
    DurationInSeconds: int | None


class RedshiftDestinationConfiguration(TypedDict):
    ClusterJDBCURL: str | None
    CopyCommand: CopyCommand | None
    Password: str | None
    RoleARN: str | None
    S3Configuration: S3DestinationConfiguration | None
    Username: str | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    ProcessingConfiguration: ProcessingConfiguration | None
    RetryOptions: RedshiftRetryOptions | None
    S3BackupConfiguration: S3DestinationConfiguration | None
    S3BackupMode: str | None


class SplunkRetryOptions(TypedDict):
    DurationInSeconds: int | None


class SplunkDestinationConfiguration(TypedDict):
    HECEndpoint: str | None
    HECEndpointType: str | None
    HECToken: str | None
    S3Configuration: S3DestinationConfiguration | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    HECAcknowledgmentTimeoutInSeconds: int | None
    ProcessingConfiguration: ProcessingConfiguration | None
    RetryOptions: SplunkRetryOptions | None
    S3BackupMode: str | None


class HttpEndpointConfiguration(TypedDict):
    Url: str | None
    AccessKey: str | None
    Name: str | None


class HttpEndpointCommonAttribute(TypedDict):
    AttributeName: str | None
    AttributeValue: str | None


class HttpEndpointRequestConfiguration(TypedDict):
    CommonAttributes: list[HttpEndpointCommonAttribute] | None
    ContentEncoding: str | None


class HttpEndpointDestinationConfiguration(TypedDict):
    EndpointConfiguration: HttpEndpointConfiguration | None
    S3Configuration: S3DestinationConfiguration | None
    BufferingHints: BufferingHints | None
    CloudWatchLoggingOptions: CloudWatchLoggingOptions | None
    ProcessingConfiguration: ProcessingConfiguration | None
    RequestConfiguration: HttpEndpointRequestConfiguration | None
    RetryOptions: RetryOptions | None
    RoleARN: str | None
    S3BackupMode: str | None


class Tag(TypedDict):
    Key: str | None
    Value: str | None


REPEATED_INVOCATION = "repeated_invocation"


class KinesisFirehoseDeliveryStreamProvider(
    ResourceProvider[KinesisFirehoseDeliveryStreamProperties]
):
    TYPE = "AWS::KinesisFirehose::DeliveryStream"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[KinesisFirehoseDeliveryStreamProperties],
    ) -> ProgressEvent[KinesisFirehoseDeliveryStreamProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/DeliveryStreamName



        Create-only properties:
          - /properties/DeliveryStreamName
          - /properties/DeliveryStreamType
          - /properties/ElasticsearchDestinationConfiguration/VpcConfiguration
          - /properties/AmazonopensearchserviceDestinationConfiguration/VpcConfiguration
          - /properties/AmazonOpenSearchServerlessDestinationConfiguration/VpcConfiguration
          - /properties/KinesisStreamSourceConfiguration

        Read-only properties:
          - /properties/Arn

        IAM permissions required:
          - firehose:CreateDeliveryStream
          - firehose:DescribeDeliveryStream
          - iam:GetRole
          - iam:PassRole
          - kms:CreateGrant
          - kms:DescribeKey

        """
        model = request.desired_state
        firehose = request.aws_client_factory.firehose
        parameters = [
            "DeliveryStreamName",
            "DeliveryStreamType",
            "S3DestinationConfiguration",
            "ElasticsearchDestinationConfiguration",
            "AmazonopensearchserviceDestinationConfiguration",
            "DeliveryStreamEncryptionConfigurationInput",
            "ExtendedS3DestinationConfiguration",
            "HttpEndpointDestinationConfiguration",
            "KinesisStreamSourceConfiguration",
            "RedshiftDestinationConfiguration",
            "SplunkDestinationConfiguration",
            "Tags",
        ]
        attrs = util.select_attributes(model, params=parameters)
        if not attrs.get("DeliveryStreamName"):
            attrs["DeliveryStreamName"] = util.generate_default_name(
                request.stack_name, request.logical_resource_id
            )

        if not request.custom_context.get(REPEATED_INVOCATION):
            response = firehose.create_delivery_stream(**attrs)
            # TODO: defaults
            # TODO: idempotency
            model["Arn"] = response["DeliveryStreamARN"]
            request.custom_context[REPEATED_INVOCATION] = True
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context=request.custom_context,
            )
        # TODO add handler for CREATE FAILED state
        stream = firehose.describe_delivery_stream(DeliveryStreamName=model["DeliveryStreamName"])
        if stream["DeliveryStreamDescription"]["DeliveryStreamStatus"] != "ACTIVE":
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context=request.custom_context,
            )

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def read(
        self,
        request: ResourceRequest[KinesisFirehoseDeliveryStreamProperties],
    ) -> ProgressEvent[KinesisFirehoseDeliveryStreamProperties]:
        """
        Fetch resource information

        IAM permissions required:
          - firehose:DescribeDeliveryStream
          - firehose:ListTagsForDeliveryStream
        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[KinesisFirehoseDeliveryStreamProperties],
    ) -> ProgressEvent[KinesisFirehoseDeliveryStreamProperties]:
        """
        Delete a resource

        IAM permissions required:
          - firehose:DeleteDeliveryStream
          - firehose:DescribeDeliveryStream
          - kms:RevokeGrant
          - kms:DescribeKey
        """
        model = request.desired_state
        firehose = request.aws_client_factory.firehose
        try:
            stream = firehose.describe_delivery_stream(
                DeliveryStreamName=model["DeliveryStreamName"]
            )
        except request.aws_client_factory.firehose.exceptions.ResourceNotFoundException:
            return ProgressEvent(
                status=OperationStatus.SUCCESS,
                resource_model=model,
                custom_context=request.custom_context,
            )

        if stream["DeliveryStreamDescription"]["DeliveryStreamStatus"] != "DELETING":
            firehose.delete_delivery_stream(DeliveryStreamName=model["DeliveryStreamName"])
        return ProgressEvent(
            status=OperationStatus.IN_PROGRESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def update(
        self,
        request: ResourceRequest[KinesisFirehoseDeliveryStreamProperties],
    ) -> ProgressEvent[KinesisFirehoseDeliveryStreamProperties]:
        """
        Update a resource

        IAM permissions required:
          - firehose:UpdateDestination
          - firehose:DescribeDeliveryStream
          - firehose:StartDeliveryStreamEncryption
          - firehose:StopDeliveryStreamEncryption
          - firehose:ListTagsForDeliveryStream
          - firehose:TagDeliveryStream
          - firehose:UntagDeliveryStream
          - kms:CreateGrant
          - kms:RevokeGrant
          - kms:DescribeKey
        """
        raise NotImplementedError

# LocalStack Resource Provider Scaffolding v2
from __future__ import annotations

from pathlib import Path
from typing import Optional, TypedDict

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)


class KinesisFirehoseDeliveryStreamProperties(TypedDict):
    AmazonOpenSearchServerlessDestinationConfiguration: Optional[
        AmazonOpenSearchServerlessDestinationConfiguration
    ]
    AmazonopensearchserviceDestinationConfiguration: Optional[
        AmazonopensearchserviceDestinationConfiguration
    ]
    Arn: Optional[str]
    DeliveryStreamEncryptionConfigurationInput: Optional[DeliveryStreamEncryptionConfigurationInput]
    DeliveryStreamName: Optional[str]
    DeliveryStreamType: Optional[str]
    ElasticsearchDestinationConfiguration: Optional[ElasticsearchDestinationConfiguration]
    ExtendedS3DestinationConfiguration: Optional[ExtendedS3DestinationConfiguration]
    HttpEndpointDestinationConfiguration: Optional[HttpEndpointDestinationConfiguration]
    KinesisStreamSourceConfiguration: Optional[KinesisStreamSourceConfiguration]
    RedshiftDestinationConfiguration: Optional[RedshiftDestinationConfiguration]
    S3DestinationConfiguration: Optional[S3DestinationConfiguration]
    SplunkDestinationConfiguration: Optional[SplunkDestinationConfiguration]
    Tags: Optional[list[Tag]]


class DeliveryStreamEncryptionConfigurationInput(TypedDict):
    KeyType: Optional[str]
    KeyARN: Optional[str]


class ElasticsearchBufferingHints(TypedDict):
    IntervalInSeconds: Optional[int]
    SizeInMBs: Optional[int]


class CloudWatchLoggingOptions(TypedDict):
    Enabled: Optional[bool]
    LogGroupName: Optional[str]
    LogStreamName: Optional[str]


class ProcessorParameter(TypedDict):
    ParameterName: Optional[str]
    ParameterValue: Optional[str]


class Processor(TypedDict):
    Type: Optional[str]
    Parameters: Optional[list[ProcessorParameter]]


class ProcessingConfiguration(TypedDict):
    Enabled: Optional[bool]
    Processors: Optional[list[Processor]]


class ElasticsearchRetryOptions(TypedDict):
    DurationInSeconds: Optional[int]


class BufferingHints(TypedDict):
    IntervalInSeconds: Optional[int]
    SizeInMBs: Optional[int]


class KMSEncryptionConfig(TypedDict):
    AWSKMSKeyARN: Optional[str]


class EncryptionConfiguration(TypedDict):
    KMSEncryptionConfig: Optional[KMSEncryptionConfig]
    NoEncryptionConfig: Optional[str]


class S3DestinationConfiguration(TypedDict):
    BucketARN: Optional[str]
    RoleARN: Optional[str]
    BufferingHints: Optional[BufferingHints]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    CompressionFormat: Optional[str]
    EncryptionConfiguration: Optional[EncryptionConfiguration]
    ErrorOutputPrefix: Optional[str]
    Prefix: Optional[str]


class VpcConfiguration(TypedDict):
    RoleARN: Optional[str]
    SecurityGroupIds: Optional[list[str]]
    SubnetIds: Optional[list[str]]


class DocumentIdOptions(TypedDict):
    DefaultDocumentIdFormat: Optional[str]


class ElasticsearchDestinationConfiguration(TypedDict):
    IndexName: Optional[str]
    RoleARN: Optional[str]
    S3Configuration: Optional[S3DestinationConfiguration]
    BufferingHints: Optional[ElasticsearchBufferingHints]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    ClusterEndpoint: Optional[str]
    DocumentIdOptions: Optional[DocumentIdOptions]
    DomainARN: Optional[str]
    IndexRotationPeriod: Optional[str]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    RetryOptions: Optional[ElasticsearchRetryOptions]
    S3BackupMode: Optional[str]
    TypeName: Optional[str]
    VpcConfiguration: Optional[VpcConfiguration]


class AmazonopensearchserviceBufferingHints(TypedDict):
    IntervalInSeconds: Optional[int]
    SizeInMBs: Optional[int]


class AmazonopensearchserviceRetryOptions(TypedDict):
    DurationInSeconds: Optional[int]


class AmazonopensearchserviceDestinationConfiguration(TypedDict):
    IndexName: Optional[str]
    RoleARN: Optional[str]
    S3Configuration: Optional[S3DestinationConfiguration]
    BufferingHints: Optional[AmazonopensearchserviceBufferingHints]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    ClusterEndpoint: Optional[str]
    DocumentIdOptions: Optional[DocumentIdOptions]
    DomainARN: Optional[str]
    IndexRotationPeriod: Optional[str]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    RetryOptions: Optional[AmazonopensearchserviceRetryOptions]
    S3BackupMode: Optional[str]
    TypeName: Optional[str]
    VpcConfiguration: Optional[VpcConfiguration]


class AmazonOpenSearchServerlessBufferingHints(TypedDict):
    IntervalInSeconds: Optional[int]
    SizeInMBs: Optional[int]


class AmazonOpenSearchServerlessRetryOptions(TypedDict):
    DurationInSeconds: Optional[int]


class AmazonOpenSearchServerlessDestinationConfiguration(TypedDict):
    IndexName: Optional[str]
    RoleARN: Optional[str]
    S3Configuration: Optional[S3DestinationConfiguration]
    BufferingHints: Optional[AmazonOpenSearchServerlessBufferingHints]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    CollectionEndpoint: Optional[str]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    RetryOptions: Optional[AmazonOpenSearchServerlessRetryOptions]
    S3BackupMode: Optional[str]
    VpcConfiguration: Optional[VpcConfiguration]


class HiveJsonSerDe(TypedDict):
    TimestampFormats: Optional[list[str]]


class OpenXJsonSerDe(TypedDict):
    CaseInsensitive: Optional[bool]
    ColumnToJsonKeyMappings: Optional[dict]
    ConvertDotsInJsonKeysToUnderscores: Optional[bool]


class Deserializer(TypedDict):
    HiveJsonSerDe: Optional[HiveJsonSerDe]
    OpenXJsonSerDe: Optional[OpenXJsonSerDe]


class InputFormatConfiguration(TypedDict):
    Deserializer: Optional[Deserializer]


class OrcSerDe(TypedDict):
    BlockSizeBytes: Optional[int]
    BloomFilterColumns: Optional[list[str]]
    BloomFilterFalsePositiveProbability: Optional[float]
    Compression: Optional[str]
    DictionaryKeyThreshold: Optional[float]
    EnablePadding: Optional[bool]
    FormatVersion: Optional[str]
    PaddingTolerance: Optional[float]
    RowIndexStride: Optional[int]
    StripeSizeBytes: Optional[int]


class ParquetSerDe(TypedDict):
    BlockSizeBytes: Optional[int]
    Compression: Optional[str]
    EnableDictionaryCompression: Optional[bool]
    MaxPaddingBytes: Optional[int]
    PageSizeBytes: Optional[int]
    WriterVersion: Optional[str]


class Serializer(TypedDict):
    OrcSerDe: Optional[OrcSerDe]
    ParquetSerDe: Optional[ParquetSerDe]


class OutputFormatConfiguration(TypedDict):
    Serializer: Optional[Serializer]


class SchemaConfiguration(TypedDict):
    CatalogId: Optional[str]
    DatabaseName: Optional[str]
    Region: Optional[str]
    RoleARN: Optional[str]
    TableName: Optional[str]
    VersionId: Optional[str]


class DataFormatConversionConfiguration(TypedDict):
    Enabled: Optional[bool]
    InputFormatConfiguration: Optional[InputFormatConfiguration]
    OutputFormatConfiguration: Optional[OutputFormatConfiguration]
    SchemaConfiguration: Optional[SchemaConfiguration]


class RetryOptions(TypedDict):
    DurationInSeconds: Optional[int]


class DynamicPartitioningConfiguration(TypedDict):
    Enabled: Optional[bool]
    RetryOptions: Optional[RetryOptions]


class ExtendedS3DestinationConfiguration(TypedDict):
    BucketARN: Optional[str]
    RoleARN: Optional[str]
    BufferingHints: Optional[BufferingHints]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    CompressionFormat: Optional[str]
    DataFormatConversionConfiguration: Optional[DataFormatConversionConfiguration]
    DynamicPartitioningConfiguration: Optional[DynamicPartitioningConfiguration]
    EncryptionConfiguration: Optional[EncryptionConfiguration]
    ErrorOutputPrefix: Optional[str]
    Prefix: Optional[str]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    S3BackupConfiguration: Optional[S3DestinationConfiguration]
    S3BackupMode: Optional[str]


class KinesisStreamSourceConfiguration(TypedDict):
    KinesisStreamARN: Optional[str]
    RoleARN: Optional[str]


class CopyCommand(TypedDict):
    DataTableName: Optional[str]
    CopyOptions: Optional[str]
    DataTableColumns: Optional[str]


class RedshiftRetryOptions(TypedDict):
    DurationInSeconds: Optional[int]


class RedshiftDestinationConfiguration(TypedDict):
    ClusterJDBCURL: Optional[str]
    CopyCommand: Optional[CopyCommand]
    Password: Optional[str]
    RoleARN: Optional[str]
    S3Configuration: Optional[S3DestinationConfiguration]
    Username: Optional[str]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    RetryOptions: Optional[RedshiftRetryOptions]
    S3BackupConfiguration: Optional[S3DestinationConfiguration]
    S3BackupMode: Optional[str]


class SplunkRetryOptions(TypedDict):
    DurationInSeconds: Optional[int]


class SplunkDestinationConfiguration(TypedDict):
    HECEndpoint: Optional[str]
    HECEndpointType: Optional[str]
    HECToken: Optional[str]
    S3Configuration: Optional[S3DestinationConfiguration]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    HECAcknowledgmentTimeoutInSeconds: Optional[int]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    RetryOptions: Optional[SplunkRetryOptions]
    S3BackupMode: Optional[str]


class HttpEndpointConfiguration(TypedDict):
    Url: Optional[str]
    AccessKey: Optional[str]
    Name: Optional[str]


class HttpEndpointCommonAttribute(TypedDict):
    AttributeName: Optional[str]
    AttributeValue: Optional[str]


class HttpEndpointRequestConfiguration(TypedDict):
    CommonAttributes: Optional[list[HttpEndpointCommonAttribute]]
    ContentEncoding: Optional[str]


class HttpEndpointDestinationConfiguration(TypedDict):
    EndpointConfiguration: Optional[HttpEndpointConfiguration]
    S3Configuration: Optional[S3DestinationConfiguration]
    BufferingHints: Optional[BufferingHints]
    CloudWatchLoggingOptions: Optional[CloudWatchLoggingOptions]
    ProcessingConfiguration: Optional[ProcessingConfiguration]
    RequestConfiguration: Optional[HttpEndpointRequestConfiguration]
    RetryOptions: Optional[RetryOptions]
    RoleARN: Optional[str]
    S3BackupMode: Optional[str]


class Tag(TypedDict):
    Key: Optional[str]
    Value: Optional[str]


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

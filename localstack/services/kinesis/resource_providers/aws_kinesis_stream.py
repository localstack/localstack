# LocalStack Resource Provider Scaffolding v2
from __future__ import annotations

from pathlib import Path
from typing import Optional, Type, TypedDict

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)


class KinesisStreamProperties(TypedDict):
    Arn: Optional[str]
    Name: Optional[str]
    RetentionPeriodHours: Optional[int]
    ShardCount: Optional[int]
    StreamEncryption: Optional[StreamEncryption]
    StreamModeDetails: Optional[StreamModeDetails]
    Tags: Optional[list[Tag]]


class StreamModeDetails(TypedDict):
    StreamMode: Optional[str]


class StreamEncryption(TypedDict):
    EncryptionType: Optional[str]
    KeyId: Optional[str]


class Tag(TypedDict):
    Key: Optional[str]
    Value: Optional[str]


REPEATED_INVOCATION = "repeated_invocation"


class KinesisStreamProvider(ResourceProvider[KinesisStreamProperties]):

    TYPE = "AWS::Kinesis::Stream"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[KinesisStreamProperties],
    ) -> ProgressEvent[KinesisStreamProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/Name



        Create-only properties:
          - /properties/Name

        Read-only properties:
          - /properties/Arn

        IAM permissions required:
          - kinesis:EnableEnhancedMonitoring
          - kinesis:DescribeStreamSummary
          - kinesis:CreateStream
          - kinesis:IncreaseStreamRetentionPeriod
          - kinesis:StartStreamEncryption
          - kinesis:AddTagsToStream
          - kinesis:ListTagsForStream

        """
        model = request.desired_state
        kinesis = request.aws_client_factory.kinesis
        if not request.custom_context.get(REPEATED_INVOCATION):
            if not model.get("Name"):
                model["Name"] = util.generate_default_name(
                    stack_name=request.stack_name, logical_resource_id=request.logical_resource_id
                )
            if not model.get("ShardCount"):
                model["ShardCount"] = 1

            if not model.get("StreamModeDetails"):
                model["StreamModeDetails"] = StreamModeDetails(StreamMode="ON_DEMAND")

            kinesis.create_stream(
                StreamName=model["Name"],
                ShardCount=model["ShardCount"],
                StreamModeDetails=model["StreamModeDetails"],
            )

            stream_data = kinesis.describe_stream(StreamName=model["Name"])["StreamDescription"]
            model["Arn"] = stream_data["StreamARN"]
            request.custom_context[REPEATED_INVOCATION] = True
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context=request.custom_context,
            )

        stream_data = kinesis.describe_stream(StreamARN=model["Arn"])["StreamDescription"]
        if stream_data["StreamStatus"] != "ACTIVE":
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
        request: ResourceRequest[KinesisStreamProperties],
    ) -> ProgressEvent[KinesisStreamProperties]:
        """
        Fetch resource information

        IAM permissions required:
          - kinesis:DescribeStreamSummary
          - kinesis:ListTagsForStream
        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[KinesisStreamProperties],
    ) -> ProgressEvent[KinesisStreamProperties]:
        """
        Delete a resource

        IAM permissions required:
          - kinesis:DescribeStreamSummary
          - kinesis:DeleteStream
          - kinesis:RemoveTagsFromStream
        """
        model = request.desired_state
        request.aws_client_factory.kinesis.delete_stream(StreamARN=model["Arn"])
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model={},
        )

    def update(
        self,
        request: ResourceRequest[KinesisStreamProperties],
    ) -> ProgressEvent[KinesisStreamProperties]:
        """
        Update a resource

        IAM permissions required:
          - kinesis:EnableEnhancedMonitoring
          - kinesis:DisableEnhancedMonitoring
          - kinesis:DescribeStreamSummary
          - kinesis:UpdateShardCount
          - kinesis:UpdateStreamMode
          - kinesis:IncreaseStreamRetentionPeriod
          - kinesis:DecreaseStreamRetentionPeriod
          - kinesis:StartStreamEncryption
          - kinesis:StopStreamEncryption
          - kinesis:AddTagsToStream
          - kinesis:RemoveTagsFromStream
          - kinesis:ListTagsForStream
        """
        raise NotImplementedError


class KinesisStreamProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Kinesis::Stream"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        self.factory = KinesisStreamProvider

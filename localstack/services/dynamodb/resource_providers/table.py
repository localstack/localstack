from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
    register_resource_provider,
)


@dataclass
class PointInTimeRecoverySpecification:
    PointInTimeRecoveryEnabled: Optional[bool] = None


@dataclass
class ProvisionedThroughput:
    ReadCapacityUnits: Optional[int] = None
    WriteCapacityUnits: Optional[int] = None


@dataclass
class SSESpecification:
    KMSMasterKeyId: Optional[str] = None
    SSEEnabled: Optional[bool] = None
    SSEType: Optional[str] = None


@dataclass
class StreamSpecification:
    StreamViewType: Optional[str] = None


@dataclass
class TimeToLiveSpecification:
    AttributeName: Optional[str] = None
    Enabled: Optional[bool] = None


@dataclass
class ContributorInsightsSpecification:
    Enabled: Optional[bool] = None


@dataclass
class KinesisStreamSpecification:
    StreamArn: Optional[str] = None


@dataclass
class S3BucketSource:
    S3Bucket: Optional[str] = None
    S3BucketOwner: Optional[str] = None
    S3KeyPrefix: Optional[str] = None


@dataclass
class Csv:
    Delimiter: Optional[str] = None
    HeaderList: Optional[list] = None


@dataclass
class InputFormatOptions:
    Csv: Optional[Csv] = None


@dataclass
class ImportSourceSpecification:
    InputCompressionType: Optional[str] = None
    InputFormat: Optional[str] = None
    InputFormatOptions: Optional[InputFormatOptions] = None
    S3BucketSource: Optional[S3BucketSource] = None


@dataclass
class DynamoDBTableProperties:
    KeySchema: dict
    Arn: Optional[str] = None
    AttributeDefinitions: Optional[list] = None
    BillingMode: Optional[str] = None
    ContributorInsightsSpecification: Optional[ContributorInsightsSpecification] = None
    DeletionProtectionEnabled: Optional[bool] = None
    GlobalSecondaryIndexes: Optional[list] = None
    ImportSourceSpecification: Optional[ImportSourceSpecification] = None
    KinesisStreamSpecification: Optional[KinesisStreamSpecification] = None
    LocalSecondaryIndexes: Optional[list] = None
    PointInTimeRecoverySpecification: Optional[PointInTimeRecoverySpecification] = None
    ProvisionedThroughput: Optional[ProvisionedThroughput] = None
    SSESpecification: Optional[SSESpecification] = None
    StreamArn: Optional[str] = None
    StreamSpecification: Optional[StreamSpecification] = None
    TableClass: Optional[str] = None
    TableName: Optional[str] = None
    Tags: Optional[list] = None
    TimeToLiveSpecification: Optional[TimeToLiveSpecification] = None


class DynamoDBTableAllProperties(DynamoDBTableProperties):
    physical_resource_id: Optional[str] = None


@register_resource_provider
class DynamoDBTableProvider(ResourceProvider[DynamoDBTableAllProperties]):

    TYPE = "AWS::DynamoDB::Table"

    def create(
        self,
        request: ResourceRequest[DynamoDBTableAllProperties],
    ) -> ProgressEvent[DynamoDBTableAllProperties]:
        """
        Create a new resource.
        """
        raise NotImplementedError
        model = request.desired_state

        # TODO: validations

        if model.physical_resource_id is None:
            # this is the first time this callback is invoked
            # TODO: defaults
            # TODO: idempotency
            # TODO: actually create the resource
            # TODO: set model.physical_resource_id
            return ProgressEvent(status=OperationStatus.IN_PROGRESS, resource_model=model)

        # TODO: check the status of the resource
        # - if finished, update the model with all fields and return success event:
        #   return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)
        # - else
        #   return ProgressEvent(status=OperationStatus.IN_PROGRESS, resource_model=model)

        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[DynamoDBTableAllProperties],
    ) -> ProgressEvent[DynamoDBTableAllProperties]:
        raise NotImplementedError

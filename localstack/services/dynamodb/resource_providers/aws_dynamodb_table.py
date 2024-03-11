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


class DynamoDBTableProperties(TypedDict):
    KeySchema: Optional[list[KeySchema] | dict]
    Arn: Optional[str]
    AttributeDefinitions: Optional[list[AttributeDefinition]]
    BillingMode: Optional[str]
    ContributorInsightsSpecification: Optional[ContributorInsightsSpecification]
    DeletionProtectionEnabled: Optional[bool]
    GlobalSecondaryIndexes: Optional[list[GlobalSecondaryIndex]]
    ImportSourceSpecification: Optional[ImportSourceSpecification]
    KinesisStreamSpecification: Optional[KinesisStreamSpecification]
    LocalSecondaryIndexes: Optional[list[LocalSecondaryIndex]]
    PointInTimeRecoverySpecification: Optional[PointInTimeRecoverySpecification]
    ProvisionedThroughput: Optional[ProvisionedThroughput]
    SSESpecification: Optional[SSESpecification]
    StreamArn: Optional[str]
    StreamSpecification: Optional[StreamSpecification]
    TableClass: Optional[str]
    TableName: Optional[str]
    Tags: Optional[list[Tag]]
    TimeToLiveSpecification: Optional[TimeToLiveSpecification]


class AttributeDefinition(TypedDict):
    AttributeName: Optional[str]
    AttributeType: Optional[str]


class KeySchema(TypedDict):
    AttributeName: Optional[str]
    KeyType: Optional[str]


class Projection(TypedDict):
    NonKeyAttributes: Optional[list[str]]
    ProjectionType: Optional[str]


class ProvisionedThroughput(TypedDict):
    ReadCapacityUnits: Optional[int]
    WriteCapacityUnits: Optional[int]


class ContributorInsightsSpecification(TypedDict):
    Enabled: Optional[bool]


class GlobalSecondaryIndex(TypedDict):
    IndexName: Optional[str]
    KeySchema: Optional[list[KeySchema]]
    Projection: Optional[Projection]
    ContributorInsightsSpecification: Optional[ContributorInsightsSpecification]
    ProvisionedThroughput: Optional[ProvisionedThroughput]


class LocalSecondaryIndex(TypedDict):
    IndexName: Optional[str]
    KeySchema: Optional[list[KeySchema]]
    Projection: Optional[Projection]


class PointInTimeRecoverySpecification(TypedDict):
    PointInTimeRecoveryEnabled: Optional[bool]


class SSESpecification(TypedDict):
    SSEEnabled: Optional[bool]
    KMSMasterKeyId: Optional[str]
    SSEType: Optional[str]


class StreamSpecification(TypedDict):
    StreamViewType: Optional[str]


class Tag(TypedDict):
    Key: Optional[str]
    Value: Optional[str]


class TimeToLiveSpecification(TypedDict):
    AttributeName: Optional[str]
    Enabled: Optional[bool]


class KinesisStreamSpecification(TypedDict):
    StreamArn: Optional[str]


class S3BucketSource(TypedDict):
    S3Bucket: Optional[str]
    S3BucketOwner: Optional[str]
    S3KeyPrefix: Optional[str]


class Csv(TypedDict):
    Delimiter: Optional[str]
    HeaderList: Optional[list[str]]


class InputFormatOptions(TypedDict):
    Csv: Optional[Csv]


class ImportSourceSpecification(TypedDict):
    InputFormat: Optional[str]
    S3BucketSource: Optional[S3BucketSource]
    InputCompressionType: Optional[str]
    InputFormatOptions: Optional[InputFormatOptions]


REPEATED_INVOCATION = "repeated_invocation"


class DynamoDBTableProvider(ResourceProvider[DynamoDBTableProperties]):
    TYPE = "AWS::DynamoDB::Table"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[DynamoDBTableProperties],
    ) -> ProgressEvent[DynamoDBTableProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/TableName

        Required properties:
          - KeySchema

        Create-only properties:
          - /properties/TableName
          - /properties/ImportSourceSpecification

        Read-only properties:
          - /properties/Arn
          - /properties/StreamArn

        IAM permissions required:
          - dynamodb:CreateTable
          - dynamodb:DescribeImport
          - dynamodb:DescribeTable
          - dynamodb:DescribeTimeToLive
          - dynamodb:UpdateTimeToLive
          - dynamodb:UpdateContributorInsights
          - dynamodb:UpdateContinuousBackups
          - dynamodb:DescribeContinuousBackups
          - dynamodb:DescribeContributorInsights
          - dynamodb:EnableKinesisStreamingDestination
          - dynamodb:DisableKinesisStreamingDestination
          - dynamodb:DescribeKinesisStreamingDestination
          - dynamodb:ImportTable
          - dynamodb:ListTagsOfResource
          - dynamodb:TagResource
          - dynamodb:UpdateTable
          - kinesis:DescribeStream
          - kinesis:PutRecords
          - iam:CreateServiceLinkedRole
          - kms:CreateGrant
          - kms:Decrypt
          - kms:Describe*
          - kms:Encrypt
          - kms:Get*
          - kms:List*
          - kms:RevokeGrant
          - logs:CreateLogGroup
          - logs:CreateLogStream
          - logs:DescribeLogGroups
          - logs:DescribeLogStreams
          - logs:PutLogEvents
          - logs:PutRetentionPolicy
          - s3:GetObject
          - s3:GetObjectMetadata
          - s3:ListBucket

        """
        model = request.desired_state

        if not request.custom_context.get(REPEATED_INVOCATION):
            request.custom_context[REPEATED_INVOCATION] = True

            if not model.get("TableName"):
                model["TableName"] = util.generate_default_name(
                    request.stack_name, request.logical_resource_id
                )

            if model.get("ProvisionedThroughput"):
                model["ProvisionedThroughput"] = self.get_ddb_provisioned_throughput(model)

            if model.get("GlobalSecondaryIndexes"):
                model["GlobalSecondaryIndexes"] = self.get_ddb_global_sec_indexes(model)

            properties = [
                "TableName",
                "AttributeDefinitions",
                "KeySchema",
                "BillingMode",
                "ProvisionedThroughput",
                "LocalSecondaryIndexes",
                "GlobalSecondaryIndexes",
                "Tags",
                "SSESpecification",
            ]
            create_params = util.select_attributes(model, properties)

            if sse_specification := create_params.get("SSESpecification"):
                # rename bool attribute to fit boto call
                sse_specification["Enabled"] = sse_specification["SSEEnabled"]
                del sse_specification["SSEEnabled"]

            if stream_spec := model.get("StreamSpecification"):
                create_params["StreamSpecification"] = {
                    "StreamEnabled": True,
                    **(stream_spec or {}),
                }

            response = request.aws_client_factory.dynamodb.create_table(**create_params)
            model["Arn"] = response["TableDescription"]["TableArn"]

            if model.get("KinesisStreamSpecification"):
                request.aws_client_factory.dynamodb.enable_kinesis_streaming_destination(
                    **self.get_ddb_kinesis_stream_specification(model)
                )

            # add TTL config
            if ttl_config := model.get("TimeToLiveSpecification"):
                request.aws_client_factory.dynamodb.update_time_to_live(
                    TableName=model["TableName"], TimeToLiveSpecification=ttl_config
                )

            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context=request.custom_context,
            )

        description = request.aws_client_factory.dynamodb.describe_table(
            TableName=model["TableName"]
        )

        if description["Table"]["TableStatus"] != "ACTIVE":
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context=request.custom_context,
            )

        if model.get("TimeToLiveSpecification"):
            request.aws_client_factory.dynamodb.update_time_to_live(
                TableName=model["TableName"],
                TimeToLiveSpecification=model["TimeToLiveSpecification"],
            )

        if description["Table"].get("LatestStreamArn"):
            model["StreamArn"] = description["Table"]["LatestStreamArn"]

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
        )

    def read(
        self,
        request: ResourceRequest[DynamoDBTableProperties],
    ) -> ProgressEvent[DynamoDBTableProperties]:
        """
        Fetch resource information

        IAM permissions required:
          - dynamodb:DescribeTable
          - dynamodb:DescribeContinuousBackups
          - dynamodb:DescribeContributorInsights
        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[DynamoDBTableProperties],
    ) -> ProgressEvent[DynamoDBTableProperties]:
        """
        Delete a resource

        IAM permissions required:
          - dynamodb:DeleteTable
          - dynamodb:DescribeTable
        """
        model = request.desired_state
        if not request.custom_context.get(REPEATED_INVOCATION):
            request.custom_context[REPEATED_INVOCATION] = True
            request.aws_client_factory.dynamodb.delete_table(TableName=model["TableName"])
            return ProgressEvent(
                status=OperationStatus.IN_PROGRESS,
                resource_model=model,
                custom_context=request.custom_context,
            )

        try:
            table_state = request.aws_client_factory.dynamodb.describe_table(
                TableName=model["TableName"]
            )

            match table_state["Table"]["TableStatus"]:
                case "DELETING":
                    return ProgressEvent(
                        status=OperationStatus.IN_PROGRESS,
                        resource_model=model,
                        custom_context=request.custom_context,
                    )
                case invalid_state:
                    return ProgressEvent(
                        status=OperationStatus.FAILED,
                        message=f"Table deletion failed. Table {model['TableName']} found in state {invalid_state}",  # TODO: not validated yet
                        resource_model={},
                    )
        except request.aws_client_factory.dynamodb.exceptions.TableNotFoundException:
            return ProgressEvent(
                status=OperationStatus.SUCCESS,
                resource_model={},
            )

    def update(
        self,
        request: ResourceRequest[DynamoDBTableProperties],
    ) -> ProgressEvent[DynamoDBTableProperties]:
        """
        Update a resource

        IAM permissions required:
          - dynamodb:UpdateTable
          - dynamodb:DescribeTable
          - dynamodb:DescribeTimeToLive
          - dynamodb:UpdateTimeToLive
          - dynamodb:UpdateContinuousBackups
          - dynamodb:UpdateContributorInsights
          - dynamodb:DescribeContinuousBackups
          - dynamodb:DescribeKinesisStreamingDestination
          - dynamodb:ListTagsOfResource
          - dynamodb:TagResource
          - dynamodb:UntagResource
          - dynamodb:DescribeContributorInsights
          - dynamodb:EnableKinesisStreamingDestination
          - dynamodb:DisableKinesisStreamingDestination
          - kinesis:DescribeStream
          - kinesis:PutRecords
          - iam:CreateServiceLinkedRole
          - kms:CreateGrant
          - kms:Describe*
          - kms:Get*
          - kms:List*
          - kms:RevokeGrant
        """
        raise NotImplementedError

    def get_ddb_provisioned_throughput(
        self,
        properties: dict,
    ) -> dict | None:
        # see https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html#cfn-dynamodb-table-provisionedthroughput
        args = properties.get("ProvisionedThroughput")
        if args == "AWS::NoValue":
            return None
        is_ondemand = properties.get("BillingMode") == "PAY_PER_REQUEST"
        # if the BillingMode is set to PAY_PER_REQUEST, you cannot specify ProvisionedThroughput
        # if the BillingMode is set to PROVISIONED (default), you have to specify ProvisionedThroughput

        if args is None:
            if is_ondemand:
                # do not return default value if it's on demand
                return

            # return default values if it's not on demand
            return {
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 5,
            }

        if isinstance(args["ReadCapacityUnits"], str):
            args["ReadCapacityUnits"] = int(args["ReadCapacityUnits"])
        if isinstance(args["WriteCapacityUnits"], str):
            args["WriteCapacityUnits"] = int(args["WriteCapacityUnits"])

        return args

    def get_ddb_global_sec_indexes(
        self,
        properties: dict,
    ) -> list | None:
        args: list = properties.get("GlobalSecondaryIndexes")
        is_ondemand = properties.get("BillingMode") == "PAY_PER_REQUEST"
        if not args:
            return

        for index in args:
            # we ignore ContributorInsightsSpecification as not supported yet in DynamoDB and CloudWatch
            index.pop("ContributorInsightsSpecification", None)
            provisioned_throughput = index.get("ProvisionedThroughput")
            if is_ondemand and provisioned_throughput is None:
                pass  # optional for API calls
            elif provisioned_throughput is not None:
                # convert types
                if isinstance((read_units := provisioned_throughput["ReadCapacityUnits"]), str):
                    provisioned_throughput["ReadCapacityUnits"] = int(read_units)
                if isinstance((write_units := provisioned_throughput["WriteCapacityUnits"]), str):
                    provisioned_throughput["WriteCapacityUnits"] = int(write_units)
            else:
                raise Exception("Can't specify ProvisionedThroughput with PAY_PER_REQUEST")
        return args

    def get_ddb_kinesis_stream_specification(
        self,
        properties: dict,
    ) -> dict:
        args = properties.get("KinesisStreamSpecification")
        if args:
            args["TableName"] = properties["TableName"]
        return args

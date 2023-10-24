# LocalStack Resource Provider Scaffolding v2
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional, TypedDict

from botocore.exceptions import ClientError

import localstack.services.cloudformation.provider_utils as util
from localstack.config import get_edge_port_http
from localstack.constants import S3_STATIC_WEBSITE_HOSTNAME, S3_VIRTUAL_HOSTNAME
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)
from localstack.services.s3.utils import normalize_bucket_name
from localstack.utils.aws import arns
from localstack.utils.testutil import delete_all_s3_objects


class S3BucketProperties(TypedDict):
    AccelerateConfiguration: Optional[AccelerateConfiguration]
    AccessControl: Optional[str]
    AnalyticsConfigurations: Optional[list[AnalyticsConfiguration]]
    Arn: Optional[str]
    BucketEncryption: Optional[BucketEncryption]
    BucketName: Optional[str]
    CorsConfiguration: Optional[CorsConfiguration]
    DomainName: Optional[str]
    DualStackDomainName: Optional[str]
    IntelligentTieringConfigurations: Optional[list[IntelligentTieringConfiguration]]
    InventoryConfigurations: Optional[list[InventoryConfiguration]]
    LifecycleConfiguration: Optional[LifecycleConfiguration]
    LoggingConfiguration: Optional[LoggingConfiguration]
    MetricsConfigurations: Optional[list[MetricsConfiguration]]
    NotificationConfiguration: Optional[NotificationConfiguration]
    ObjectLockConfiguration: Optional[ObjectLockConfiguration]
    ObjectLockEnabled: Optional[bool]
    OwnershipControls: Optional[OwnershipControls]
    PublicAccessBlockConfiguration: Optional[PublicAccessBlockConfiguration]
    RegionalDomainName: Optional[str]
    ReplicationConfiguration: Optional[ReplicationConfiguration]
    Tags: Optional[list[Tag]]
    VersioningConfiguration: Optional[VersioningConfiguration]
    WebsiteConfiguration: Optional[WebsiteConfiguration]
    WebsiteURL: Optional[str]


class AccelerateConfiguration(TypedDict):
    AccelerationStatus: Optional[str]


class TagFilter(TypedDict):
    Key: Optional[str]
    Value: Optional[str]


class Destination(TypedDict):
    BucketArn: Optional[str]
    Format: Optional[str]
    BucketAccountId: Optional[str]
    Prefix: Optional[str]


class DataExport(TypedDict):
    Destination: Optional[Destination]
    OutputSchemaVersion: Optional[str]


class StorageClassAnalysis(TypedDict):
    DataExport: Optional[DataExport]


class AnalyticsConfiguration(TypedDict):
    Id: Optional[str]
    StorageClassAnalysis: Optional[StorageClassAnalysis]
    Prefix: Optional[str]
    TagFilters: Optional[list[TagFilter]]


class ServerSideEncryptionByDefault(TypedDict):
    SSEAlgorithm: Optional[str]
    KMSMasterKeyID: Optional[str]


class ServerSideEncryptionRule(TypedDict):
    BucketKeyEnabled: Optional[bool]
    ServerSideEncryptionByDefault: Optional[ServerSideEncryptionByDefault]


class BucketEncryption(TypedDict):
    ServerSideEncryptionConfiguration: Optional[list[ServerSideEncryptionRule]]


class CorsRule(TypedDict):
    AllowedMethods: Optional[list[str]]
    AllowedOrigins: Optional[list[str]]
    AllowedHeaders: Optional[list[str]]
    ExposedHeaders: Optional[list[str]]
    Id: Optional[str]
    MaxAge: Optional[int]


class CorsConfiguration(TypedDict):
    CorsRules: Optional[list[CorsRule]]


class Tiering(TypedDict):
    AccessTier: Optional[str]
    Days: Optional[int]


class IntelligentTieringConfiguration(TypedDict):
    Id: Optional[str]
    Status: Optional[str]
    Tierings: Optional[list[Tiering]]
    Prefix: Optional[str]
    TagFilters: Optional[list[TagFilter]]


class InventoryConfiguration(TypedDict):
    Destination: Optional[Destination]
    Enabled: Optional[bool]
    Id: Optional[str]
    IncludedObjectVersions: Optional[str]
    ScheduleFrequency: Optional[str]
    OptionalFields: Optional[list[str]]
    Prefix: Optional[str]


class AbortIncompleteMultipartUpload(TypedDict):
    DaysAfterInitiation: Optional[int]


class NoncurrentVersionExpiration(TypedDict):
    NoncurrentDays: Optional[int]
    NewerNoncurrentVersions: Optional[int]


class NoncurrentVersionTransition(TypedDict):
    StorageClass: Optional[str]
    TransitionInDays: Optional[int]
    NewerNoncurrentVersions: Optional[int]


class Transition(TypedDict):
    StorageClass: Optional[str]
    TransitionDate: Optional[str]
    TransitionInDays: Optional[int]


class Rule(TypedDict):
    Status: Optional[str]
    AbortIncompleteMultipartUpload: Optional[AbortIncompleteMultipartUpload]
    ExpirationDate: Optional[str]
    ExpirationInDays: Optional[int]
    ExpiredObjectDeleteMarker: Optional[bool]
    Id: Optional[str]
    NoncurrentVersionExpiration: Optional[NoncurrentVersionExpiration]
    NoncurrentVersionExpirationInDays: Optional[int]
    NoncurrentVersionTransition: Optional[NoncurrentVersionTransition]
    NoncurrentVersionTransitions: Optional[list[NoncurrentVersionTransition]]
    ObjectSizeGreaterThan: Optional[str]
    ObjectSizeLessThan: Optional[str]
    Prefix: Optional[str]
    TagFilters: Optional[list[TagFilter]]
    Transition: Optional[Transition]
    Transitions: Optional[list[Transition]]


class LifecycleConfiguration(TypedDict):
    Rules: Optional[list[Rule]]


class LoggingConfiguration(TypedDict):
    DestinationBucketName: Optional[str]
    LogFilePrefix: Optional[str]


class MetricsConfiguration(TypedDict):
    Id: Optional[str]
    AccessPointArn: Optional[str]
    Prefix: Optional[str]
    TagFilters: Optional[list[TagFilter]]


class EventBridgeConfiguration(TypedDict):
    EventBridgeEnabled: Optional[bool]


class FilterRule(TypedDict):
    Name: Optional[str]
    Value: Optional[str]


class S3KeyFilter(TypedDict):
    Rules: Optional[list[FilterRule]]


class NotificationFilter(TypedDict):
    S3Key: Optional[S3KeyFilter]


class LambdaConfiguration(TypedDict):
    Event: Optional[str]
    Function: Optional[str]
    Filter: Optional[NotificationFilter]


class QueueConfiguration(TypedDict):
    Event: Optional[str]
    Queue: Optional[str]
    Filter: Optional[NotificationFilter]


class TopicConfiguration(TypedDict):
    Event: Optional[str]
    Topic: Optional[str]
    Filter: Optional[NotificationFilter]


class NotificationConfiguration(TypedDict):
    EventBridgeConfiguration: Optional[EventBridgeConfiguration]
    LambdaConfigurations: Optional[list[LambdaConfiguration]]
    QueueConfigurations: Optional[list[QueueConfiguration]]
    TopicConfigurations: Optional[list[TopicConfiguration]]


class DefaultRetention(TypedDict):
    Days: Optional[int]
    Mode: Optional[str]
    Years: Optional[int]


class ObjectLockRule(TypedDict):
    DefaultRetention: Optional[DefaultRetention]


class ObjectLockConfiguration(TypedDict):
    ObjectLockEnabled: Optional[str]
    Rule: Optional[ObjectLockRule]


class OwnershipControlsRule(TypedDict):
    ObjectOwnership: Optional[str]


class OwnershipControls(TypedDict):
    Rules: Optional[list[OwnershipControlsRule]]


class PublicAccessBlockConfiguration(TypedDict):
    BlockPublicAcls: Optional[bool]
    BlockPublicPolicy: Optional[bool]
    IgnorePublicAcls: Optional[bool]
    RestrictPublicBuckets: Optional[bool]


class DeleteMarkerReplication(TypedDict):
    Status: Optional[str]


class AccessControlTranslation(TypedDict):
    Owner: Optional[str]


class EncryptionConfiguration(TypedDict):
    ReplicaKmsKeyID: Optional[str]


class ReplicationTimeValue(TypedDict):
    Minutes: Optional[int]


class Metrics(TypedDict):
    Status: Optional[str]
    EventThreshold: Optional[ReplicationTimeValue]


class ReplicationTime(TypedDict):
    Status: Optional[str]
    Time: Optional[ReplicationTimeValue]


class ReplicationDestination(TypedDict):
    Bucket: Optional[str]
    AccessControlTranslation: Optional[AccessControlTranslation]
    Account: Optional[str]
    EncryptionConfiguration: Optional[EncryptionConfiguration]
    Metrics: Optional[Metrics]
    ReplicationTime: Optional[ReplicationTime]
    StorageClass: Optional[str]


class ReplicationRuleAndOperator(TypedDict):
    Prefix: Optional[str]
    TagFilters: Optional[list[TagFilter]]


class ReplicationRuleFilter(TypedDict):
    And: Optional[ReplicationRuleAndOperator]
    Prefix: Optional[str]
    TagFilter: Optional[TagFilter]


class ReplicaModifications(TypedDict):
    Status: Optional[str]


class SseKmsEncryptedObjects(TypedDict):
    Status: Optional[str]


class SourceSelectionCriteria(TypedDict):
    ReplicaModifications: Optional[ReplicaModifications]
    SseKmsEncryptedObjects: Optional[SseKmsEncryptedObjects]


class ReplicationRule(TypedDict):
    Destination: Optional[ReplicationDestination]
    Status: Optional[str]
    DeleteMarkerReplication: Optional[DeleteMarkerReplication]
    Filter: Optional[ReplicationRuleFilter]
    Id: Optional[str]
    Prefix: Optional[str]
    Priority: Optional[int]
    SourceSelectionCriteria: Optional[SourceSelectionCriteria]


class ReplicationConfiguration(TypedDict):
    Role: Optional[str]
    Rules: Optional[list[ReplicationRule]]


class Tag(TypedDict):
    Key: Optional[str]
    Value: Optional[str]


class VersioningConfiguration(TypedDict):
    Status: Optional[str]


class RedirectRule(TypedDict):
    HostName: Optional[str]
    HttpRedirectCode: Optional[str]
    Protocol: Optional[str]
    ReplaceKeyPrefixWith: Optional[str]
    ReplaceKeyWith: Optional[str]


class RoutingRuleCondition(TypedDict):
    HttpErrorCodeReturnedEquals: Optional[str]
    KeyPrefixEquals: Optional[str]


class RoutingRule(TypedDict):
    RedirectRule: Optional[RedirectRule]
    RoutingRuleCondition: Optional[RoutingRuleCondition]


class RedirectAllRequestsTo(TypedDict):
    HostName: Optional[str]
    Protocol: Optional[str]


class WebsiteConfiguration(TypedDict):
    ErrorDocument: Optional[str]
    IndexDocument: Optional[str]
    RedirectAllRequestsTo: Optional[RedirectAllRequestsTo]
    RoutingRules: Optional[list[RoutingRule]]


REPEATED_INVOCATION = "repeated_invocation"


class S3BucketProvider(ResourceProvider[S3BucketProperties]):
    TYPE = "AWS::S3::Bucket"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[S3BucketProperties],
    ) -> ProgressEvent[S3BucketProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/BucketName


        Create-only properties:
          - /properties/BucketName
          - /properties/ObjectLockEnabled

        Read-only properties:
          - /properties/Arn
          - /properties/DomainName
          - /properties/DualStackDomainName
          - /properties/RegionalDomainName
          - /properties/WebsiteURL

        IAM permissions required:
          - s3:CreateBucket
          - s3:PutBucketTagging
          - s3:PutAnalyticsConfiguration
          - s3:PutEncryptionConfiguration
          - s3:PutBucketCORS
          - s3:PutInventoryConfiguration
          - s3:PutLifecycleConfiguration
          - s3:PutMetricsConfiguration
          - s3:PutBucketNotification
          - s3:PutBucketReplication
          - s3:PutBucketWebsite
          - s3:PutAccelerateConfiguration
          - s3:PutBucketPublicAccessBlock
          - s3:PutReplicationConfiguration
          - s3:PutObjectAcl
          - s3:PutBucketObjectLockConfiguration
          - s3:GetBucketAcl
          - s3:ListBucket
          - iam:PassRole
          - s3:DeleteObject
          - s3:PutBucketLogging
          - s3:PutBucketVersioning
          - s3:PutObjectLockConfiguration
          - s3:PutBucketOwnershipControls
          - s3:PutBucketIntelligentTieringConfiguration

        """
        model = request.desired_state
        s3_client = request.aws_client_factory.s3

        if not model.get("BucketName"):
            model["BucketName"] = util.generate_default_name(
                stack_name=request.stack_name, logical_resource_id=request.logical_resource_id
            )
        model["BucketName"] = normalize_bucket_name(model["BucketName"])

        self._create_bucket_if_does_not_exist(model, request.region_name, s3_client)

        self._setup_post_creation_attributes(model)

        if put_config := self._get_s3_bucket_notification_config(model):
            s3_client.put_bucket_notification_configuration(**put_config)

        if version_conf := model.get("VersioningConfiguration"):
            s3_client.put_bucket_versioning(
                Bucket=model["BucketName"],
                VersioningConfiguration={
                    "Status": version_conf.get("Status", "Disabled"),
                },
            )

        if cors_configuration := self._transform_cfn_cors(model.get("CorsConfiguration")):
            s3_client.put_bucket_cors(
                Bucket=model["BucketName"],
                CORSConfiguration=cors_configuration,
            )

        if tags := model.get("Tags"):
            s3_client.put_bucket_tagging(Bucket=model["BucketName"], Tagging={"TagSet": tags})

        if website_config := self._transform_website_configuration(
            model.get("WebsiteConfiguration")
        ):
            s3_client.put_bucket_website(
                Bucket=model["BucketName"],
                WebsiteConfiguration=website_config,
            )

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def _transform_website_configuration(self, website_configuration: dict) -> dict:
        if not website_configuration:
            return {}
        output = {}
        if index := website_configuration.get("IndexDocument"):
            output["IndexDocument"] = {"Suffix": index}
        if error := website_configuration.get("ErrorDocument"):
            output["ErrorDocument"] = {"Key": error}
        if redirect_all := website_configuration.get("RedirectAllRequestsTo"):
            output["RedirectAllRequestsTo"] = redirect_all

        for r in website_configuration.get("RoutingRules", []):
            rule = {}
            if condition := r.get("RoutingRuleCondition"):
                rule["Condition"] = condition
            if redirect := r.get("RedirectRule"):
                rule["Redirect"] = redirect
            output.setdefault("RoutingRules", []).append(rule)

        return output

    def _transform_cfn_cors(self, cors_config):
        # See https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketCors.html
        # https://docs.aws.amazon.com/AmazonS3/latest/API/API_CORSRule.html
        # only AllowedMethods and AllowedOrigins are required
        if not cors_config:
            return {}

        cors_rules = []
        for cfn_rule in cors_config.get("CorsRules", []):
            rule = {
                "AllowedOrigins": cfn_rule.get("AllowedOrigins"),
                "AllowedMethods": cfn_rule.get("AllowedMethods"),
            }
            # we should not pass those to PutBucketCors if they are None, as S3 will provide default values and
            # does not accept None
            if (allowed_headers := cfn_rule.get("AllowedHeaders")) is not None:
                rule["AllowedHeaders"] = allowed_headers

            if (allowed_headers := cfn_rule.get("ExposedHeaders")) is not None:
                rule["ExposeHeaders"] = allowed_headers

            if (allowed_headers := cfn_rule.get("MaxAge")) is not None:
                rule["MaxAgeSeconds"] = allowed_headers

            if (allowed_headers := cfn_rule.get("Id")) is not None:
                rule["ID"] = allowed_headers

            cors_rules.append(rule)

        return {"CORSRules": cors_rules}

    def _get_s3_bucket_notification_config(
        self,
        properties: dict,
    ) -> dict | None:
        notif_config = properties.get("NotificationConfiguration")
        if not notif_config:
            return None

        lambda_configs = []
        queue_configs = []
        topic_configs = []

        attr_tuples = (
            (
                "LambdaConfigurations",
                lambda_configs,
                "LambdaFunctionArn",
                "Function",
            ),
            ("QueueConfigurations", queue_configs, "QueueArn", "Queue"),
            ("TopicConfigurations", topic_configs, "TopicArn", "Topic"),
        )

        # prepare lambda/queue/topic notification configs
        for attrs in attr_tuples:
            for notif_cfg in notif_config.get(attrs[0]) or []:
                filter_rules = notif_cfg.get("Filter", {}).get("S3Key", {}).get("Rules")
                entry = {
                    attrs[2]: notif_cfg[attrs[3]],
                    "Events": [notif_cfg["Event"]],
                }
                if filter_rules:
                    entry["Filter"] = {"Key": {"FilterRules": filter_rules}}
                attrs[1].append(entry)

        # construct final result
        result = {
            "Bucket": properties.get("BucketName"),
            "NotificationConfiguration": {
                "LambdaFunctionConfigurations": lambda_configs,
                "QueueConfigurations": queue_configs,
                "TopicConfigurations": topic_configs,
            },
        }
        if notif_config.get("EventBridgeConfiguration", {}).get("EventBridgeEnabled"):
            result["NotificationConfiguration"]["EventBridgeConfiguration"] = {}

        return result

    def _setup_post_creation_attributes(self, model):
        model["Arn"] = arns.s3_bucket_arn(model["BucketName"])
        domain_name = f"{model['BucketName']}.{S3_VIRTUAL_HOSTNAME}"
        model["DomainName"] = domain_name
        model["RegionalDomainName"] = domain_name
        # by default (parity) s3 website only supports http
        #   https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteHosting.html
        #   "Amazon S3 website endpoints do not support HTTPS. If you want to use HTTPS,
        #   you can use Amazon CloudFront [...]"
        model[
            "WebsiteURL"
        ] = f"http://{model['BucketName']}.{S3_STATIC_WEBSITE_HOSTNAME}:{get_edge_port_http()}"
        # resource["Properties"]["DualStackDomainName"] = ?

    def _create_bucket_if_does_not_exist(self, model, region_name, s3_client):
        try:
            s3_client.head_bucket(Bucket=model["BucketName"])
        except ClientError as e:
            if e.response["Error"]["Message"] != "Not Found":
                return

            params = {
                "Bucket": model["BucketName"],
                "ACL": self._convert_acl_cf_to_s3(model.get("AccessControl", "PublicRead")),
            }

            if region_name != "us-east-1":
                params["CreateBucketConfiguration"] = {
                    "LocationConstraint": region_name,
                }

            s3_client.create_bucket(**params)

    def _convert_acl_cf_to_s3(self, acl):
        """Convert a CloudFormation ACL string (e.g., 'PublicRead') to an S3 ACL string (e.g., 'public-read')"""
        return re.sub("(?<!^)(?=[A-Z])", "-", acl).lower()

    def read(
        self,
        request: ResourceRequest[S3BucketProperties],
    ) -> ProgressEvent[S3BucketProperties]:
        """
        Fetch resource information

        IAM permissions required:
          - s3:GetAccelerateConfiguration
          - s3:GetLifecycleConfiguration
          - s3:GetBucketPublicAccessBlock
          - s3:GetAnalyticsConfiguration
          - s3:GetBucketCORS
          - s3:GetEncryptionConfiguration
          - s3:GetInventoryConfiguration
          - s3:GetBucketLogging
          - s3:GetMetricsConfiguration
          - s3:GetBucketNotification
          - s3:GetBucketVersioning
          - s3:GetReplicationConfiguration
          - S3:GetBucketWebsite
          - s3:GetBucketPublicAccessBlock
          - s3:GetBucketObjectLockConfiguration
          - s3:GetBucketTagging
          - s3:GetBucketOwnershipControls
          - s3:GetIntelligentTieringConfiguration
          - s3:ListBucket
        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[S3BucketProperties],
    ) -> ProgressEvent[S3BucketProperties]:
        """
        Delete a resource

        IAM permissions required:
          - s3:DeleteBucket
        """
        model = request.desired_state
        s3_client = request.aws_client_factory.s3

        # TODO: divergence from how AWS deals with bucket deletes (should throw an error)
        try:
            delete_all_s3_objects(s3_client, model["BucketName"])
        except s3_client.exceptions.ClientError as e:
            if "NoSuchBucket" not in str(e):
                raise

        s3_client.delete_bucket(Bucket=model["BucketName"])

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def update(
        self,
        request: ResourceRequest[S3BucketProperties],
    ) -> ProgressEvent[S3BucketProperties]:
        """
        Update a resource

        IAM permissions required:
          - s3:PutBucketAcl
          - s3:PutBucketTagging
          - s3:PutAnalyticsConfiguration
          - s3:PutEncryptionConfiguration
          - s3:PutBucketCORS
          - s3:PutInventoryConfiguration
          - s3:PutLifecycleConfiguration
          - s3:PutMetricsConfiguration
          - s3:PutBucketNotification
          - s3:PutBucketReplication
          - s3:PutBucketWebsite
          - s3:PutAccelerateConfiguration
          - s3:PutBucketPublicAccessBlock
          - s3:PutReplicationConfiguration
          - s3:PutBucketOwnershipControls
          - s3:PutBucketIntelligentTieringConfiguration
          - s3:DeleteBucketWebsite
          - s3:PutBucketLogging
          - s3:PutBucketVersioning
          - s3:PutObjectLockConfiguration
          - s3:DeleteBucketAnalyticsConfiguration
          - s3:DeleteBucketCors
          - s3:DeleteBucketMetricsConfiguration
          - s3:DeleteBucketEncryption
          - s3:DeleteBucketLifecycle
          - s3:DeleteBucketReplication
          - iam:PassRole
        """
        raise NotImplementedError

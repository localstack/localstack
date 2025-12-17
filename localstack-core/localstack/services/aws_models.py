"""
TypedDict models for AWS-specific LocalStack endpoints.

These endpoints provide LocalStack-specific functionality for AWS services,
such as retrospective access to messages, metrics, and testing utilities.
"""

from typing import NotRequired, TypedDict


class CloudWatchDimension(TypedDict):
    """CloudWatch metric dimension."""

    n: str  # Dimension name
    v: str | int  # Dimension value


class CloudWatchMetric(TypedDict):
    """CloudWatch metric data point."""

    ns: str  # Namespace
    n: str  # Metric name
    v: str | int  # Metric value
    t: str | float  # Timestamp
    d: list[CloudWatchDimension]  # Dimensions
    account: str  # Account ID
    region: str  # Region name


class CloudWatchMetrics(TypedDict):
    """Response from CloudWatch raw metrics endpoint."""

    metrics: list[CloudWatchMetric]


class DynamoDBExpiredItemsResponse(TypedDict):
    """Response from DynamoDB expired items deletion endpoint."""

    ExpiredItems: int  # Number of expired items that were deleted


# SNS Models


class SNSMessage(TypedDict):
    """SNS message sent via SMS or to platform endpoints."""

    Message: str
    MessageId: str
    MessageAttributes: NotRequired[dict]
    MessageStructure: NotRequired[str | None]
    PhoneNumber: NotRequired[str]
    Subject: NotRequired[str | None]
    SubscriptionArn: NotRequired[str | None]
    TargetArn: NotRequired[str]
    TopicArn: NotRequired[str | None]


class SNSPlatformEndpointMessagesResponse(TypedDict):
    """Response from SNS platform endpoint messages endpoint."""

    region: str
    platform_endpoint_messages: dict[str, list[SNSMessage]]


class SNSSMSMessagesResponse(TypedDict):
    """Response from SNS SMS messages endpoint."""

    region: str
    sms_messages: dict[str, list[SNSMessage]]


class SNSSubscriptionTokenResponse(TypedDict):
    """Response from SNS subscription token endpoint."""

    subscription_arn: str
    subscription_token: str


class SNSSubscriptionTokenError(TypedDict):
    """Error response from SNS subscription token endpoint."""

    error: str
    subscription_arn: str

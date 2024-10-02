from localstack.feature_catalog.service_feature import (
    ImplementationStatus,
    ServiceFeature,
    SupportStatus,
)

"""
This is only a PoC on how features could be divided
For CloudWatch the features are not yet complete, only experimented with a couple of features and hierarchies

Attributes are subject to discussion as well
"""


class CloudWatchFeature(ServiceFeature):
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED


class Metric(CloudWatchFeature):
    general_docs: str = "Collect metrics from AWS services, or generate custom metrics"
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    support_type: SupportStatus = SupportStatus.SUPPORTED
    limitations: str = "AWS service metrics are only reported for selected services and metrics"
    aws_docs_link: str = (
        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/working_with_metrics.html"
    )


class AWSMetric(Metric):
    general_docs: str = "Collects application metrics from AWS services"
    supported_services: list[str] = ["Lambda", "SQS"]
    supported_details: dict[str] = {
        "Lambda": "Supports Invocations and Errors metrics.",
        "SQS": "Supports Approximate* metrics, NumberOfMessagesSent, and other metrics triggered by events such as message received or sending.",
    }


class Alarm(CloudWatchFeature):
    general_docs: str = "Alarms are used to set thresholds for metrics and trigger actions"
    supported: SupportStatus = SupportStatus.SUPPORTED_PARTIALLY_EMULATED
    implementation_status: ImplementationStatus = ImplementationStatus.PARTIALLY_IMPLEMENTED
    aws_docs_link: str = (
        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html"
    )


class CompositeAlarm(Alarm):
    supported: SupportStatus = SupportStatus.SUPPORTED_MOCKED_ONLY
    aws_docs_link: str = (
        "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Create_Composite_Alarm.html"
    )


class MetricAlarm(Alarm):
    supported: SupportStatus = SupportStatus.SUPPORTED
    supported_triggers: list[str] = ["SNS", "Lambda"]

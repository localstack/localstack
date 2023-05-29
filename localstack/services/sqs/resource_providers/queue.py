from __future__ import annotations

import json
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
class SQSQueueProperties:
    Arn: Optional[str] = None
    ContentBasedDeduplication: Optional[bool] = None
    DeduplicationScope: Optional[str] = None
    DelaySeconds: Optional[int] = None
    FifoQueue: Optional[bool] = None
    FifoThroughputLimit: Optional[str] = None
    KmsDataKeyReusePeriodSeconds: Optional[int] = None
    KmsMasterKeyId: Optional[str] = None
    MaximumMessageSize: Optional[int] = None
    MessageRetentionPeriod: Optional[int] = None
    QueueName: Optional[str] = None
    QueueUrl: Optional[str] = None
    ReceiveMessageWaitTimeSeconds: Optional[int] = None
    RedriveAllowPolicy: Optional[dict[str, str]] = None
    RedrivePolicy: Optional[dict[str, str]] = None
    SqsManagedSseEnabled: Optional[bool] = None
    Tags: Optional[list] = None
    VisibilityTimeout: Optional[int] = None


_queue_attribute_list = [
    "ContentBasedDeduplication",
    "DeduplicationScope",
    "DelaySeconds",
    "FifoQueue",
    "FifoThroughputLimit",
    "KmsDataKeyReusePeriodSeconds",
    "KmsMasterKeyId",
    "MaximumMessageSize",
    "MessageRetentionPeriod",
    "ReceiveMessageWaitTimeSeconds",
    "RedriveAllowPolicy",
    "RedrivePolicy",
    "SqsManagedSseEnabled",
    "VisibilityTimeout",
]


class SQSQueueAllProperties(SQSQueueProperties):
    physical_resource_id: Optional[str] = None


@register_resource_provider
class SQSQueueProvider(ResourceProvider[SQSQueueAllProperties]):
    TYPE = "AWS::SQS::Queue"

    def create(
        self,
        request: ResourceRequest[SQSQueueAllProperties],
    ) -> ProgressEvent[SQSQueueAllProperties]:
        """
        Create a new resource.
        """
        model = request.desired_state

        assert model.QueueName is not None

        attributes = self._compile_sqs_queue_attributes(model)
        tags = {tag["Key"]: tag["Value"] for tag in model.Tags} if model.Tags else {}

        result = request.aws_client_factory.sqs.create_queue(
            QueueName=model.QueueName,
            Attributes=attributes,  # noqa
            tags=tags,
        )
        model.physical_resource_id = result["QueueUrl"]

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

    def delete(
        self,
        request: ResourceRequest[SQSQueueAllProperties],
    ) -> ProgressEvent[SQSQueueAllProperties]:
        sqs = request.aws_client_factory.sqs

        try:
            queue_url = sqs.get_queue_url(QueueName=request.desired_state.QueueName)["QueueUrl"]
            sqs.delete_queue(QueueUrl=queue_url)
        except sqs.exceptions.QueueDoesNotExist:
            return ProgressEvent(
                status=OperationStatus.SUCCESS, resource_model=request.desired_state
            )

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=request.desired_state)

    def _compile_sqs_queue_attributes(self, properties: SQSQueueProperties) -> dict[str, str]:
        """
        SQS is really awkward in how the ``CreateQueue`` operation expects arguments. Most of a Queue's
        attributes are passed as a string values in the "Attributes" dictionary. So we need to compile this
        dictionary here.

        :param properties: the properties passed from cloudformation
        :return: a mapping used for the ``Attributes`` argument of the `CreateQueue` call.
        """
        result = {}

        for k in _queue_attribute_list:
            v = getattr(properties, k, None)

            if v is None:
                continue
            elif isinstance(v, str):
                pass
            elif isinstance(v, bool):
                v = str(v).lower()
            elif isinstance(v, dict):
                # RedrivePolicy and RedriveAllowPolicy
                v = json.dumps(v)
            elif isinstance(v, int):
                v = str(v)
            else:
                raise TypeError(f"cannot convert attribute {k}, unhandled type {type(v)}")

            result[k] = v

        return result

# LocalStack Resource Provider Scaffolding v2
import json

from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceRequest,
)
from localstack.services.sqs.resource_providers.generated.aws_sqs_queueinlinepolicy_base import (
    SQSQueueInlinePolicyProperties,
    SQSQueueInlinePolicyProviderBase,
)


class SQSQueueInlinePolicyProvider(SQSQueueInlinePolicyProviderBase):
    def create(
        self,
        request: ResourceRequest[SQSQueueInlinePolicyProperties],
    ) -> ProgressEvent[SQSQueueInlinePolicyProperties]:
        model = request.desired_state
        sqs = request.aws_client_factory.sqs

        queue = model.get("Queue")
        policy = model.get("PolicyDocument")
        sqs.set_queue_attributes(QueueUrl=queue, Attributes={"Policy": json.dumps(policy)})

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def read(
        self,
        request: ResourceRequest[SQSQueueInlinePolicyProperties],
    ) -> ProgressEvent[SQSQueueInlinePolicyProperties]:
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[SQSQueueInlinePolicyProperties],
    ) -> ProgressEvent[SQSQueueInlinePolicyProperties]:
        model = request.desired_state
        sqs = request.aws_client_factory.sqs

        queue = model.get("Queue")
        sqs.set_queue_attributes(QueueUrl=queue, Attributes={"Policy": ""})

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model={})

    def update(
        self,
        request: ResourceRequest[SQSQueueInlinePolicyProperties],
    ) -> ProgressEvent[SQSQueueInlinePolicyProperties]:
        model = request.desired_state
        sqs = request.aws_client_factory.sqs

        queue = model.get("Queue")
        policy = model.get("PolicyDocument")
        sqs.set_queue_attributes(QueueUrl=queue, Attributes={"Policy": json.dumps(policy)})

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def list(
        self,
        request: ResourceRequest[SQSQueueInlinePolicyProperties],
    ) -> ProgressEvent[SQSQueueInlinePolicyProperties]:
        """
        List available resources of this type

        """
        raise NotImplementedError

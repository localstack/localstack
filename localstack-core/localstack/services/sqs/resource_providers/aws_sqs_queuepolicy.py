# LocalStack Resource Provider Scaffolding v2
import json

import localstack.services.cloudformation.provider_utils as util
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceRequest,
)
from localstack.services.sqs.resource_providers.generated.aws_sqs_queuepolicy_base import (
    SQSQueuePolicyProperties,
    SQSQueuePolicyProviderBase,
)


class SQSQueuePolicyProvider(SQSQueuePolicyProviderBase):
    def create(
        self,
        request: ResourceRequest[SQSQueuePolicyProperties],
    ) -> ProgressEvent[SQSQueuePolicyProperties]:
        """
        Create a new resource.
        """
        model = request.desired_state
        sqs = request.aws_client_factory.sqs
        for queue in model.get("Queues", []):
            policy = json.dumps(model["PolicyDocument"])
            sqs.set_queue_attributes(QueueUrl=queue, Attributes={"Policy": policy})

        physical_resource_id = util.generate_default_name(
            stack_name=request.stack_name, logical_resource_id=request.logical_resource_id
        )
        model["Id"] = physical_resource_id

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def read(
        self,
        request: ResourceRequest[SQSQueuePolicyProperties],
    ) -> ProgressEvent[SQSQueuePolicyProperties]:
        """
        Fetch resource information
        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[SQSQueuePolicyProperties],
    ) -> ProgressEvent[SQSQueuePolicyProperties]:
        """
        Delete a resource
        """
        sqs = request.aws_client_factory.sqs
        for queue in request.previous_state["Queues"]:
            try:
                sqs.set_queue_attributes(QueueUrl=queue, Attributes={"Policy": ""})

            except sqs.exceptions.QueueDoesNotExist:
                return ProgressEvent(status=OperationStatus.FAILED, resource_model={})

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model={},
        )

    def update(
        self,
        request: ResourceRequest[SQSQueuePolicyProperties],
    ) -> ProgressEvent[SQSQueuePolicyProperties]:
        """
        Update a resource
        """
        model = request.desired_state
        sqs = request.aws_client_factory.sqs

        # handle new/updated queues
        desired_queues = model.get("Queues", [])
        for queue in desired_queues:
            policy = json.dumps(model["PolicyDocument"])
            sqs.set_queue_attributes(QueueUrl=queue, Attributes={"Policy": policy})

        # handle queues no longer in the desired state
        previous_queues = request.previous_state.get("Queues", [])
        outdated_queues = set(previous_queues) - set(desired_queues)
        for queue in outdated_queues:
            sqs.set_queue_attributes(QueueUrl=queue, Attributes={"Policy": ""})

        model["Id"] = request.previous_state["Id"]

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
        )

    def list(
        self,
        request: ResourceRequest[SQSQueuePolicyProperties],
    ) -> ProgressEvent[SQSQueuePolicyProperties]:
        """
        List available resources of this type
        """
        raise NotImplementedError

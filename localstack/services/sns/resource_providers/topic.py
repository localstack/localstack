from __future__ import annotations

from typing import Optional, TypedDict

from localstack.services.cloudformation.deployment_utils import generate_default_name
from localstack.services.cloudformation.resource_provider import (
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
    register_resource_provider,
)
from localstack.utils.common import canonicalize_bool_to_str


class SNSTopicProperties(TypedDict):
    ContentBasedDeduplication: Optional[bool]
    DataProtectionPolicy: Optional[dict]
    DisplayName: Optional[str]
    FifoTopic: Optional[bool]
    KmsMasterKeyId: Optional[str]
    SignatureVersion: Optional[str]
    Subscription: Optional[list]
    Tags: Optional[list]
    TopicArn: Optional[str]
    TopicName: Optional[str]
    TracingConfig: Optional[str]


class SNSTopicAllProperties(SNSTopicProperties):
    physical_resource_id: Optional[str] = None


@register_resource_provider
class SNSTopicProvider(ResourceProvider[SNSTopicAllProperties]):

    TYPE = "AWS::SNS::Topic"

    def create(
        self,
        request: ResourceRequest[SNSTopicAllProperties],
    ) -> ProgressEvent[SNSTopicAllProperties]:
        """
        Create a new resource.
        """
        model = request.desired_state

        # TODO: validations

        if model["physical_resource_id"] is None:
            # this is the first time this callback is invoked
            if not model["TopicName"]:
                model.Name = generate_default_name(request.stack_name, request.logical_resource_id)

            attributes = {}
            if model["ContentBasedDeduplication"]:
                attributes["ContentBasedDeduplication"] = canonicalize_bool_to_str(
                    model["ContentBasedDeduplication"]
                )
            if model["DisplayName"]:
                attributes["DisplayName"] = model["DisplayName"]
            if model["FifoTopic"] is not None:
                attributes["FifoTopic"] = canonicalize_bool_to_str(model["FifoTopic"])
            if model["KmsMasterKeyId"]:
                attributes["KmsMasterKeyId"] = model["KmsMasterKeyId"]

            try:
                request.aws_client_factory.sns.describe_topic(TopicArn=model["TopicArn"])
                return ProgressEvent(
                    status=OperationStatus.FAILED,
                    resource_model=model,
                    message="Topic already exists",
                )
            except request.aws_client_factory.sns.exceptions.NotFoundException:
                pass

                response = request.aws_client_factory.sns.create_topic(
                    Name=model["TopicName"],
                    Attributes=attributes,
                    Tags=model["Tags"],
                )
                model["TopicArn"] = response["TopicArn"]
                model["physical_resource_id"] = response["TopicArn"]

                return ProgressEvent(status=OperationStatus.IN_PROGRESS, resource_model=model)

        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

    def delete(
        self,
        request: ResourceRequest[SNSTopicAllProperties],
    ) -> ProgressEvent[SNSTopicAllProperties]:
        """
        Delete an existing resource.
        """
        model = request.desired_state
        request.aws_client_factory.sns.delete_topic(TopicArn=model["TopicArn"])
        return ProgressEvent(status=OperationStatus.SUCCESS, resource_model=model)

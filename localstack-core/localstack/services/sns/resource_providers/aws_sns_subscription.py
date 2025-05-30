# LocalStack Resource Provider Scaffolding v2
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, TypedDict

import localstack.services.cloudformation.provider_utils as util
from localstack import config
from localstack.aws.connect import ServiceLevelClientFactory
from localstack.services.cloudformation.resource_provider import (
    ConvertingInternalClientFactory,
    OperationStatus,
    ProgressEvent,
    ResourceProvider,
    ResourceRequest,
)


class SNSSubscriptionProperties(TypedDict):
    Protocol: Optional[str]
    TopicArn: Optional[str]
    DeliveryPolicy: Optional[dict]
    Endpoint: Optional[str]
    FilterPolicy: Optional[dict]
    FilterPolicyScope: Optional[str]
    Id: Optional[str]
    RawMessageDelivery: Optional[bool]
    RedrivePolicy: Optional[dict]
    Region: Optional[str]
    ReplayPolicy: Optional[dict]
    SubscriptionRoleArn: Optional[str]


REPEATED_INVOCATION = "repeated_invocation"


class SNSSubscriptionProvider(ResourceProvider[SNSSubscriptionProperties]):
    TYPE = "AWS::SNS::Subscription"  # Autogenerated. Don't change
    SCHEMA = util.get_schema_path(Path(__file__))  # Autogenerated. Don't change

    def create(
        self,
        request: ResourceRequest[SNSSubscriptionProperties],
    ) -> ProgressEvent[SNSSubscriptionProperties]:
        """
        Create a new resource.

        Primary identifier fields:
          - /properties/Id

        Required properties:
          - TopicArn
          - Protocol

        Create-only properties:
          - /properties/Endpoint
          - /properties/Protocol
          - /properties/TopicArn

        Read-only properties:
          - /properties/Id



        """
        model = request.desired_state
        sns = self._get_client(request).sns

        params = util.select_attributes(model=model, params=["TopicArn", "Protocol", "Endpoint"])

        attrs = [
            "DeliveryPolicy",
            "FilterPolicy",
            "FilterPolicyScope",
            "RawMessageDelivery",
            "RedrivePolicy",
        ]
        attributes = {a: self.attr_val(model[a]) for a in attrs if a in model}

        if attributes:
            params["Attributes"] = attributes

        result = sns.subscribe(**params)
        model["Id"] = result["SubscriptionArn"]

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def read(
        self,
        request: ResourceRequest[SNSSubscriptionProperties],
    ) -> ProgressEvent[SNSSubscriptionProperties]:
        """
        Fetch resource information


        """
        raise NotImplementedError

    def delete(
        self,
        request: ResourceRequest[SNSSubscriptionProperties],
    ) -> ProgressEvent[SNSSubscriptionProperties]:
        """
        Delete a resource


        """
        model = request.desired_state
        sns = request.aws_client_factory.sns

        sns.unsubscribe(SubscriptionArn=model["Id"])

        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    def update(
        self,
        request: ResourceRequest[SNSSubscriptionProperties],
    ) -> ProgressEvent[SNSSubscriptionProperties]:
        """
        Update a resource

        """
        model = request.desired_state
        model["Id"] = request.previous_state["Id"]
        sns = self._get_client(request).sns

        attrs = [
            "DeliveryPolicy",
            "FilterPolicy",
            "FilterPolicyScope",
            "RawMessageDelivery",
            "RedrivePolicy",
        ]
        for a in attrs:
            if a in model:
                sns.set_subscription_attributes(
                    SubscriptionArn=model["Id"],
                    AttributeName=a,
                    AttributeValue=self.attr_val(model[a]),
                )
        return ProgressEvent(
            status=OperationStatus.SUCCESS,
            resource_model=model,
            custom_context=request.custom_context,
        )

    @staticmethod
    def attr_val(val):
        return json.dumps(val) if isinstance(val, dict) else str(val)

    @staticmethod
    def _get_client(
        request: ResourceRequest[SNSSubscriptionProperties],
    ) -> ServiceLevelClientFactory:
        model = request.desired_state
        if subscription_region := model.get("Region"):
            # FIXME: this is hacky, maybe we should have access to the original parameters for the `aws_client_factory`
            #  as we now need to manually use them
            # Not all internal CloudFormation requests will be directed to the same region and account
            # maybe we could need to expose a proper client factory where we can override some parameters like the
            # Region
            factory = ConvertingInternalClientFactory(use_ssl=config.DISTRIBUTED_MODE)
            client_params = dict(request.aws_client_factory._client_creation_params)
            client_params["region_name"] = subscription_region
            service_factory = factory(**client_params)
        else:
            service_factory = request.aws_client_factory

        return service_factory

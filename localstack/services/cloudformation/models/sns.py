import json

from localstack.services.cloudformation.deployment_utils import (
    generate_default_name,
    is_none_or_empty_value,
)
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack
from localstack.utils.common import canonicalize_bool_to_str


def retrieve_topic_arn(sns_client, topic_name):
    topics = sns_client.list_topics()["Topics"]
    topic_arns = [t["TopicArn"] for t in topics if t["TopicArn"].endswith(":%s" % topic_name)]
    return topic_arns[0]


class SNSTopic(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SNS::Topic"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return aws_stack.sns_topic_arn(self.props["TopicName"])

    def fetch_state(self, stack_name, resources):
        topic_name = self.resolve_refs_recursively(stack_name, self.props["TopicName"], resources)
        topics = aws_stack.connect_to_service("sns").list_topics()
        result = list(
            filter(
                lambda item: item["TopicArn"].split(":")[-1] == topic_name,
                topics.get("Topics", []),
            )
        )
        return result[0] if result else None

    @staticmethod
    def add_defaults(resource, stack_name: str):
        role_name = resource.get("Properties", {}).get("TopicName")
        if not role_name:
            resource["Properties"]["TopicName"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

    @classmethod
    def get_deploy_templates(cls):
        def _create_params(params, *args, **kwargs):
            attributes = {}
            dedup = params.get("ContentBasedDeduplication")
            display_name = params.get("DisplayName")
            fifo_topic = params.get("FifoTopic")
            kms_master_key = params.get("KmsMasterKeyId")
            tags = params.get("Tags") or []
            topic_name = params.get("TopicName")
            if dedup is not None:
                attributes["ContentBasedDeduplication"] = canonicalize_bool_to_str(dedup)
            if display_name:
                attributes["DisplayName"] = display_name
            if fifo_topic is not None:
                attributes["FifoTopic"] = canonicalize_bool_to_str(fifo_topic)
            if kms_master_key:
                attributes["KmsMasterKeyId"] = kms_master_key
            result = {"Name": topic_name, "Attributes": attributes, "Tags": tags}
            return result

        def _topic_arn(params, resources, resource_id, **kwargs):
            resource = cls(resources[resource_id])
            return resource.physical_resource_id or resource.get_physical_resource_id()

        def _add_topics(resource_id, resources, resource_type, func, stack_name):
            sns = aws_stack.connect_to_service("sns")
            resource = cls(resources[resource_id])
            props = resource.props

            subscriptions = props.get("Subscription", [])
            for subscription in subscriptions:
                if is_none_or_empty_value(subscription):
                    continue
                endpoint = subscription["Endpoint"]
                topic_arn = retrieve_topic_arn(sns, props["TopicName"])
                sns.subscribe(
                    TopicArn=topic_arn, Protocol=subscription["Protocol"], Endpoint=endpoint
                )

        return {
            "create": [
                {
                    "function": "create_topic",
                    "parameters": _create_params,
                },
                {"function": _add_topics},
            ],
            "delete": {
                "function": "delete_topic",
                "parameters": {"TopicArn": _topic_arn},
            },
        }


class SNSSubscription(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SNS::Subscription"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("SubscriptionArn")

    def fetch_state(self, stack_name, resources):
        props = self.props
        topic_arn = props.get("TopicArn")
        topic_arn = self.resolve_refs_recursively(stack_name, topic_arn, resources)
        if topic_arn is None:
            return
        subs = aws_stack.connect_to_service("sns").list_subscriptions_by_topic(TopicArn=topic_arn)
        result = [
            sub
            for sub in subs["Subscriptions"]
            if props.get("Protocol") == sub["Protocol"] and props.get("Endpoint") == sub["Endpoint"]
        ]
        # TODO: use get_subscription_attributes to compare FilterPolicy
        return result[0] if result else None

    @staticmethod
    def get_deploy_templates():
        def sns_subscription_arn(params, resources, resource_id, **kwargs):
            resource = resources[resource_id]
            return resource["PhysicalResourceId"]

        def sns_subscription_params(params, **kwargs):
            def attr_val(val):
                return json.dumps(val) if isinstance(val, (dict, list)) else str(val)

            attrs = [
                "DeliveryPolicy",
                "FilterPolicy",
                "RawMessageDelivery",
                "RedrivePolicy",
            ]
            result = dict([(a, attr_val(params[a])) for a in attrs if a in params])
            return result

        return {
            "create": {
                "function": "subscribe",
                "parameters": {
                    "TopicArn": "TopicArn",
                    "Protocol": "Protocol",
                    "Endpoint": "Endpoint",
                    "Attributes": sns_subscription_params,
                },
            },
            "delete": {
                "function": "unsubscribe",
                "parameters": {"SubscriptionArn": sns_subscription_arn},
            },
        }

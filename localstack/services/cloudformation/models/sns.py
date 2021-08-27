import json

from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack
from localstack.utils.common import canonicalize_bool_to_str


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
    def get_deploy_templates():
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
            resource = SNSTopic(resources[resource_id])
            return resource.physical_resource_id or resource.get_physical_resource_id()

        return {
            # TODO: add second creation function to add topic subscriptions
            "create": {
                "function": "create_topic",
                "parameters": _create_params,
            },
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

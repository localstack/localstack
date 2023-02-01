import json

from botocore.exceptions import ClientError

from localstack.services.cloudformation.deployment_utils import (
    generate_default_name,
    is_none_or_empty_value,
)
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import arns, aws_stack
from localstack.utils.common import canonicalize_bool_to_str


class SNSTopic(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SNS::Topic"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return arns.sns_topic_arn(self.props["TopicName"])

    def fetch_state(self, stack_name, resources):
        topic_name = self.props["TopicName"]
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

        def _list_all_topics(sns_client):
            rs = sns_client.list_topics()
            topics = rs.get("Topics", [])
            key = rs.get("NextToken")

            while key and key != "":
                rs = sns_client.list_topics(NextToken=key)
                topics.extend(rs.get("Topics", []))
                key = rs.get("NextToken")

            return topics

        def _add_topics(resource_id, resources, resource_type, func, stack_name):
            sns_client = aws_stack.connect_to_service("sns")
            topics = _list_all_topics(sns_client)
            topics_by_name = {t["TopicArn"].split(":")[-1]: t for t in topics}

            resource = cls(resources[resource_id])
            props = resource.props

            subscriptions = props.get("Subscription", [])
            for subscription in subscriptions:
                if is_none_or_empty_value(subscription):
                    continue
                endpoint = subscription["Endpoint"]
                topic_arn = topics_by_name[props["TopicName"]]["TopicArn"]
                sns_client.subscribe(
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
            result = {a: attr_val(params[a]) for a in attrs if a in params}
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


class SNSTopicPolicy(GenericBaseModel):
    @classmethod
    def cloudformation_type(cls):
        return "AWS::SNS::TopicPolicy"

    def fetch_state(self, stack_name, resources):
        sns_client = aws_stack.connect_to_service("sns")
        result = {}
        props = self.props
        for topic_arn in props["Topics"]:
            result[topic_arn] = None
            attrs = sns_client.get_topic_attributes(TopicArn=topic_arn)
            policy = attrs["Attributes"].get("Policy")
            if not policy:
                continue
            policy = json.loads(policy)
            # check if content matches policy defined in the template
            if policy.get("Statement") == props["PolicyDocument"].get("Statement"):
                result[topic_arn] = policy
        if not all(list(result.values())):
            # return None if not all policies for all topics are properly deployed yet
            return None
        return result

    @classmethod
    def get_deploy_templates(cls):
        def _create(resource_id, resources, resource_type, func, stack_name):
            sns_client = aws_stack.connect_to_service("sns")
            resource = cls(resources[resource_id])
            props = resource.props

            resources[resource_id]["PhysicalResourceId"] = generate_default_name(
                stack_name, resource_id
            )

            policy = json.dumps(props["PolicyDocument"])
            for topic_arn in props["Topics"]:
                sns_client.set_topic_attributes(
                    TopicArn=topic_arn, AttributeName="Policy", AttributeValue=policy
                )

        def _delete(resource_id, resources, *args, **kwargs):
            sns_client = aws_stack.connect_to_service("sns")
            resource = cls(resources[resource_id])
            props = resource.props

            for topic_arn in props["Topics"]:
                try:
                    sns_client.set_topic_attributes(
                        TopicArn=topic_arn, AttributeName="Policy", AttributeValue=""
                    )
                except ClientError as err:
                    if "NotFound" not in err.response["Error"]["Code"]:
                        raise

        return {
            "create": {"function": _create},
            "delete": {
                "function": _delete,
            },
        }

import json

from botocore.exceptions import ClientError

from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import (
    generate_default_name,
    is_none_or_empty_value,
)
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.common import canonicalize_bool_to_str


class SNSTopic(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SNS::Topic"

    def fetch_state(self, stack_name, resources):
        topic_name = self.props["TopicName"]
        topics = connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).sns.list_topics()
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
        def _create_params(
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ) -> dict:
            attributes = {}
            dedup = properties.get("ContentBasedDeduplication")
            display_name = properties.get("DisplayName")
            fifo_topic = properties.get("FifoTopic")
            kms_master_key = properties.get("KmsMasterKeyId")
            tags = properties.get("Tags") or []
            topic_name = properties.get("TopicName")
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

        def _topic_arn(
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ) -> dict:
            provider = cls(account_id, region_name, resource)
            return provider.physical_resource_id

        def _list_all_topics(sns_client):
            rs = sns_client.list_topics()
            topics = rs.get("Topics", [])
            key = rs.get("NextToken")

            while key and key != "":
                rs = sns_client.list_topics(NextToken=key)
                topics.extend(rs.get("Topics", []))
                key = rs.get("NextToken")

            return topics

        def _add_topics(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: str,
            stack_name: str,
        ):
            sns_client = connect_to(aws_access_key_id=account_id, region_name=region_name).sns
            topics = _list_all_topics(sns_client)
            topics_by_name = {t["TopicArn"].split(":")[-1]: t for t in topics}

            provider = cls(account_id, region_name, resource)
            props = provider.props

            subscriptions = props.get("Subscription", [])
            for subscription in subscriptions:
                if is_none_or_empty_value(subscription):
                    continue
                endpoint = subscription["Endpoint"]
                topic_arn = topics_by_name[props["TopicName"]]["TopicArn"]
                sns_client.subscribe(
                    TopicArn=topic_arn, Protocol=subscription["Protocol"], Endpoint=endpoint
                )

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = result["TopicArn"]
            resource["Properties"]["TopicArn"] = result["TopicArn"]

        return {
            "create": [
                {
                    "function": "create_topic",
                    "parameters": _create_params,
                    "result_handler": _handle_result,
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

    def fetch_state(self, stack_name, resources):
        props = self.props
        topic_arn = props.get("TopicArn")
        if topic_arn is None:
            return
        subs = connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).sns.list_subscriptions_by_topic(TopicArn=topic_arn)
        result = [
            sub
            for sub in subs["Subscriptions"]
            if props.get("Protocol") == sub["Protocol"] and props.get("Endpoint") == sub["Endpoint"]
        ]
        # TODO: use get_subscription_attributes to compare FilterPolicy
        return result[0] if result else None

    @staticmethod
    def get_deploy_templates():
        def sns_subscription_arn(
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ) -> dict:
            return resource["PhysicalResourceId"]

        def sns_subscription_params(
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ) -> dict:
            def attr_val(val):
                return json.dumps(val) if isinstance(val, (dict, list)) else str(val)

            attrs = [
                "DeliveryPolicy",
                "FilterPolicy",
                "FilterPolicyScope",
                "RawMessageDelivery",
                "RedrivePolicy",
            ]
            result = {a: attr_val(properties[a]) for a in attrs if a in properties}
            return result

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = result["SubscriptionArn"]

        return {
            "create": {
                "function": "subscribe",
                "parameters": {
                    "TopicArn": "TopicArn",
                    "Protocol": "Protocol",
                    "Endpoint": "Endpoint",
                    "Attributes": sns_subscription_params,
                },
                "result_handler": _handle_result,
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
        sns_client = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).sns
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
        def _create(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            sns_client = connect_to(aws_access_key_id=account_id, region_name=region_name).sns
            provider = cls(account_id, region_name, resource)
            props = provider.props

            resource["PhysicalResourceId"] = generate_default_name(stack_name, logical_resource_id)

            policy = json.dumps(props["PolicyDocument"])
            for topic_arn in props["Topics"]:
                sns_client.set_topic_attributes(
                    TopicArn=topic_arn, AttributeName="Policy", AttributeValue=policy
                )

        def _delete(
            account_id: str,
            region_name: str,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ):
            sns_client = connect_to(aws_access_key_id=account_id, region_name=region_name).sns
            provider = cls(account_id, region_name, resource)
            props = provider.props

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

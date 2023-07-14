import json
import logging

from botocore.exceptions import ClientError

from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import (
    generate_default_name,
    params_list_to_dict,
    params_select_attributes,
)
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import arns
from localstack.utils.common import short_uid

LOG = logging.getLogger(__name__)


class QueuePolicy(GenericBaseModel):
    @classmethod
    def cloudformation_type(cls):
        return "AWS::SQS::QueuePolicy"

    def fetch_state(self, stack_name, resources):
        if self.resource_json.get("PhysicalResourceId"):
            return {"something": "something"}  # gotta return <something> since {} is falsey :)

    @classmethod
    def get_deploy_templates(cls):
        def _create(logical_resource_id: str, resource: dict, stack_name: str):
            sqs_client = connect_to().sqs
            resource_provider = cls(resource)
            props = resource_provider.props

            resource["PhysicalResourceId"] = "%s-%s-%s" % (
                stack_name,
                logical_resource_id,
                short_uid(),
            )

            policy = json.dumps(props["PolicyDocument"])
            for queue in props["Queues"]:
                sqs_client.set_queue_attributes(QueueUrl=queue, Attributes={"Policy": policy})

        def _delete(logical_resource_id: str, resource: dict, stack_name: str):
            sqs_client = connect_to().sqs
            resource_provider = cls(resource)
            props = resource_provider.props

            for queue in props["Queues"]:
                try:
                    sqs_client.set_queue_attributes(QueueUrl=queue, Attributes={"Policy": ""})
                except ClientError as err:
                    if "AWS.SimpleQueueService.NonExistentQueue" != err.response["Error"]["Code"]:
                        raise

        return {
            "create": {"function": _create},
            "delete": {
                "function": _delete,
            },
        }


class SQSQueue(GenericBaseModel):
    @classmethod
    def cloudformation_type(cls):
        return "AWS::SQS::Queue"

    def get_cfn_attribute(self, attribute_name):
        if attribute_name == "Arn":
            return arns.sqs_queue_arn(self.properties["QueueName"])
        return super().get_cfn_attribute(attribute_name)

    def fetch_state(self, stack_name, resources):
        queue_name = self.props["QueueName"]
        sqs_client = connect_to().sqs
        queues = sqs_client.list_queues()
        result = list(
            filter(
                lambda item:
                # TODO possibly find a better way to compare resource_id with queue URLs
                item.endswith("/%s" % queue_name),
                queues.get("QueueUrls", []),
            )
        )
        if not result:
            return None
        result = sqs_client.get_queue_attributes(QueueUrl=result[0], AttributeNames=["All"])[
            "Attributes"
        ]
        result["Arn"] = result["QueueArn"]
        return result

    @staticmethod
    def add_defaults(resource, stack_name: str):
        role_name = resource.get("Properties", {}).get("QueueName")

        if not role_name:
            resource["Properties"]["QueueName"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )
            if resource["Properties"].get("FifoQueue"):
                resource["Properties"]["QueueName"] += ".fifo"

    @classmethod
    def get_deploy_templates(cls):
        def _queue_url(properties: dict, logical_resource_id: str, resource: dict, stack_name: str):
            provider = cls(resource)
            queue_url = provider.physical_resource_id or properties.get("QueueUrl")
            if queue_url:
                return queue_url
            return arns.sqs_queue_url_for_arn(properties["QueueArn"])

        def _handle_result(result: dict, logical_resource_id: str, resource: dict):
            resource["PhysicalResourceId"] = result["QueueUrl"]

        return {
            "create": {
                "function": "create_queue",
                "parameters": {
                    "QueueName": "QueueName",
                    "Attributes": params_select_attributes(
                        "ContentBasedDeduplication",
                        "DelaySeconds",
                        "FifoQueue",
                        "MaximumMessageSize",
                        "MessageRetentionPeriod",
                        "VisibilityTimeout",
                        "RedrivePolicy",
                        "ReceiveMessageWaitTimeSeconds",
                    ),
                    "tags": params_list_to_dict("Tags"),
                },
                "result_handler": _handle_result,
            },
            "delete": {
                "function": "delete_queue",
                "parameters": {"QueueUrl": _queue_url},
            },
        }

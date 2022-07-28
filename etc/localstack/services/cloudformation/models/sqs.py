import json
import logging

from botocore.exceptions import ClientError

from localstack.services.cloudformation.deployment_utils import (
    PLACEHOLDER_RESOURCE_NAME,
    generate_default_name,
    params_list_to_dict,
    params_select_attributes,
)
from localstack.services.cloudformation.service_models import (
    DependencyNotYetSatisfied,
    GenericBaseModel,
)
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid

LOG = logging.getLogger(__name__)


class QueuePolicy(GenericBaseModel):
    @classmethod
    def cloudformation_type(cls):
        return "AWS::SQS::QueuePolicy"

    @classmethod
    def get_deploy_templates(cls):
        def _create(resource_id, resources, resource_type, func, stack_name):
            sqs_client = aws_stack.connect_to_service("sqs")
            resource = cls(resources[resource_id])
            props = resource.props

            # TODO: generalize/support in get_physical_resource_id
            resources[resource_id]["PhysicalResourceId"] = "%s-%s-%s" % (
                stack_name,
                resource_id,
                short_uid(),
            )

            policy = json.dumps(props["PolicyDocument"])
            for queue in props["Queues"]:
                sqs_client.set_queue_attributes(QueueUrl=queue, Attributes={"Policy": policy})

        def _delete(resource_id, resources, *args, **kwargs):
            sqs_client = aws_stack.connect_to_service("sqs")
            resource = cls(resources[resource_id])
            props = resource.props

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

    def get_resource_name(self):
        return self.props.get("QueueName")

    def get_physical_resource_id(self, attribute=None, **kwargs):
        queue_url = None
        props = self.props
        try:
            queue_url = aws_stack.get_sqs_queue_url(props.get("QueueName"))
        except Exception as e:
            if "NonExistentQueue" in str(e):
                raise DependencyNotYetSatisfied(
                    resource_ids=self.resource_id, message="Unable to get queue: %s" % e
                )
        if attribute == "Arn":
            return aws_stack.sqs_queue_arn(props.get("QueueName"))
        return queue_url

    def fetch_state(self, stack_name, resources):
        queue_name = self.resolve_refs_recursively(stack_name, self.props["QueueName"], resources)
        sqs_client = aws_stack.connect_to_service("sqs")
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
        def _queue_url(params, resources, resource_id, **kwargs):
            resource = cls(resources[resource_id])
            props = resource.props
            queue_url = resource.physical_resource_id or props.get("QueueUrl")
            if queue_url:
                return queue_url
            return aws_stack.sqs_queue_url_for_arn(props["QueueArn"])

        return {
            "create": {
                "function": "create_queue",
                "parameters": {
                    "QueueName": ["QueueName", PLACEHOLDER_RESOURCE_NAME],
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
            },
            "delete": {
                "function": "delete_queue",
                "parameters": {"QueueUrl": _queue_url},
            },
        }

from moto.sqs.models import Queue as MotoQueue

from localstack.services.cloudformation.deployment_utils import (
    PLACEHOLDER_RESOURCE_NAME,
    params_list_to_dict,
    params_select_attributes,
)
from localstack.services.cloudformation.service_models import (
    DependencyNotYetSatisfied,
    GenericBaseModel,
)
from localstack.utils.aws import aws_stack


class QueuePolicy(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SQS::QueuePolicy"

    # TODO: add deployment methods


class SQSQueue(GenericBaseModel, MotoQueue):
    @staticmethod
    def cloudformation_type():
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
    def get_deploy_templates():
        def _queue_url(params, resources, resource_id, **kwargs):
            resource = SQSQueue(resources[resource_id])
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

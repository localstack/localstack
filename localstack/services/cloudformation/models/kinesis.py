from localstack.services.cloudformation.deployment_utils import generate_default_name
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack


class KinesisStreamConsumer(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Kinesis::StreamConsumer"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("ConsumerARN")

    def fetch_state(self, stack_name, resources):
        props = self.props
        stream_arn = self.resolve_refs_recursively(stack_name, props["StreamARN"], resources)
        result = aws_stack.connect_to_service("kinesis").list_stream_consumers(StreamARN=stream_arn)
        result = [r for r in result["Consumers"] if r["ConsumerName"] == props["ConsumerName"]]
        return (result or [None])[0]

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {"function": "register_stream_consumer"},
            "delete": {"function": "deregister_stream_consumer"},
        }


class KinesisStream(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Kinesis::Stream"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return aws_stack.kinesis_stream_arn(self.props.get("Name"))

    def fetch_state(self, stack_name, resources):
        stream_name = self.resolve_refs_recursively(stack_name, self.props["Name"], resources)
        result = aws_stack.connect_to_service("kinesis").describe_stream(StreamName=stream_name)
        return result

    @staticmethod
    def add_defaults(resource, stack_name: str):
        name = resource["Properties"].get("Name")
        if not name:
            resource["Properties"]["Name"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

    @staticmethod
    def get_deploy_templates():
        def get_delete_params(params, **kwargs):
            return {"StreamName": params["Name"], "EnforceConsumerDeletion": True}

        return {
            "create": {
                "function": "create_stream",
                "parameters": {"StreamName": "Name", "ShardCount": "ShardCount"},
                "defaults": {"ShardCount": 1},
            },
            "delete": {"function": "delete_stream", "parameters": get_delete_params},
        }

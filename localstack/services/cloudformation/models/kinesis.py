from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import generate_default_name
from localstack.services.cloudformation.service_models import GenericBaseModel


class KinesisStreamConsumer(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Kinesis::StreamConsumer"

    def fetch_state(self, stack_name, resources):
        props = self.props
        stream_arn = props["StreamARN"]
        result = connect_to().kinesis.list_stream_consumers(StreamARN=stream_arn)
        result = [r for r in result["Consumers"] if r["ConsumerName"] == props["ConsumerName"]]
        return (result or [None])[0]

    @staticmethod
    def get_deploy_templates():
        def _handle_result(result, resource_id, resources, resource_type):
            resource = resources[resource_id]
            resource["PhysicalResourceId"] = result["Consumer"]["ConsumerARN"]
            resource["Properties"]["ConsumerARN"] = result["Consumer"]["ConsumerARN"]
            resource["Properties"]["ConsumerCreationTimestamp"] = result["Consumer"][
                "ConsumerCreationTimestamp"
            ]
            resource["Properties"]["ConsumerStatus"] = result["Consumer"]["ConsumerStatus"]

        return {
            "create": {"function": "register_stream_consumer", "result_handler": _handle_result},
            "delete": {"function": "deregister_stream_consumer"},
        }


class KinesisStream(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Kinesis::Stream"

    def fetch_state(self, stack_name, resources):
        stream_name = self.props["Name"]
        result = connect_to().kinesis.describe_stream(StreamName=stream_name)
        return result

    @staticmethod
    def add_defaults(resource, stack_name: str):
        props = resource["Properties"]
        name = props.get("Name")
        if not name:
            props["Name"] = generate_default_name(stack_name, resource["LogicalResourceId"])

        shard_count = props.get("ShardCount")
        if shard_count is None:
            props["ShardCount"] = 1

    @staticmethod
    def get_deploy_templates():
        def get_delete_params(
            properties: dict, logical_resource_id: str, resource: dict, stack_name: str
        ) -> dict:
            return {"StreamName": properties["Name"], "EnforceConsumerDeletion": True}

        def _handle_result(result: dict, logical_resource_id: str, resource: dict):
            client = connect_to().kinesis
            stream_name = resource["Properties"]["Name"]

            description = client.describe_stream(StreamName=stream_name)
            while description["StreamDescription"]["StreamStatus"] != "ACTIVE":
                description = client.describe_stream(StreamName=stream_name)

            resource["PhysicalResourceId"] = stream_name
            resource["Properties"]["Arn"] = description["StreamDescription"]["StreamARN"]

        return {
            "create": {
                "function": "create_stream",
                "parameters": {"StreamName": "Name", "ShardCount": "ShardCount"},
                "result_handler": _handle_result,
            },
            "delete": {"function": "delete_stream", "parameters": get_delete_params},
        }

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
        result = connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).kinesis.list_stream_consumers(StreamARN=stream_arn)
        result = [r for r in result["Consumers"] if r["ConsumerName"] == props["ConsumerName"]]
        return (result or [None])[0]

    @staticmethod
    def get_deploy_templates():
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
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

    # def fetch_state(self, stack_name, resources):
    #     stream_name = self.props["Name"]
    #     result = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).kinesis.describe_stream(StreamName=stream_name)
    #     return result

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
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ) -> dict:
            return {"StreamName": properties["Name"], "EnforceConsumerDeletion": True}

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            client = connect_to(aws_access_key_id=account_id, region_name=region_name).kinesis
            stream_name = resource["Properties"]["Name"]

            client.get_waiter("stream_exists").wait(StreamName=stream_name)

            description = client.describe_stream(StreamName=stream_name)
            resource["Properties"]["Arn"] = description["StreamDescription"]["StreamARN"]
            resource["PhysicalResourceId"] = stream_name

        return {
            "create": {
                "function": "create_stream",
                "parameters": {"StreamName": "Name", "ShardCount": "ShardCount"},
                "result_handler": _handle_result,
            },
            "delete": {"function": "delete_stream", "parameters": get_delete_params},
        }

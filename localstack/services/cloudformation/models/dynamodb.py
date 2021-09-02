from localstack.services.cloudformation.deployment_utils import PLACEHOLDER_AWS_NO_VALUE
from localstack.services.cloudformation.service_models import REF_ID_ATTRS, GenericBaseModel
from localstack.utils import common
from localstack.utils.aws import aws_stack


def get_ddb_provisioned_throughput(params, **kwargs):
    args = params.get("ProvisionedThroughput")
    if args == PLACEHOLDER_AWS_NO_VALUE:
        return {}
    if args:
        if isinstance(args["ReadCapacityUnits"], str):
            args["ReadCapacityUnits"] = int(args["ReadCapacityUnits"])
        if isinstance(args["WriteCapacityUnits"], str):
            args["WriteCapacityUnits"] = int(args["WriteCapacityUnits"])
    return args


def get_ddb_global_sec_indexes(params, **kwargs):
    args = params.get("GlobalSecondaryIndexes")
    if args:
        for index in args:
            provisoned_throughput = index["ProvisionedThroughput"]
            if isinstance(provisoned_throughput["ReadCapacityUnits"], str):
                provisoned_throughput["ReadCapacityUnits"] = int(
                    provisoned_throughput["ReadCapacityUnits"]
                )
            if isinstance(provisoned_throughput["WriteCapacityUnits"], str):
                provisoned_throughput["WriteCapacityUnits"] = int(
                    provisoned_throughput["WriteCapacityUnits"]
                )
    return args


def get_ddb_kinesis_stream_specification(params, **kwargs):
    args = params.get("KinesisStreamSpecification")
    if args:
        args["TableName"] = params["TableName"]
    return args


class DynamoDBTable(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::DynamoDB::Table"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        table_name = self.props.get("TableName")
        if attribute in REF_ID_ATTRS:
            return table_name
        return aws_stack.dynamodb_table_arn(table_name)

    def fetch_state(self, stack_name, resources):
        table_name = self.props.get("TableName") or self.resource_id
        table_name = self.resolve_refs_recursively(stack_name, table_name, resources)
        return aws_stack.connect_to_service("dynamodb").describe_table(TableName=table_name)

    @staticmethod
    def get_deploy_templates():
        return {
            "create": [
                {
                    "function": "create_table",
                    "parameters": {
                        "TableName": "TableName",
                        "AttributeDefinitions": "AttributeDefinitions",
                        "KeySchema": "KeySchema",
                        "ProvisionedThroughput": get_ddb_provisioned_throughput,
                        "LocalSecondaryIndexes": "LocalSecondaryIndexes",
                        "GlobalSecondaryIndexes": get_ddb_global_sec_indexes,
                        "StreamSpecification": lambda params, **kwargs: (
                            common.merge_dicts(
                                params.get("StreamSpecification"),
                                {"StreamEnabled": True},
                                default=None,
                            )
                        ),
                    },
                    "defaults": {
                        "ProvisionedThroughput": {
                            "ReadCapacityUnits": 5,
                            "WriteCapacityUnits": 5,
                        }
                    },
                },
                {
                    "function": "enable_kinesis_streaming_destination",
                    "parameters": get_ddb_kinesis_stream_specification,
                },
            ],
            "delete": {
                "function": "delete_table",
                "parameters": {"TableName": "TableName"},
            },
        }

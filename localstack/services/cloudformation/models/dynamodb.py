from localstack.services.cloudformation.deployment_utils import (
    PLACEHOLDER_AWS_NO_VALUE,
    generate_default_name,
)
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils import common
from localstack.utils.aws import aws_stack


def get_ddb_provisioned_throughput(params, **kwargs):
    args = params.get("ProvisionedThroughput")
    if args == PLACEHOLDER_AWS_NO_VALUE:
        return {}
    is_ondemand = params.get("BillingMode") == "PAY_PER_REQUEST"
    if is_ondemand and args is None:
        return
    if args:
        if isinstance(args["ReadCapacityUnits"], str):
            args["ReadCapacityUnits"] = int(args["ReadCapacityUnits"])
        if isinstance(args["WriteCapacityUnits"], str):
            args["WriteCapacityUnits"] = int(args["WriteCapacityUnits"])
    return args


def get_ddb_global_sec_indexes(params: dict, **kwargs) -> list | None:
    args: list = params.get("GlobalSecondaryIndexes")
    is_ondemand = params.get("BillingMode") == "PAY_PER_REQUEST"
    if not args:
        return

    for index in args:
        # we ignore ContributorInsightsSpecification as not supported yet in DynamoDB and CloudWatch
        index.pop("ContributorInsightsSpecification", None)
        provisioned_throughput = index.get("ProvisionedThroughput")
        if is_ondemand and provisioned_throughput is None:
            pass  # optional for API calls
        elif provisioned_throughput is not None:
            # convert types
            if isinstance((read_units := provisioned_throughput["ReadCapacityUnits"]), str):
                provisioned_throughput["ReadCapacityUnits"] = int(read_units)
            if isinstance((write_units := provisioned_throughput["WriteCapacityUnits"]), str):
                provisioned_throughput["WriteCapacityUnits"] = int(write_units)
        else:
            raise Exception("Can't specify ProvisionedThroughput with PAY_PER_REQUEST")
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

    def get_cfn_attribute(self, attribute_name):
        actual_attribute = "LatestStreamArn" if attribute_name == "StreamArn" else attribute_name
        value = self.props.get("Table", {}).get(actual_attribute)
        if value:
            return value
        #
        # if attribute_name == "Arn":
        #     return self.props.get("TableArn")
        return super(DynamoDBTable, self).get_cfn_attribute(attribute_name)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        if attribute == "Arn":
            return self.props.get("Table", {}).get("TableArn")
        return self.props.get("TableName")

    def fetch_state(self, stack_name, resources):
        table_name = self.props.get("TableName") or self.logical_resource_id
        table_name = self.resolve_refs_recursively(stack_name, table_name, resources)
        return aws_stack.connect_to_service("dynamodb").describe_table(TableName=table_name)

    @staticmethod
    def add_defaults(resource, stack_name: str):
        is_pay_per_request = resource.get("Properties", {}).get("BillingMode") == "PAY_PER_REQUEST"

        if not is_pay_per_request:
            resource["Properties"]["ProvisionedThroughput"] = {
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 5,
            }

        table_name = resource.get("Properties", {}).get("TableName")
        resource["Properties"]["TableName"] = table_name or generate_default_name(
            stack_name, resource["LogicalResourceId"]
        )

    @classmethod
    def get_deploy_templates(cls):
        return {
            "create": [
                {
                    "function": "create_table",
                    "parameters": {
                        "TableName": "TableName",
                        "AttributeDefinitions": "AttributeDefinitions",
                        "KeySchema": "KeySchema",
                        "BillingMode": "BillingMode",
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

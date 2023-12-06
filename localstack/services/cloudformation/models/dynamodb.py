from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import (
    PLACEHOLDER_AWS_NO_VALUE,
    generate_default_name,
)
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils import common


def get_ddb_provisioned_throughput(
    account_id: str,
    region_name: str,
    properties: dict,
    logical_resource_id: str,
    resource: dict,
    stack_name: str,
) -> dict | None:
    # see https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dynamodb-table.html#cfn-dynamodb-table-provisionedthroughput
    args = properties.get("ProvisionedThroughput")
    if args == PLACEHOLDER_AWS_NO_VALUE:
        return None
    is_ondemand = properties.get("BillingMode") == "PAY_PER_REQUEST"
    # if the BillingMode is set to PAY_PER_REQUEST, you cannot specify ProvisionedThroughput
    # if the BillingMode is set to PROVISIONED (default), you have to specify ProvisionedThroughput

    if args is None:
        if is_ondemand:
            # do not return default value if it's on demand
            return

        # return default values if it's not on demand
        return {
            "ReadCapacityUnits": 5,
            "WriteCapacityUnits": 5,
        }

    if isinstance(args["ReadCapacityUnits"], str):
        args["ReadCapacityUnits"] = int(args["ReadCapacityUnits"])
    if isinstance(args["WriteCapacityUnits"], str):
        args["WriteCapacityUnits"] = int(args["WriteCapacityUnits"])

    return args


def get_ddb_global_sec_indexes(
    account_id: str,
    region_name: str,
    properties: dict,
    logical_resource_id: str,
    resource: dict,
    stack_name: str,
) -> list | None:
    args: list = properties.get("GlobalSecondaryIndexes")
    is_ondemand = properties.get("BillingMode") == "PAY_PER_REQUEST"
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


def get_ddb_kinesis_stream_specification(
    account_id: str,
    region_name: str,
    properties: dict,
    logical_resource_id: str,
    resource: dict,
    stack_name: str,
) -> dict:
    args = properties.get("KinesisStreamSpecification")
    if args:
        args["TableName"] = properties["TableName"]
    return args


class DynamoDBTable(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::DynamoDB::Table"

    def fetch_state(self, stack_name, resources):
        table_name = self.props.get("TableName") or self.logical_resource_id
        return connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).dynamodb.describe_table(TableName=table_name)

    @staticmethod
    def add_defaults(resource, stack_name: str):
        table_name = resource.get("Properties", {}).get("TableName")
        resource["Properties"]["TableName"] = table_name or generate_default_name(
            stack_name, resource["LogicalResourceId"]
        )

    @classmethod
    def get_deploy_templates(cls):
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            table_name = result["TableDescription"]["TableName"]
            connect_to(aws_access_key_id=account_id, region_name=region_name).dynamodb.get_waiter(
                "table_exists"
            ).wait(TableName=table_name)
            desc_table = connect_to(
                aws_access_key_id=account_id, region_name=region_name
            ).dynamodb.describe_table(TableName=table_name)
            resource["Properties"]["Arn"] = desc_table["Table"]["TableArn"]
            if stream_arn := desc_table["Table"].get("LatestStreamArn"):
                resource["Properties"]["StreamArn"] = stream_arn
            resource["PhysicalResourceId"] = table_name

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
                        "StreamSpecification": lambda account_id, region_name, properties, logical_resource_id, *args, **kwargs: (
                            common.merge_dicts(
                                properties.get("StreamSpecification"),
                                {"StreamEnabled": True},
                                default=None,
                            )
                        ),
                        "Tags": "Tags",
                    },
                    "result_handler": _handle_result,
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

from localstack.services.cloudformation.deployment_utils import PLACEHOLDER_AWS_NO_VALUE
from localstack.services.cloudformation.service_models import REF_ID_ATTRS, GenericBaseModel
from localstack.utils import common
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid


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


def get_ddb_global_sec_indexes(params, **kwargs):
    args = params.get("GlobalSecondaryIndexes")
    is_ondemand = params.get("BillingMode") == "PAY_PER_REQUEST"
    if args:
        for index in args:
            provisioned_throughput = index.get("ProvisionedThroughput")
            if is_ondemand and provisioned_throughput is None:
                pass  # optional for API calls
            elif provisioned_throughput is not None:
                # convert types
                if isinstance(provisioned_throughput["ReadCapacityUnits"], str):
                    provisioned_throughput["ReadCapacityUnits"] = int(
                        provisioned_throughput["ReadCapacityUnits"]
                    )
                if isinstance(provisioned_throughput["WriteCapacityUnits"], str):
                    provisioned_throughput["WriteCapacityUnits"] = int(
                        provisioned_throughput["WriteCapacityUnits"]
                    )
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
        return super(DynamoDBTable, self).get_cfn_attribute(attribute_name)

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
    def add_defaults(resource, stack_name: str):
        is_pay_per_request = resource.get("Properties", {}).get("BillingMode") == "PAY_PER_REQUEST"
        if not is_pay_per_request:
            resource["Properties"]["ProvisionedThroughput"] = {
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 5,
            }

    @classmethod
    def get_deploy_templates(cls):
        def _pre_create(resource_id, resources, resource_type, func, stack_name):
            resource = resources[resource_id]
            props = resource["Properties"]

            def _generate_res_name():  # TODO: generalize
                return "%s-%s-%s" % (stack_name, resource_id, short_uid())

            props["TableName"] = props.get("TableName") or _generate_res_name()

        return {
            "create": [
                {"function": _pre_create},
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

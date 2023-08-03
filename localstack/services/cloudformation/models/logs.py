from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import generate_default_name
from localstack.services.cloudformation.service_models import GenericBaseModel


class LogsLogGroup(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Logs::LogGroup"

    def fetch_state(self, stack_name, resources):
        group_name = self.props.get("LogGroupName")
        logs = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).logs
        groups = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"]
        return ([g for g in groups if g["logGroupName"] == group_name] or [None])[0]

    @staticmethod
    def add_defaults(resource, stack_name: str):
        name = resource.get("Properties", {}).get("LogGroupName")
        if not name:
            resource["Properties"]["LogGroupName"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

    @staticmethod
    def get_deploy_templates():
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            log_group_name = resource["Properties"]["LogGroupName"]
            describe_result = connect_to(
                aws_access_key_id=account_id, region_name=region_name
            ).logs.describe_log_groups(logGroupNamePrefix=log_group_name)
            resource["Properties"]["Arn"] = describe_result["logGroups"][0]["arn"]
            resource["PhysicalResourceId"] = log_group_name

        return {
            "create": {
                "function": "create_log_group",
                "parameters": {"logGroupName": "LogGroupName"},
                "result_handler": _handle_result,
            },
            "delete": {
                "function": "delete_log_group",
                "parameters": {"logGroupName": "LogGroupName"},
            },
        }


class LogsLogStream(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Logs::LogStream"

    def fetch_state(self, stack_name, resources):
        group_name = self.props.get("LogGroupName")
        stream_name = self.props.get("LogStreamName")
        logs = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).logs
        streams = logs.describe_log_streams(
            logGroupName=group_name, logStreamNamePrefix=stream_name
        )["logStreams"]
        return ([s for s in streams if s["logStreamName"] == stream_name] or [None])[0]

    @staticmethod
    def add_defaults(resource, stack_name: str):
        name = resource.get("Properties", {}).get("LogStreamName")
        if not name:
            resource["Properties"]["LogStreamName"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

    @staticmethod
    def get_deploy_templates():
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = resource["Properties"]["LogStreamName"]

        return {
            "create": {
                "function": "create_log_stream",
                "parameters": {"logGroupName": "LogGroupName", "logStreamName": "LogStreamName"},
                "result_handler": _handle_result,
            },
            "delete": {
                "function": "delete_log_stream",
                "parameters": {"logGroupName": "LogGroupName", "logStreamName": "LogStreamName"},
            },
        }


class LogsSubscriptionFilter(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Logs::SubscriptionFilter"

    def fetch_state(self, stack_name, resources):
        props = self.props
        group_name = props.get("LogGroupName")
        filter_pattern = props.get("FilterPattern")
        logs = connect_to(aws_access_key_id=self.account_id, region_name=self.region_name).logs
        groups = logs.describe_subscription_filters(logGroupName=group_name)["subscriptionFilters"]
        groups = [g for g in groups if g.get("filterPattern") == filter_pattern]
        return (groups or [None])[0]

    @staticmethod
    def get_deploy_templates():
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = resource["Properties"]["LogGroupName"]

        return {
            "create": {
                "function": "put_subscription_filter",
                "parameters": {
                    "logGroupName": "LogGroupName",
                    "filterName": "LogGroupName",  # there can only be one filter associated with a log group
                    "filterPattern": "FilterPattern",
                    "destinationArn": "DestinationArn",
                },
                "result_handler": _handle_result,
            },
            "delete": {
                "function": "delete_subscription_filter",
                "parameters": {
                    "logGroupName": "LogGroupName",
                    "filterName": "LogGroupName",
                },
            },
        }

from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack


class LogsLogGroup(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Logs::LogGroup"

    def get_cfn_attribute(self, attribute_name):
        props = self.props
        if attribute_name == "Arn":
            return props.get("arn")
        return super(LogsLogGroup, self).get_cfn_attribute(attribute_name)

    def get_physical_resource_id(self, attribute=None, **kwargs):
        if attribute == "Arn":
            return self.get_cfn_attribute("Arn")
        return self.props.get("LogGroupName")

    def fetch_state(self, stack_name, resources):
        group_name = self.props.get("LogGroupName")
        group_name = self.resolve_refs_recursively(stack_name, group_name, resources)
        logs = aws_stack.connect_to_service("logs")
        groups = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"]
        return ([g for g in groups if g["logGroupName"] == group_name] or [None])[0]

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "create_log_group",
                "parameters": {"logGroupName": "LogGroupName"},
            },
            "delete": {
                "function": "delete_log_group",
                "parameters": {"logGroupName": "LogGroupName"},
            },
        }


class LogsSubscriptionFilter(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Logs::SubscriptionFilter"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("LogGroupName")

    def fetch_state(self, stack_name, resources):
        props = self.props
        group_name = self.resolve_refs_recursively(stack_name, props.get("LogGroupName"), resources)
        filter_pattern = self.resolve_refs_recursively(
            stack_name, props.get("FilterPattern"), resources
        )
        logs = aws_stack.connect_to_service("logs")
        groups = logs.describe_subscription_filters(logGroupName=group_name)["subscriptionFilters"]
        groups = [g for g in groups if g.get("filterPattern") == filter_pattern]
        return (groups or [None])[0]

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "put_subscription_filter",
                "parameters": {
                    "logGroupName": "LogGroupName",
                    "filterName": "LogGroupName",  # there can only be one filter associated with a log group
                    "filterPattern": "FilterPattern",
                    "destinationArn": "DestinationArn",
                },
            },
            "delete": {
                "function": "delete_subscription_filter",
                "parameters": {
                    "logGroupName": "LogGroupName",
                    "filterName": "LogGroupName",
                },
            },
        }

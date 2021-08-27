from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack


class CloudWatchAlarm(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::CloudWatch::Alarm"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("AlarmName")

    def _response_name(self):
        return "MetricAlarms"

    @classmethod
    def _create_function_name(self):
        return "put_metric_alarm"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("cloudwatch")
        alarm_name = self.resolve_refs_recursively(stack_name, self.props["AlarmName"], resources)
        result = client.describe_alarms(AlarmNames=[alarm_name]).get(self._response_name(), [])
        return (result or [None])[0]

    @classmethod
    def get_deploy_templates(cls):
        def get_delete_params(params, **kwargs):
            return {"AlarmNames": [params["AlarmName"]]}

        return {
            "create": {"function": cls._create_function_name()},
            "delete": {"function": "delete_alarms", "parameters": get_delete_params},
        }


class CloudWatchCompositeAlarm(CloudWatchAlarm):
    @staticmethod
    def cloudformation_type():
        return "AWS::CloudWatch::CompositeAlarm"

    def _response_name(self):
        return "CompositeAlarms"

    @classmethod
    def _create_function_name(self):
        return "put_composite_alarm"

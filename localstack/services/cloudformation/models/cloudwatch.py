from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import generate_default_name
from localstack.services.cloudformation.service_models import GenericBaseModel


class CloudWatchAlarm(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::CloudWatch::Alarm"

    def _response_name(self):
        return "MetricAlarms"

    @classmethod
    def _create_function_name(self):
        return "put_metric_alarm"

    def fetch_state(self, stack_name, resources):
        client = connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).cloudwatch
        alarm_name = self.props["AlarmName"]
        result = client.describe_alarms(AlarmNames=[alarm_name]).get(self._response_name(), [])
        return (result or [None])[0]

    @staticmethod
    def add_defaults(resource, stack_name: str):
        role_name = resource.get("Properties", {}).get("AlarmName")
        if not role_name:
            resource["Properties"]["AlarmName"] = generate_default_name(
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
            alarms = connect_to(
                aws_access_key_id=account_id, region_name=region_name
            ).cloudwatch.describe_alarms(AlarmNames=[resource["Properties"]["AlarmName"]])
            arn = alarms["MetricAlarms"][0]["AlarmArn"]
            resource["Properties"]["Arn"] = arn
            resource["PhysicalResourceId"] = resource["Properties"]["AlarmName"]

        def get_delete_params(
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
        ) -> dict:
            return {"AlarmNames": [properties["AlarmName"]]}

        return {
            "create": {"function": cls._create_function_name(), "result_handler": _handle_result},
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

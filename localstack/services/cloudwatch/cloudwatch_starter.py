import json
import logging

import moto.cloudwatch.responses as cloudwatch_responses
from moto.cloudwatch.models import FakeAlarm

from localstack import config
from localstack.services.infra import start_moto_server
from localstack.utils.aws import aws_stack
from localstack.utils.patch import patch

LOG = logging.getLogger(__name__)


def apply_patches():
    if "<TreatMissingData>" not in cloudwatch_responses.DESCRIBE_ALARMS_TEMPLATE:
        cloudwatch_responses.DESCRIBE_ALARMS_TEMPLATE = (
            cloudwatch_responses.DESCRIBE_ALARMS_TEMPLATE.replace(
                "</AlarmName>",
                "</AlarmName><TreatMissingData>{{ alarm.treat_missing_data }}</TreatMissingData>",
            )
        )

    # add put_composite_alarm

    def put_composite_alarm(self):
        return self.put_metric_alarm()

    if not hasattr(cloudwatch_responses.CloudWatchResponse, "put_composite_alarm"):
        cloudwatch_responses.CloudWatchResponse.put_composite_alarm = put_composite_alarm

    @patch(target=FakeAlarm.update_state)
    def update_state(target, self, reason, reason_data, state_value):
        old_state = self.state_value
        target(self, reason, reason_data, state_value)

        # check the state and trigger required actions
        if not self.actions_enabled or old_state == self.state_value:
            return
        actions = None
        if self.state_value == "OK":
            actions = self.ok_actions
        elif self.state_value == "ALARM":
            actions = self.alarm_actions
        else:
            actions = self.insufficient_data_actions
        for action in actions:
            data = aws_stack.parse_arn(action)
            # test for sns - can this be done in a more generic way?
            if data["service"] == "sns":
                service = aws_stack.connect_to_service(data["service"])
                subject = f"""{self.state_value}: "{self.name}" in {self.region_name}"""
                message = create_message_response_update_state(self, old_state)
                service.publish(TopicArn=action, Subject=subject, Message=message)
            else:
                # TODO: support other actions
                LOG.warning(
                    "Action for service %s not implemented, action '%s' will not be triggered.",
                    data["service"],
                    action,
                )


def create_message_response_update_state(alarm, old_state):
    response = {
        "OldStateValue": old_state,
        "AlarmName": alarm.name,
        "AlarmDescription": alarm.description or "",
        "AlarmConfigurationUpdatedTimestamp": alarm.configuration_updated_timestamp,
        "NewStateValue": alarm.state_value,
        "NewStateReason": alarm.state_reason,
        "StateChangeTime": alarm.state_updated_timestamp,
        "Region": alarm.region_name,
        "AlarmArn": alarm.alarm_arn,
        "OKActions": alarm.ok_actions or "",
        "AlarmActions": alarm.alarm_actions or "",
        "InsufficientDataActions": alarm.insufficient_data_actions or "",
    }

    # collect trigger details
    details = {
        "MetricName": alarm.metric_name or "",
        "Namespace": alarm.namespace or "",
        "Unit": alarm.unit or "",
        "Period": int(alarm.period) if alarm.period else 0,
        "EvaluationPeriods": int(alarm.evaluation_periods) if alarm.evaluation_periods else 0,
        "ComparisonOperator": alarm.comparison_operator or "",
        "Threshold": float(alarm.threshold) if alarm.threshold else 0.0,
        "TreatMissingData": alarm.treat_missing_data or "",
        "EvaluateLowSampleCountPercentile": alarm.evaluate_low_sample_count_percentile or "",
    }

    # Dimensions not serializable
    dimensions = []
    if alarm.dimensions:
        for d in alarm.dimensions:
            dimensions.append({"value": d.value, "name": d.name})

    details["Dimensions"] = dimensions or ""

    if alarm.statistic:
        details["StatisticType"] = "Statistic"
        details["Statistic"] = alarm.statistic.upper()  # AWS returns uppercase
    elif alarm.extended_statistic:
        details["StatisticType"] = "ExtendedStatistic"
        details["ExtendedStatistic"] = alarm.extended_statistic

    response["Trigger"] = details

    return json.dumps(response)


def start_cloudwatch(port=None, asynchronous=False, update_listener=None):
    port = port or config.service_port("cloudwatch")
    apply_patches()
    return start_moto_server(
        "cloudwatch",
        port,
        name="CloudWatch",
        update_listener=update_listener,
        asynchronous=asynchronous,
    )

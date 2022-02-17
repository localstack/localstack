import json
import logging

from moto.cloudwatch import cloudwatch_backends
from moto.cloudwatch.models import FakeAlarm

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.cloudwatch import (
    AmazonResourceName,
    CloudwatchApi,
    ListTagsForResourceOutput,
    PutCompositeAlarmInput,
    PutMetricAlarmInput,
    TagKeyList,
    TagList,
    TagResourceOutput,
    UntagResourceOutput,
)
from localstack.http import Request
from localstack.services import moto
from localstack.services.edge import ROUTER
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws import aws_stack
from localstack.utils.patch import patch
from localstack.utils.tagging import TaggingService

PATH_GET_RAW_METRICS = "/cloudwatch/metrics/raw"

LOG = logging.getLogger(__name__)


@patch(target=FakeAlarm.update_state)
def update_state(target, self, reason, reason_data, state_value):
    old_state = self.state_value
    target(self, reason, reason_data, state_value)

    # check the state and trigger required actions
    if not self.actions_enabled or old_state == self.state_value:
        return
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


class CloudwatchProvider(CloudwatchApi, ServiceLifecycleHook):
    """
    Cloudwatch provider.

    LIMITATIONS:
        - no alarm rule evaluation
    """

    def __init__(self):
        self.tags = TaggingService()

    def on_after_init(self):
        ROUTER.add(PATH_GET_RAW_METRICS, self.get_raw_metrics)

    def get_raw_metrics(self, request: Request):
        region = aws_stack.extract_region_from_auth_header(request.headers)
        backend = cloudwatch_backends.get(region)
        if backend:
            result = backend.metric_data
        else:
            result = []

        result = [
            {
                "ns": r.namespace,
                "n": r.name,
                "v": r.value,
                "t": r.timestamp,
                "d": [{"n": d.name, "v": d.value} for d in r.dimensions],
            }
            for r in result
        ]
        return {"metrics": result}

    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName
    ) -> ListTagsForResourceOutput:
        tags = self.tags.list_tags_for_resource(resource_arn)
        return ListTagsForResourceOutput(Tags=tags.get("Tags", []))

    def untag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tag_keys: TagKeyList
    ) -> UntagResourceOutput:
        self.tags.untag_resource(resource_arn, tag_keys)
        return UntagResourceOutput()

    def tag_resource(
        self, context: RequestContext, resource_arn: AmazonResourceName, tags: TagList
    ) -> TagResourceOutput:
        self.tags.tag_resource(resource_arn, tags)
        return TagResourceOutput()

    @handler("PutMetricAlarm", expand=False)
    def put_metric_alarm(
        self,
        context: RequestContext,
        request: PutMetricAlarmInput,
    ) -> None:
        moto.call_moto(context)

        name = request.get("AlarmName")
        arn = aws_stack.cloudwatch_alarm_arn(name)
        self.tags.tag_resource(arn, request.get("Tags"))

    @handler("PutCompositeAlarm", expand=False)
    def put_composite_alarm(
        self,
        context: RequestContext,
        request: PutCompositeAlarmInput,
    ) -> None:
        pass
        backend = cloudwatch_backends[context.region]
        backend.put_metric_alarm(
            name=request.get("AlarmName"),
            namespace=None,
            metric_name=None,
            metric_data_queries=None,
            comparison_operator=None,
            evaluation_periods=None,
            datapoints_to_alarm=None,
            period=None,
            threshold=None,
            statistic=None,
            extended_statistic=None,
            description=request.get("AlarmDescription"),
            dimensions=[],
            alarm_actions=request.get("AlarmActions", []),
            ok_actions=request.get("OKActions", []),
            insufficient_data_actions=request.get("InsufficientDataActions", []),
            unit=None,
            actions_enabled=request.get("ActionsEnabled"),
            treat_missing_data=None,
            evaluate_low_sample_count_percentile=None,
            threshold_metric_id=None,
            rule=request.get("AlarmRule"),
            tags=request.get("Tags", []),
        )

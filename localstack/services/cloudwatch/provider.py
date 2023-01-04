import json
import logging
from xml.sax.saxutils import escape

from moto.cloudwatch import cloudwatch_backends
from moto.cloudwatch.models import CloudWatchBackend, FakeAlarm, MetricDatum

from localstack.aws.accounts import get_aws_account_id
from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.cloudwatch import (
    AlarmNames,
    AmazonResourceName,
    CloudwatchApi,
    DescribeAlarmsInput,
    DescribeAlarmsOutput,
    GetMetricDataInput,
    GetMetricDataOutput,
    GetMetricStatisticsInput,
    GetMetricStatisticsOutput,
    ListTagsForResourceOutput,
    PutCompositeAlarmInput,
    PutMetricAlarmInput,
    StateValue,
    TagKeyList,
    TagList,
    TagResourceOutput,
    UntagResourceOutput,
)
from localstack.constants import DEFAULT_AWS_ACCOUNT_ID
from localstack.deprecations import deprecated_endpoint
from localstack.http import Request
from localstack.services import moto
from localstack.services.cloudwatch.alarm_scheduler import AlarmScheduler
from localstack.services.edge import ROUTER
from localstack.services.plugins import SERVICE_PLUGINS, ServiceLifecycleHook
from localstack.utils.aws import arns, aws_stack
from localstack.utils.aws.aws_stack import extract_access_key_id_from_auth_header
from localstack.utils.patch import patch
from localstack.utils.sync import poll_condition
from localstack.utils.tagging import TaggingService
from localstack.utils.threads import start_worker_thread

PATH_GET_RAW_METRICS = "/_aws/cloudwatch/metrics/raw"
DEPRECATED_PATH_GET_RAW_METRICS = "/cloudwatch/metrics/raw"
MOTO_INITIAL_UNCHECKED_REASON = "Unchecked: Initial alarm creation"

LOG = logging.getLogger(__name__)


@patch(target=FakeAlarm.update_state)
def update_state(target, self, reason, reason_data, state_value):
    if reason_data is None:
        reason_data = ""
    if self.state_reason == MOTO_INITIAL_UNCHECKED_REASON:
        old_state = StateValue.INSUFFICIENT_DATA
    else:
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
        data = arns.parse_arn(action)
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


@patch(target=CloudWatchBackend.put_metric_alarm)
def put_metric_alarm(
    target,
    self,
    name,
    namespace,
    metric_name,
    metric_data_queries,
    comparison_operator,
    evaluation_periods,
    datapoints_to_alarm,
    period,
    threshold,
    statistic,
    extended_statistic,
    description,
    dimensions,
    alarm_actions,
    ok_actions,
    insufficient_data_actions,
    unit,
    actions_enabled,
    treat_missing_data,
    evaluate_low_sample_count_percentile,
    threshold_metric_id,
    rule=None,
    tags=None,
):
    if description:
        description = escape(description)
    target(
        self,
        name,
        namespace,
        metric_name,
        metric_data_queries,
        comparison_operator,
        evaluation_periods,
        datapoints_to_alarm,
        period,
        threshold,
        statistic,
        extended_statistic,
        description,
        dimensions,
        alarm_actions,
        ok_actions,
        insufficient_data_actions,
        unit,
        actions_enabled,
        treat_missing_data,
        evaluate_low_sample_count_percentile,
        threshold_metric_id,
        rule,
        tags,
    )


def create_message_response_update_state(alarm, old_state):
    response = {
        "AWSAccountId": get_aws_account_id(),
        "OldStateValue": old_state,
        "AlarmName": alarm.name,
        "AlarmDescription": alarm.description or "",
        "AlarmConfigurationUpdatedTimestamp": alarm.configuration_updated_timestamp,
        "NewStateValue": alarm.state_value,
        "NewStateReason": alarm.state_reason,
        "StateChangeTime": alarm.state_updated_timestamp,
        # the long-name for 'region' should be used - as we don't have it, we use the short name
        # which needs to be slightly changed to make snapshot tests work
        "Region": alarm.region_name.replace("-", " ").capitalize(),
        "AlarmArn": alarm.alarm_arn,
        "OKActions": alarm.ok_actions or [],
        "AlarmActions": alarm.alarm_actions or [],
        "InsufficientDataActions": alarm.insufficient_data_actions or [],
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


class ValidationError(CommonServiceException):
    def __init__(self, message: str):
        super().__init__("ValidationError", message, 400, True)


def _set_alarm_actions(context, alarm_names, enabled):
    backend = cloudwatch_backends[context.account_id][context.region]
    for name in alarm_names:
        alarm = backend.alarms.get(name)
        if alarm:
            alarm.actions_enabled = enabled


def _cleanup_describe_output(alarm):
    reason_data = alarm.get("StateReasonData")
    if reason_data is not None and reason_data in ("{}", ""):
        alarm.pop("StateReasonData")
    if (
        alarm.get("StateReason", "") == MOTO_INITIAL_UNCHECKED_REASON
        and alarm.get("StateValue") != StateValue.INSUFFICIENT_DATA
    ):
        alarm["StateValue"] = StateValue.INSUFFICIENT_DATA


class CloudwatchProvider(CloudwatchApi, ServiceLifecycleHook):
    """
    Cloudwatch provider.

    LIMITATIONS:
        - no alarm rule evaluation
    """

    def __init__(self):
        self.tags = TaggingService()
        self.alarm_scheduler = None

    def on_after_init(self):
        ROUTER.add(PATH_GET_RAW_METRICS, self.get_raw_metrics)
        # TODO remove with 2.0
        ROUTER.add(
            DEPRECATED_PATH_GET_RAW_METRICS,
            deprecated_endpoint(
                self.get_raw_metrics,
                previous_path=DEPRECATED_PATH_GET_RAW_METRICS,
                deprecation_version="1.3.0",
                new_path=PATH_GET_RAW_METRICS,
            ),
        )
        self.alarm_scheduler = AlarmScheduler()

    def on_before_start(self):
        # re-schedule alarms for persistence use-case
        def restart_alarms(*args):
            poll_condition(lambda: SERVICE_PLUGINS.is_running("cloudwatch"))
            self.alarm_scheduler.restart_existing_alarms()

        start_worker_thread(restart_alarms)

    def on_before_stop(self):
        self.alarm_scheduler.shutdown_scheduler()

    def delete_alarms(self, context: RequestContext, alarm_names: AlarmNames) -> None:
        moto.call_moto(context)
        for alarm_name in alarm_names:
            arn = arns.cloudwatch_alarm_arn(alarm_name)
            self.alarm_scheduler.delete_scheduler_for_alarm(arn)

    def get_raw_metrics(self, request: Request):
        region = aws_stack.extract_region_from_auth_header(request.headers)
        account_id = (
            extract_access_key_id_from_auth_header(request.headers) or DEFAULT_AWS_ACCOUNT_ID
        )
        backend = cloudwatch_backends[account_id][region]
        if backend:
            result = [m for m in backend.metric_data if isinstance(m, MetricDatum)]
            # TODO handle aggregated metrics as well (MetricAggregatedDatum)
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

    @handler("GetMetricData", expand=False)
    def get_metric_data(
        self, context: RequestContext, request: GetMetricDataInput
    ) -> GetMetricDataOutput:
        result = moto.call_moto(context)
        # moto currently uses hardcoded label metric_name + stat
        # parity tests shows that default is MetricStat, but there might also be a label explicitly set
        metric_data_queries = request["MetricDataQueries"]
        for i in range(0, len(metric_data_queries)):
            metric_query = metric_data_queries[i]
            label = metric_query.get("Label") or metric_query.get("MetricStat", {}).get(
                "Metric", {}
            ).get("MetricName")
            if label:
                result["MetricDataResults"][i]["Label"] = label
        if "Messages" not in result:
            # parity tests reveals that an empty messages list is added
            result["Messages"] = []
        return result

    @handler("PutMetricAlarm", expand=False)
    def put_metric_alarm(
        self,
        context: RequestContext,
        request: PutMetricAlarmInput,
    ) -> None:

        # missing will be the default, when not set (but it will not explicitly be set)
        if not request.get("TreatMissingData", "missing") in [
            "breaching",
            "notBreaching",
            "ignore",
            "missing",
        ]:
            raise ValidationError(
                f"The value {request['TreatMissingData']} is not supported for TreatMissingData parameter. Supported values are [breaching, notBreaching, ignore, missing]."
            )
        # do some sanity checks:
        if request.get("Period"):
            # Valid values are 10, 30, and any multiple of 60.
            value = request.get("Period")
            if value not in (10, 30):
                if value % 60 != 0:
                    raise ValidationError("Period must be 10, 30 or a multiple of 60")
        if request.get("Statistic"):
            if not request.get("Statistic") in [
                "SampleCount",
                "Average",
                "Sum",
                "Minimum",
                "Maximum",
            ]:
                raise ValidationError(
                    f"Value '{request.get('Statistic')}' at 'statistic' failed to satisfy constraint: Member must satisfy enum value set: [Maximum, SampleCount, Sum, Minimum, Average]"
                )

        moto.call_moto(context)

        name = request.get("AlarmName")
        arn = arns.cloudwatch_alarm_arn(name)
        self.tags.tag_resource(arn, request.get("Tags"))
        self.alarm_scheduler.schedule_metric_alarm(arn)

    @handler("PutCompositeAlarm", expand=False)
    def put_composite_alarm(
        self,
        context: RequestContext,
        request: PutCompositeAlarmInput,
    ) -> None:
        backend = cloudwatch_backends[context.account_id][context.region]
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
        LOG.warning(
            "Composite Alarms configuration is not yet supported, alarm state will not be evaluated"
        )

    @handler("EnableAlarmActions")
    def enable_alarm_actions(self, context: RequestContext, alarm_names: AlarmNames) -> None:
        _set_alarm_actions(context, alarm_names, enabled=True)

    @handler("DisableAlarmActions")
    def disable_alarm_actions(self, context: RequestContext, alarm_names: AlarmNames) -> None:
        _set_alarm_actions(context, alarm_names, enabled=False)

    @handler("DescribeAlarms", expand=False)
    def describe_alarms(
        self, context: RequestContext, request: DescribeAlarmsInput
    ) -> DescribeAlarmsOutput:
        response = moto.call_moto(context)

        for c in response["CompositeAlarms"]:
            _cleanup_describe_output(c)
        for m in response["MetricAlarms"]:
            _cleanup_describe_output(m)

        return response

    @handler("GetMetricStatistics", expand=False)
    def get_metric_statistics(
        self, context: RequestContext, request: GetMetricStatisticsInput
    ) -> GetMetricStatisticsOutput:
        response = moto.call_moto(context)

        # cleanup -> ExtendendStatics is not included in AWS response if it returned empty
        for datapoint in response.get("Datapoints"):
            if "ExtendedStatistics" in datapoint and not datapoint.get("ExtendedStatistics"):
                datapoint.pop("ExtendedStatistics")

        return response

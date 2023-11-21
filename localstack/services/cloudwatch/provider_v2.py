import logging

from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.cloudwatch import (
    ActionPrefix,
    AlarmName,
    AlarmNamePrefix,
    AlarmNames,
    AlarmTypes,
    AmazonResourceName,
    CloudwatchApi,
    DashboardBody,
    DashboardName,
    DashboardNamePrefix,
    DashboardNames,
    DeleteDashboardsOutput,
    DescribeAlarmsOutput,
    GetDashboardOutput,
    InvalidParameterValueException,
    ListDashboardsOutput,
    ListTagsForResourceOutput,
    MaxRecords,
    NextToken,
    PutDashboardOutput,
    PutMetricAlarmInput,
    StateValue,
    TagKeyList,
    TagList,
    TagResourceOutput,
    UntagResourceOutput,
)
from localstack.http import Request
from localstack.services.cloudwatch.alarm_scheduler import AlarmScheduler
from localstack.services.cloudwatch.models import (
    CloudWatchStore,
    LocalStackDashboard,
    LocalStackMetricAlarm,
    cloudwatch_stores,
)
from localstack.services.edge import ROUTER
from localstack.services.plugins import SERVICE_PLUGINS, ServiceLifecycleHook
from localstack.utils.aws import arns
from localstack.utils.sync import poll_condition
from localstack.utils.tagging import TaggingService
from localstack.utils.threads import start_worker_thread

PATH_GET_RAW_METRICS = "/_aws/cloudwatch/metrics/raw"
DEPRECATED_PATH_GET_RAW_METRICS = "/cloudwatch/metrics/raw"
MOTO_INITIAL_UNCHECKED_REASON = "Unchecked: Initial alarm creation"

LOG = logging.getLogger(__name__)


class ValidationError(CommonServiceException):
    # TODO: check this error against AWS (doesn't exist in the API)
    def __init__(self, message: str):
        super().__init__("ValidationError", message, 400, True)


class CloudwatchProvider(CloudwatchApi, ServiceLifecycleHook):
    """
    Cloudwatch provider.

    LIMITATIONS:
        - no alarm rule evaluation
    """

    def __init__(self):
        self.tags = TaggingService()
        self.alarm_scheduler: AlarmScheduler = None
        self.store = None

    @staticmethod
    def get_store(account_id: str, region: str) -> CloudWatchStore:
        return cloudwatch_stores[account_id][region]

    def on_after_init(self):
        ROUTER.add(PATH_GET_RAW_METRICS, self.get_raw_metrics)
        self.start_alarm_scheduler()

    def on_before_state_reset(self):
        self.shutdown_alarm_scheduler()

    def on_after_state_reset(self):
        self.start_alarm_scheduler()

    def on_before_state_load(self):
        self.shutdown_alarm_scheduler()

    def on_after_state_load(self):
        self.start_alarm_scheduler()

        def restart_alarms(*args):
            poll_condition(lambda: SERVICE_PLUGINS.is_running("cloudwatch"))
            self.alarm_scheduler.restart_existing_alarms()

        start_worker_thread(restart_alarms)

    def on_before_stop(self):
        self.shutdown_alarm_scheduler()

    def start_alarm_scheduler(self):
        if not self.alarm_scheduler:
            LOG.debug("starting cloudwatch scheduler")
            self.alarm_scheduler = AlarmScheduler()

    def shutdown_alarm_scheduler(self):
        LOG.debug("stopping cloudwatch scheduler")
        self.alarm_scheduler.shutdown_scheduler()
        self.alarm_scheduler = None

    def delete_alarms(self, context: RequestContext, alarm_names: AlarmNames) -> None:
        """
        Delete alarms.
        """

        for alarm_name in alarm_names:
            alarm_arn = arns.cloudwatch_alarm_arn(alarm_name)  # obtain alarm ARN from alarm name
            self.alarm_scheduler.delete_scheduler_for_alarm(alarm_arn)

    def get_raw_metrics(self, request: Request):
        # TODO this needs to be read from the database
        # FIXME this is just a placeholder for now
        return {"metrics": []}

    @handler("PutMetricAlarm", expand=False)
    def put_metric_alarm(self, context: RequestContext, request: PutMetricAlarmInput) -> None:
        # missing will be the default, when not set (but it will not explicitly be set)
        if request.get("TreatMissingData", "missing") not in [
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
            if request.get("Statistic") not in [
                "SampleCount",
                "Average",
                "Sum",
                "Minimum",
                "Maximum",
            ]:
                raise ValidationError(
                    f"Value '{request.get('Statistic')}' at 'statistic' failed to satisfy constraint: Member must satisfy enum value set: [Maximum, SampleCount, Sum, Minimum, Average]"
                )

        extended_statistic = request.get("ExtendedStatistic")
        if extended_statistic and not extended_statistic.startswith("p"):
            raise InvalidParameterValueException(
                f"The value {extended_statistic} for parameter ExtendedStatistic is not supported."
            )
        evaluate_low_sample_count_percentile = request.get("EvaluateLowSampleCountPercentile")
        if evaluate_low_sample_count_percentile and evaluate_low_sample_count_percentile not in (
            "evaluate",
            "ignore",
        ):
            raise ValidationError(
                f"Option {evaluate_low_sample_count_percentile} is not supported. "
                "Supported options for parameter EvaluateLowSampleCountPercentile are evaluate and ignore."
            )

        store = self.get_store(context.account_id, context.region)
        metric_alarm = LocalStackMetricAlarm(context.account_id, context.region, {**request})
        alarm_arn = metric_alarm.alarm["AlarmArn"]
        store.Alarms[alarm_arn] = metric_alarm
        self.alarm_scheduler.schedule_metric_alarm(alarm_arn)

    def describe_alarms(
        self,
        context: RequestContext,
        alarm_names: AlarmNames = None,
        alarm_name_prefix: AlarmNamePrefix = None,
        alarm_types: AlarmTypes = None,
        children_of_alarm_name: AlarmName = None,
        parents_of_alarm_name: AlarmName = None,
        state_value: StateValue = None,
        action_prefix: ActionPrefix = None,
        max_records: MaxRecords = None,
        next_token: NextToken = None,
    ) -> DescribeAlarmsOutput:
        store = self.get_store(context.account_id, context.region)
        alarms = list(store.Alarms.values())
        if action_prefix:
            alarms = [a.alarm for a in alarms if a.alarm["AlarmAction"].startswith(action_prefix)]
        elif alarm_name_prefix:
            alarms = [a.alarm for a in alarms if a.alarm["AlarmName"].startswith(alarm_name_prefix)]
        elif alarm_names:
            alarms = [a.alarm for a in alarms if a.alarm["AlarmName"] in alarm_names]
        elif state_value:
            alarms = [a.alarm for a in alarms if a.alarm["StateValue"] == state_value]
        else:
            alarms = [a.alarm for a in list(store.Alarms.values())]

        # TODO: Pagination
        metric_alarms = [a for a in alarms if a.get("AlarmRule") is None]
        composite_alarms = [a for a in alarms if a.get("AlarmRule") is not None]
        return DescribeAlarmsOutput(CompositeAlarms=composite_alarms, MetricAlarms=metric_alarms)

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

    def put_dashboard(
        self, context: RequestContext, dashboard_name: DashboardName, dashboard_body: DashboardBody
    ) -> PutDashboardOutput:
        store = self.get_store(context.account_id, context.region)
        store.Dashboards[dashboard_name] = LocalStackDashboard(
            context.account_id, context.region, dashboard_name, dashboard_body
        )
        return PutDashboardOutput()

    def get_dashboard(
        self, context: RequestContext, dashboard_name: DashboardName
    ) -> GetDashboardOutput:
        store = self.get_store(context.account_id, context.region)
        dashboard = store.Dashboards.get(dashboard_name)
        if not dashboard:
            raise InvalidParameterValueException(f"Dashboard {dashboard_name} does not exist.")

        return GetDashboardOutput(
            DashboardName=dashboard_name,
            DashboardBody=dashboard.dashboard_body,
            DashboardArn=dashboard.dashboard_arn,
        )

    def delete_dashboards(
        self, context: RequestContext, dashboard_names: DashboardNames
    ) -> DeleteDashboardsOutput:
        store = self.get_store(context.account_id, context.region)
        for dashboard_name in dashboard_names:
            store.Dashboards.pop(dashboard_name, None)
        return DeleteDashboardsOutput()

    def list_dashboards(
        self,
        context: RequestContext,
        dashboard_name_prefix: DashboardNamePrefix = None,
        next_token: NextToken = None,
    ) -> ListDashboardsOutput:
        store = self.get_store(context.account_id, context.region)
        dashboard_names = list(store.Dashboards.keys())
        dashboard_names = [
            name for name in dashboard_names if name.startswith(dashboard_name_prefix or "")
        ]

        entries = [
            {
                "DashboardName": name,
                "DashboardArn": store.Dashboards[name].dashboard_arn,
                "LastModified": store.Dashboards[name].last_modified,
                "Size": store.Dashboards[name].size,
            }
            for name in dashboard_names
        ]
        return ListDashboardsOutput(
            DashboardEntries=entries,
        )

import datetime
import json
import logging
from typing import List

from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.cloudwatch import (
    AccountId,
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
    DimensionFilters,
    Dimensions,
    ExtendedStatistics,
    GetDashboardOutput,
    GetMetricDataMaxDatapoints,
    GetMetricDataOutput,
    GetMetricStatisticsOutput,
    HistoryItemType,
    IncludeLinkedAccounts,
    InvalidParameterCombinationException,
    InvalidParameterValueException,
    LabelOptions,
    ListDashboardsOutput,
    ListMetricsOutput,
    ListTagsForResourceOutput,
    MaxRecords,
    MetricData,
    MetricDataQueries,
    MetricDataQuery,
    MetricDataResult,
    MetricDataResultMessages,
    MetricName,
    MetricStat,
    Namespace,
    NextToken,
    Period,
    PutCompositeAlarmInput,
    PutDashboardOutput,
    PutMetricAlarmInput,
    RecentlyActive,
    ResourceNotFound,
    ScanBy,
    StandardUnit,
    StateReason,
    StateReasonData,
    StateValue,
    Statistics,
    TagKeyList,
    TagList,
    TagResourceOutput,
    Timestamp,
    UntagResourceOutput,
)
from localstack.aws.connect import connect_to
from localstack.http import Request
from localstack.services.cloudwatch.alarm_scheduler import AlarmScheduler
from localstack.services.cloudwatch.cloudwatch_database_helper import CloudwatchDatabase
from localstack.services.cloudwatch.models import (
    CloudWatchStore,
    LocalStackAlarm,
    LocalStackDashboard,
    LocalStackMetricAlarm,
    cloudwatch_stores,
)
from localstack.services.edge import ROUTER
from localstack.services.plugins import SERVICE_PLUGINS, ServiceLifecycleHook
from localstack.utils.aws import arns
from localstack.utils.collections import PaginatedList
from localstack.utils.json import CustomEncoder as JSONEncoder
from localstack.utils.sync import poll_condition
from localstack.utils.tagging import TaggingService
from localstack.utils.threads import start_worker_thread
from localstack.utils.time import timestamp_millis

PATH_GET_RAW_METRICS = "/_aws/cloudwatch/metrics/raw"
MOTO_INITIAL_UNCHECKED_REASON = "Unchecked: Initial alarm creation"
LIST_METRICS_MAX_RESULTS = 500
# If the values in these fields are not the same, their values are added when generating labels
LABEL_DIFFERENTIATORS = ["Stat", "Period"]


LOG = logging.getLogger(__name__)


class ValidationError(CommonServiceException):
    # TODO: check this error against AWS (doesn't exist in the API)
    def __init__(self, message: str):
        super().__init__("ValidationError", message, 400, True)


def _validate_parameters_for_put_metric_data(metric_data: MetricData) -> None:
    for index, metric_item in enumerate(metric_data):
        indexplusone = index + 1
        if metric_item.get("Value") and metric_item.get("Values"):
            raise InvalidParameterCombinationException(
                f"The parameters MetricData.member.{indexplusone}.Value and MetricData.member.{indexplusone}.Values are mutually exclusive and you have specified both."
            )

        if metric_item.get("StatisticValues") and metric_item.get("Value"):
            raise InvalidParameterCombinationException(
                f"The parameters MetricData.member.{indexplusone}.Value and MetricData.member.{indexplusone}.StatisticValues are mutually exclusive and you have specified both."
            )

        if metric_item.get("Values") and metric_item.get("Counts"):
            values = metric_item.get("Values")
            counts = metric_item.get("Counts")
            if len(values) != len(counts):
                raise InvalidParameterValueException(
                    f"The parameters MetricData.member.{indexplusone}.Values and MetricData.member.{indexplusone}.Counts must be of the same size."
                )


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
        self.cloudwatch_database = CloudwatchDatabase()

    @staticmethod
    def get_store(account_id: str, region: str) -> CloudWatchStore:
        return cloudwatch_stores[account_id][region]

    def on_after_init(self):
        ROUTER.add(PATH_GET_RAW_METRICS, self.get_raw_metrics)
        self.start_alarm_scheduler()

    def on_before_state_reset(self):
        self.shutdown_alarm_scheduler()
        self.cloudwatch_database.clear_tables()

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
            alarm_arn = arns.cloudwatch_alarm_arn(
                alarm_name, account_id=context.account_id, region_name=context.region
            )  # obtain alarm ARN from alarm name
            self.alarm_scheduler.delete_scheduler_for_alarm(alarm_arn)

    def put_metric_data(
        self, context: RequestContext, namespace: Namespace, metric_data: MetricData
    ) -> None:
        _validate_parameters_for_put_metric_data(metric_data)

        self.cloudwatch_database.add_metric_data(
            context.account_id, context.region, namespace, metric_data
        )

    def get_metric_data(
        self,
        context: RequestContext,
        metric_data_queries: MetricDataQueries,
        start_time: Timestamp,
        end_time: Timestamp,
        next_token: NextToken = None,
        scan_by: ScanBy = None,
        max_datapoints: GetMetricDataMaxDatapoints = None,
        label_options: LabelOptions = None,
    ) -> GetMetricDataOutput:
        results: List[MetricDataResult] = []
        limit = max_datapoints or 100_800
        messages: MetricDataResultMessages = []
        nxt = None
        label_additions = []

        for diff in LABEL_DIFFERENTIATORS:
            non_unique = []
            for query in metric_data_queries:
                non_unique.append(query["MetricStat"][diff])
            if len(set(non_unique)) > 1:
                label_additions.append(diff)

        for query in metric_data_queries:
            query_result = self.cloudwatch_database.get_metric_data_stat(
                account_id=context.account_id,
                region=context.region,
                query=query,
                start_time=start_time,
                end_time=end_time,
                scan_by=scan_by,
            )
            if query_result.get("messages"):
                messages.extend(query_result.get("messages"))

            label = query.get("Label") or f'{query["MetricStat"]["Metric"]["MetricName"]}'
            # TODO: does this happen even if a label is set in the query?
            for label_addition in label_additions:
                label = f"{label} {query['MetricStat'][label_addition]}"

            timestamps = query_result.get("timestamps", {})
            values = query_result.get("values", {})

            # Paginate
            timestamp_value_dicts = [
                {
                    "Timestamp": timestamp,
                    "Value": value,
                }
                for timestamp, value in zip(timestamps, values)
            ]

            pagination = PaginatedList(timestamp_value_dicts)
            timestamp_page, nxt = pagination.get_page(
                lambda item: item.get("Timestamp"),
                next_token=next_token,
                page_size=limit,
            )

            timestamps = [item.get("Timestamp") for item in timestamp_page]
            values = [item.get("Value") for item in timestamp_page]

            metric_data_result = {
                "Id": query.get("Id"),
                "Label": label,
                "StatusCode": "Complete",
                "Timestamps": timestamps,
                "Values": values,
            }
            results.append(MetricDataResult(**metric_data_result))

        return GetMetricDataOutput(MetricDataResults=results, NextToken=nxt, Messages=messages)

    def set_alarm_state(
        self,
        context: RequestContext,
        alarm_name: AlarmName,
        state_value: StateValue,
        state_reason: StateReason,
        state_reason_data: StateReasonData = None,
    ) -> None:
        try:
            if state_reason_data:
                json.loads(state_reason_data)
        except ValueError:
            raise InvalidParameterValueException(
                "TODO: check right error message: Json was not correctly formatted"
            )

        store = self.get_store(context.account_id, context.region)
        alarm = store.Alarms.get(
            arns.cloudwatch_alarm_arn(
                alarm_name, account_id=context.account_id, region_name=context.region
            )
        )
        if not alarm:
            raise ResourceNotFound()

        old_state = alarm.alarm["StateValue"]
        if state_value not in ("OK", "ALARM", "INSUFFICIENT_DATA"):
            raise ValidationError(
                f"1 validation error detected: Value '{state_value}' at 'stateValue' failed to satisfy constraint: Member must satisfy enum value set: [INSUFFICIENT_DATA, ALARM, OK]"
            )

        self._update_state(context, alarm, state_value, state_reason, state_reason_data)

        if not alarm.alarm["ActionsEnabled"] or old_state == state_value:
            return
        if state_value == "OK":
            actions = alarm.alarm["OKActions"]
        elif state_value == "ALARM":
            actions = alarm.alarm["AlarmActions"]
        else:
            actions = alarm.alarm["InsufficientDataActions"]
        for action in actions:
            data = arns.parse_arn(action)
            # test for sns - can this be done in a more generic way?
            if data["service"] == "sns":
                sns_client = connect_to(
                    aws_access_key_id=data["account"], region_name=data["region"]
                ).sns
                subject = f"""{state_value}: "{alarm_name}" in {context.region}"""
                message = self.create_message_response_update_state(context, alarm, old_state)
                sns_client.publish(TopicArn=action, Subject=subject, Message=message)
            else:
                # TODO: support other actions
                LOG.warning(
                    "Action for service %s not implemented, action '%s' will not be triggered.",
                    data["service"],
                    action,
                )

    def get_raw_metrics(self, request: Request):
        """this feature was introduced with https://github.com/localstack/localstack/pull/3535
        # in the meantime, it required a valid aws-header so that the account-id/region could be extracted
        # with the new implementation, we want to return all data, but add the account-id/region as additional attributes

        # TODO endpoint should be refactored or deprecated at some point
        #   - result should be paginated
        #   - include aggregated metrics (but we would also need to change/adapt the shape of "metrics" that we return)
        :returns: json {"metrics": [{"ns": "namespace", "n": "metric_name", "v": value, "t": timestamp,
        "d": [<dimensions-key-pair-values>],"account": account, "region": region}]}
        """
        return {"metrics": self.cloudwatch_database.get_all_metric_data() or []}

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

    @handler("PutCompositeAlarm", expand=False)
    def put_composite_alarm(self, context: RequestContext, request: PutCompositeAlarmInput) -> None:
        composite_to_metric_alarm = {
            "AlarmName": request.get("AlarmName"),
            "Description": request.get("AlarmDescription"),
            "AlarmActions": request.get("AlarmActions", []),
            "OKActions": request.get("OKActions", []),
            "InsufficientDataActions": request.get("InsufficientDataActions", []),
            "ActionsEnabled": request.get("ActionsEnabled"),
            "AlarmRule": request.get("AlarmRule"),
            "Tags": request.get("Tags", []),
        }
        self.put_metric_alarm(context=context, request=composite_to_metric_alarm)

        LOG.warning(
            "Composite Alarms configuration is not yet supported, alarm state will not be evaluated"
        )

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

    def list_metrics(
        self,
        context: RequestContext,
        namespace: Namespace = None,
        metric_name: MetricName = None,
        dimensions: DimensionFilters = None,
        next_token: NextToken = None,
        recently_active: RecentlyActive = None,
        include_linked_accounts: IncludeLinkedAccounts = None,
        owning_account: AccountId = None,
    ) -> ListMetricsOutput:
        result = self.cloudwatch_database.list_metrics(
            context.account_id,
            context.region,
            namespace,
            metric_name,
            dimensions or [],
        )

        metrics = [
            {
                "Namespace": metric.get("namespace"),
                "MetricName": metric.get("metric_name"),
                "Dimensions": metric.get("dimensions"),
            }
            for metric in result.get("metrics", [])
        ]

        aliases_list = PaginatedList(metrics)
        page, nxt = aliases_list.get_page(
            lambda metric: metric.get("MetricName"),
            next_token=next_token,
            page_size=LIST_METRICS_MAX_RESULTS,
        )
        return ListMetricsOutput(Metrics=page, NextToken=nxt)

    def get_metric_statistics(
        self,
        context: RequestContext,
        namespace: Namespace,
        metric_name: MetricName,
        start_time: Timestamp,
        end_time: Timestamp,
        period: Period,
        dimensions: Dimensions = None,
        statistics: Statistics = None,
        extended_statistics: ExtendedStatistics = None,
        unit: StandardUnit = None,
    ) -> GetMetricStatisticsOutput:
        stat_datapoints = {}
        for stat in statistics:
            query_result = self.cloudwatch_database.get_metric_data_stat(
                account_id=context.account_id,
                region=context.region,
                start_time=start_time,
                end_time=end_time,
                scan_by="TimestampDescending",
                query=MetricDataQuery(
                    MetricStat=MetricStat(
                        Metric={
                            "MetricName": metric_name,
                            "Namespace": namespace,
                            "Dimensions": dimensions or [],
                        },
                        Period=period,
                        Stat=stat,
                        Unit=unit,
                    )
                ),
            )

            timestamps = query_result.get("timestamps", [])
            values = query_result.get("values", [])
            for i, timestamp in enumerate(timestamps):
                stat_datapoints.setdefault(timestamp, {})
                stat_datapoints[timestamp][stat] = values[i]

        datapoints = []
        for timestamp, stats in stat_datapoints.items():
            datapoints.append(
                {
                    "Timestamp": timestamp,
                    "SampleCount": stats.get("SampleCount"),
                    "Average": stats.get("Average"),
                    "Sum": stats.get("Sum"),
                    "Minimum": stats.get("Minimum"),
                    "Maximum": stats.get("Maximum"),
                    "Unit": unit,
                }
            )

        return GetMetricStatisticsOutput(Datapoints=datapoints, Label=metric_name)

    def _update_state(
        self,
        context: RequestContext,
        alarm: LocalStackAlarm,
        state_value: str,
        state_reason: str,
        state_reason_data: str = None,
    ):
        old_state = alarm.alarm["StateValue"]
        store = self.get_store(context.account_id, context.region)
        current_time = datetime.datetime.now()
        store.Histories.append(
            {
                "Timestamp": timestamp_millis(alarm.alarm["StateUpdatedTimestamp"]),
                "HistoryItemType": HistoryItemType.StateUpdate,
                "AlarmName": alarm.alarm["AlarmName"],
                "HistoryData": alarm.alarm.get(
                    "StateReasonData"
                ),  # FIXME general formatting and data content not on par with AWS at the moment
                "HistorySummary": f"Alarm updated from {old_state} to {state_value}",
            }
        )
        alarm.alarm["StateValue"] = state_value
        alarm.alarm["StateReason"] = state_reason
        alarm.alarm["StateReasonData"] = state_reason_data
        alarm.alarm["StateUpdatedTimestamp"] = current_time

    @staticmethod
    def create_message_response_update_state(
        context: RequestContext, alarm: LocalStackAlarm, old_state
    ):
        alarm = alarm.alarm
        response = {
            "AWSAccountId": context.account_id,
            "OldStateValue": old_state,
            "AlarmName": alarm["AlarmName"],
            "AlarmDescription": alarm.get("AlarmDescription"),
            "AlarmConfigurationUpdatedTimestamp": alarm["AlarmConfigurationUpdatedTimestamp"],
            "NewStateValue": alarm["StateValue"],
            "NewStateReason": alarm["StateReason"],
            "StateChangeTime": alarm["StateUpdatedTimestamp"],
            # the long-name for 'region' should be used - as we don't have it, we use the short name
            # which needs to be slightly changed to make snapshot tests work
            "Region": context.region.replace("-", " ").capitalize(),
            "AlarmArn": alarm["AlarmArn"],
            "OKActions": alarm.get("OKActions", []),
            "AlarmActions": alarm.get("AlarmActions", []),
            "InsufficientDataActions": alarm.get("InsufficientDataActions", []),
        }

        # collect trigger details
        details = {
            "MetricName": alarm.get("MetricName", ""),
            "Namespace": alarm.get("Namespace", ""),
            "Unit": alarm.get("Unit", ""),
            "Period": int(alarm.get("Period", 0)),
            "EvaluationPeriods": int(alarm.get("EvaluationPeriods", 0)),
            "ComparisonOperator": alarm.get("ComparisonOperator", ""),
            "Threshold": float(alarm.get("Threshold", 0.0)),
            "TreatMissingData": alarm.get("TreatMissingData", ""),
            "EvaluateLowSampleCountPercentile": alarm.get("EvaluateLowSampleCountPercentile", ""),
        }

        # Dimensions not serializable
        dimensions = []
        alarm_dimensions = alarm.get("Dimensions", [])
        if alarm_dimensions:
            for d in alarm["Dimensions"]:
                dimensions.append({"value": d["Value"], "name": d["Name"]})
        details["Dimensions"] = dimensions or ""

        alarm_statistic = alarm.get("Statistic")
        alarm_extended_statistic = alarm.get("ExtendedStatistic")

        if alarm_statistic:
            details["StatisticType"] = "Statistic"
            details["Statistic"] = alarm_statistic.upper()  # AWS returns uppercase
        elif alarm_extended_statistic:
            details["StatisticType"] = "ExtendedStatistic"
            details["ExtendedStatistic"] = alarm_extended_statistic

        response["Trigger"] = details

        return json.dumps(response, cls=JSONEncoder)

    def disable_alarm_actions(self, context: RequestContext, alarm_names: AlarmNames) -> None:
        self._set_alarm_actions(context, alarm_names, enabled=False)

    def enable_alarm_actions(self, context: RequestContext, alarm_names: AlarmNames) -> None:
        self._set_alarm_actions(context, alarm_names, enabled=True)

    def _set_alarm_actions(self, context, alarm_names, enabled):
        store = self.get_store(context.account_id, context.region)
        for name in alarm_names:
            alarm_arn = arns.cloudwatch_alarm_arn(
                name, account_id=context.account_id, region_name=context.region
            )
            alarm = store.Alarms.get(alarm_arn)
            if alarm:
                alarm.alarm["ActionsEnabled"] = enabled

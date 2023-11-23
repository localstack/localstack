import datetime
from typing import Dict, List

from moto.cloudwatch.models import CloudWatchBackend as MotoCloudWatchBackend
from moto.cloudwatch.models import cloudwatch_backends as moto_cloudwatch_backend

from localstack.aws.api.cloudwatch import CompositeAlarm, DashboardBody, MetricAlarm, StateValue
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)
from localstack.utils.aws import arns


def get_moto_logs_backend(account_id: str, region_name: str) -> MotoCloudWatchBackend:
    return moto_cloudwatch_backend[account_id][region_name]


class LocalStackMetricAlarm:
    region: str
    account_id: str
    alarm: MetricAlarm

    def __init__(self, account_id: str, region: str, alarm: MetricAlarm):
        self.account_id = account_id
        self.region = region
        self.alarm = alarm
        self.set_default_attributes()

    def set_default_attributes(self):
        current_time = datetime.datetime.utcnow()
        self.alarm["AlarmArn"] = arns.cloudwatch_alarm_arn(
            self.alarm["AlarmName"], account_id=self.account_id, region_name=self.region
        )
        self.alarm["AlarmConfigurationUpdatedTimestamp"] = current_time
        self.alarm.setdefault("ActionsEnabled", True)
        self.alarm.setdefault("OKActions", [])
        self.alarm.setdefault("AlarmActions", [])
        self.alarm.setdefault("InsufficientDataActions", [])
        self.alarm["StateValue"] = StateValue.INSUFFICIENT_DATA
        self.alarm["StateReason"] = "Unchecked: Initial alarm creation"
        self.alarm["StateUpdatedTimestamp"] = current_time
        self.alarm.setdefault("Dimensions", [])
        self.alarm["StateTransitionedTimestamp"] = current_time


class LocalStackCompositeAlarm:
    region: str
    account_id: str
    alarm: CompositeAlarm

    def __init__(self, account_id: str, region: str, alarm: CompositeAlarm):
        self.account_id = account_id
        self.region = region
        self.alarm = alarm
        self.set_default_attributes()

    def set_default_attributes(self):
        # TODO
        pass


class LocalStackDashboard:
    region: str
    account_id: str
    dashboard_name: str
    dashboard_arn: str
    dashboard_body: DashboardBody

    def __init__(
        self, account_id: str, region: str, dashboard_name: str, dashboard_body: DashboardBody
    ):
        self.account_id = account_id
        self.region = region
        self.dashboard_name = dashboard_name
        self.dashboard_arn = arns.cloudwatch_dashboard_arn(
            self.dashboard_name, account_id=self.account_id, region_name=self.region
        )
        self.dashboard_body = dashboard_body
        self.last_modified = datetime.datetime.now()
        self.size = 225  # TODO: calculate size


LocalStackAlarm = LocalStackMetricAlarm | LocalStackCompositeAlarm


class CloudWatchStore(BaseStore):
    # maps resource ARN to tags
    TAGS: Dict[str, Dict[str, str]] = CrossRegionAttribute(default=dict)

    # maps resource ARN to alarms
    Alarms: Dict[str, LocalStackAlarm] = LocalAttribute(default=dict)

    # Contains all the Alarm Histories. Per documentation, an alarm history is retained even if the alarm is deleted,
    # making it necessary to save this at store level
    # TODO: check if list of dicts over all alarm is suitable datastructure
    Histories: List[Dict] = LocalAttribute(default=list)

    Dashboards: Dict[str, LocalStackDashboard] = LocalAttribute(default=dict)


cloudwatch_stores = AccountRegionBundle("cloudwatch", CloudWatchStore)

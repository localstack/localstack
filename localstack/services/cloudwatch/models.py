import datetime
from typing import Dict

from moto.cloudwatch.models import CloudWatchBackend as MotoCloudWatchBackend
from moto.cloudwatch.models import cloudwatch_backends as moto_cloudwatch_backend

from localstack.aws.api.cloudwatch import CompositeAlarm, MetricAlarm, StateValue
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
        current_time = datetime.datetime.now()
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


class CloudWatchStore(BaseStore):
    # maps resource ARN to tags
    TAGS: Dict[str, Dict[str, str]] = CrossRegionAttribute(default=dict)

    # maps resource ARN to alarms
    Alarms: Dict[str, LocalStackMetricAlarm | LocalStackCompositeAlarm] = LocalAttribute(
        default=dict
    )


cloudwatch_stores = AccountRegionBundle("cloudwatch", CloudWatchStore)

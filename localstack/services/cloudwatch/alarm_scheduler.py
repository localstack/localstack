import json
import logging
import math
import threading
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, List, Optional

from localstack.aws.api.cloudwatch import MetricAlarm, MetricDataQuery, StateValue
from localstack.utils.aws import arns, aws_stack
from localstack.utils.scheduler import Scheduler

if TYPE_CHECKING:
    from mypy_boto3_cloudwatch import CloudWatchClient

LOG = logging.getLogger(__name__)

# TODO currently not supported, used for anomaly detection models:
# LessThanLowerOrGreaterThanUpperThreshold
# LessThanLowerThreshold
# GreaterThanUpperThreshold
COMPARISON_OPS = {
    "GreaterThanOrEqualToThreshold": (lambda value, threshold: value >= threshold),
    "GreaterThanThreshold": (lambda value, threshold: value > threshold),
    "LessThanThreshold": (lambda value, threshold: value < threshold),
    "LessThanOrEqualToThreshold": (lambda value, threshold: value <= threshold),
}

DEFAULT_REASON = "Alarm Evaluation"
THRESHOLD_CROSSED = "Threshold Crossed"
INSUFFICIENT_DATA = "Insufficient Data"


class AlarmScheduler:
    def __init__(self) -> None:
        """
        Creates a new AlarmScheduler, with a Scheduler, that will be started in a new thread
        """
        super().__init__()
        self.scheduler = Scheduler()
        self.thread = threading.Thread(target=self.scheduler.run, name="cloudwatch-scheduler")
        self.thread.start()
        self.scheduled_alarms = {}

    def shutdown_scheduler(self) -> None:
        """
        Shutsdown the scheduler, must be called before application stops
        """
        self.scheduler.close()
        self.thread.join(5)

    def schedule_metric_alarm(self, alarm_arn: str) -> None:
        """(Re-)schedules the alarm, if the alarm is re-scheduled, the running alarm scheduler will be cancelled before
        starting a new one"""
        alarm_details = get_metric_alarm_details_for_alarm_arn(alarm_arn)
        self.delete_scheduler_for_alarm(alarm_arn)
        if not alarm_details:
            LOG.warning("Scheduling alarm failed: could not find alarm %s", alarm_arn)
            return

        if not self._is_alarm_supported(alarm_details):
            LOG.warning(
                "Given alarm configuration not yet supported, alarm state will not be evaluated."
            )
            return

        period = alarm_details["Period"]
        evaluation_periods = alarm_details["EvaluationPeriods"]
        schedule_period = evaluation_periods * period

        def on_error(e):
            LOG.exception("Error executing scheduled alarm", exc_info=e)

        task = self.scheduler.schedule(
            func=calculate_alarm_state,
            period=schedule_period,
            fixed_rate=True,
            args=[alarm_arn],
            on_error=on_error,
        )

        self.scheduled_alarms[alarm_arn] = task

    def delete_scheduler_for_alarm(self, alarm_arn: str) -> None:
        """
        Deletes the recurring scheduler for an alarm

        :param alarm_arn: the arn of the alarm to be removed
        """
        task = self.scheduled_alarms.pop(alarm_arn, None)
        if task:
            task.cancel()

    def restart_existing_alarms(self) -> None:
        """
        Only used re-create persistent state. Reschedules alarms that already exist
        """
        service = "cloudwatch"
        for region in aws_stack.get_valid_regions_for_service(service):
            client = aws_stack.connect_to_service(service, region_name=region)
            result = client.describe_alarms()
            for metric_alarm in result["MetricAlarms"]:
                arn = metric_alarm["AlarmArn"]
                self.schedule_metric_alarm(alarm_arn=arn)

    def _is_alarm_supported(self, alarm_details: MetricAlarm) -> bool:
        required_parameters = ["Period", "Statistic", "MetricName", "Threshold"]
        for param in required_parameters:
            if param not in alarm_details.keys():
                LOG.debug(
                    f"Currently only simple MetricAlarm are supported. Alarm is missing '{param}'. ExtendedStatistic is not yet supported."
                )
                return False
        if alarm_details["ComparisonOperator"] not in COMPARISON_OPS.keys():
            LOG.debug(
                f"ComparisonOperator '{alarm_details['ComparisonOperator']}' not yet supported."
            )
            return False
        return True


def get_metric_alarm_details_for_alarm_arn(alarm_arn: str) -> Optional[MetricAlarm]:
    alarm_name = arns.extract_resource_from_arn(alarm_arn).split(":", 1)[1]
    client = get_cloudwatch_client_for_region_of_alarm(alarm_arn)
    metric_alarms = client.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    return metric_alarms[0] if metric_alarms else None


def get_cloudwatch_client_for_region_of_alarm(alarm_arn: str) -> "CloudWatchClient":
    region = arns.extract_region_from_arn(alarm_arn)
    return aws_stack.connect_to_service("cloudwatch", region_name=region)


def generate_metric_query(alarm_details: MetricAlarm) -> MetricDataQuery:
    """Creates the dict with the required data for MetricDataQueries when calling client.get_metric_data"""

    metric = {
        "MetricName": alarm_details["MetricName"],
    }
    if alarm_details.get("Namespace"):
        metric["Namespace"] = alarm_details["Namespace"]
    if alarm_details.get("Dimensions"):
        metric["Dimensions"] = alarm_details["Dimensions"]
    return {
        "Id": alarm_details["AlarmName"],
        "MetricStat": {
            "Metric": metric,
            "Period": alarm_details["Period"],
            "Stat": alarm_details["Statistic"].capitalize(),
        },
        # TODO other fields might be required in the future
    }


def is_threshold_exceeded(metric_values: List[float], alarm_details: MetricAlarm) -> bool:
    """Evaluates if the threshold is exceeded for the configured alarm and given metric values

    :param metric_values: values to compare against threshold
    :param alarm_details: Alarm Description, as returned from describe_alarms

    :return: True if threshold is exceeded, else False
    """
    threshold = alarm_details["Threshold"]
    comparison_operator = alarm_details["ComparisonOperator"]
    treat_missing_data = alarm_details.get("TreatMissingData", "missing")
    evaluation_periods = alarm_details.get("EvaluationPeriods")
    datapoints_to_alarm = alarm_details.get("DatapointsToAlarm", evaluation_periods)
    evaluated_datapoints = []
    for value in metric_values:
        if value is None:
            if treat_missing_data == "breaching":
                evaluated_datapoints.append(True)
            elif treat_missing_data == "notBreaching":
                evaluated_datapoints.append(False)
            # else we can ignore the data
        else:
            evaluated_datapoints.append(COMPARISON_OPS.get(comparison_operator)(value, threshold))

    sum_breaching = evaluated_datapoints.count(True)
    if sum_breaching >= datapoints_to_alarm:
        return True
    return False


def is_triggering_premature_alarm(metric_values: List[float], alarm_details: MetricAlarm) -> bool:
    """
    Checks if a premature alarm should be triggered.
    https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html#CloudWatch-alarms-avoiding-premature-transition:

    [...] alarms are designed to always go into ALARM state when the oldest available breaching datapoint during the Evaluation
    Periods number of data points is at least as old as the value of Datapoints to Alarm, and all other more recent data
    points are breaching or missing. In this case, the alarm goes into ALARM state even if the total number of datapoints
    available is lower than M (Datapoints to Alarm).
    This alarm logic applies to M out of N alarms as well.
    """
    treat_missing_data = alarm_details.get("TreatMissingData", "missing")
    if treat_missing_data not in ("missing", "ignore"):
        return False

    datapoints_to_alarm = alarm_details.get("DatapointsToAlarm", 1)
    if datapoints_to_alarm > 1:
        comparison_operator = alarm_details["ComparisonOperator"]
        threshold = alarm_details["Threshold"]
        oldest_datapoints = metric_values[:-datapoints_to_alarm]
        if oldest_datapoints.count(None) == len(oldest_datapoints):
            if metric_values[-datapoints_to_alarm] and COMPARISON_OPS.get(comparison_operator)(
                metric_values[-datapoints_to_alarm], threshold
            ):
                values = list(filter(None, metric_values[len(oldest_datapoints) :]))
                if all(
                    COMPARISON_OPS.get(comparison_operator)(value, threshold) for value in values
                ):
                    return True
    return False


def collect_metric_data(alarm_details: MetricAlarm, client: "CloudWatchClient") -> List[float]:
    """
    Collects the metric data for the evaluation interval.

    :param alarm_details: the alarm details as returned by describe_alarms
    :param client: the cloudwatch client
    :return: list with data points
    """
    metric_values = []

    evaluation_periods = alarm_details["EvaluationPeriods"]
    period = alarm_details["Period"]

    # From the docs: "Whenever an alarm evaluates whether to change state, CloudWatch attempts to retrieve a higher number of data
    # points than the number specified as Evaluation Periods."
    # No other indication, try to calculate a reasonable value:
    magic_number = max(math.floor(evaluation_periods / 3), 2)
    collected_periods = evaluation_periods + magic_number

    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    metric_query = generate_metric_query(alarm_details)

    # get_metric_data needs to be run in a loop, so we also collect empty data points on the right position
    for i in range(0, collected_periods):
        start_time = now - timedelta(seconds=period)
        end_time = now
        metric_data = client.get_metric_data(
            MetricDataQueries=[metric_query], StartTime=start_time, EndTime=end_time
        )["MetricDataResults"][0]
        val = metric_data["Values"]
        # oldest datapoint should be at the beginning of the list
        metric_values.insert(0, val[0] if val else None)
        now = start_time
    return metric_values


def update_alarm_state(
    client: "CloudWatchClient",
    alarm_name: str,
    current_state: str,
    desired_state: str,
    reason: str = DEFAULT_REASON,
    state_reason_data: dict = None,
) -> None:
    """Updates the alarm state, if the current_state is different than the desired_state

    :param client: the cloudwatch client
    :param alarm_name: the name of the alarm
    :param current_state: the state the alarm is currently in
    :param desired_state: the state the alarm should have after updating
    :param reason: reason why the state is set, will be used to for set_alarm_state
    :param state_reason_data: data associated with the state change, optional
    """
    if current_state == desired_state:
        return
    client.set_alarm_state(
        AlarmName=alarm_name,
        StateValue=desired_state,
        StateReason=reason,
        StateReasonData=json.dumps(state_reason_data),
    )


def calculate_alarm_state(alarm_arn: str) -> None:
    """
    Calculates and updates the state of the alarm

    :param alarm_arn: the arn of the alarm to be evaluated
    """
    alarm_details = get_metric_alarm_details_for_alarm_arn(alarm_arn)
    if not alarm_details:
        LOG.warning("Could not find alarm %s", alarm_arn)
        return

    client = get_cloudwatch_client_for_region_of_alarm(alarm_arn)

    query_date = datetime.utcnow().strftime(format="%Y-%m-%dT%H:%M:%S+0000")
    metric_values = collect_metric_data(alarm_details, client)

    state_reason_data = {
        "version": "1.0",
        "queryDate": query_date,
        "period": alarm_details["Period"],
        "recentDatapoints": [v for v in metric_values if v is not None],
        "threshold": alarm_details["Threshold"],
    }
    if alarm_details.get("Statistic"):
        state_reason_data["statistic"] = alarm_details["Statistic"]
    if alarm_details.get("Unit"):
        state_reason_data["unit"] = alarm_details["Unit"]

    alarm_name = alarm_details["AlarmName"]
    alarm_state = alarm_details["StateValue"]
    treat_missing_data = alarm_details.get("TreatMissingData", "missing")

    empty_datapoints = metric_values.count(None)
    if empty_datapoints == len(metric_values):
        evaluation_periods = alarm_details["EvaluationPeriods"]
        details_msg = (
            f"no datapoints were received for {evaluation_periods} period{'s' if evaluation_periods > 1 else ''} and "
            f"{evaluation_periods} missing datapoint{'s were' if evaluation_periods > 1 else ' was'} treated as"
        )
        if treat_missing_data == "missing":
            update_alarm_state(
                client,
                alarm_name,
                alarm_state,
                StateValue.INSUFFICIENT_DATA,
                f"{INSUFFICIENT_DATA}: {details_msg} [{treat_missing_data.capitalize()}].",
                state_reason_data=state_reason_data,
            )
        elif treat_missing_data == "breaching":
            update_alarm_state(
                client,
                alarm_name,
                alarm_state,
                StateValue.ALARM,
                f"{THRESHOLD_CROSSED}: {details_msg} [{treat_missing_data.capitalize()}].",
                state_reason_data=state_reason_data,
            )
        elif treat_missing_data == "notBreaching":
            update_alarm_state(
                client,
                alarm_name,
                alarm_state,
                StateValue.OK,
                f"{THRESHOLD_CROSSED}: {details_msg} [NonBreaching].",
                state_reason_data=state_reason_data,
            )
        # 'ignore': keep the same state
        return

    if is_triggering_premature_alarm(metric_values, alarm_details):
        if treat_missing_data == "missing":
            update_alarm_state(
                client,
                alarm_name,
                alarm_state,
                StateValue.ALARM,
                f"{THRESHOLD_CROSSED}: premature alarm for missing datapoints",
                state_reason_data=state_reason_data,
            )
        # for 'ignore' the state should be retained
        return

    # collect all non-empty datapoints from the evaluation interval
    collected_datapoints = [val for val in reversed(metric_values) if val is not None]

    # adding empty data points until amount of data points == "evaluation periods"
    evaluation_periods = alarm_details["EvaluationPeriods"]
    while len(collected_datapoints) < evaluation_periods and treat_missing_data in (
        "breaching",
        "notBreaching",
    ):
        # breaching/non-breaching datapoints will be evaluated
        # ignore/missing are not relevant
        collected_datapoints.append(None)

    if is_threshold_exceeded(collected_datapoints, alarm_details):
        update_alarm_state(
            client,
            alarm_name,
            alarm_state,
            StateValue.ALARM,
            THRESHOLD_CROSSED,
            state_reason_data=state_reason_data,
        )
    else:
        update_alarm_state(
            client,
            alarm_name,
            alarm_state,
            StateValue.OK,
            THRESHOLD_CROSSED,
            state_reason_data=state_reason_data,
        )

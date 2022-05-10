import datetime
import ipaddress
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional

from moto.events.responses import EventsHandler as MotoEventsHandler

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.api.events import (
    Boolean,
    EventBusNameOrArn,
    EventPattern,
    EventsApi,
    PutRuleResponse,
    RoleArn,
    RuleDescription,
    RuleName,
    RuleState,
    ScheduleExpression,
    TagList,
)
from localstack.constants import APPLICATION_AMZ_JSON_1_1, TEST_AWS_ACCOUNT_ID
from localstack.services.events.scheduler import JobScheduler
from localstack.services.generic_proxy import RegionBackend
from localstack.services.moto import call_moto
from localstack.utils.aws import aws_stack
from localstack.utils.aws.message_forwarding import send_event_to_target
from localstack.utils.common import TMP_FILES, mkdir, save_file, truncate
from localstack.utils.json import extract_jsonpath
from localstack.utils.strings import long_uid, short_uid

LOG = logging.getLogger(__name__)

# list of events used to run assertions during integration testing (not exposed to the user)
TEST_EVENTS_CACHE = []
EVENTS_TMP_DIR = "cw_events"
DEFAULT_EVENT_BUS_NAME = "default"
CONTENT_BASE_FILTER_KEYWORDS = ["prefix", "anything-but", "numeric", "cidr", "exists"]


class EventsProvider(EventsApi):
    def __init__(self):
        apply_patches()
        JobScheduler.start()

    @staticmethod
    def get_scheduled_rule_func(rule_name: RuleName):
        def func(*args, **kwargs):
            client = aws_stack.connect_to_service("events")
            targets = client.list_targets_by_rule(Rule=rule_name)["Targets"]
            if targets:
                LOG.debug(
                    "Notifying %s targets in response to triggered Events rule %s",
                    len(targets),
                    rule_name,
                )
            for target in targets:
                arn = target.get("Arn")
                event_str = target.get("Input") or "{}"
                event = json.loads(event_str)
                attr = aws_stack.get_events_target_attributes(target)
                try:
                    send_event_to_target(arn, event, target_attributes=attr, target=target)
                except Exception as e:
                    LOG.info(
                        f"Unable to send event notification {truncate(event)} to target {target}: {e}"
                    )

        return func

    @staticmethod
    def convert_schedule_to_cron(schedule):
        """Convert Events schedule like "cron(0 20 * * ? *)" or "rate(5 minutes)" """
        cron_regex = r"\s*cron\s*\(([^\)]*)\)\s*"
        if re.match(cron_regex, schedule):
            cron = re.sub(cron_regex, r"\1", schedule)
            return cron
        rate_regex = r"\s*rate\s*\(([^\)]*)\)\s*"
        if re.match(rate_regex, schedule):
            rate = re.sub(rate_regex, r"\1", schedule)
            value, unit = re.split(r"\s+", rate.strip())
            if "minute" in unit:
                return "*/%s * * * *" % value
            if "hour" in unit:
                return "* */%s * * *" % value
            if "day" in unit:
                return "* * */%s * *" % value
            raise Exception("Unable to parse events schedule expression: %s" % schedule)
        return schedule

    @staticmethod
    def put_rule_job_scheduler(
        name: Optional[RuleName],
        state: Optional[RuleState],
        schedule_expression: Optional[ScheduleExpression],
    ):
        enabled = state != "DISABLED"
        if schedule_expression:
            job_func = EventsProvider.get_scheduled_rule_func(name)
            cron = EventsProvider.convert_schedule_to_cron(schedule_expression)
            LOG.debug("Adding new scheduled Events rule with cron schedule %s", cron)

            job_id = JobScheduler.instance().add_job(job_func, cron, enabled)
            rule_scheduled_jobs = EventsBackend.get().rule_scheduled_jobs
            rule_scheduled_jobs[name] = job_id

    def put_rule(
        self,
        context: RequestContext,
        name: RuleName,
        schedule_expression: ScheduleExpression = None,
        event_pattern: EventPattern = None,
        state: RuleState = None,
        description: RuleDescription = None,
        role_arn: RoleArn = None,
        tags: TagList = None,
        event_bus_name: EventBusNameOrArn = None,
    ) -> PutRuleResponse:
        self.put_rule_job_scheduler(name, state, schedule_expression)
        return call_moto(context)

    def delete_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        force: Boolean = None,
    ) -> None:
        rule_scheduled_jobs = EventsBackend.get().rule_scheduled_jobs
        job_id = rule_scheduled_jobs.get(name)
        if job_id:
            LOG.debug("Removing scheduled Events: {} | job_id: {}".format(name, job_id))
            JobScheduler.instance().cancel_job(job_id=job_id)
        call_moto(context)

    def disable_rule(
        self, context: RequestContext, name: RuleName, event_bus_name: EventBusNameOrArn = None
    ) -> None:
        rule_scheduled_jobs = EventsBackend.get().rule_scheduled_jobs
        job_id = rule_scheduled_jobs.get(name)
        if job_id:
            LOG.debug("Disabling Rule: {} | job_id: {}".format(name, job_id))
            JobScheduler.instance().disable_job(job_id=job_id)
        call_moto(context)


class EventsBackend(RegionBackend):
    # maps rule name to job_id
    rule_scheduled_jobs: Dict[str, str]

    def __init__(self):
        self.rule_scheduled_jobs = {}


def _get_events_tmp_dir():
    return os.path.join(config.dirs.tmp, EVENTS_TMP_DIR)


def _create_and_register_temp_dir():
    tmp_dir = _get_events_tmp_dir()
    if not os.path.exists(tmp_dir):
        mkdir(tmp_dir)
        TMP_FILES.append(tmp_dir)
    return tmp_dir


def _dump_events_to_files(events_with_added_uuid):
    try:
        _create_and_register_temp_dir()
        current_time_millis = int(round(time.time() * 1000))
        for event in events_with_added_uuid:
            target = os.path.join(
                _get_events_tmp_dir(),
                "%s_%s" % (current_time_millis, event["uuid"]),
            )
            save_file(target, json.dumps(event["event"]))
    except Exception as e:
        LOG.info("Unable to dump events to tmp dir %s: %s", _get_events_tmp_dir(), e)


def handle_numeric_conditions(conditions: List[Any], value: float):
    for i in range(0, len(conditions), 2):
        if conditions[i] == "<" and not (value < conditions[i + 1]):
            return False
        if conditions[i] == ">" and not (value > conditions[i + 1]):
            return False
        if conditions[i] == "<=" and not (value <= conditions[i + 1]):
            return False
        if conditions[i] == ">=" and not (value >= conditions[i + 1]):
            return False
    return True


def check_valid_numeric_content_base_rule(list_of_operators):
    if len(list_of_operators) > 4:
        return False

    if "=" in list_of_operators:
        return False

    if len(list_of_operators) > 2:
        upper_limit = None
        lower_limit = None
        for index in range(len(list_of_operators)):
            if not isinstance(list_of_operators[index], int) and "<" in list_of_operators[index]:
                upper_limit = list_of_operators[index + 1]
            if not isinstance(list_of_operators[index], int) and ">" in list_of_operators[index]:
                lower_limit = list_of_operators[index + 1]
            if upper_limit and lower_limit and upper_limit < lower_limit:
                return False
            index = index + 1
    return True


def filter_event_with_content_base_parameter(pattern_value, event_value):
    for element in pattern_value:
        if (isinstance(element, (str, int))) and (event_value == element or element in event_value):
            return True
        elif isinstance(element, dict):
            element_key = list(element.keys())[0]
            element_value = element.get(element_key)
            if element_key.lower() == "prefix":
                if isinstance(event_value, str) and event_value.startswith(element_value):
                    return True
            elif element_key.lower() == "exists":
                if element_value and event_value:
                    return True
                elif not element_value and not event_value:
                    return True
            elif element_key.lower() == "cidr":
                ips = [str(ip) for ip in ipaddress.IPv4Network(element_value)]
                if event_value in ips:
                    return True
            elif element_key.lower() == "numeric":
                if check_valid_numeric_content_base_rule(element_value):
                    for index in range(len(element_value)):
                        if isinstance(element_value[index], int):
                            continue
                        if (
                            element_value[index] == ">"
                            and isinstance(element_value[index + 1], int)
                            and event_value <= element_value[index + 1]
                        ):
                            break
                        elif (
                            element_value[index] == ">="
                            and isinstance(element_value[index + 1], int)
                            and event_value < element_value[index + 1]
                        ):
                            break
                        elif (
                            element_value[index] == "<"
                            and isinstance(element_value[index + 1], int)
                            and event_value >= element_value[index + 1]
                        ):
                            break
                        elif (
                            element_value[index] == "<="
                            and isinstance(element_value[index + 1], int)
                            and event_value > element_value[index + 1]
                        ):
                            break
                    else:
                        return True

            elif element_key.lower() == "anything-but":
                if isinstance(element_value, list) and event_value not in element_value:
                    return True
                elif (isinstance(element_value, (str, int))) and event_value != element_value:
                    return True
                elif isinstance(element_value, dict):
                    nested_key = list(element_value)[0]
                    if nested_key == "prefix" and not re.match(
                        r"^{}".format(element_value.get(nested_key)), event_value
                    ):
                        return True
    return False


# TODO: unclear shared responsibility for filtering with filter_event_with_content_base_parameter
def handle_prefix_filtering(event_pattern, value):
    for element in event_pattern:
        if isinstance(element, (int, str)):
            if str(element) == str(value):
                return True
        elif isinstance(element, dict) and "prefix" in element:
            if value.startswith(element.get("prefix")):
                return True
        elif isinstance(element, dict) and "anything-but" in element:
            if element.get("anything-but") != value:
                return True
        elif "numeric" in element:
            return handle_numeric_conditions(element.get("numeric"), value)
        elif isinstance(element, list):
            if value in list:
                return True
    return False


def identify_content_base_parameter_in_pattern(parameters) -> bool:
    return any(
        list(param.keys())[0] in CONTENT_BASE_FILTER_KEYWORDS
        for param in parameters
        if isinstance(param, dict)
    )


def get_two_lists_intersection(lst1: List, lst2: List) -> List:
    lst3 = [value for value in lst1 if value in lst2]
    return lst3


# TODO: refactor/simplify!
def filter_event_based_on_event_format(self, rule_name: str, event: Dict[str, Any]):
    def filter_event(event_pattern_filter: Dict[str, Any], event: Dict[str, Any]):
        for key, value in event_pattern_filter.items():
            # match keys in the event in a case-agnostic way
            event_value = event.get(key.lower(), event.get(key))
            if event_value is None:
                return False

            # 1. check if certain values in the event do not match the expected pattern
            if event_value and isinstance(event_value, dict):
                for key_a, value_a in event_value.items():
                    if key_a == "ip":
                        # TODO add IP-Address check here
                        continue
                    if isinstance(value.get(key_a), (int, str)):
                        if value_a != value.get(key_a):
                            return False
                    if isinstance(value.get(key_a), list) and value_a not in value.get(key_a):
                        if not handle_prefix_filtering(value.get(key_a), value_a):
                            return False

            # 2. check if the pattern is a list and event values are not contained in it
            if isinstance(value, list):
                if identify_content_base_parameter_in_pattern(value):
                    if not filter_event_with_content_base_parameter(value, event_value):
                        return False
                else:
                    if (
                        isinstance(event_value, list)
                        and get_two_lists_intersection(value, event_value) == []
                    ):
                        return False
                    if (
                        not isinstance(event_value, list)
                        and isinstance(event_value, (str, int))
                        and event_value not in value
                    ):
                        return False

            # 3. recursively call filter_event(..) for dict types
            elif isinstance(value, (str, dict)):
                try:
                    value = json.loads(value) if isinstance(value, str) else value
                    if isinstance(value, dict) and not filter_event(value, event_value):
                        return False
                except json.decoder.JSONDecodeError:
                    return False

        return True

    rule_information = self.events_backend.describe_rule(rule_name)
    if not rule_information:
        LOG.info('Unable to find rule "%s" in backend: %s', rule_name, rule_information)
        return False
    if rule_information.event_pattern._pattern:
        event_pattern = rule_information.event_pattern._pattern
        if not filter_event(event_pattern, event):
            return False
    return True


def filter_event_with_target_input_path(target: Dict, event: Dict) -> Dict:
    input_path = target.get("InputPath")
    if input_path:
        event = extract_jsonpath(event, input_path)
    return event


def process_events(event: Dict, targets: List[Dict]):
    for target in targets:
        arn = target["Arn"]
        changed_event = filter_event_with_target_input_path(target, event)
        if target.get("Input"):
            changed_event = json.loads(target.get("Input"))
        try:
            send_event_to_target(
                arn, changed_event, aws_stack.get_events_target_attributes(target), target=target
            )
        except Exception as e:
            LOG.info(f"Unable to send event notification {truncate(event)} to target {target}: {e}")


# specific logic for put_events which forwards matching events to target listeners
def events_handler_put_events(self):
    entries = self._get_param("Entries")

    # keep track of events for local integration testing
    if config.is_local_test_mode():
        TEST_EVENTS_CACHE.extend(entries)

    events = list(map(lambda event: {"event": event, "uuid": str(long_uid())}, entries))

    _dump_events_to_files(events)
    event_rules = self.events_backend.rules

    for event_envelope in events:
        event = event_envelope["event"]
        event_bus = event.get("EventBusName") or DEFAULT_EVENT_BUS_NAME

        matchine_rules = [r for r in event_rules.values() if r.event_bus_name == event_bus]
        if not matchine_rules:
            continue

        formatted_event = {
            "version": "0",
            "id": event_envelope["uuid"],
            "detail-type": event.get("DetailType"),
            "source": event.get("Source"),
            "account": TEST_AWS_ACCOUNT_ID,
            "time": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "region": self.region,
            "resources": event.get("Resources", []),
            "detail": json.loads(event.get("Detail", "{}")),
        }

        targets = []
        for rule in matchine_rules:
            if filter_event_based_on_event_format(self, rule.name, formatted_event):
                targets.extend(self.events_backend.list_targets_by_rule(rule.name)["Targets"])

        # process event
        process_events(formatted_event, targets)

    content = {
        "FailedEntryCount": 0,  # TODO: dynamically set proper value when refactoring
        "Entries": list(map(lambda event: {"EventId": event["uuid"]}, events)),
    }

    self.response_headers.update(
        {"Content-Type": APPLICATION_AMZ_JSON_1_1, "x-amzn-RequestId": short_uid()}
    )

    return json.dumps(content), self.response_headers


def apply_patches():
    MotoEventsHandler.put_events = events_handler_put_events

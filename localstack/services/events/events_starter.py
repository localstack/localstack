import datetime
import ipaddress
import json
import logging
import re
import uuid
from typing import Any, Dict, List

from moto.events.models import Rule as rule_model
from moto.events.responses import EventsHandler as events_handler

from localstack import config
from localstack.constants import APPLICATION_AMZ_JSON_1_1, TEST_AWS_ACCOUNT_ID
from localstack.services.events.events_listener import (
    DEFAULT_EVENT_BUS_NAME,
    EventsBackend,
    _create_and_register_temp_dir,
    _dump_events_to_files,
)
from localstack.services.events.scheduler import JobScheduler
from localstack.services.infra import start_moto_server
from localstack.utils.aws import aws_stack
from localstack.utils.aws.message_forwarding import send_event_to_target
from localstack.utils.common import extract_jsonpath, short_uid, truncate

LOG = logging.getLogger(__name__)

CONTENT_BASE_FILTER_KEYWORDS = ["prefix", "anything-but", "numeric", "cidr", "exists"]


def filter_event_with_target_input_path(target: Dict, event: Dict) -> Dict:
    input_path = target.get("InputPath")
    if input_path:
        event = extract_jsonpath(event, input_path)
    return event


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


def filter_event_based_on_event_format(self, rule, event: Dict[str, Any]):
    def filter_event(event_pattern_filter: Dict[str, Any], event: Dict[str, Any]):
        for key, value in event_pattern_filter.items():
            event_value = event.get(key.lower())
            if event_value is None:
                return False

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

            elif isinstance(value, list) and not identify_content_base_parameter_in_pattern(value):
                if (
                    isinstance(event_value, list)
                    and get_two_lists_intersection(value, event_value) == []
                ):
                    return False
                elif (
                    not isinstance(event_value, list)
                    and isinstance(event_value, (str, int))
                    and event_value not in value
                ):
                    return False

            elif isinstance(value, list) and identify_content_base_parameter_in_pattern(value):
                if not filter_event_with_content_base_parameter(value, event_value):
                    return False

            elif isinstance(value, (str, dict)):
                try:
                    value = json.loads(value) if isinstance(value, str) else value
                    if isinstance(value, dict) and not filter_event(value, event_value):
                        return False
                except json.decoder.JSONDecodeError:
                    return False
        return True

    rule_information = self.events_backend.describe_rule(rule)
    if not rule_information:
        LOG.info('Unable to find rule "%s" in backend: %s' % (rule, rule_information))
        return False
    if rule_information.event_pattern._pattern:
        event_pattern = rule_information.event_pattern._pattern
        if not filter_event(event_pattern, event):
            return False
    return True


def process_events(event: Dict, targets: List[Dict]):
    for target in targets:
        arn = target["Arn"]
        changed_event = filter_event_with_target_input_path(target, event)
        try:
            send_event_to_target(arn, changed_event, aws_stack.get_events_target_attributes(target))
        except Exception as e:
            LOG.info(f"Unable to send event notification {truncate(event)} to target {target}: {e}")


def apply_patches():
    # Fix events arn
    def rule_model_generate_arn(self, name):
        return "arn:aws:events:{region_name}:{account_id}:rule/{name}".format(
            region_name=self.region_name, account_id=TEST_AWS_ACCOUNT_ID, name=name
        )

    events_handler_put_rule_orig = events_handler.put_rule

    def events_handler_put_rule(self):
        name = self._get_param("Name")
        event_bus = self._get_param("EventBusName") or DEFAULT_EVENT_BUS_NAME

        event_rules = EventsBackend.get().event_rules
        event_rules.setdefault(event_bus, set())
        event_rules[event_bus].add(name)

        return events_handler_put_rule_orig(self)

    events_handler_delete_rule_orig = events_handler.delete_rule

    def events_handler_delete_rule(self):
        name = self._get_param("Name")
        event_bus = self._get_param("EventBusName") or DEFAULT_EVENT_BUS_NAME

        event_rules = EventsBackend.get().event_rules
        rules_set = event_rules.get(event_bus, set())
        if name not in rules_set:
            return self.error(
                "ValidationException",
                'Rule "%s" not found for event bus "%s"' % (name, event_bus),
            )
        rules_set.remove(name)

        return events_handler_delete_rule_orig(self)

    # 2101 Events put-targets does not respond
    def events_handler_put_targets(self):
        event_rules = EventsBackend.get().event_rules

        def is_rule_present(rule_name):
            for rule in event_rules.get(event_bus, []):
                if rule == rule_name:
                    return True
            return False

        rule_name = self._get_param("Rule")
        targets = self._get_param("Targets")
        event_bus = self._get_param("EventBusName") or DEFAULT_EVENT_BUS_NAME

        if not rule_name:
            return self.error("ValidationException", "Parameter Rule is required.")

        if not targets:
            return self.error("ValidationException", "Parameter Targets is required.")

        if not self.events_backend.put_targets(rule_name, event_bus, targets):
            if not is_rule_present(rule_name):
                return self.error(
                    "ResourceNotFoundException",
                    "Rule " + rule_name + " does not exist.",
                )

        return (
            json.dumps({"FailedEntryCount": 0, "FailedEntries": []}),
            self.response_headers,
        )

    def events_handler_put_events(self):
        entries = self._get_param("Entries")
        events = list(map(lambda event: {"event": event, "uuid": str(uuid.uuid4())}, entries))

        _create_and_register_temp_dir()
        _dump_events_to_files(events)
        event_rules = EventsBackend.get().event_rules

        for event_envelope in events:
            event = event_envelope["event"]
            event_bus = event.get("EventBusName") or DEFAULT_EVENT_BUS_NAME

            rules = event_rules.get(event_bus, [])

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
            for rule in rules:
                if filter_event_based_on_event_format(self, rule, formatted_event):
                    targets.extend(self.events_backend.list_targets_by_rule(rule)["Targets"])

            # process event
            process_events(formatted_event, targets)

        content = {"Entries": list(map(lambda event: {"EventId": event["uuid"]}, events))}

        self.response_headers.update(
            {"Content-Type": APPLICATION_AMZ_JSON_1_1, "x-amzn-RequestId": short_uid()}
        )

        return json.dumps(content), self.response_headers

    rule_model._generate_arn = rule_model_generate_arn
    events_handler.put_rule = events_handler_put_rule
    events_handler.delete_rule = events_handler_delete_rule
    events_handler.put_events = events_handler_put_events


def start_scheduler():
    JobScheduler.start()


def start_events(port=None, asynchronous=None, update_listener=None):
    port = port or config.PORT_EVENTS

    apply_patches()
    start_scheduler()

    return start_moto_server(
        key="events",
        port=port,
        name="Cloudwatch Events",
        asynchronous=asynchronous,
        update_listener=update_listener,
    )


# ---------------
# HELPER METHODS
# ---------------


def get_two_lists_intersection(lst1, lst2):
    lst3 = [value for value in lst1 if value in lst2]
    return lst3


def identify_content_base_parameter_in_pattern(parameters):
    if any(
        [
            list(param.keys())[0] in CONTENT_BASE_FILTER_KEYWORDS
            for param in parameters
            if isinstance(param, dict)
        ]
    ):
        return True


def filter_event_with_content_base_parameter(pattern_value, event_value):
    for element in pattern_value:
        if (isinstance(element, (str, int))) and (event_value == element or element in event_value):
            return True
        elif isinstance(element, dict):
            element_key = list(element.keys())[0]
            element_value = element.get(element_key)
            if element_key.lower() == "prefix":
                if re.match(r"^{}".format(element_value), event_value):
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

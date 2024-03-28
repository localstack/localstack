import ipaddress
import json
import re
from typing import Any

CONTENT_BASE_FILTER_KEYWORDS = ["prefix", "anything-but", "numeric", "cidr", "exists"]


# TODO: consider re-naming to matches_rule(event, rule) to match the AWS event-ruler API: https://github.com/aws/event-ruler
# TODO: create companion PR to refactor the copy/pasted implementation in Pipes
def filter_event(event_pattern_filter: dict[str, Any], event: dict[str, Any]):
    """Matches an event_pattern_filter to an event.
    Returns True if the event_pattern_filter matches or False otherwise.
    """
    for key, value in event_pattern_filter.items():
        fallback = object()
        # TODO: why do we need key.lower() and the fallback?
        event_value = event.get(key.lower(), event.get(key, fallback))
        if event_value is fallback and event_pattern_prefix_bool_filter(value):
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
                if isinstance(event_value, list) and is_list_intersection_empty(value, event_value):
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


def event_pattern_prefix_bool_filter(event_pattern_filter_value_list: list[dict[str, Any]]) -> bool:
    for event_pattern_filter_value in event_pattern_filter_value_list:
        if "exists" in event_pattern_filter_value:
            return event_pattern_filter_value.get("exists")
        else:
            return True


def filter_event_with_content_base_parameter(pattern_value: list, event_value: str | int):
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
                elif not element_value and isinstance(event_value, object):
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


def is_list_intersection_empty(list1: list, list2: list) -> bool:
    """Checks if the intersection of two lists is empty.

    Example: is_list_intersection_empty([1, 2, None], [None]) == False

    Following the definition from AWS:
    "If the value in the event is an array, then the event pattern matches if the intersection of the
    event pattern array and the event array is non-empty."
    https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns-arrays.html

    Implementation: set operations are more efficient than using lists
    """
    return len(set(list1) & set(list2)) == 0


# TODO: unclear shared responsibility for filtering with filter_event_with_content_base_parameter
def handle_prefix_filtering(event_pattern, value):
    for element in event_pattern:
        if isinstance(element, (int, str)):
            if str(element) == str(value):
                return True
            if element in value:
                return True
        elif isinstance(element, dict) and "prefix" in element:
            if value.startswith(element.get("prefix")):
                return True
        elif isinstance(element, dict) and "anything-but" in element:
            if element.get("anything-but") != value:
                return True
        elif isinstance(element, dict) and "exists" in element:
            if element.get("exists") and value:
                return True
        elif isinstance(element, dict) and "numeric" in element:
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


def handle_numeric_conditions(conditions: list[Any], value: float):
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

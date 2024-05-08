import ipaddress
import json
import logging
import re
from typing import Any

from localstack.services.events.models import InvalidEventPatternException

CONTENT_BASE_FILTER_KEYWORDS = ["prefix", "anything-but", "numeric", "cidr", "exists"]

LOG = logging.getLogger(__name__)


def matches_event(event_pattern: dict[str, any], event: dict[str, Any]) -> bool:
    """Decides whether an event pattern matches an event or not.
    Returns True if the `event_pattern` matches the given `event` and False otherwise.

    Implements "Amazon EventBridge event patterns":
    https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html
    Used in different places:
    * EventBridge: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html
    * Lambda ESM: https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html
    * EventBridge Pipes: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-filtering.html
    * SNS: https://docs.aws.amazon.com/sns/latest/dg/sns-subscription-filter-policies.html

    Open source AWS rule engine: https://github.com/aws/event-ruler
    """
    for key, value in event_pattern.items():
        fallback = object()
        # Keys are case-sensitive according to the test case `key_case_sensitive_NEG`
        event_value = event.get(key, fallback)
        if event_value is fallback and event_pattern_prefix_bool_filter(value):
            return False

        # 1. check if certain values in the event do not match the expected pattern
        if event_value and isinstance(event_value, dict):
            for key_a, value_a in event_value.items():
                # TODO: why does the ip part appear here again, while cidr is handled in filter_event_with_content_base_parameter?
                if key_a == "cidr":
                    # TODO add IP-Address check here
                    LOG.warning(
                        "Unsupported filter operator cidr. Please create a feature request."
                    )
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

        # 3. recursively call matches_event(..) for dict types
        elif isinstance(value, (str, dict)):
            try:
                # TODO: validate whether inner JSON-encoded strings actually get decoded recursively
                value = json.loads(value) if isinstance(value, str) else value
                if isinstance(event_value, list):
                    return any(matches_event(value, ev) for ev in event_value)
                else:
                    if isinstance(value, dict) and not matches_event(value, event_value):
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
            # Only the first operator gets evaluated and further operators in the list are silently ignored
            operator = list(element.keys())[0]
            element_value = element.get(operator)
            # TODO: why do we implement the operators here again? They are already in handle_prefix_filtering?!
            if operator == "prefix":
                if isinstance(event_value, str) and event_value.startswith(element_value):
                    return True
            elif operator == "exists":
                if element_value and event_value:
                    return True
                elif not element_value and isinstance(event_value, object):
                    return True
            elif operator == "cidr":
                ips = [str(ip) for ip in ipaddress.IPv4Network(element_value)]
                if event_value in ips:
                    return True
            elif operator == "numeric":
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
                        elif (
                            element_value[index] == "="
                            and isinstance(element_value[index + 1], int)
                            and event_value == element_value[index + 1]
                        ):
                            break
                    else:
                        return True

            elif operator == "anything-but":
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
        # TODO: fix direct int or string matching, which is not allowed. A list with possible values is required.
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
            if value in element:
                return True
    return False


def identify_content_base_parameter_in_pattern(parameters) -> bool:
    return any(
        list(param.keys())[0] in CONTENT_BASE_FILTER_KEYWORDS
        for param in parameters
        if isinstance(param, dict)
    )


def check_valid_numeric_content_base_rule(list_of_operators):
    # TODO: validate?
    if len(list_of_operators) > 4:
        return False

    # TODO: Why?
    if "=" in list_of_operators:
        return False

    if len(list_of_operators) > 2:
        upper_limit = None
        lower_limit = None
        # TODO: what is this for, why another operator check?
        for index in range(len(list_of_operators)):
            if not isinstance(list_of_operators[index], int) and "<" in list_of_operators[index]:
                upper_limit = list_of_operators[index + 1]
            if not isinstance(list_of_operators[index], int) and ">" in list_of_operators[index]:
                lower_limit = list_of_operators[index + 1]
            if upper_limit and lower_limit and upper_limit < lower_limit:
                return False
    return True


def handle_numeric_conditions(conditions: list[any], value: int | float):
    """Implements numeric matching for a given list of conditions.
    Example: { "numeric": [ ">", 0, "<=", 5 ] }

    Numeric matching works with values that are JSON numbers.
    It is limited to values between -5.0e9 and +5.0e9 inclusive, with 15 digits of precision,
    or six digits to the right of the decimal point.
    https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns-content-based-filtering.html#filtering-numeric-matchinghttps://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns-content-based-filtering.html#filtering-numeric-matching
    """

    # Invalid example for uneven list: { "numeric": [ ">", 0, "<" ] }
    if len(conditions) % 2 > 0:
        raise InvalidEventPatternException("Bad numeric range operator")

    if not isinstance(value, (int, float)):
        raise InvalidEventPatternException(
            f"The value {value} for the numeric comparison {conditions} is not a valid number"
        )

    for i in range(0, len(conditions), 2):
        operator = conditions[i]
        second_operand_str = conditions[i + 1]
        try:
            second_operand = float(second_operand_str)
        except ValueError:
            raise InvalidEventPatternException(
                f"Could not convert filter value {second_operand_str} to a valid number"
            )

        if operator == "<" and not (value < second_operand):
            return False
        if operator == ">" and not (value > second_operand):
            return False
        if operator == "<=" and not (value <= second_operand):
            return False
        if operator == ">=" and not (value >= second_operand):
            return False
        if operator == "=" and not (value == second_operand):
            return False
    return True

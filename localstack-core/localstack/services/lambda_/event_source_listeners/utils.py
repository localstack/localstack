import json
import logging
import re

from localstack import config
from localstack.aws.api.lambda_ import FilterCriteria
from localstack.services.events.event_ruler import matches_rule
from localstack.utils.strings import first_char_to_lower

LOG = logging.getLogger(__name__)


class InvalidEventPatternException(Exception):
    reason: str

    def __init__(self, reason=None, message=None) -> None:
        self.reason = reason
        self.message = message or f"Event pattern is not valid. Reason: {reason}"


def filter_stream_records(records, filters: list[FilterCriteria]):
    filtered_records = []
    for record in records:
        for filter in filters:
            for rule in filter["Filters"]:
                if config.EVENT_RULE_ENGINE == "java":
                    event_str = json.dumps(record)
                    event_pattern_str = rule["Pattern"]
                    match_result = matches_rule(event_str, event_pattern_str)
                else:
                    filter_pattern: dict[str, any] = json.loads(rule["Pattern"])
                    match_result = does_match_event(filter_pattern, record)
                if match_result:
                    filtered_records.append(record)
                    break
    return filtered_records


def does_match_event(event_pattern: dict[str, any], event: dict[str, any]) -> bool:
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
    # TODO: test this conditional: https://coveralls.io/builds/66584026/source?filename=localstack%2Fservices%2Flambda_%2Fevent_source_listeners%2Futils.py#L25
    if not event_pattern:
        return True
    does_match_results = []
    for key, value in event_pattern.items():
        # check if rule exists in event
        event_value = event.get(key) if isinstance(event, dict) else None
        does_pattern_match = False
        if event_value is not None:
            # check if filter rule value is a list (leaf of rule tree) or a dict (recursively call function)
            if isinstance(value, list):
                if len(value) > 0:
                    if isinstance(value[0], (str, int)):
                        does_pattern_match = event_value in value
                    if isinstance(value[0], dict):
                        does_pattern_match = verify_dict_filter(event_value, value[0])
                else:
                    LOG.warning(f"Empty lambda filter: {key}")
            elif isinstance(value, dict):
                does_pattern_match = does_match_event(value, event_value)
        else:
            # special case 'exists'
            def _filter_rule_value_list(val):
                if isinstance(val[0], dict):
                    return not val[0].get("exists", True)
                elif val[0] is None:
                    # support null filter
                    return True

            def _filter_rule_value_dict(val):
                for k, v in val.items():
                    return (
                        _filter_rule_value_list(val[k])
                        if isinstance(val[k], list)
                        else _filter_rule_value_dict(val[k])
                    )
                return True

            if isinstance(value, list) and len(value) > 0:
                does_pattern_match = _filter_rule_value_list(value)
            elif isinstance(value, dict):
                # special case 'exists' for S type, e.g. {"S": [{"exists": false}]}
                # https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Streams.Lambda.Tutorial2.html
                does_pattern_match = _filter_rule_value_dict(value)

        does_match_results.append(does_pattern_match)
    return all(does_match_results)


def verify_dict_filter(record_value: any, dict_filter: dict[str, any]) -> bool:
    # https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html#filtering-syntax
    does_match_filter = False
    for key, filter_value in dict_filter.items():
        if key == "anything-but":
            does_match_filter = record_value not in filter_value
        elif key == "numeric":
            does_match_filter = handle_numeric_conditions(record_value, filter_value)
        elif key == "exists":
            does_match_filter = bool(
                filter_value
            )  # exists means that the key exists in the event record
        elif key == "prefix":
            if not isinstance(record_value, str):
                LOG.warning(f"Record Value {record_value} does not seem to be a valid string.")
            does_match_filter = isinstance(record_value, str) and record_value.startswith(
                str(filter_value)
            )
        if does_match_filter:
            return True

    return does_match_filter


def handle_numeric_conditions(
    first_operand: int | float, conditions: list[str | int | float]
) -> bool:
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

    if not isinstance(first_operand, (int, float)):
        raise InvalidEventPatternException(
            f"The value {first_operand} for the numeric comparison {conditions} is not a valid number"
        )

    for i in range(0, len(conditions), 2):
        operator = conditions[i]
        second_operand_str = conditions[i + 1]
        try:
            second_operand = float(second_operand_str)
        except ValueError:
            raise InvalidEventPatternException(
                f"Could not convert filter value {second_operand_str} to a valid number"
            ) from ValueError

        if operator == ">" and not (first_operand > second_operand):
            return False
        if operator == ">=" and not (first_operand >= second_operand):
            return False
        if operator == "=" and not (first_operand == second_operand):
            return False
        if operator == "<" and not (first_operand < second_operand):
            return False
        if operator == "<=" and not (first_operand <= second_operand):
            return False
    return True


def contains_list(filter: dict) -> bool:
    if isinstance(filter, dict):
        for key, value in filter.items():
            if isinstance(value, list) and len(value) > 0:
                return True
            return contains_list(value)
    return False


def validate_filters(filter: FilterCriteria) -> bool:
    # filter needs to be json serializeable
    for rule in filter["Filters"]:
        try:
            if not (filter_pattern := json.loads(rule["Pattern"])):
                return False
            return contains_list(filter_pattern)
        except json.JSONDecodeError:
            return False
    # needs to contain on what to filter (some list with citerias)
    # https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html#filtering-syntax

    return True


def message_attributes_to_lower(message_attrs):
    """Convert message attribute details (first characters) to lower case (e.g., stringValue, dataType)."""
    message_attrs = message_attrs or {}
    for _, attr in message_attrs.items():
        if not isinstance(attr, dict):
            continue
        for key, value in dict(attr).items():
            attr[first_char_to_lower(key)] = attr.pop(key)
    return message_attrs


def event_source_arn_matches(mapped: str, searched: str) -> bool:
    if not mapped:
        return False
    if not searched or mapped == searched:
        return True
    # Some types of ARNs can end with a path separated by slashes, for
    # example the ARN of a DynamoDB stream is tableARN/stream/ID. It's
    # a little counterintuitive that a more specific mapped ARN can
    # match a less specific ARN on the event, but some integration tests
    # rely on it for things like subscribing to a stream and matching an
    # event labeled with the table ARN.
    if re.match(r"^%s$" % searched, mapped):
        return True
    if mapped.startswith(searched):
        suffix = mapped[len(searched) :]
        return suffix[0] == "/"
    return False


def has_data_filter_criteria(filters: list[FilterCriteria]) -> bool:
    for filter in filters:
        for rule in filter.get("Filters", []):
            parsed_pattern = json.loads(rule["Pattern"])
            if "data" in parsed_pattern:
                return True
    return False

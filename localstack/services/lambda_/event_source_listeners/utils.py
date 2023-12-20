import json
import logging
import re
from typing import Dict, List, Union

from localstack.aws.api.lambda_ import FilterCriteria
from localstack.utils.strings import first_char_to_lower

LOG = logging.getLogger(__name__)


def filter_stream_records(records, filters: List[FilterCriteria]):
    filtered_records = []
    for record in records:
        for filter in filters:
            for rule in filter["Filters"]:
                if filter_stream_record(json.loads(rule["Pattern"]), record):
                    filtered_records.append(record)
                    break
    return filtered_records


def filter_stream_record(filter_rule: Dict[str, any], record: Dict[str, any]) -> bool:
    if not filter_rule:
        return True
    # https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html#filtering-syntax
    filter_results = []
    for key, value in filter_rule.items():
        # check if rule exists in event
        record_value = (
            record.get(key.lower(), record.get(key)) if isinstance(record, Dict) else None
        )
        append_record = False
        if record_value is not None:
            # check if filter rule value is a list (leaf of rule tree) or a dict (rescursively call function)
            if isinstance(value, list):
                if len(value) > 0:
                    if isinstance(value[0], (str, int)):
                        append_record = record_value in value
                    if isinstance(value[0], dict):
                        append_record = verify_dict_filter(record_value, value[0])
                else:
                    LOG.warning(f"Empty lambda filter: {key}")
            elif isinstance(value, dict):
                append_record = filter_stream_record(value, record_value)
        else:
            # special case 'exists'
            if isinstance(value, list) and len(value) > 0:
                if isinstance(value[0], dict):
                    append_record = not value[0].get("exists", True)
                elif value[0] is None:
                    # support null filter
                    append_record = True

        filter_results.append(append_record)
    return all(filter_results)


def verify_dict_filter(record_value: any, dict_filter: Dict[str, any]) -> bool:
    # https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html#filtering-syntax
    fits_filter = False
    for key, filter_value in dict_filter.items():
        if key.lower() == "anything-but":
            fits_filter = record_value not in filter_value
        elif key.lower() == "numeric":
            fits_filter = parse_and_apply_numeric_filter(record_value, filter_value)
        elif key.lower() == "exists":
            fits_filter = bool(filter_value)  # exists means that the key exists in the event record
        elif key.lower() == "prefix":
            if not isinstance(record_value, str):
                LOG.warning(f"Record Value {record_value} does not seem to be a valid string.")
            fits_filter = isinstance(record_value, str) and record_value.startswith(
                str(filter_value)
            )

        if fits_filter:
            return True
    return fits_filter


def parse_and_apply_numeric_filter(
    record_value: Dict, numeric_filter: List[Union[str, int]]
) -> bool:
    if len(numeric_filter) % 2 > 0:
        LOG.warning("Invalid numeric lambda filter given")
        return True

    if not isinstance(record_value, (int, float)):
        LOG.warning(f"Record {record_value} seem not to be a valid number")
        return False

    for idx in range(0, len(numeric_filter), 2):
        try:
            if numeric_filter[idx] == ">" and not (record_value > float(numeric_filter[idx + 1])):
                return False
            if numeric_filter[idx] == ">=" and not (record_value >= float(numeric_filter[idx + 1])):
                return False
            if numeric_filter[idx] == "=" and not (record_value == float(numeric_filter[idx + 1])):
                return False
            if numeric_filter[idx] == "<" and not (record_value < float(numeric_filter[idx + 1])):
                return False
            if numeric_filter[idx] == "<=" and not (record_value <= float(numeric_filter[idx + 1])):
                return False
        except ValueError:
            LOG.warning(
                f"Could not convert filter value {numeric_filter[idx + 1]} to a valid number value for filtering"
            )
    return True


def contains_list(filter: Dict) -> bool:
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


def has_data_filter_criteria(filters: List[FilterCriteria]) -> bool:
    for filter in filters:
        for rule in filter.get("Filters", []):
            parsed_pattern = json.loads(rule["Pattern"])
            if "data" in parsed_pattern:
                return True
    return False

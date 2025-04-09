import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from botocore.utils import ArnParser

from localstack.aws.api import RequestContext
from localstack.aws.api.events import (
    ArchiveName,
    Arn,
    ConnectionArn,
    ConnectionName,
    EventBusName,
    EventBusNameOrArn,
    EventTime,
    PutEventsRequestEntry,
    RuleArn,
    Timestamp,
)
from localstack.services.events.models import (
    FormattedEvent,
    ResourceType,
    TransformedEvent,
    ValidationException,
)
from localstack.utils.aws.arns import ARN_PARTITION_REGEX, parse_arn
from localstack.utils.strings import long_uid

LOG = logging.getLogger(__name__)

RULE_ARN_CUSTOM_EVENT_BUS_PATTERN = re.compile(
    rf"{ARN_PARTITION_REGEX}:events:[a-z0-9-]+:\d{{12}}:rule/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+$"
)

RULE_ARN_ARCHIVE_PATTERN = re.compile(
    rf"{ARN_PARTITION_REGEX}:events:[a-z0-9-]+:\d{{12}}:archive/[a-zA-Z0-9_-]+$"
)
ARCHIVE_NAME_ARN_PATTERN = re.compile(
    rf"{ARN_PARTITION_REGEX}:events:[a-z0-9-]+:\d{{12}}:archive/(?P<name>.+)$"
)
CONNECTION_NAME_ARN_PATTERN = re.compile(
    rf"{ARN_PARTITION_REGEX}:events:[a-z0-9-]+:\d{{12}}:connection/(?P<name>[^/]+)/(?P<id>[^/]+)$"
)

TARGET_ID_PATTERN = re.compile(r"[\.\-_A-Za-z0-9]+")


class EventJSONEncoder(json.JSONEncoder):
    """This json encoder is used to serialize datetime object
    of a eventbridge event to time strings."""

    def default(self, obj):
        if isinstance(obj, datetime):
            return event_time_to_time_string(obj)
        return super().default(obj)


def to_json_str(obj: Any, separators: Optional[tuple[str, str]] = (",", ":")) -> str:
    return json.dumps(obj, cls=EventJSONEncoder, separators=separators)


def extract_region_and_account_id(
    name_or_arn: EventBusNameOrArn, context: RequestContext
) -> tuple[str, str]:
    """Returns the region and account id from the arn,
    or falls back on the region and account id of the context"""
    account_id = None
    region = None
    if ArnParser.is_arn(name_or_arn):
        parsed_arn = parse_arn(name_or_arn)
        region = parsed_arn.get("region")
        account_id = parsed_arn.get("account")
    if not account_id or not region:
        region = context.get("region")
        account_id = context.get("account_id")
    return region, account_id


def extract_event_bus_name(
    resource_arn_or_name: EventBusNameOrArn | RuleArn | None,
) -> EventBusName:
    """Return the event bus name. Input can be either an event bus name or ARN."""
    if not resource_arn_or_name:
        return "default"
    if not re.match(f"{ARN_PARTITION_REGEX}:events", resource_arn_or_name):
        return resource_arn_or_name
    resource_type = get_resource_type(resource_arn_or_name)
    if resource_type == ResourceType.EVENT_BUS:
        return resource_arn_or_name.split("/")[-1]
    if resource_type == ResourceType.RULE:
        if bool(RULE_ARN_CUSTOM_EVENT_BUS_PATTERN.match(resource_arn_or_name)):
            return resource_arn_or_name.split("rule/", 1)[1].split("/", 1)[0]
        return "default"


def extract_connection_name(
    connection_arn: ConnectionArn,
) -> ConnectionName:
    match = CONNECTION_NAME_ARN_PATTERN.match(connection_arn)
    if not match:
        raise ValidationException(
            f"Parameter {connection_arn} is not valid. Reason: Provided Arn is not in correct format."
        )
    return match.group("name")


def extract_archive_name(arn: Arn) -> ArchiveName:
    match = ARCHIVE_NAME_ARN_PATTERN.match(arn)
    if not match:
        raise ValidationException(
            f"Parameter {arn} is not valid. Reason: Provided Arn is not in correct format."
        )
    return match.group("name")


def is_archive_arn(arn: Arn) -> bool:
    return bool(RULE_ARN_ARCHIVE_PATTERN.match(arn))


def get_resource_type(arn: Arn) -> ResourceType:
    parsed_arn = parse_arn(arn)
    resource_type = parsed_arn["resource"].split("/", 1)[0]
    if resource_type == "event-bus":
        return ResourceType.EVENT_BUS
    if resource_type == "rule":
        return ResourceType.RULE
    raise ValidationException(
        f"Parameter {arn} is not valid. Reason: Provided Arn is not in correct format."
    )


def get_event_time(event: PutEventsRequestEntry) -> EventTime:
    event_time = datetime.now(timezone.utc)
    if event_timestamp := event.get("Time"):
        try:
            # use time from event if provided
            event_time = event_timestamp.replace(tzinfo=timezone.utc)
        except ValueError:
            # use current time if event time is invalid
            LOG.debug(
                "Could not parse the `Time` parameter, falling back to current time for the following Event: '%s'",
                event,
            )
    return event_time


def event_time_to_time_string(event_time: EventTime) -> str:
    return event_time.strftime("%Y-%m-%dT%H:%M:%SZ")


def convert_to_timezone_aware_datetime(
    timestamp: Timestamp,
) -> Timestamp:
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp


def recursive_remove_none_values_from_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively removes keys with non values from a dictionary.
    """
    if not isinstance(d, dict):
        return d

    clean_dict = {}
    for key, value in d.items():
        if value is None:
            continue
        if isinstance(value, list):
            nested_list = [recursive_remove_none_values_from_dict(item) for item in value]
            nested_list = [item for item in nested_list if item]
            if nested_list:
                clean_dict[key] = nested_list
        elif isinstance(value, dict):
            nested_dict = recursive_remove_none_values_from_dict(value)
            if nested_dict:
                clean_dict[key] = nested_dict
        else:
            clean_dict[key] = value
    return clean_dict


def format_event(
    event: PutEventsRequestEntry, region: str, account_id: str, event_bus_name: EventBusName
) -> FormattedEvent:
    # See https://docs.aws.amazon.com/AmazonS3/latest/userguide/ev-events.html
    trace_header = event.get("TraceHeader")
    message = {}
    if trace_header:
        try:
            message = json.loads(trace_header)
        except json.JSONDecodeError:
            pass
    message_id = message.get("original_id", str(long_uid()))
    region = message.get("original_region", region)
    account_id = message.get("original_account", account_id)
    # Format the datetime to ISO-8601 string
    event_time = get_event_time(event)
    formatted_time = event_time_to_time_string(event_time)

    formatted_event = {
        "version": "0",
        "id": message_id,
        "detail-type": event.get("DetailType"),
        "source": event.get("Source"),
        "account": account_id,
        "time": formatted_time,
        "region": region,
        "resources": event.get("Resources", []),
        "detail": json.loads(event.get("Detail", "{}")),
        "event-bus-name": event_bus_name,  # current workaround for EventStudio extension
    }
    if replay_name := event.get("ReplayName"):
        formatted_event["replay-name"] = replay_name  # required for replay from archive

    return formatted_event


def re_format_event(event: FormattedEvent, event_bus_name: EventBusName) -> PutEventsRequestEntry:
    """Transforms the event to the original event structure."""
    re_formatted_event = {
        "Source": event["source"],
        "DetailType": event[
            "detail-type"
        ],  # detail_type automatically interpreted as detail-type in typedict
        "Detail": json.dumps(event["detail"]),
        "Time": event["time"],
    }
    if event.get("resources"):
        re_formatted_event["Resources"] = event["resources"]
    if event_bus_name:
        re_formatted_event["EventBusName"] = event_bus_name
    if event.get("replay-name"):
        re_formatted_event["ReplayName"] = event["replay_name"]
    return re_formatted_event


def get_trace_header_encoded_region_account(
    event: PutEventsRequestEntry | FormattedEvent | TransformedEvent,
    source_region: str,
    source_account_id: str,
    target_region: str,
    target_account_id: str,
) -> str | None:
    """Encode the original region and account_id for cross-region and cross-account
    event bus communication in the trace header. For event bus to event bus communication
    in a different account the event id is preserved. This is not the case if the region differs."""
    if event.get("TraceHeader"):
        return None
    if source_region != target_region and source_account_id != target_account_id:
        return json.dumps(
            {
                "original_region": source_region,
                "original_account": source_account_id,
            }
        )
    if source_region != target_region:
        return json.dumps({"original_region": source_region})
    if source_account_id != target_account_id:
        if original_id := event.get("id"):
            return json.dumps({"original_id": original_id, "original_account": source_account_id})
        else:
            return json.dumps({"original_account": source_account_id})


def is_nested_in_string(template: str, match: re.Match[str]) -> bool:
    """
    Determines if a match (string) is within quotes in the given template.

    Examples:
    True for "users-service/users/<userId>"  # nested within larger string
    True for "<userId>"                      # simple quoted placeholder
    True for "Hello <name>"                  # nested within larger string
    False for {"id": <userId>}               # not in quotes at all
    """
    start = match.start()
    end = match.end()

    left_quote = template.rfind('"', 0, start)
    right_quote = template.find('"', end)
    next_comma = template.find(",", end)
    next_brace = template.find("}", end)

    # If no right quote, or if comma/brace comes before right quote, not nested
    if (
        right_quote == -1
        or (next_comma != -1 and next_comma < right_quote)
        or (next_brace != -1 and next_brace < right_quote)
    ):
        return False

    return left_quote != -1

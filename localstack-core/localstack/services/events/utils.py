import re

from localstack.aws.api.events import (
    Arn,
    EventBusName,
    EventBusNameOrArn,
    RuleArn,
)
from localstack.services.events.models import (
    ResourceType,
    ValidationException,
)
from localstack.utils.aws.arns import parse_arn

RULE_ARN_CUSTOM_EVENT_BUS_PATTERN = re.compile(
    r"^arn:aws:events:[a-z0-9-]+:\d{12}:rule/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+$"
)


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


def extract_event_bus_name(
    resource_arn_or_name: EventBusNameOrArn | RuleArn | None,
) -> EventBusName:
    """Return the event bus name. Input can be either an event bus name or ARN."""
    if not resource_arn_or_name:
        return "default"
    if "arn:aws:events" not in resource_arn_or_name:
        return resource_arn_or_name
    resource_type = get_resource_type(resource_arn_or_name)
    # TODO how to deal with / in event bus name or rule name
    if resource_type == ResourceType.EVENT_BUS:
        return resource_arn_or_name.split("/")[-1]
    if resource_type == ResourceType.RULE:
        if bool(RULE_ARN_CUSTOM_EVENT_BUS_PATTERN.match(resource_arn_or_name)):
            return resource_arn_or_name.split("rule/", 1)[1].split("/", 1)[0]
        return "default"


from typing import Any, Dict


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

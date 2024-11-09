import json
from typing import Union, Dict, Any

from localstack import config
from localstack.services.events.v1.utils import matches_event as python_matches_event
from localstack.services.events.event_ruler import matches_rule as java_matches_rule


def matches_event(
    event_pattern: Union[str, Dict[str, Any]], 
    event: Union[str, Dict[str, Any]]
) -> bool:
    """
    Match an event against an event pattern using the configured rule engine.

    Args:
        event_pattern: Event pattern to match against (string or dictionary)
        event: Event to check (string or dictionary)

    Returns:
        bool: Whether the event matches the pattern
    """
    # Normalize inputs to dictionaries if they are strings
    if isinstance(event_pattern, str):
        event_pattern = json.loads(event_pattern)
    if isinstance(event, str):
        event = json.loads(event)

    # Use Java rule engine by default
    if config.EVENT_RULE_ENGINE == "java":
        # Convert back to JSON strings for Java rule engine
        return java_matches_rule(
            json.dumps(event_pattern), 
            json.dumps(event)
        )
    else:
        # Use Python rule engine
        return python_matches_event(event_pattern, event)


def validate_event_pattern(event_pattern: Union[str, Dict[str, Any]]) -> bool:
    """
    Validate the structure of an event pattern.

    Args:
        event_pattern: Event pattern to validate

    Returns:
        bool: Whether the event pattern is valid
    """
    try:
        # Normalize to dictionary if it's a string
        if isinstance(event_pattern, str):
            event_pattern = json.loads(event_pattern)
        
        # Basic validation - could be expanded
        if not isinstance(event_pattern, dict):
            return False
        
        return True
    except (json.JSONDecodeError, TypeError):
        return False

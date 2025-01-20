import json
from typing import Any

from localstack import config
from localstack.services.events.event_rule_engine import (
    EventPatternCompiler,
    EventRuleEngine,
    InvalidEventPatternException,
)
from localstack.services.events.event_ruler import matches_rule

_event_pattern_compiler = EventPatternCompiler()
_event_rule_engine = EventRuleEngine()


def matches_event(event_pattern: dict[str, Any] | str | None, event: dict[str, Any] | str) -> bool:
    """
    Match events based on configured rule engine.

    Note: Different services handle patterns/events differently:
    - EventBridge uses strings
    - ESM and Pipes use dicts

    Args:
        event_pattern: Event pattern (str for EventBridge, dict for ESM/Pipes)
        event: Event to match against pattern (str for EventBridge, dict for ESM/Pipes)

    Returns:
        bool: True if event matches pattern, False otherwise

    Examples:
        # EventBridge (string-based):
        >>> pattern = '{"source": ["aws.ec2"]}'
        >>> event = '{"source": "aws.ec2"}'

        # ESM/Pipes (dict-based):
        >>> pattern = {"source": ["aws.ec2"]}
        >>> event = {"source": "aws.ec2"}

    References:
        - EventBridge Patterns: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html
        - EventBridge Pipes: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-filtering.html
        - Event Source Mappings: https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html
    """
    if not event_pattern:
        return True

    if config.EVENT_RULE_ENGINE == "java":
        # If inputs are already strings (EventBridge), use directly
        if isinstance(event, str) and isinstance(event_pattern, str):
            return matches_rule(event, event_pattern)
        # Convert dicts (ESM/Pipes) to strings for Java engine
        event_str = event if isinstance(event, str) else json.dumps(event)
        pattern_str = event_pattern if isinstance(event_pattern, str) else json.dumps(event_pattern)
        return matches_rule(event_str, pattern_str)

    # Python implementation (default)
    compiled_event_pattern = _event_pattern_compiler.compile_event_pattern(
        event_pattern=event_pattern
    )
    return _event_rule_engine.evaluate_pattern_on_event(
        compiled_event_pattern=compiled_event_pattern,
        event=event,
    )


def validate_event_pattern(event_pattern: dict[str, Any] | str | None) -> bool:
    try:
        _ = _event_pattern_compiler.compile_event_pattern(event_pattern=event_pattern)
    except InvalidEventPatternException:
        return False

    return True

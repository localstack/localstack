# localstack/utils/event_matcher.py
import json
from typing import Dict, Union
from localstack import config
from localstack.services.events.event_ruler import matches_rule
from localstack.services.events.v1.utils import matches_event as python_matches_event

def matches_event(event_pattern: Union[Dict, str], event: Union[Dict, str]) -> bool:
    """
    Match events based on configured rule engine.
    Note: Different services handle patterns/events differently:
    - EventBridge uses strings 
    - ESM and Pipes use dicts
    """
    if config.EVENT_RULE_ENGINE == "java":
        # If inputs are already strings (EventBridge), use directly
        if isinstance(event, str) and isinstance(event_pattern, str):
            return matches_rule(event, event_pattern)
        # Convert dicts (ESM/Pipes) to strings for Java engine
        event_str = event if isinstance(event, str) else json.dumps(event)
        pattern_str = event_pattern if isinstance(event_pattern, str) else json.dumps(event_pattern)
        return matches_rule(event_str, pattern_str)
    
    # Python implementation needs dicts
    event_dict = json.loads(event) if isinstance(event, str) else event
    pattern_dict = json.loads(event_pattern) if isinstance(event_pattern, str) else event_pattern
    return python_matches_event(pattern_dict, event_dict)
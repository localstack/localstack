import json
import os
import re
from typing import Dict, Set, Tuple

import botocore

from localstack.utils.files import load_file
from localstack.utils.strings import to_bytes, to_str

# maps service names/versions to list of action names
SERVICE_ACTIONS_CACHE: Dict[str, Set[str]] = {}

# default service versions
DEFAULT_SERVICE_VERSIONS: Dict[str, str] = {
    "sns": "2010-03-31",
    "sqs": "2012-11-05",
}

# regexes to extract info from URL paths / payloads
_REGEX_ACTION = r"(^|.*\?|.*&)Action=([a-zA-Z0-9_]+)($|&)"
_REGEX_VERSION = r"(^|.*\?|.*&)Version=([a-zA-Z0-9_]+)($|&)"
REGEX_ACTION: re.Pattern = re.compile(_REGEX_ACTION)
REGEX_VERSION: re.Pattern = re.compile(_REGEX_VERSION)
REGEXB_ACTION: re.Pattern = re.compile(to_bytes(_REGEX_ACTION))
REGEXB_VERSION: re.Pattern = re.compile(to_bytes(_REGEX_VERSION))

# TODO: Add more comprehensive tests for AWS SDK v2. It seems that
#  the v2 SDK (e.g., from Java) in certain configurations is not sending
#  the Authorization header we depend on. We can use some of the heuristics
#  below for routing requests to the correct target services (based on
#  'Action' or 'Version' attributes in the request), but the more severe issue
#  seems to be that the region info is not being transmitted in certain
#  situations. If this turns out to be true, then we may need to think about
#  a more comprehensive refactoring of our routing/region-targeting approach.


def get_service_action_names(service: str, version: str = None) -> Set[str]:
    """Returns, for a given service name and version, the list of available service action names."""
    version = version or DEFAULT_SERVICE_VERSIONS.get(service)
    key = f"{service}:{version}"
    result = SERVICE_ACTIONS_CACHE.get(key)
    if not result:
        file_path = os.path.join(
            os.path.dirname(botocore.__file__), "data", service, version, "service-2.json"
        )
        content = json.loads(to_str(load_file(file_path)) or "{}")
        result = set(content.get("operations", {}).keys())
        SERVICE_ACTIONS_CACHE[key] = result
    return result


def matches_service_action(service: str, action: str, version: str = None):
    action_names = get_service_action_names(service, version=version)
    return action in action_names


def extract_version_and_action(path: str, data_bytes: bytes) -> Tuple[str, str]:
    """Extract Version=... and Action=... info from request path and/or data bytes."""
    result = {}
    candidates = (
        ("version", REGEX_VERSION, REGEXB_VERSION),
        ("action", REGEX_ACTION, REGEXB_ACTION),
    )
    for attr, regex, regexb in candidates:
        match = regex.match(path)
        if match:
            result[attr] = match.group(2)
        else:
            match = regexb.match(data_bytes)
            if match:
                result[attr] = match.group(2)

    version = to_str(result.get("version") or "") or None
    action = to_str(result.get("action") or "") or None
    return version, action

from typing import (
    Any,
    Mapping,
    TypeVar,
)

from rolo.routing import (
    PortConverter,
    RegexConverter,
    Router,
    RuleAdapter,
    RuleGroup,
    WithHost,
    route,
)
from rolo.routing.router import Dispatcher, call_endpoint
from werkzeug.routing import PathConverter

HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE")

E = TypeVar("E")
RequestArguments = Mapping[str, Any]


class GreedyPathConverter(PathConverter):
    """
    This converter makes sure that the path ``/mybucket//mykey`` can be matched to the pattern
    ``<Bucket>/<path:Key>`` and will result in `Key` being `/mykey`.
    """

    regex = ".*?"

    part_isolating = False
    """From the werkzeug docs: If a custom converter can match a forward slash, /, it should have the
    attribute part_isolating set to False. This will ensure that rules using the custom converter are
    correctly matched."""


__all__ = [
    "RequestArguments",
    "HTTP_METHODS",
    "RegexConverter",
    "PortConverter",
    "Dispatcher",
    "route",
    "call_endpoint",
    "Router",
    "RuleAdapter",
    "WithHost",
    "RuleGroup",
    "GreedyPathConverter",
]

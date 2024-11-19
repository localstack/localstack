import datetime
from typing import Final

from localstack.services.stepfunctions.asl.component.common.jsonata.jsonata_template_value_terminal import (
    JSONataTemplateValueTerminalExpression,
)
from localstack.services.stepfunctions.asl.component.state.state_wait.wait_function.wait_function import (
    WaitFunction,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment

TIMESTAMP_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%SZ"
# TODO: could be a bit more exact (e.g. 90 shouldn't be a valid minute)
TIMESTAMP_PATTERN: Final[str] = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$"


def parse_timestamp(timestamp: str) -> datetime.datetime:
    # TODO: need to fix this like we're doing for TimestampPath & add a test
    return datetime.datetime.strptime(timestamp, TIMESTAMP_FORMAT)


class Timestamp(WaitFunction):
    # Timestamp
    # An absolute time to state_wait until beginning the state specified in the Next field.
    # Timestamps must conform to the RFC3339 profile of ISO 8601, with the further
    # restrictions that an uppercase T must separate the date and time portions, and
    # an uppercase Z must denote that a numeric time zone offset is not present, for
    # example, 2016-08-18T17:33:00Z.
    # Note
    # Currently, if you specify the state_wait time as a timestamp, Step Functions considers
    # the time value up to seconds and truncates milliseconds.

    def __init__(self, timestamp_literal: str):
        self.timestamp: Final[datetime.datetime] = parse_timestamp(timestamp_literal)

    def _get_wait_seconds(self, env: Environment) -> int:
        delta = self.timestamp - datetime.datetime.now()
        delta_sec = int(delta.total_seconds())
        return delta_sec


class TimestampJSONata(WaitFunction):
    jsonata_template_value_terminal_expression: Final[JSONataTemplateValueTerminalExpression]

    def __init__(
        self, jsonata_template_value_terminal_expression: JSONataTemplateValueTerminalExpression
    ):
        super().__init__()
        self.jsonata_template_value_terminal_expression = jsonata_template_value_terminal_expression

    def _get_wait_seconds(self, env: Environment) -> int:
        # TODO: add snapshot tests to verify AWS's behaviour about invalid values.
        self.jsonata_template_value_terminal_expression.eval(env=env)
        timestamp_str: str = env.stack.pop()
        timestamp_datetime = parse_timestamp(timestamp_str)
        delta = timestamp_datetime - datetime.datetime.now()
        delta_sec = int(delta.total_seconds())
        return delta_sec

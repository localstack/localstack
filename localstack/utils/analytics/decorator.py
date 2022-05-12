import datetime
import functools
from multiprocessing import Process
from typing import List

import click

from localstack import config

from .client import AnalyticsClient
from .events import Event, EventMetadata
from .metadata import get_session_id
from .publisher import AnalyticsClientPublisher

ANALYTICS_API_RESPONSE_TIMEOUT_SECS = 0.5


def _publish_cmd_as_analytics_event(command_name: str, params: dict):
    event = Event(
        name="cli_cmd",
        payload={"cmd": command_name, "params": params},
        metadata=EventMetadata(
            session_id=get_session_id(),
            client_time=str(datetime.datetime.now()),  # TODO: consider using utcnow()
        ),
    )
    publisher = AnalyticsClientPublisher(AnalyticsClient())
    publisher.publish([event])


def _get_parent_commands(ctx: click.Context) -> List[str]:
    parent_commands = []
    parent = ctx.parent
    while parent is not None:
        parent_commands.insert(0, parent.command.name)
        parent = parent.parent
    return parent_commands


def publish_invocation(fn):
    """
    Decorator for capturing CLI commands from Click and publishing them to the backend as analytics events.
    This decorator should only be used on outermost subcommands, e.g. "localstack status docker" not "localstack status"
    otherwise it may publish multiple events for a single invocation.
    If DISABLE_EVENTS is set then nothing is collected.
    For performance reasons, the API call to the backend runs on a separate process and is killed if it takes longer
    than ANALYTICS_API_RESPONSE_TIMEOUT_SECS.
    """

    @functools.wraps(fn)
    def publisher_wrapper(*args, **kwargs):
        if config.DISABLE_EVENTS:
            return fn(*args, **kwargs)

        ctx = click.get_current_context()
        full_command = " ".join(_get_parent_commands(ctx) + [ctx.command.name])
        publish_cmd_process = Process(
            target=_publish_cmd_as_analytics_event, args=(full_command, ctx.params)
        )
        publish_cmd_process.start()
        publish_cmd_process.join(ANALYTICS_API_RESPONSE_TIMEOUT_SECS)
        publish_cmd_process.terminate()
        return fn(*args, **kwargs)

    return publisher_wrapper

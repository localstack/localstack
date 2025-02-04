import logging
import re

from moto.scheduler.models import EventBridgeSchedulerBackend

from localstack.aws.api.scheduler import SchedulerApi, ValidationException
from localstack.services.events.rule import RULE_SCHEDULE_CRON_REGEX, RULE_SCHEDULE_RATE_REGEX
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.patch import patch

LOG = logging.getLogger(__name__)

AT_REGEX = (
    r"^at[(](19|20)\d\d-(0[1-9]|1[012])-([012]\d|3[01])T([01]\d|2[0-3]):([0-5]\d):([0-5]\d)[)]$"
)
RULE_SCHEDULE_AT_REGEX = re.compile(AT_REGEX)


class SchedulerProvider(SchedulerApi, ServiceLifecycleHook):
    pass


def _validate_schedule_expression(schedule_expression: str) -> None:
    if not (
        RULE_SCHEDULE_CRON_REGEX.match(schedule_expression)
        or RULE_SCHEDULE_RATE_REGEX.match(schedule_expression)
        or RULE_SCHEDULE_AT_REGEX.match(schedule_expression)
    ):
        raise ValidationException(f"Invalid Schedule Expression {schedule_expression}.")


@patch(EventBridgeSchedulerBackend.create_schedule)
def create_schedule(fn, self, **kwargs):
    if schedule_expression := kwargs.get("schedule_expression"):
        _validate_schedule_expression(schedule_expression)
    return fn(self, **kwargs)

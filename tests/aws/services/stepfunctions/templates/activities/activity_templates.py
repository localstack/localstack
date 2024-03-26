import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class ActivityTemplate(TemplateLoader):
    BASE_ACTIVITY_TASK: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_activity_task.json5"
    )
    BASE_ACTIVITY_TASK_HEARTBEAT: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_activity_task_heartbeat.json5"
    )
    BASE_ACTIVITY_TASK_TIMEOUT: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_activity_task_timeout.json5"
    )
    BASE_ID_ACTIVITY_CONSUMER: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_id_activity_consumer.json5"
    )
    BASE_ID_ACTIVITY_CONSUMER_FAIL: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_id_activity_consumer_fail.json5"
    )
    BASE_ID_ACTIVITY_CONSUMER_TIMEOUT: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_id_activity_consumer_timeout.json5"
    )
    HEARTBEAT_ID_ACTIVITY_CONSUMER: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/heartbeat_id_activity_consumer.json5"
    )

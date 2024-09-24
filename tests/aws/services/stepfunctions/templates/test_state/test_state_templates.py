import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class TestStateTemplate(TemplateLoader):
    BASE_FAIL_STATE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/base_fail_state.json5")
    BASE_SUCCEED_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_succeed_state.json5"
    )
    BASE_WAIT_STATE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/base_wait_state.json5")
    BASE_PASS_STATE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/base_pass_state.json5")
    BASE_CHOICE_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_choice_state.json5"
    )
    BASE_RESULT_PASS_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_result_pass_state.json5"
    )
    IO_PASS_STATE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/io_pass_state.json5")
    IO_RESULT_PASS_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/io_result_pass_state.json5"
    )

    BASE_LAMBDA_TASK_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_lambda_task_state.json5"
    )
    BASE_LAMBDA_SERVICE_TASK_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_lambda_service_task_state.json5"
    )
    IO_LAMBDA_SERVICE_TASK_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/io_lambda_service_task_state.json5"
    )

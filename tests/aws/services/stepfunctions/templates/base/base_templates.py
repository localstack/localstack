import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class BaseTemplate(TemplateLoader):
    BASE_INVALID_DER: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/invalid_der.json5")
    BASE_PASS_RESULT: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/pass_result.json5")
    BASE_TASK_SEQ_2: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/task_seq_2.json5")
    BASE_WAIT_1_MIN: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/wait_1_min.json5")
    BASE_RAISE_FAILURE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/raise_failure.json5")
    DECL_VERSION_1_0: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/decl_version_1_0.json5"
    )
    RAISE_EMPTY_FAILURE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/raise_empty_failure.json5"
    )
    WAIT_AND_FAIL: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/wait_and_fail.json5")
    QUERY_CONTEXT_OBJECT_VALUES: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/query_context_object_values.json5"
    )
    PASS_RESULT_NULL_INPUT_OUTPUT_PATHS: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/pass_result_null_input_output_paths.json5"
    )
    PASS_START_TIME: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/pass_start_time_format.json5"
    )

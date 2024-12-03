import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class StateVariablesTemplate(TemplateLoader):
    LAMBDA_FUNCTION_ARN_LITERAL_PLACEHOLDER = "%LAMBDA_FUNCTION_ARN_LITERAL_PLACEHOLDER%"

    TASK_CATCH_ERROR_OUTPUT_TO_JSONPATH = os.path.join(
        _THIS_FOLDER, "statemachines/task_catch_error_output_to_jsonpath.json5"
    )
    TASK_CATCH_ERROR_OUTPUT = os.path.join(
        _THIS_FOLDER, "statemachines/task_catch_error_output.json5"
    )

    TASK_CATCH_ERROR_VARIABLE_SAMPLING_TO_JSONPATH = os.path.join(
        _THIS_FOLDER, "statemachines/task_catch_error_variable_sampling_to_jsonpath.json5"
    )

    TASK_CATCH_ERROR_VARIABLE_SAMPLING = os.path.join(
        _THIS_FOLDER, "statemachines/task_catch_error_variable_sampling.json5"
    )

    TASK_CATCH_ERROR_OUTPUT_WITH_RETRY_TO_JSONPATH = os.path.join(
        _THIS_FOLDER, "statemachines/task_catch_error_output_with_retry_to_jsonpath.json5"
    )

    TASK_CATCH_ERROR_OUTPUT_WITH_RETRY = os.path.join(
        _THIS_FOLDER, "statemachines/task_catch_error_output_with_retry.json5"
    )

    MAP_CATCH_ERROR_OUTPUT = os.path.join(
        _THIS_FOLDER, "statemachines/map_catch_error_output.json5"
    )

    MAP_CATCH_ERROR_OUTPUT_WITH_RETRY = os.path.join(
        _THIS_FOLDER, "statemachines/map_catch_error_output_with_retry.json5"
    )

    MAP_CATCH_ERROR_VARIABLE_SAMPLING = os.path.join(
        _THIS_FOLDER, "statemachines/map_catch_error_variable_sampling.json5"
    )

    PARALLEL_CATCH_ERROR_OUTPUT = os.path.join(
        _THIS_FOLDER, "statemachines/parallel_catch_error_output.json5"
    )

    PARALLEL_CATCH_ERROR_VARIABLE_SAMPLING = os.path.join(
        _THIS_FOLDER, "statemachines/parallel_catch_error_variable_sampling.json5"
    )

    PARALLEL_CATCH_ERROR_OUTPUT_WITH_RETRY = os.path.join(
        _THIS_FOLDER, "statemachines/parallel_catch_error_output_with_retry.json5"
    )

import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class AssignTemplate(TemplateLoader):
    TEMP = os.path.join(_THIS_FOLDER, "statemachines/temp.json5")
    BASE_CONSTANT_LITERALS = os.path.join(
        _THIS_FOLDER, "statemachines/base_constant_literals.json5"
    )
    BASE_EMPTY = os.path.join(_THIS_FOLDER, "statemachines/base_empty.json5")
    BASE_PATHS = os.path.join(_THIS_FOLDER, "statemachines/base_paths.json5")
    BASE_SCOPE_MAP = os.path.join(_THIS_FOLDER, "statemachines/base_scope_map.json5")
    BASE_SCOPE_PARALLEL = os.path.join(_THIS_FOLDER, "statemachines/base_scope_parallel.json5")
    BASE_VAR = os.path.join(_THIS_FOLDER, "statemachines/base_var.json5")
    BASE_UNDEFINED_ARGUMENTS_FIELD = os.path.join(
        _THIS_FOLDER, "statemachines/base_undefined_arguments_field.json5"
    )
    BASE_UNDEFINED_ARGUMENTS = os.path.join(
        _THIS_FOLDER, "statemachines/base_undefined_arguments.json5"
    )
    BASE_UNDEFINED_OUTPUT = os.path.join(_THIS_FOLDER, "statemachines/base_undefined_output.json5")
    BASE_UNDEFINED_OUTPUT_FIELD = os.path.join(
        _THIS_FOLDER, "statemachines/base_undefined_output_field.json5"
    )
    BASE_UNDEFINED_OUTPUT_MULTIPLE_STATES = os.path.join(
        _THIS_FOLDER, "statemachines/base_undefined_output_multiple_states.json5"
    )
    BASE_UNDEFINED_ASSIGN = os.path.join(_THIS_FOLDER, "statemachines/base_undefined_assign.json5")
    BASE_UNDEFINED_ARGUMENTS = os.path.join(
        _THIS_FOLDER, "statemachines/base_undefined_arguments.json5"
    )
    # Testing the evaluation order of state types
    BASE_EVALUATION_ORDER_PASS_STATE = os.path.join(
        _THIS_FOLDER, "statemachines/base_evaluation_order_pass_state.json5"
    )

    # Testing referencing assigned variables
    BASE_REFERENCE_IN_PARAMETERS = os.path.join(
        _THIS_FOLDER, "statemachines/base_reference_in_parameters.json5"
    )
    BASE_REFERENCE_IN_WAIT = os.path.join(
        _THIS_FOLDER, "statemachines/base_reference_in_wait.json5"
    )
    BASE_REFERENCE_IN_CHOICE = os.path.join(
        _THIS_FOLDER, "statemachines/base_reference_in_choice.json5"
    )
    BASE_REFERENCE_IN_ITERATOR_OUTER_SCOPE = os.path.join(
        _THIS_FOLDER, "statemachines/base_reference_in_iterator_outer_scope.json5"
    )
    BASE_REFERENCE_IN_INPUTPATH = os.path.join(
        _THIS_FOLDER, "statemachines/base_reference_in_inputpath.json5"
    )
    BASE_REFERENCE_IN_OUTPUTPATH = os.path.join(
        _THIS_FOLDER, "statemachines/base_reference_in_outputpath.json5"
    )
    BASE_REFERENCE_IN_INTRINSIC_FUNCTION = os.path.join(
        _THIS_FOLDER, "statemachines/base_reference_in_intrinsic_function.json5"
    )
    BASE_REFERENCE_IN_FAIL = os.path.join(
        _THIS_FOLDER, "statemachines/base_reference_in_fail.json5"
    )

    # Requires 'FunctionName' and 'AccountID' as execution input
    BASE_REFERENCE_IN_LAMBDA_TASK_FIELDS = os.path.join(
        _THIS_FOLDER, "statemachines/base_reference_in_lambda_task_fields.json5"
    )

    # Testing assigning variables dynamically
    BASE_ASSIGN_FROM_PARAMETERS = os.path.join(
        _THIS_FOLDER, "statemachines/base_assign_from_parameters.json5"
    )
    BASE_ASSIGN_FROM_RESULT = os.path.join(
        _THIS_FOLDER, "statemachines/base_assign_from_result.json5"
    )

    BASE_ASSIGN_FROM_INTRINSIC_FUNCTION = os.path.join(
        _THIS_FOLDER, "statemachines/base_assign_from_intrinsic_function.json5"
    )

    BASE_ASSIGN_FROM_LAMBDA_TASK_RESULT = os.path.join(
        _THIS_FOLDER, "statemachines/base_assign_from_lambda_task_result.json5"
    )

    # Testing assigning variables dynamically
    BASE_ASSIGN_IN_CHOICE = os.path.join(_THIS_FOLDER, "statemachines/base_assign_in_choice.json5")

    BASE_ASSIGN_IN_WAIT = os.path.join(_THIS_FOLDER, "statemachines/base_assign_in_wait.json5")

    BASE_ASSIGN_IN_CATCH = os.path.join(_THIS_FOLDER, "statemachines/base_assign_in_catch.json5")

    # Raises exceptions on creation
    TASK_RETRY_REFERENCE_EXCEPTION = os.path.join(
        _THIS_FOLDER, "statemachines/task_retry_reference_exception.json5"
    )

    # ----------------------------------
    # VARIABLE REFERENCING IN MAP STATES
    # ----------------------------------

    MAP_STATE_REFERENCE_IN_INTRINSIC_FUNCTION = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_reference_in_intrinsic_function.json5"
    )

    MAP_STATE_REFERENCE_IN_ITEMS_PATH = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_reference_in_items_path.json5"
    )

    MAP_STATE_REFERENCE_IN_MAX_CONCURRENCY_PATH = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_reference_in_max_concurrency_path.json5"
    )

    MAP_STATE_REFERENCE_IN_MAX_PER_BATCH_PATH = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_reference_in_max_per_batch_path.json5"
    )

    MAP_STATE_REFERENCE_IN_MAX_ITEMS_PATH = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_reference_in_max_items_path.json5"
    )

    MAP_STATE_REFERENCE_IN_TOLERATED_FAILURE_PATH = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_reference_in_tolerated_failure_path.json5"
    )

    MAP_STATE_REFERENCE_IN_ITEM_SELECTOR = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_reference_in_item_selector.json5"
    )

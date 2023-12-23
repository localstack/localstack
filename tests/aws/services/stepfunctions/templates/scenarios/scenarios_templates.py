import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class ScenariosTemplate(TemplateLoader):
    CATCH_EMPTY: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/catch_empty.json5")
    CATCH_STATES_RUNTIME: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/catch_states_runtime.json5"
    )
    PARALLEL_STATE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/parallel_state.json5")
    PARALLEL_STATE_FAIL: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/parallel_state_fail.json5"
    )
    PARALLEL_STATE_CATCH: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/parallel_state_catch.json5"
    )
    PARALLEL_STATE_RETRY: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/parallel_state_retry.json5"
    )
    PARALLEL_STATE_ORDER: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/parallel_state_order.json5"
    )
    MAP_STATE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/map_state.json5")
    MAP_STATE_LEGACY: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_legacy.json5"
    )
    MAP_STATE_NO_PROCESSOR_CONFIG: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_no_processor_config.json5"
    )
    MAP_ITEM_READER_BASE_LIST_OBJECTS_V2: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_item_reader_base_list_objects_v2.json5"
    )
    MAP_ITEM_READER_BASE_CSV_HEADERS_FIRST_LINE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_item_reader_base_csv_headers_first_line.json5"
    )
    MAP_ITEM_READER_BASE_CSV_HEADERS_DECL: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_item_reader_base_csv_headers_decl.json5"
    )
    MAP_ITEM_READER_BASE_JSON: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_item_reader_base_json.json5"
    )
    MAP_STATE_ITEM_SELECTOR: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_item_selector.json5"
    )
    MAP_STATE_PARAMETERS_LEGACY: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_parameters_legacy.json5"
    )
    MAP_STATE_ITEM_SELECTOR_SINGLETON: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_item_selector_singletons.json5"
    )
    MAP_STATE_PARAMETERS_SINGLETON_LEGACY: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_parameters_singletons_legacy.json5"
    )
    MAP_STATE_CATCH: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/map_state_catch.json5")
    MAP_STATE_CATCH_EMPTY_FAIL: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_catch_empty_fail.json5"
    )
    MAP_STATE_CATCH_LEGACY: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_catch_legacy.json5"
    )
    MAP_STATE_RETRY: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/map_state_retry.json5")
    MAP_STATE_RETRY_LEGACY: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_retry_legacy.json5"
    )
    MAP_STATE_RETRY_MULTIPLE_RETRIERS: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_retry_multiple_retriers.json5"
    )
    MAP_STATE_BREAK_CONDITION: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_break_condition.json5"
    )
    MAP_STATE_BREAK_CONDITION_LEGACY: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_break_condition_legacy.json5"
    )
    CHOICE_STATE_UNSORTED_CHOICE_PARAMETERS: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/choice_state_unsorted_choice_parameters.json5"
    )
    CHOICE_STATE_SINGLETON_COMPOSITE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/choice_state_singleton_composite.json5"
    )
    CHOICE_STATE_AWS_SCENARIO: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/choice_state_aws_scenario.json5"
    )
    LAMBDA_EMPTY_RETRY: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/lambda_empty_retry.json5"
    )
    LAMBDA_INVOKE_WITH_RETRY_BASE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/lambda_invoke_with_retry_base.json5"
    )
    LAMBDA_INVOKE_WITH_RETRY_BASE_EXTENDED_INPUT: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/lambda_invoke_with_retry_extended_input.json5"
    )
    LAMBDA_SERVICE_INVOKE_WITH_RETRY_BASE_EXTENDED_INPUT: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/lambda_service_invoke_with_retry_extended_input.json5"
    )
    WAIT_TIMESTAMP: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/wait_timestamp.json5")
    WAIT_TIMESTAMP_PATH: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/wait_timestamp_path.json5"
    )

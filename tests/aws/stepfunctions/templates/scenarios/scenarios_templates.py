import os
from typing import Final

from tests.aws.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class ScenariosTemplate(TemplateLoader):
    PARALLEL_STATE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/parallel_state.json5")
    MAP_STATE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/map_state.json5")
    MAP_STATE_LEGACY: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_legacy.json5"
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

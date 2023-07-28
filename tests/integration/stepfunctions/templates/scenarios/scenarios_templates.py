import os
from typing import Final

from tests.integration.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class ScenariosTemplate(TemplateLoader):
    PARALLEL_STATE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/parallel_state.json5")
    MAP_STATE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/map_state.json5")
    MAP_STATE_ITEM_SELECTOR: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_item_selector.json5"
    )
    MAP_STATE_ITEM_SELECTOR_SINGLETON: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_item_selector_singletons.json5"
    )
    MAP_STATE_CATCH: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/map_state_catch.json5")
    MAP_STATE_RETRY: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/map_state_retry.json5")
    MAP_STATE_BREAK_CONDITION: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_state_break_condition.json5"
    )

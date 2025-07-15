from typing import Final

from localstack.services.cloudformation.engine.v2.change_set_model_preproc import (
    ChangeSetModelPreproc,
)
from localstack.services.cloudformation.v2.entities import ChangeSet, ResolvedParameter


class ChangeSetModelParameterResolver(ChangeSetModelPreproc):
    _before_parameters: Final[dict]
    _after_parameters: Final[dict]

    def __init__(self, change_set: ChangeSet, before_parameters: dict, after_parameters: dict):
        super().__init__(change_set)
        self._before_parameters = before_parameters
        self._after_parameters = after_parameters

    def resolve_parameters(self) -> list[ResolvedParameter]:
        self._setup_runtime_cache()
        node_template = self._change_set.update_model.node_template

        self._save_runtime_cache()

        return []

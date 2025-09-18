from __future__ import annotations

from localstack.services.cloudformation.engine.v2.change_set_model_static_preproc import (
    _AWS_URL_SUFFIX,
    _PSEUDO_PARAMETERS,
    MOCKED_REFERENCE,
    ChangeSetModelStaticPreproc,
    PreprocEntityDelta,
    PreprocOutput,
    PreprocProperties,
    PreprocResource,
)

__all__ = [
    "_AWS_URL_SUFFIX",
    "_PSEUDO_PARAMETERS",
    "ChangeSetModelPreproc",
    "PreprocEntityDelta",
    "PreprocOutput",
    "PreprocProperties",
    "PreprocResource",
    "MOCKED_REFERENCE",
]


class ChangeSetModelPreproc(ChangeSetModelStaticPreproc):
    pass

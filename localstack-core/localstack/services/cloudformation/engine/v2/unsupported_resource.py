from __future__ import annotations

from localstack import config
from localstack.aws.api.cloudformation import ChangeSetType


def should_ignore_unsupported_resource_type(
    resource_type: str, change_set_type: ChangeSetType
) -> bool:
    if config.CFN_IGNORE_UNSUPPORTED_RESOURCE_TYPES:
        return True

    match change_set_type:
        case ChangeSetType.CREATE:
            return resource_type in config.CFN_IGNORE_UNSUPPORTED_TYPE_CREATE
        case ChangeSetType.UPDATE | ChangeSetType.IMPORT:
            return resource_type in config.CFN_IGNORE_UNSUPPORTED_TYPE_UPDATE
        case _:
            return False

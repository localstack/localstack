from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.error_name.error_name import ErrorName

ILLEGAL_CUSTOM_ERROR_PREFIX: Final[str] = "States."


class CustomErrorName(ErrorName):
    """
    States MAY report errors with other names, which MUST NOT begin with the prefix "States.".
    """

    def __init__(self, error_name: Optional[str]):
        if error_name is not None and error_name.startswith(ILLEGAL_CUSTOM_ERROR_PREFIX):
            raise ValueError(
                f"Custom Error Names MUST NOT begin with the prefix 'States.', got '{error_name}'."
            )
        super().__init__(error_name=error_name)

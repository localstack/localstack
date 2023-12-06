from typing import Final

from localstack.services.stepfunctions.asl.component.common.error_name.error_name import ErrorName


class CustomErrorName(ErrorName):
    """
    States MAY report errors with other names, which MUST NOT begin with the prefix "States.".
    """

    _ILLEGAL_PREFIX: Final[str] = "States."

    def __init__(self, error_name: str):
        if error_name.startswith(CustomErrorName._ILLEGAL_PREFIX):
            raise ValueError(
                f"Custom Error Names MUST NOT begin with the prefix 'States.', got '{error_name}'."
            )
        super().__init__(error_name=error_name)

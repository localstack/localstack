import os
from typing import Final

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


def lambda_handler(file_name: str) -> str:
    if not file_name.endswith(".py"):
        file_name += ".py"
    return os.path.join(_THIS_FOLDER, f"lambda_functions/{file_name}")

import argparse
import logging
from typing import NoReturn, Optional

LOG = logging.getLogger(__name__)


class NoExitArgumentParser(argparse.ArgumentParser):
    """Implements the `exit_on_error=False` behavior introduced in Python 3.9 to support older Python versions
    and prevents further SystemExit for other error categories.
    * Limitations of error categories: https://stackoverflow.com/a/67891066/6875981
    * ArgumentParser subclassing example: https://stackoverflow.com/a/59072378/6875981
    """

    def exit(self, status: int = ..., message: Optional[str] = ...) -> NoReturn:
        LOG.warning(f"Error in argument parser but preventing exit: {message}")

    def error(self, message: str) -> NoReturn:
        raise NotImplementedError(f"Unsupported flag by this Docker client: {message}")

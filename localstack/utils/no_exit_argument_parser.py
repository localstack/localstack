import argparse
import logging
from typing import NoReturn

LOG = logging.getLogger(__name__)


# Implements the `exit_on_error=False` behavior introduced in Python 3.9 to support older Python versions
# and prevents further SystemExit for other error categories.
# Limitations of error cases: https://stackoverflow.com/a/67891066/6875981
# Subclassing workaround example: https://stackoverflow.com/a/59072378/6875981
class NoExitArgumentParser(argparse.ArgumentParser):
    def exit(self, status: int = ..., message: str | None = ...) -> NoReturn:
        LOG.warning(f"Error in argument parser but preventing exit: {message}")

    def error(self, message: str) -> NoReturn:
        raise NotImplementedError(f"Unsupported flag by this Docker client: {message}")


# Copied from argparse.BooleanOptionalAction to support older versions than Python 3.9
# See https://docs.python.org/3/library/argparse.html#action
class BooleanOptionalAction(argparse.Action):
    def __init__(
        self,
        option_strings,
        dest,
        default=None,
        type=None,
        choices=None,
        required=False,
        help=None,
        metavar=None,
    ):

        _option_strings = []
        for option_string in option_strings:
            _option_strings.append(option_string)

            if option_string.startswith("--"):
                option_string = "--no-" + option_string[2:]
                _option_strings.append(option_string)

        if help is not None and default is not None and default is not argparse.SUPPRESS:
            help += " (default: %(default)s)"

        super().__init__(
            option_strings=_option_strings,
            dest=dest,
            nargs=0,
            default=default,
            type=type,
            choices=choices,
            required=required,
            help=help,
            metavar=metavar,
        )

    def __call__(self, parser, namespace, values, option_string=None):
        if option_string in self.option_strings:
            setattr(namespace, self.dest, not option_string.startswith("--no-"))

    def format_usage(self):
        return " | ".join(self.option_strings)

import os
import sys
from typing import Optional

# important: this needs to be free of localstack imports


def set_profile_from_sys_argv():
    """
    Reads the --profile flag from sys.argv and then sets the 'CONFIG_PROFILE' os variable accordingly. This is later
    picked up by ``localstack.config``.
    """
    profile = parse_profile_argument(sys.argv)
    if profile:
        os.environ["CONFIG_PROFILE"] = profile.strip()


def parse_profile_argument(args) -> Optional[str]:
    """
    Lightweight arg parsing to find ``--profile <config>``, or ``--profile=<config>`` and return the value of
    ``<config>`` from the given arguments.

    :param args: list of CLI arguments
    :returns: the value of ``--profile``.
    """
    for i, arg in enumerate(args):
        if arg.startswith("--profile="):
            return arg[10:]
        if arg == "--profile":
            try:
                return arg[i + 1]
            except KeyError:
                return None

    return None

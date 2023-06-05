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
    for i, current_arg in enumerate(args):
        if current_arg.startswith("--profile="):
            # if using the "<arg>=<value>" notation, we remove the "--profile=" prefix to get the value
            return current_arg[10:]
        elif current_arg.startswith("-p="):
            # if using the "<arg>=<value>" notation, we remove the "-p=" prefix to get the value
            return current_arg[3:]
        if current_arg in ["--profile", "-p"]:
            # otherwise use the next arg in the args list as value
            try:
                return args[i + 1]
            except KeyError:
                return None

    return None

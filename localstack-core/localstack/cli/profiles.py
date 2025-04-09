import os
import sys
from typing import Optional

# important: this needs to be free of localstack imports


def set_profile_from_sys_argv():
    """
    Reads the --profile flag from sys.argv and then sets the 'CONFIG_PROFILE' os variable accordingly. This is later
    picked up by ``localstack.config``.
    """
    profile = parse_profile_argument()
    if profile:
        os.environ["CONFIG_PROFILE"] = profile.strip()


def parse_profile_argument() -> Optional[str]:
    """
    Lightweight arg parsing to find ``--profile <config>``, or ``--profile=<config>`` and return the value of
    ``<config>`` from the given arguments.

    :param args: list of CLI arguments
    :returns: the value of ``--profile``.
    """
    args_without_profile = []
    profile_is_next_arg = False
    profile = None

    for i, current_arg in enumerate(sys.argv):
        if profile_is_next_arg:
            # if the previous arg was "--profile", we take the next arg as value.
            profile = current_arg
            profile_is_next_arg = False
        else:
            if current_arg.startswith("--profile="):
                # if using the "<arg>=<value>" notation, we remove the "--profile=" prefix to get the value
                profile = current_arg[10:]
            elif current_arg.startswith("-p="):
                # if using the "<arg>=<value>" notation, we remove the "-p=" prefix to get the value
                profile = current_arg[3:]
            elif current_arg in ["--profile", "-p"]:
                # otherwise use the next arg in the args list as value
                profile_is_next_arg = True
            else:
                args_without_profile.append(current_arg)

    # Now replace the command line arguments with the ones without the profile argument.
    sys.argv = args_without_profile

    return profile

import argparse
import os
import sys
from typing import Optional

# important: this needs to be free of localstack imports


def set_and_remove_profile_from_sys_argv():
    """
    Performs the following steps:

    1. Use argparse to parse the command line arguments for the --profile flag.
       All occurrences are removed from the sys.argv list, and the value from
       the last occurrence is used.  This allows the user to specify a profile
       at any point on the command line.

    2. If a --profile flag is not found, check for the -p flag.  The first
       occurrence of the -p flag is used and it is not removed from sys.argv.
       The reasoning for this is that at least one of the CLI subcommands has
       a -p flag, and we want to keep it in sys.argv for that command to
       pick up.  An existing bug means that if a -p flag is used with a
       subcommand, it could erroneously be used as the profile value as well.
       This behaviour is undesired, but we must maintain back-compatibility of
       allowing the profile to be specified using -p.

    3. If a profile is found, the 'CONFIG_PROFILE' os variable is set
       accordingly. This is later picked up by ``localstack.config``.

    WARNING:  Any --profile options are REMOVED from sys.argv, so that they are
              not passed to the localstack CLI. This allows the profile option
              to be set at any point on the command line.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile")
    namespace, sys.argv = parser.parse_known_args(sys.argv)
    profile = namespace.profile

    if not profile:
        # if no profile is given, check for the -p argument
        profile = parse_p_argument(sys.argv)

    if profile:
        os.environ["CONFIG_PROFILE"] = profile.strip()


def parse_p_argument(args) -> Optional[str]:
    """
    Lightweight arg parsing to find the first occurrence of ``-p <config>``, or ``-p=<config>`` and return the value of
    ``<config>`` from the given arguments.

    :param args: list of CLI arguments
    :returns: the value of ``-p``.
    """
    for i, current_arg in enumerate(args):
        if current_arg.startswith("-p="):
            # if using the "<arg>=<value>" notation, we remove the "-p=" prefix to get the value
            return current_arg[3:]
        if current_arg == "-p":
            # otherwise use the next arg in the args list as value
            try:
                return args[i + 1]
            except IndexError:
                return None

    return None

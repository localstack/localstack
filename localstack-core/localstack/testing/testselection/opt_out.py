import fnmatch
from typing import Iterable

OPT_OUT = []


def opted_out(changed_files: list[str], opt_out: Iterable[str] | None = None) -> bool:
    """
    Do not perform test selection if at least one file is opted out

    :param changed_files: List of changed file paths
    :param opt_out: Iterable of globs to match the changed files against. Defaults to the rules defined in OPT_OUT
    :return: True if any changed file matches at least one glob, False otherwise
    """
    if opt_out is None:
        opt_out = OPT_OUT

    return any(any(fnmatch.fnmatch(cf, glob) for glob in opt_out) for cf in changed_files)

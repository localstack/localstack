import logging
import shutil
import subprocess as sp
from pathlib import Path

LOG = logging.getLogger(__name__)


def format_file(path: str | Path):
    if bin_path := shutil.which("rain"):
        format_with_rain(bin_path, path)
        return


def format_with_rain(bin_path: str, path: str | Path):
    LOG.debug("formatting output file '%s' with rain", path)
    cmd = [bin_path, "fmt", "--write", str(path)]
    sp.check_call(cmd)

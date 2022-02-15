import configparser
import os

# TODO: move other file utils from common.py in here as well
from pathlib import Path
from typing import Dict

from localstack.utils.common import is_linux, is_mac_os, is_windows, load_file


def parse_config_file(file_or_str: str, single_section: bool = True) -> Dict:
    """Parse the given properties config file/string and return a dict of section->key->value.
    If the config contains a single section, and 'single_section' is True, returns"""

    config = configparser.RawConfigParser()

    if os.path.exists(file_or_str):
        file_or_str = load_file(file_or_str)

    try:
        config.read_string(file_or_str)
    except configparser.MissingSectionHeaderError:
        file_or_str = f"[default]\n{file_or_str}"
        config.read_string(file_or_str)

    sections = list(config.sections())

    result = {sec: dict(config.items(sec)) for sec in sections}
    if len(sections) == 1 and single_section:
        result = result[sections[0]]

    return result


def cache_dir() -> Path:
    if is_windows():
        return Path("%LOCALAPPDATA%", "cache", "localstack")
    if is_mac_os():
        return Path.home() / "Library" / "Caches" / "localstack"
    if is_linux():
        string_path = os.environ.get("XDG_CACHE_HOME")
        if string_path and os.path.isabs(string_path):
            return Path(string_path)
    # Use the common place to store caches in Linux as a default
    return Path.home() / ".cache" / "localstack"

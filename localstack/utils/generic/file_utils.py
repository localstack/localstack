import configparser
import os

# TODO: move other file utils from common.py in here as well
from typing import Dict

from localstack.utils.common import load_file


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

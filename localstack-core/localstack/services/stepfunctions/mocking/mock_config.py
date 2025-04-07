import json
import logging
import os
from typing import Optional, Tuple

from localstack import config

LOG = logging.getLogger(__name__)

_SFN_MOCK_CONFIG_CACHE: Optional[Tuple[int, dict]] = None


def load_sfn_mock_config_file() -> Optional[dict]:
    configuration_file_path = config.SFN_MOCK_CONFIG
    if not configuration_file_path:
        return None

    global _SFN_MOCK_CONFIG_CACHE

    try:
        modified_time = os.path.getmtime(configuration_file_path)
        modified_epoch = int(modified_time)
    except Exception as ex:
        LOG.warning(
            "Unable to access the step functions mock configuration file at '%s' due to %s",
            configuration_file_path,
            ex,
        )
        return None

    if _SFN_MOCK_CONFIG_CACHE is None or _SFN_MOCK_CONFIG_CACHE[0] < modified_epoch:
        with open(configuration_file_path, "r") as df:
            try:
                mock_config = json.load(df)
            except Exception as ex:
                LOG.warning(
                    "Unable to load step functions mock configuration file at '%s' due to %s",
                    configuration_file_path,
                    ex,
                )
                return None
        _SFN_MOCK_CONFIG_CACHE = (modified_epoch, mock_config)
    return _SFN_MOCK_CONFIG_CACHE[1]

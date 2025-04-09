import json
import logging
import os
from functools import lru_cache
from typing import Optional

from localstack import config

LOG = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _retrieve_sfn_mock_config(file_path: str, modified_epoch: int) -> Optional[dict]:  # noqa
    """
    Load and cache the Step Functions mock configuration from a JSON file.

    This function is memoized using `functools.lru_cache` to avoid re-reading the file
    from disk unless it has changed. The `modified_epoch` parameter is used solely to
    trigger cache invalidation when the file is updated. If either the file path or the
    modified timestamp changes, the cached result is discarded and the file is reloaded.

    Parameters:
        file_path (str):
            The absolute path to the JSON configuration file.

        modified_epoch (int):
            The last modified time of the file, in epoch seconds. This value is used
            as part of the cache key to ensure the cache is refreshed when the file is updated.

    Returns:
        Optional[dict]:
            The parsed configuration as a dictionary if the file is successfully loaded,
            or `None` if an error occurs during reading or parsing.

    Notes:
        - The `modified_epoch` argument is not used inside the function logic, but is
          necessary to ensure cache correctness via `lru_cache`.
        - Logging is used to capture warnings if file access or parsing fails.
    """
    try:
        with open(file_path, "r") as df:
            mock_config = json.load(df)
        return mock_config
    except Exception as ex:
        LOG.warning(
            "Unable to load step functions mock configuration file at '%s' due to %s",
            file_path,
            ex,
        )
        return None


def load_sfn_mock_config_file() -> Optional[dict]:
    configuration_file_path = config.SFN_MOCK_CONFIG
    if not configuration_file_path:
        return None

    try:
        modified_time = int(os.path.getmtime(configuration_file_path))
    except Exception as ex:
        LOG.warning(
            "Unable to access the step functions mock configuration file at '%s' due to %s",
            configuration_file_path,
            ex,
        )
        return None

    mock_config = _retrieve_sfn_mock_config(configuration_file_path, modified_time)
    return mock_config

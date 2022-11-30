from contextlib import contextmanager
from typing import Optional

import pytest


@pytest.fixture(autouse=True)
def switch_region():
    """A fixture which allows to easily switch the region in the config within a `with` context."""

    @contextmanager
    def _switch_region(region: Optional[str]):
        from localstack import config

        # FIXME adapt or remove with 2.0
        previous_region = config.DEFAULT_REGION
        try:
            config.DEFAULT_REGION = region
            yield
        finally:
            config.DEFAULT_REGION = previous_region

    return _switch_region

import json

import pytest

from localstack import config


@pytest.fixture(autouse=True)
def use_new_providers(monkeypatch):
    """
    For tests within this subdirectory, make sure we are using the new providers.

    This fixture is applied to all tests.
    """
    monkeypatch.setattr(
        config,
        "CFN_RESOURCE_PROVIDER_OVERRIDES",
        json.dumps({"AWS::OpenSearchService::Domain": "ResourceProvider"}),
    )

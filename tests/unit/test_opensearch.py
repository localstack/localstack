import pytest

from localstack.services.opensearch.provider import OpensearchProvider


def test_opensearch_get_store_raises_exception():
    """
    Tests if OpensearchProvider.get_store raises an error if the region is not given and cannot be determined from
    the request context (i.e. we're not within a request scoped thread).
    """
    with pytest.raises(AssertionError):
        OpensearchProvider.get_store()

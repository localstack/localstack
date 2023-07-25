import pytest


class CacheFile:
    def write_file(self, relative_path: str, content: str):
        pass


@pytest.fixture
def cache_file() -> CacheFile:
    return CacheFile()

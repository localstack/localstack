from localstack.constants import LOCALHOST
from localstack.utils.common import short_uid
from localstack.utils.net_utils import resolve_hostname


def test_resolve_hostname():
    assert "127." in resolve_hostname(LOCALHOST)
    assert resolve_hostname("example.com")
    assert resolve_hostname(f"non-existing-host-{short_uid()}") is None

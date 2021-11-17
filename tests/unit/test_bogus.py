from localstack.utils.common import get_arch


def test_get_arch_amd64():
    assert get_arch() == "amd64"


def test_get_arch_arm64():
    assert get_arch() == "arm64"

import pytest

from localstack.services.moto import get_dispatcher


def test_get_dispatcher_for_path_with_optional_slashes():
    assert get_dispatcher("route53", "/2013-04-01/hostedzone/BOR36Z3H458JKS9/rrset/")
    assert get_dispatcher("route53", "/2013-04-01/hostedzone/BOR36Z3H458JKS9/rrset")


def test_get_dispatcher_for_non_existing_path_raises_not_implemented():
    with pytest.raises(NotImplementedError):
        get_dispatcher("route53", "/non-existing")

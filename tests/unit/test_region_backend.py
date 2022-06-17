from typing import Any
from unittest.mock import patch

from pytest import fixture

from localstack.services.generic_proxy import RegionBackend


@fixture
def sample_region_backend():
    class SampleRegionBackend(RegionBackend):
        CLASS_ATTR: list[Any] = []
        instance_attr: list[Any]

        def __init__(self):
            self.instance_attr = []

    return SampleRegionBackend


def test_region_backend_namespacing(sample_region_backend):
    account1 = "696969696969"
    account2 = "424242424242"

    eu_region = "eu-central-1"
    ap_region = "ap-south-1"

    with patch("localstack.aws.accounts.account_id_resolver", new=lambda: account1):
        # Get backends for same account but different regions
        backend1_eu = sample_region_backend.get(region=eu_region)
        assert backend1_eu.account_id == account1
        assert backend1_eu.name == eu_region

        backend1_ap = sample_region_backend.get(region=ap_region)
        assert backend1_ap.account_id == account1
        assert backend1_ap.name == ap_region

        # Ensure region-specific data isolation
        backend1_eu.instance_attr.extend([1, 2, 3])
        assert backend1_ap.instance_attr == []

        # Ensure cross-region data sharing
        backend1_eu.CLASS_ATTR.extend([4, 5, 6])
        assert backend1_ap.CLASS_ATTR == [4, 5, 6]

        # Ensure backend internals
        assert id(backend1_ap._ACCOUNT_BACKENDS) == id(backend1_eu._ACCOUNT_BACKENDS)
        assert len(backend1_ap._ACCOUNT_BACKENDS) == len(backend1_eu._ACCOUNT_BACKENDS) == 1
        assert id(backend1_ap._ACCOUNTS_CLS) == id(backend1_eu._ACCOUNTS_CLS)
        assert len(backend1_ap._ACCOUNTS_CLS) == len(backend1_eu._ACCOUNTS_CLS) == 1

    with patch("localstack.aws.accounts.account_id_resolver", new=lambda: account2):
        # Get backends for a different AWS account
        backend2_eu = sample_region_backend.get(region=eu_region)
        assert backend2_eu.account_id == account2
        assert backend2_eu.name == eu_region

        backend2_ap = sample_region_backend.get(region=ap_region)
        assert backend2_ap.account_id == account2
        assert backend2_ap.name == ap_region

        # Ensure account-specific data isolation
        assert backend2_eu.CLASS_ATTR == []
        assert backend2_ap.CLASS_ATTR == []

        assert backend2_eu.instance_attr == []
        assert backend2_ap.instance_attr == []

        # Ensure region backend internals
        assert (
            id(backend2_ap._ACCOUNT_BACKENDS)
            == id(backend2_eu._ACCOUNT_BACKENDS)
            == id(backend1_eu._ACCOUNT_BACKENDS)
        )
        assert len(backend2_ap._ACCOUNT_BACKENDS) == len(backend2_eu._ACCOUNT_BACKENDS) == 2
        assert (
            id(backend2_ap._ACCOUNTS_CLS)
            == id(backend2_eu._ACCOUNTS_CLS)
            == id(backend1_eu._ACCOUNTS_CLS)
        )
        assert len(backend2_ap._ACCOUNTS_CLS) == len(backend2_eu._ACCOUNTS_CLS) == 2

import pytest

from localstack.services.stores import AccountRegionBundle, BaseStore


class TestStores:
    def test_store_reset(self, sample_stores):
        """Ensure reset functionality of Stores and encapsulation works."""
        account1 = "696969696969"
        account2 = "424242424242"

        eu_region = "eu-central-1"
        ap_region = "ap-south-1"

        store1 = sample_stores[account1][eu_region]
        store2 = sample_stores[account1][ap_region]
        store3 = sample_stores[account2][ap_region]

        store1.region_specific_attr.extend([1, 2, 3])
        store1.CROSS_REGION_ATTR.extend(["a", "b", "c"])
        store1.CROSS_ACCOUNT_ATTR.extend([100j, 200j, 300j])
        store2.region_specific_attr.extend([4, 5, 6])
        store2.CROSS_ACCOUNT_ATTR.extend([400j])
        store3.region_specific_attr.extend([7, 8, 9])
        store3.CROSS_REGION_ATTR.extend([0.1, 0.2, 0.3])
        store3.CROSS_ACCOUNT_ATTR.extend([500j])

        # Ensure all stores are affected by cross-account attributes
        assert store1.CROSS_ACCOUNT_ATTR == [100j, 200j, 300j, 400j, 500j]
        assert store2.CROSS_ACCOUNT_ATTR == [100j, 200j, 300j, 400j, 500j]
        assert store3.CROSS_ACCOUNT_ATTR == [100j, 200j, 300j, 400j, 500j]

        assert store1.CROSS_ACCOUNT_ATTR.pop() == 500j

        assert store2.CROSS_ACCOUNT_ATTR == [100j, 200j, 300j, 400j]
        assert store3.CROSS_ACCOUNT_ATTR == [100j, 200j, 300j, 400j]

        # Ensure other account stores are not affected by RegionBundle reset
        # Ensure cross-account attributes are not affected by RegionBundle reset
        sample_stores[account1].reset()

        assert store1.region_specific_attr == []
        assert store1.CROSS_REGION_ATTR == []
        assert store1.CROSS_ACCOUNT_ATTR == [100j, 200j, 300j, 400j]
        assert store2.region_specific_attr == []
        assert store2.CROSS_REGION_ATTR == []
        assert store2.CROSS_ACCOUNT_ATTR == [100j, 200j, 300j, 400j]
        assert store3.region_specific_attr == [7, 8, 9]
        assert store3.CROSS_REGION_ATTR == [0.1, 0.2, 0.3]
        assert store3.CROSS_ACCOUNT_ATTR == [100j, 200j, 300j, 400j]

        # Ensure AccountRegionBundle reset
        sample_stores.reset()

        assert store1.CROSS_ACCOUNT_ATTR == []
        assert store2.CROSS_ACCOUNT_ATTR == []
        assert store3.region_specific_attr == []
        assert store3.CROSS_REGION_ATTR == []
        assert store3.CROSS_ACCOUNT_ATTR == []

        # Ensure essential properties are retained after reset
        assert store1._region_name == eu_region
        assert store2._region_name == ap_region
        assert store3._region_name == ap_region
        assert store1._account_id == account1
        assert store2._account_id == account1
        assert store3._account_id == account2

    def test_store_namespacing(self, sample_stores):
        account1 = "696969696969"
        account2 = "424242424242"

        eu_region = "eu-central-1"
        ap_region = "ap-south-1"

        #
        # For Account 1
        #
        # Get backends for same account but different regions
        backend1_eu = sample_stores[account1][eu_region]
        assert backend1_eu._account_id == account1
        assert backend1_eu._region_name == eu_region

        backend1_ap = sample_stores[account1][ap_region]
        assert backend1_ap._account_id == account1
        assert backend1_ap._region_name == ap_region

        # Ensure region-specific data isolation
        backend1_eu.region_specific_attr.extend([1, 2, 3])
        assert backend1_ap.region_specific_attr == []

        # Ensure cross-region data sharing
        backend1_eu.CROSS_REGION_ATTR.extend([4, 5, 6])
        assert backend1_ap.CROSS_REGION_ATTR == [4, 5, 6]

        # Ensure global attributes are shared across regions
        assert (
            id(backend1_ap._global)
            == id(backend1_eu._global)
            == id(sample_stores[account1]._global)
        )

        #
        # For Account 2
        #
        # Get backends for a different AWS account
        backend2_eu = sample_stores[account2][eu_region]
        assert backend2_eu._account_id == account2
        assert backend2_eu._region_name == eu_region

        backend2_ap = sample_stores[account2][ap_region]
        assert backend2_ap._account_id == account2
        assert backend2_ap._region_name == ap_region

        # Ensure account-specific data isolation
        assert backend2_eu.CROSS_REGION_ATTR == []
        assert backend2_ap.CROSS_REGION_ATTR == []

        assert backend2_eu.region_specific_attr == []
        assert backend2_ap.region_specific_attr == []

        # Ensure global attributes are shared for same account ID across regions
        assert (
            id(backend2_ap._global)
            == id(backend2_eu._global)
            == id(sample_stores[account2]._global)
            != id(backend1_ap._global)
        )

        # Ensure cross-account data sharing
        backend1_eu.CROSS_ACCOUNT_ATTR.extend([100j, 200j, 300j])
        assert backend1_ap.CROSS_ACCOUNT_ATTR == [100j, 200j, 300j]
        assert backend1_eu.CROSS_ACCOUNT_ATTR == [100j, 200j, 300j]
        assert backend2_ap.CROSS_ACCOUNT_ATTR == [100j, 200j, 300j]
        assert backend2_eu.CROSS_ACCOUNT_ATTR == [100j, 200j, 300j]
        assert (
            id(backend1_ap._universal)
            == id(backend1_eu._universal)
            == id(backend2_ap._universal)
            == id(backend2_eu._universal)
        )

    def test_valid_regions(self):
        class SampleStore(BaseStore):
            pass

        stores = AccountRegionBundle("sns", SampleStore)
        account1 = "696969696969"

        # assert regular regions work
        assert stores[account1]["us-east-1"]
        # assert extended regions work
        assert stores[account1]["cn-north-1"]
        assert stores[account1]["us-gov-west-1"]
        # assert invalid regions don't pass validation
        with pytest.raises(Exception) as exc:
            assert stores[account1]["invalid-region"]
        exc.match("not a valid AWS region")

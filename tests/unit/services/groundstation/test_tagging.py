"""Unit tests for Ground Station tagging operations."""

import pytest

from localstack.aws.api import RequestContext
from localstack.aws.api.groundstation import ResourceNotFoundException
from localstack.services.groundstation.models import groundstation_stores
from localstack.services.groundstation.provider import GroundStationProvider


@pytest.fixture
def provider():
    """Create a GroundStation provider instance."""
    return GroundStationProvider()


@pytest.fixture
def context():
    """Create a request context."""
    context = RequestContext(None)
    context.account_id = "000000000000"
    context.region = "us-east-1"
    return context


@pytest.fixture(autouse=True)
def clear_store():
    """Clear the store before each test."""
    groundstation_stores.configs.clear()
    groundstation_stores.mission_profiles.clear()
    groundstation_stores.contacts.clear()
    groundstation_stores.dataflow_endpoint_groups.clear()
    groundstation_stores.tags.clear()
    yield
    groundstation_stores.configs.clear()
    groundstation_stores.mission_profiles.clear()
    groundstation_stores.contacts.clear()
    groundstation_stores.dataflow_endpoint_groups.clear()
    groundstation_stores.tags.clear()


class TestTagResource:
    """Tests for TagResource operation."""

    def test_tag_config(self, provider, context):
        """Test tagging a configuration."""
        # Create a config
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        config_resp = provider.create_config(
            context=context, name="test-config", config_data=config_data
        )
        config_arn = config_resp["configArn"]

        # Tag it
        tags = {"Environment": "production", "Team": "satellite-ops"}
        provider.tag_resource(context=context, resource_arn=config_arn, tags=tags)

        # Verify tags were added
        assert config_arn in groundstation_stores.tags
        assert groundstation_stores.tags[config_arn] == tags

    def test_tag_mission_profile(self, provider, context):
        """Test tagging a mission profile."""
        # Create configs
        tracking_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        tracking_resp = provider.create_config(
            context=context, name="tracking", config_data=tracking_data
        )

        downlink_data = {
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 2200.0, "units": "MHz"},
                    "bandwidth": {"value": 125.0, "units": "MHz"},
                }
            }
        }
        downlink_resp = provider.create_config(
            context=context, name="downlink", config_data=downlink_data
        )

        # Create mission profile
        mp_resp = provider.create_mission_profile(
            context=context,
            name="test-mission",
            minimum_viable_contact_duration_seconds=60,
            contact_pre_pass_duration_seconds=120,
            contact_post_pass_duration_seconds=60,
            tracking_config_arn=tracking_resp["configArn"],
            dataflow_edges=[[tracking_resp["configArn"], downlink_resp["configArn"]]],
        )
        mp_id = mp_resp["missionProfileId"]
        mp_arn = f"arn:aws:groundstation:us-east-1:000000000000:mission-profile/{mp_id}"

        # Tag it
        tags = {"Project": "ISS", "CostCenter": "Science"}
        provider.tag_resource(context=context, resource_arn=mp_arn, tags=tags)

        # Verify
        assert mp_arn in groundstation_stores.tags
        assert groundstation_stores.tags[mp_arn] == tags

    def test_tag_adds_to_existing_tags(self, provider, context):
        """Test that tagging adds to existing tags."""
        # Create a config with initial tags
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        config_resp = provider.create_config(
            context=context,
            name="test-config",
            config_data=config_data,
            tags={"Initial": "tag"},
        )
        config_arn = config_resp["configArn"]

        # Add more tags
        new_tags = {"Additional": "tag", "Another": "one"}
        provider.tag_resource(context=context, resource_arn=config_arn, tags=new_tags)

        # Verify both old and new tags exist
        all_tags = groundstation_stores.tags[config_arn]
        assert all_tags["Initial"] == "tag"
        assert all_tags["Additional"] == "tag"
        assert all_tags["Another"] == "one"

    def test_tag_nonexistent_resource(self, provider, context):
        """Test tagging a non-existent resource."""
        with pytest.raises(ResourceNotFoundException):
            provider.tag_resource(
                context=context,
                resource_arn="arn:aws:groundstation:us-east-1:000000000000:config/tracking/nonexistent",
                tags={"Tag": "value"},
            )


class TestUntagResource:
    """Tests for UntagResource operation."""

    def test_untag_resource(self, provider, context):
        """Test removing tags from a resource."""
        # Create a config with tags
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        config_resp = provider.create_config(
            context=context,
            name="test-config",
            config_data=config_data,
            tags={"Tag1": "value1", "Tag2": "value2", "Tag3": "value3"},
        )
        config_arn = config_resp["configArn"]

        # Remove some tags
        provider.untag_resource(context=context, resource_arn=config_arn, tag_keys=["Tag1", "Tag3"])

        # Verify only Tag2 remains
        remaining_tags = groundstation_stores.tags[config_arn]
        assert "Tag2" in remaining_tags
        assert "Tag1" not in remaining_tags
        assert "Tag3" not in remaining_tags

    def test_untag_nonexistent_keys(self, provider, context):
        """Test removing non-existent tag keys (should not fail)."""
        # Create a config with tags
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        config_resp = provider.create_config(
            context=context,
            name="test-config",
            config_data=config_data,
            tags={"Tag1": "value1"},
        )
        config_arn = config_resp["configArn"]

        # Remove non-existent key (should not fail)
        provider.untag_resource(context=context, resource_arn=config_arn, tag_keys=["NonExistent"])

        # Verify original tag still exists
        assert "Tag1" in groundstation_stores.tags[config_arn]

    def test_untag_nonexistent_resource(self, provider, context):
        """Test untagging a non-existent resource."""
        with pytest.raises(ResourceNotFoundException):
            provider.untag_resource(
                context=context,
                resource_arn="arn:aws:groundstation:us-east-1:000000000000:config/tracking/nonexistent",
                tag_keys=["Tag1"],
            )


class TestListTagsForResource:
    """Tests for ListTagsForResource operation."""

    def test_list_tags_for_config(self, provider, context):
        """Test listing tags for a configuration."""
        # Create a config with tags
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        tags = {"Environment": "production", "Team": "ops"}
        config_resp = provider.create_config(
            context=context, name="test-config", config_data=config_data, tags=tags
        )
        config_arn = config_resp["configArn"]

        # List tags
        response = provider.list_tags_for_resource(context=context, resource_arn=config_arn)

        assert response["tags"] == tags

    def test_list_tags_for_untagged_resource(self, provider, context):
        """Test listing tags for a resource with no tags."""
        # Create a config without tags
        config_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
        config_resp = provider.create_config(
            context=context, name="test-config", config_data=config_data
        )
        config_arn = config_resp["configArn"]

        # List tags
        response = provider.list_tags_for_resource(context=context, resource_arn=config_arn)

        assert response["tags"] == {}

    def test_list_tags_nonexistent_resource(self, provider, context):
        """Test listing tags for a non-existent resource."""
        with pytest.raises(ResourceNotFoundException):
            provider.list_tags_for_resource(
                context=context,
                resource_arn="arn:aws:groundstation:us-east-1:000000000000:config/tracking/nonexistent",
            )

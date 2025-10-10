"""Unit tests for Ground Station mission profile operations."""

from datetime import datetime

import pytest

from localstack.aws.api import RequestContext
from localstack.aws.api.groundstation import (
    DependencyException,
    InvalidParameterException,
    ResourceNotFoundException,
)
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


@pytest.fixture
def test_configs(provider, context):
    """Create test configurations for mission profiles."""
    # Create tracking config
    tracking_data = {"trackingConfig": {"autotrack": "REQUIRED"}}
    tracking_resp = provider.create_config(
        context=context, name="test-tracking", config_data=tracking_data
    )

    # Create downlink config
    downlink_data = {
        "antennaDownlinkConfig": {
            "spectrumConfig": {
                "centerFrequency": {"value": 2200.0, "units": "MHz"},
                "bandwidth": {"value": 125.0, "units": "MHz"},
            }
        }
    }
    downlink_resp = provider.create_config(
        context=context, name="test-downlink", config_data=downlink_data
    )

    # Create dataflow endpoint config
    def_data = {
        "dataflowEndpointConfig": {
            "dataflowEndpointName": "test-endpoint",
            "dataflowEndpointRegion": "us-east-1",
        }
    }
    def_resp = provider.create_config(context=context, name="test-dataflow", config_data=def_data)

    return {
        "tracking_arn": tracking_resp["configArn"],
        "downlink_arn": downlink_resp["configArn"],
        "dataflow_arn": def_resp["configArn"],
    }


class TestCreateMissionProfile:
    """Tests for CreateMissionProfile operation."""

    def test_create_basic_mission_profile(self, provider, context, test_configs):
        """Test creating a basic mission profile."""
        response = provider.create_mission_profile(
            context=context,
            name="test-mission",
            minimum_viable_contact_duration_seconds=60,
            contact_pre_pass_duration_seconds=120,
            contact_post_pass_duration_seconds=60,
            tracking_config_arn=test_configs["tracking_arn"],
            dataflow_edges=[
                [test_configs["tracking_arn"], test_configs["downlink_arn"]],
                [test_configs["downlink_arn"], test_configs["dataflow_arn"]],
            ],
        )

        assert "missionProfileId" in response
        assert response["missionProfileId"] in groundstation_stores.mission_profiles

    def test_create_mission_profile_with_tags(self, provider, context, test_configs):
        """Test creating a mission profile with tags."""
        tags = {"Environment": "test", "Project": "satellite"}

        response = provider.create_mission_profile(
            context=context,
            name="test-mission-tagged",
            minimum_viable_contact_duration_seconds=60,
            contact_pre_pass_duration_seconds=120,
            contact_post_pass_duration_seconds=60,
            tracking_config_arn=test_configs["tracking_arn"],
            dataflow_edges=[[test_configs["tracking_arn"], test_configs["downlink_arn"]]],
            tags=tags,
        )

        mp_id = response["missionProfileId"]
        mp = groundstation_stores.mission_profiles[mp_id]
        assert mp.tags == tags

    def test_create_mission_profile_invalid_duration(self, provider, context, test_configs):
        """Test that invalid durations are rejected."""
        # Pre-pass duration too long
        with pytest.raises(InvalidParameterException):
            provider.create_mission_profile(
                context=context,
                name="invalid-mission",
                minimum_viable_contact_duration_seconds=60,
                contact_pre_pass_duration_seconds=7201,  # Max is 7200
                contact_post_pass_duration_seconds=60,
                tracking_config_arn=test_configs["tracking_arn"],
                dataflow_edges=[[test_configs["tracking_arn"], test_configs["downlink_arn"]]],
            )

    def test_create_mission_profile_with_dataflow_edges(self, provider, context, test_configs):
        """Test creating mission profile with multiple dataflow edges."""
        response = provider.create_mission_profile(
            context=context,
            name="multi-edge-mission",
            minimum_viable_contact_duration_seconds=60,
            contact_pre_pass_duration_seconds=120,
            contact_post_pass_duration_seconds=60,
            tracking_config_arn=test_configs["tracking_arn"],
            dataflow_edges=[
                [test_configs["tracking_arn"], test_configs["downlink_arn"]],
                [test_configs["downlink_arn"], test_configs["dataflow_arn"]],
            ],
        )

        assert "missionProfileId" in response
        mp_id = response["missionProfileId"]

        # Verify the edges were stored
        mp = groundstation_stores.mission_profiles[mp_id]
        assert len(mp.dataflow_edges) == 2


class TestGetMissionProfile:
    """Tests for GetMissionProfile operation."""

    def test_get_existing_mission_profile(self, provider, context, test_configs):
        """Test getting an existing mission profile."""
        # Create a mission profile
        create_resp = provider.create_mission_profile(
            context=context,
            name="test-mission",
            minimum_viable_contact_duration_seconds=60,
            contact_pre_pass_duration_seconds=120,
            contact_post_pass_duration_seconds=60,
            tracking_config_arn=test_configs["tracking_arn"],
            dataflow_edges=[[test_configs["tracking_arn"], test_configs["downlink_arn"]]],
        )
        mp_id = create_resp["missionProfileId"]

        # Get the mission profile
        response = provider.get_mission_profile(context=context, mission_profile_id=mp_id)

        assert response["missionProfileId"] == mp_id
        assert response["name"] == "test-mission"
        assert response["minimumViableContactDurationSeconds"] == 60
        assert response["contactPrePassDurationSeconds"] == 120
        assert response["contactPostPassDurationSeconds"] == 60
        assert response["trackingConfigArn"] == test_configs["tracking_arn"]
        assert len(response["dataflowEdges"]) == 1

    def test_get_nonexistent_mission_profile(self, provider, context):
        """Test getting a non-existent mission profile."""
        with pytest.raises(ResourceNotFoundException):
            provider.get_mission_profile(context=context, mission_profile_id="nonexistent-id")


class TestUpdateMissionProfile:
    """Tests for UpdateMissionProfile operation."""

    def test_update_mission_profile_name(self, provider, context, test_configs):
        """Test updating a mission profile name."""
        # Create a mission profile
        create_resp = provider.create_mission_profile(
            context=context,
            name="original-name",
            minimum_viable_contact_duration_seconds=60,
            contact_pre_pass_duration_seconds=120,
            contact_post_pass_duration_seconds=60,
            tracking_config_arn=test_configs["tracking_arn"],
            dataflow_edges=[[test_configs["tracking_arn"], test_configs["downlink_arn"]]],
        )
        mp_id = create_resp["missionProfileId"]

        # Update the name
        provider.update_mission_profile(
            context=context, mission_profile_id=mp_id, name="updated-name"
        )

        # Verify the update
        get_resp = provider.get_mission_profile(context=context, mission_profile_id=mp_id)
        assert get_resp["name"] == "updated-name"

    def test_update_mission_profile_duration(self, provider, context, test_configs):
        """Test updating mission profile durations."""
        # Create a mission profile
        create_resp = provider.create_mission_profile(
            context=context,
            name="test-mission",
            minimum_viable_contact_duration_seconds=60,
            contact_pre_pass_duration_seconds=120,
            contact_post_pass_duration_seconds=60,
            tracking_config_arn=test_configs["tracking_arn"],
            dataflow_edges=[[test_configs["tracking_arn"], test_configs["downlink_arn"]]],
        )
        mp_id = create_resp["missionProfileId"]

        # Update durations
        provider.update_mission_profile(
            context=context,
            mission_profile_id=mp_id,
            minimum_viable_contact_duration_seconds=90,
            contact_pre_pass_duration_seconds=180,
        )

        # Verify the updates
        get_resp = provider.get_mission_profile(context=context, mission_profile_id=mp_id)
        assert get_resp["minimumViableContactDurationSeconds"] == 90
        assert get_resp["contactPrePassDurationSeconds"] == 180


class TestDeleteMissionProfile:
    """Tests for DeleteMissionProfile operation."""

    def test_delete_unused_mission_profile(self, provider, context, test_configs):
        """Test deleting a mission profile with no contacts."""
        # Create a mission profile
        create_resp = provider.create_mission_profile(
            context=context,
            name="test-mission",
            minimum_viable_contact_duration_seconds=60,
            contact_pre_pass_duration_seconds=120,
            contact_post_pass_duration_seconds=60,
            tracking_config_arn=test_configs["tracking_arn"],
            dataflow_edges=[[test_configs["tracking_arn"], test_configs["downlink_arn"]]],
        )
        mp_id = create_resp["missionProfileId"]

        # Delete it
        response = provider.delete_mission_profile(context=context, mission_profile_id=mp_id)

        assert response["missionProfileId"] == mp_id
        assert mp_id not in groundstation_stores.mission_profiles

    def test_delete_mission_profile_with_active_contacts(self, provider, context, test_configs):
        """Test that deleting a mission profile with active contacts fails."""
        # Create a mission profile
        create_resp = provider.create_mission_profile(
            context=context,
            name="test-mission",
            minimum_viable_contact_duration_seconds=60,
            contact_pre_pass_duration_seconds=120,
            contact_post_pass_duration_seconds=60,
            tracking_config_arn=test_configs["tracking_arn"],
            dataflow_edges=[[test_configs["tracking_arn"], test_configs["downlink_arn"]]],
        )
        mp_id = create_resp["missionProfileId"]
        mp_arn = f"arn:aws:groundstation:us-east-1:000000000000:mission-profile/{mp_id}"

        # Reserve a contact
        start_time = datetime(2026, 12, 31, 12, 0, 0)
        end_time = datetime(2026, 12, 31, 13, 0, 0)

        provider.reserve_contact(
            context=context,
            mission_profile_arn=mp_arn,
            satellite_arn="arn:aws:groundstation:us-east-1:000000000000:satellite/11111111-1111-1111-1111-000000025544",
            start_time=start_time,
            end_time=end_time,
            ground_station="Ohio Ground Station",
        )

        # Try to delete the mission profile
        with pytest.raises(DependencyException) as exc:
            provider.delete_mission_profile(context=context, mission_profile_id=mp_id)

        assert "has active contacts" in str(exc.value)


class TestListMissionProfiles:
    """Tests for ListMissionProfiles operation."""

    def test_list_empty_mission_profiles(self, provider, context):
        """Test listing when no mission profiles exist."""
        response = provider.list_mission_profiles(context=context)

        assert response["missionProfileList"] == []

    def test_list_multiple_mission_profiles(self, provider, context, test_configs):
        """Test listing multiple mission profiles."""
        # Create several mission profiles
        for i in range(3):
            provider.create_mission_profile(
                context=context,
                name=f"mission-{i}",
                minimum_viable_contact_duration_seconds=60,
                contact_pre_pass_duration_seconds=120,
                contact_post_pass_duration_seconds=60,
                tracking_config_arn=test_configs["tracking_arn"],
                dataflow_edges=[[test_configs["tracking_arn"], test_configs["downlink_arn"]]],
            )

        # List all mission profiles
        response = provider.list_mission_profiles(context=context)

        assert len(response["missionProfileList"]) == 3
        names = [mp["name"] for mp in response["missionProfileList"]]
        assert "mission-0" in names
        assert "mission-1" in names
        assert "mission-2" in names
